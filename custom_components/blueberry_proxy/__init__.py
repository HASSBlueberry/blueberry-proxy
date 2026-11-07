"""Authenticated HA frontend bridge for a local BlueberryProxy instance."""
from __future__ import annotations
import asyncio
from collections import deque
from datetime import timedelta
import json
import logging
from pathlib import Path

import voluptuous as vol
from aiohttp import ClientError, WSMsgType
from homeassistant.components import frontend, websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .client import DOMAIN, ProxyClient

_LOGGER = logging.getLogger(__name__)
CARD_URL = '/blueberry_proxy/blueberry-proxy-card.js?v=0.1.0'


async def async_setup(hass, config):
    if DOMAIN in hass.data:
        return True
    hass.data[DOMAIN] = {'entries': {}}
    path = str(Path(__file__).parent / 'frontend' / 'blueberry-proxy-card.js')
    await hass.http.async_register_static_paths([StaticPathConfig('/blueberry_proxy/blueberry-proxy-card.js', path, False)])
    frontend.add_extra_js_url(hass, CARD_URL)
    for command in (ws_entries, ws_subscribe, ws_command):
        websocket_api.async_register_command(hass, command)
    return True


def broadcast(runtime, message):
    for callback in tuple(runtime['callbacks']):
        callback(message)


async def stream(runtime):
    client = runtime['client']
    pending = deque(maxlen=100)
    flush_handle = None
    backoff = 1
    def flush():
        nonlocal flush_handle
        flush_handle = None
        events = list(pending)
        pending.clear()
        if events:
            broadcast(runtime, {'kind': 'flow', 'events': events})
    try:
        while runtime['running']:
            try:
                async with client.session.ws_connect(client.url + '/events', ssl=client.ssl, heartbeat=20, timeout=10) as websocket:
                    backoff = 1
                    broadcast(runtime, {'kind': 'stream', 'connected': True})
                    async for message in websocket:
                        if message.type != WSMsgType.TEXT:
                            continue
                        try:
                            event = json.loads(message.data)
                        except (ValueError, TypeError):
                            continue
                        if not isinstance(event, dict) or event.get('type') not in ('dns', 'request', 'response', 'discovery', 'scan'):
                            continue
                        if event.get('type') == 'discovery':
                            runtime['hass'].bus.async_fire('blueberry_proxy_discovery', {'entry_id': runtime['entry_id'], **event})
                        elif event.get('type') == 'scan':
                            runtime['hass'].bus.async_fire('blueberry_proxy_scan', {'entry_id': runtime['entry_id'], **event})
                        pending.append(event)
                        if flush_handle is None:
                            flush_handle = asyncio.get_running_loop().call_later(0.25, flush)
            except (ClientError, TimeoutError, OSError):
                pass
            broadcast(runtime, {'kind': 'stream', 'connected': False})
            await asyncio.sleep(backoff)
            backoff = min(30, backoff * 2)
    finally:
        if flush_handle:
            flush_handle.cancel()


async def async_setup_entry(hass, entry):
    client = ProxyClient(async_get_clientsession(hass), entry.data['url'], entry.data.get('verify_ssl', True))
    async def update():
        try:
            return await client.snapshot()
        except (ClientError, TimeoutError, ValueError) as err:
            raise UpdateFailed('Cannot reach BlueberryProxy') from err
    coordinator = DataUpdateCoordinator(hass, _LOGGER, name='BlueberryProxy', update_method=update,
                                        update_interval=timedelta(seconds=5))
    await coordinator.async_config_entry_first_refresh()
    hass.data[DOMAIN]['entries'][entry.entry_id] = {
        'client': client, 'coordinator': coordinator, 'callbacks': set(), 'unsubscribers': set(), 'task': None, 'title': entry.title,
        'hass': hass, 'entry_id': entry.entry_id, 'running': True,
    }
    runtime = hass.data[DOMAIN]['entries'][entry.entry_id]
    runtime['task'] = hass.async_create_background_task(stream(runtime), 'BlueberryProxy discovery events')
    return True


async def async_unload_entry(hass, entry):
    runtime = hass.data[DOMAIN]['entries'].pop(entry.entry_id, None)
    if runtime:
        broadcast(runtime, {'kind': 'stream', 'connected': False, 'unloaded': True})
        runtime['running'] = False
        task = runtime['task']
        for unsubscribe in tuple(runtime['unsubscribers']):
            unsubscribe()
        runtime['callbacks'].clear()
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    return True


def admin_runtime(hass, connection, msg):
    if not connection.user or not connection.user.is_admin:
        connection.send_error(msg['id'], 'unauthorized', 'Administrator access required')
        return None
    runtime = hass.data[DOMAIN]['entries'].get(msg['entry_id'])
    if runtime is None:
        connection.send_error(msg['id'], 'not_found', 'BlueberryProxy is not configured or is unavailable')
    return runtime


@websocket_api.websocket_command({vol.Required('type'): 'blueberry_proxy/entries'})
@websocket_api.async_response
async def ws_entries(hass, connection, msg):
    if not connection.user or not connection.user.is_admin:
        connection.send_error(msg['id'], 'unauthorized', 'Administrator access required')
        return
    connection.send_result(msg['id'], [{'entry_id': key, 'title': runtime['title']}
                                      for key, runtime in hass.data[DOMAIN]['entries'].items()])


@websocket_api.websocket_command({vol.Required('type'): 'blueberry_proxy/subscribe', vol.Required('entry_id'): str})
@websocket_api.async_response
async def ws_subscribe(hass, connection, msg):
    runtime = admin_runtime(hass, connection, msg)
    if runtime is None:
        return
    def send(event):
        connection.send_event(msg['id'], event)
    def snapshot():
        send({'kind': 'snapshot', 'data': runtime['coordinator'].data,
              'available': runtime['coordinator'].last_update_success})
    remove_listener = runtime['coordinator'].async_add_listener(snapshot)
    runtime['callbacks'].add(send)
    active = True
    def unsubscribe():
        nonlocal active
        if not active:
            return
        active = False
        runtime['unsubscribers'].discard(unsubscribe)
        remove_listener()
        runtime['callbacks'].discard(send)
    runtime['unsubscribers'].add(unsubscribe)
    connection.subscriptions[msg['id']] = unsubscribe
    connection.send_result(msg['id'])
    snapshot()
    if runtime['task'] is None or runtime['task'].done():
        runtime['task'] = hass.async_create_background_task(stream(runtime), 'BlueberryProxy event stream')


@websocket_api.websocket_command({
    vol.Required('type'): 'blueberry_proxy/command', vol.Required('entry_id'): str,
    vol.Required('action'): vol.In(['blocking', 'clear_cache', 'refresh_blocklists', 'domain_rule', 'toggle_map', 'uscan_start', 'uscan_cancel']),
    vol.Optional('values', default={}): dict,
})
@websocket_api.async_response
async def ws_command(hass, connection, msg):
    runtime = admin_runtime(hass, connection, msg)
    if runtime is None:
        return
    try:
        result = await runtime['client'].command(msg['action'], msg['values'], runtime['coordinator'].data or {})
        await runtime['coordinator'].async_request_refresh()
        connection.send_result(msg['id'], result)
    except (ClientError, TimeoutError, ValueError) as err:
        connection.send_error(msg['id'], 'command_failed', 'BlueberryProxy command failed. Check its connection and the supplied values.')
