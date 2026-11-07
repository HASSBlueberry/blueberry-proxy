"""Local management API with a fixed command surface for the HA frontend."""
from __future__ import annotations
import asyncio
import re
from aiohttp import ClientResponseError
from urllib.parse import urlsplit

DOMAIN = 'blueberry_proxy'


def validate_url(value):
    value = value.strip().rstrip('/')
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Enter an HTTP or HTTPS proxy URL without credentials or a query')
    return value


class ProxyClient:
    def __init__(self, session, url, verify_ssl=True):
        self.session = session
        self.url = validate_url(url)
        self.ssl = None if verify_ssl else False

    async def request(self, path, body=None):
        async with self.session.request('GET' if body is None else 'POST', self.url + path,
                                        json=body, ssl=self.ssl, timeout=30) as response:
            response.raise_for_status()
            return await response.json()

    async def snapshot(self):
        stats, maps = await asyncio.gather(self.request('/stats'), self.request('/proxy/maps'))
        try:
            uscan = await self.request('/uscan?limit=200')
        except ClientResponseError as error:
            if error.status != 404:
                raise
            uscan = {}
        return {'stats': stats, 'maps': maps.get('maps', []), 'uscan': uscan}

    async def command(self, action, values, snapshot):
        if action == 'uscan_start':
            parameters = values.get('parameters', {})
            ids = values.get('scanner_ids')
            if not isinstance(parameters, dict) or ids is not None and not isinstance(ids, list):
                raise ValueError('Invalid scanner selection or parameters')
            return await self.request('/uscan/jobs', {'parameters': parameters, **({'scanner_ids': ids} if ids else {})})
        if action == 'uscan_cancel':
            job_id = str(values.get('job_id', ''))
            if not re.fullmatch(r'[a-f0-9-]{36}', job_id):
                raise ValueError('Invalid scan job ID')
            async with self.session.delete(self.url + '/uscan/jobs', params={'id': job_id}, ssl=self.ssl, timeout=10) as response:
                response.raise_for_status()
                return await response.json()
        if action == 'blocking':
            if not isinstance(values.get('enabled'), bool):
                raise ValueError('enabled must be a boolean')
            return await self.request('/settings', {'blocking-enabled': values['enabled']})
        if action == 'clear_cache':
            return await self.request('/cache/clear', {})
        if action == 'refresh_blocklists':
            return await self.request('/blocklists/refresh', {})
        if action == 'domain_rule':
            domain = str(values.get('domain', '')).strip().lower().rstrip('.')
            decision = values.get('decision')
            if len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
                raise ValueError('Enter a valid DNS domain')
            if decision not in ('passthrough', 'blackhole'):
                raise ValueError('Choose allow or block')
            return await self.request('/rules', {'id': 'dashboard-' + domain, 'match_type': 'exact', 'match': domain, 'action': decision, 'priority': 100})
        if action == 'toggle_map':
            maps = snapshot.get('maps', [])
            record = next((record for record in maps if str(record.get('id')) == values.get('map_id')), None)
            if record is None:
                raise ValueError('Unknown map')
            if not isinstance(values.get('enabled'), bool):
                raise ValueError('enabled must be a boolean')
            return await self.request('/proxy/maps', {**record, 'enabled': values['enabled']})
        raise ValueError('Unsupported command')
