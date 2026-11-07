import voluptuous as vol
from aiohttp import ClientError
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .client import DOMAIN, ProxyClient


class BlueberryProxyFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input:
            try:
                client = ProxyClient(async_get_clientsession(self.hass), user_input['url'], user_input.get('verify_ssl', True))
                status = await client.request('/status')
                if status.get('name') != 'blueberryProxy':
                    raise ValueError('Not BlueberryProxy')
                await client.snapshot()
                async with client.session.ws_connect(client.url + '/events', ssl=client.ssl, timeout=10) as socket:
                    await socket.close()
                await self.async_set_unique_id(client.url.lower())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title='BlueberryProxy', data={**user_input, 'url': client.url})
            except (ClientError, TimeoutError, ValueError, KeyError):
                errors['base'] = 'cannot_connect'
        return self.async_show_form(step_id='user', data_schema=vol.Schema({
            vol.Required('url', default='http://127.0.0.1:8055'): str,
            vol.Optional('verify_ssl', default=True): bool,
        }), errors=errors)
