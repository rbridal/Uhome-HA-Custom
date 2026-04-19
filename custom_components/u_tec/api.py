"""API for Uhome bound to Home Assistant OAuth."""

import json
import logging
import secrets
from datetime import timedelta

from aiohttp import ClientSession, web

from homeassistant.components import webhook, cloud
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_entry_oauth2_flow, network
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.network import NoURLAvailableError
from utec_py.api import AbstractAuth, UHomeApi
from utec_py.exceptions import ApiError, UHomeError

from .const import DOMAIN, WEBHOOK_HANDLER, WEBHOOK_ID_PREFIX

_LOGGER = logging.getLogger(__name__)

# Re-register the webhook with a fresh secret every 24 hours
_REREGISTER_INTERVAL = timedelta(hours=24)


class AsyncConfigEntryAuth(AbstractAuth):
    """Provide Uhome Oauth2 authentication tied to an OAuth2 based config entry."""

    def __init__(
        self,
        websession: ClientSession,
        oauth_session: config_entry_oauth2_flow.OAuth2Session,
    ) -> None:
        """Initialize Oauth2 auth."""
        super().__init__(websession)
        self._oauth_session = oauth_session

    async def async_get_access_token(self) -> str:
        """Return a valid access token."""
        await self._oauth_session.async_ensure_token_valid()
        return self._oauth_session.token["access_token"]


class AsyncPushUpdateHandler:
    """Handle webhook registration and processing for Uhome API."""

    def __init__(self, hass: HomeAssistant, api: UHomeApi, entry_id: str) -> None:
        """Initialize the webhook handler."""
        self.hass = hass
        self.entry_id = entry_id
        self.webhook_id = f"{WEBHOOK_ID_PREFIX}{entry_id}"
        self.webhook_url = None
        self._unregister_webhook = None
        self._cancel_reregister = None
        self._push_secret: str | None = None
        self.api = api
        self._auth_data = None

    def _generate_secret(self) -> str:
        """Generate a fresh random secret token for push validation."""
        return secrets.token_urlsafe(32)

    async def async_register_webhook(self, auth_data) -> bool:
        """Register webhook with Home Assistant and the Uhome API."""
        self._auth_data = auth_data

        if cloud.async_active_subscription(self.hass):
            webhook_url = await cloud.async_get_or_create_cloudhook(
                self.hass, 
                self.webhook_id,
            )
            cloudhook = True
        else:
            webhook_url = webhook.async_generate_url(
                self.hass, 
                self.webhook_id,
                allow_internal=False,
                allow_ip=False,
                allow_external=True,
            )
            cloudhook = False

        if webhook_url:
            _LOGGER.debug(
                "Resolved webhook base URL: %s (cloud=%s)",
                webhook_url, cloudhook,
            )
        else:
            _LOGGER.warning(
                "Could not resolve webhook URL to an external address"
            )
            return False

        # Generate a fresh secret for this registration
        self._push_secret = self._generate_secret()
        _LOGGER.debug("Generated new push secret for webhook registration")

        try:
            _LOGGER.debug("Registering webhook URL: %s", webhook_url)
            result = await self.api.set_push_status(webhook_url, self._push_secret)
            _LOGGER.debug("Webhook registration result: %s", result)
        except ApiError as err:
            _LOGGER.error("Failed to register webhook with U-Tec API: %s", err)
            return False

        # Register HA-side webhook handler (only once)
        if not self._unregister_webhook:
            self._unregister_webhook = webhook.async_register(
                self.hass,
                DOMAIN,
                WEBHOOK_HANDLER,
                self.webhook_id,
                self._handle_webhook,
            )

        self.webhook_url = webhook_url
        self.cloudhook = cloudhook

        # Schedule daily re-registration with a fresh secret
        if self._cancel_reregister:
            self._cancel_reregister()
        self._cancel_reregister = async_track_time_interval(
            self.hass,
            self._async_reregister,
            _REREGISTER_INTERVAL,
        )
        _LOGGER.debug("Scheduled daily webhook re-registration")

        return True

    @callback
    def _async_reregister(self, _now) -> None:
        """Trigger webhook re-registration with a fresh secret (called by scheduler)."""
        _LOGGER.debug("Daily webhook re-registration triggered")
        self.hass.async_create_task(
            self.async_register_webhook(self._auth_data)
        )

    async def unregister_webhook(self) -> None:
        """Unregister the webhook and cancel the re-registration scheduler."""
        if self._cancel_reregister:
            self._cancel_reregister()
            self._cancel_reregister = None
        if self._unregister_webhook:
            webhook.async_unregister(self.hass, self.webhook_id)
            self._unregister_webhook = None
            _LOGGER.debug("Unregistered webhook %s", self.webhook_id)

    async def _handle_webhook(
        self, hass: HomeAssistant, webhook_id, request
    ) -> web.Response | None:
        """Handle webhook callback."""
        _LOGGER.debug("Handling incoming push request")

        try:
            if request.method != "POST":
                _LOGGER.warning("Unsupported method: %s", request.method)
                return web.Response(status=405)

            try:
                data = await request.json()
            except ValueError:
                _LOGGER.warning("Invalid JSON payload")
                return empty_okay_response(status=400)

            if self._push_secret is None:
                _LOGGER.error("HA side push secret not set")
                return web.Response(status=500)
        
            auth_header = request.headers.get("Authorization", "")
            incoming_token = auth_header.removeprefix("Bearer ").strip()
        
            if not incoming_token:
                _LOGGER.warning("Webhook received with no authorization header")
                return web.Response(status=401)
            
            if not secrets.compare_digest(incoming_token, self._push_secret):
                _LOGGER.error("Webhook received with invalid Bearer token")
                return web.Response(status=403)

            _LOGGER.debug("Push request authenticated successfully")

            if self.entry_id not in hass.data.get(DOMAIN, {}):
                _LOGGER.error("Unknown entry_id in webhook: %s", self.entry_id)
                return web.Response(status=404)

            coordinator = hass.data[DOMAIN][self.entry_id]["coordinator"]
            await coordinator.update_push_data(data)

        except UHomeError as err:
            _LOGGER.error("Error processing webhook: %s", err)
            return web.json_response({"success": False, "error": str(err)}, status=400)
            
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Unexpected error processing webhook: %s", err)
            return web.json_response({"success": False, "error": "Internal error"}, status=500)
            
        else:
            return web.json_response({"success": True})
