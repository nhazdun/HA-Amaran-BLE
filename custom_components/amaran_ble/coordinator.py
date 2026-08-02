"""Connection coordinator for a provisioned amaran fixture."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .amaran import protocol
from .amaran.products import Product
from .const import (
    CONF_CONFIGURED,
    CONF_DEV_KEY,
    CONF_SEQUENCE,
    CONF_VENDOR_MODELS,
    DOMAIN,
    PROVISIONER_ADDRESS,
    SEQUENCE_PERSIST_INTERVAL,
    SEQUENCE_RESTART_MARGIN,
)
from .mesh.session import MeshCredentials, MeshSession, MeshSessionError

_LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 25.0
COMMAND_RETRIES = 2


@dataclass(slots=True)
class LightState:
    """Locally tracked state of the fixture.

    amaran fixtures do not push unsolicited status, so this is optimistic:
    it reflects what we last commanded, updated by any status frame the
    fixture happens to send back.
    """

    is_on: bool = False
    intensity: int = 0  # tenths of a percent, 0-1000
    kelvin: int = 5600
    effect: str | None = None
    available: bool = False
    #: Extra attributes reported by the fixture, if it ever answers.
    reported: dict[str, int] = field(default_factory=dict)


class AmaranCoordinator:
    """Owns the BLE link and mesh session for one fixture."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        credentials: MeshCredentials,
        node_address: int,
        ble_address: str,
        product: Product | None,
    ) -> None:
        """Set up the coordinator without connecting yet."""
        self.hass = hass
        self.entry = entry
        self.credentials = credentials
        self.node_address = node_address
        self.ble_address = ble_address
        self.product = product
        self.state = LightState()

        self._session: MeshSession | None = None
        self._client: BleakClientWithServiceCache | None = None
        self._lock = asyncio.Lock()
        self._persist_countdown = SEQUENCE_PERSIST_INTERVAL
        self._closing = False

    @property
    def signal_update(self) -> str:
        """Dispatcher signal fired when the tracked state changes."""
        return f"{DOMAIN}_{self.entry.entry_id}_update"

    @property
    def min_kelvin(self) -> int:
        """Lowest colour temperature the fixture supports."""
        if self.product and self.product.cct_min:
            return self.product.min_kelvin
        return 2700

    @property
    def max_kelvin(self) -> int:
        """Highest colour temperature the fixture supports."""
        if self.product and self.product.cct_max:
            return self.product.max_kelvin
        return 6500

    # -- connection --------------------------------------------------------

    async def async_start(self) -> None:
        """Bring the link up, tolerating a fixture that is currently away."""
        try:
            async with self._lock:
                await self._ensure_connected()
                await self._ensure_configured()
        except (MeshSessionError, TimeoutError, OSError) as err:
            _LOGGER.debug("initial connect to %s failed: %s", self.ble_address, err)

    async def _ensure_configured(self) -> None:
        """Add and bind the AppKey if the config flow could not finish that.

        Provisioning is irreversible but configuration is not, so a fixture
        can end up provisioned yet unconfigured. Retrying here means such a
        fixture recovers on its own instead of needing a factory reset.
        """
        if self.entry.data.get(CONF_CONFIGURED) or self._session is None:
            return

        dev_key = bytes.fromhex(self.entry.data[CONF_DEV_KEY])
        session = self._session
        _LOGGER.debug("completing deferred configuration for 0x%04x", self.node_address)

        composition = await session.get_composition_data(self.node_address, dev_key)
        await session.add_app_key(self.node_address, dev_key)

        vendor_models: list[list[int]] = []
        for element in composition.elements:
            for company_id, model_id in element.vendor_models:
                await session.bind_model(
                    self.node_address,
                    dev_key,
                    element.address,
                    model_id,
                    company_id=company_id,
                )
                vendor_models.append([company_id, model_id])

        self.hass.config_entries.async_update_entry(
            self.entry,
            data={
                **self.entry.data,
                CONF_VENDOR_MODELS: vendor_models,
                CONF_CONFIGURED: True,
            },
        )
        _LOGGER.info(
            "configuration complete for 0x%04x, bound %d vendor model(s)",
            self.node_address,
            len(vendor_models),
        )

    async def async_stop(self) -> None:
        """Disconnect and persist the sequence number."""
        self._closing = True
        async with self._lock:
            await self._teardown()
        self._persist_sequence(force=True)

    async def _ensure_connected(self) -> MeshSession:
        if self._session is not None and self._client and self._client.is_connected:
            return self._session

        await self._teardown()

        device = bluetooth.async_ble_device_from_address(
            self.hass, self.ble_address, connectable=True
        )
        if device is None:
            raise MeshSessionError(f"{self.ble_address} is not in range")

        self._client = await establish_connection(
            BleakClientWithServiceCache,
            device,
            f"{DOMAIN}-{self.ble_address}",
            self._on_disconnect,
            timeout=CONNECT_TIMEOUT,
        )

        session = MeshSession(
            self._client,
            self.credentials,
            sequence=self.entry.data.get(CONF_SEQUENCE, 0) + SEQUENCE_RESTART_MARGIN,
            on_message=self._on_mesh_message,
        )
        await session.start()
        try:
            await session.set_proxy_filter([PROVISIONER_ADDRESS])
        except Exception as err:  # noqa: BLE001 - optional optimisation
            _LOGGER.debug("proxy filter setup failed (continuing): %s", err)

        self._session = session
        self._set_available(True)
        return session

    async def _teardown(self) -> None:
        if self._session is not None:
            await self._session.stop()
            self._session = None
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as err:  # noqa: BLE001 - best effort
                _LOGGER.debug("disconnect failed: %s", err)
            self._client = None

    @callback
    def _on_disconnect(self, _client: BleakClientWithServiceCache) -> None:
        """Handle an unexpected link drop."""
        self._session = None
        if not self._closing:
            _LOGGER.debug("%s disconnected", self.ble_address)
            self._set_available(False)

    @callback
    def _on_mesh_message(self, src: int, opcode: int, params: bytes) -> None:
        """Absorb a status frame from the fixture."""
        if src != self.node_address or opcode != protocol.VENDOR_OPCODE:
            return
        if len(params) != protocol.PAYLOAD_BYTES:
            return

        command = protocol.command_of(params)
        if command == protocol.Command.CCT:
            parsed = protocol.parse_cct(params)
            self.state.intensity = parsed["intensity"]
            self.state.kelvin = parsed["cct"] * 10
            self.state.is_on = bool(parsed["sleep_mode"]) and parsed["intensity"] > 0
            self.state.reported = parsed
        elif command == protocol.Command.SLEEP:
            self.state.is_on = bool(protocol.parse_sleep(params))
        else:
            return

        self._notify()

    # -- commands ----------------------------------------------------------

    async def async_send(self, payload: bytes) -> None:
        """Send one vendor payload, reconnecting once if the link dropped."""
        last_error: Exception | None = None

        for attempt in range(COMMAND_RETRIES):
            async with self._lock:
                try:
                    session = await self._ensure_connected()
                    await session.send_access(
                        self.node_address, protocol.VENDOR_OPCODE, payload
                    )
                except (MeshSessionError, TimeoutError, OSError, EOFError) as err:
                    last_error = err
                    _LOGGER.debug(
                        "send to %s failed (attempt %d/%d): %s",
                        self.ble_address,
                        attempt + 1,
                        COMMAND_RETRIES,
                        err,
                    )
                    await self._teardown()
                    continue
                else:
                    self._track_sequence(session)
                    self._set_available(True)
                    return

        self._set_available(False)
        raise MeshSessionError(
            f"could not reach {self.ble_address}: {last_error}"
        ) from last_error

    def _track_sequence(self, session: MeshSession) -> None:
        """Persist the sequence number occasionally so restarts stay valid."""
        self._persist_countdown -= 1
        if self._persist_countdown <= 0:
            self._persist_countdown = SEQUENCE_PERSIST_INTERVAL
            self._persist_sequence(session=session)

    def _persist_sequence(
        self, *, session: MeshSession | None = None, force: bool = False
    ) -> None:
        session = session or self._session
        if session is None:
            return
        current = session.sequence
        if not force and self.entry.data.get(CONF_SEQUENCE, 0) >= current:
            return
        self.hass.config_entries.async_update_entry(
            self.entry, data={**self.entry.data, CONF_SEQUENCE: current}
        )

    def _set_available(self, available: bool) -> None:
        if self.state.available != available:
            self.state.available = available
            self._notify()

    def _notify(self) -> None:
        async_dispatcher_send(self.hass, self.signal_update)
