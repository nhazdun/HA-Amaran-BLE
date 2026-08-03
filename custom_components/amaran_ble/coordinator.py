"""Connection coordinator for a provisioned amaran fixture."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothServiceInfoBleak,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval

from .amaran import protocol
from .amaran.products import Product
from .const import (
    CONF_CONFIGURED,
    CONF_DEV_KEY,
    CONF_SEQUENCE,
    CONF_SEQUENCE_RESERVED,
    CONF_VENDOR_MODELS,
    DOMAIN,
    PROVISIONER_ADDRESS,
    SEQUENCE_BLOCK,
    SEQUENCE_HEADROOM,
    SEQUENCE_RECOVERY_JUMP,
)
from .mesh.session import MeshCredentials, MeshSession, MeshSessionError

_LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 25.0
COMMAND_RETRIES = 2
#: How long to wait for a power report before concluding the model sends none.
POWER_PROBE_TICKS = 10
POWER_PROBE_INTERVAL = 0.3
#: Backstop reconnect poll, for when the fixture stops advertising entirely.
RECONNECT_INTERVAL = timedelta(seconds=60)


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
    #: 4-bit frequency field applied to whichever system effect is running.
    effect_speed: int = protocol.EFFECT_SPEED_DEFAULT
    #: Dimming response curve currently selected on the fixture.
    dimming_curve: int = int(protocol.DimmingCurve.LINEAR)
    #: Latest power/battery report, empty until the fixture answers one.
    power: dict[str, int] = field(default_factory=dict)


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
        self._sequence_ceiling = 0
        self._closing = False
        self._reconnecting = False
        self._unsubscribe: list[Callable[[], None]] = []

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
        """Bring the link up and keep it up."""
        self._unsubscribe.append(
            bluetooth.async_register_callback(
                self.hass,
                self._on_advertisement,
                BluetoothCallbackMatcher(address=self.ble_address, connectable=True),
                bluetooth.BluetoothScanningMode.ACTIVE,
            )
        )
        self._unsubscribe.append(
            async_track_time_interval(
                self.hass, self._reconnect_tick, RECONNECT_INTERVAL
            )
        )

        try:
            async with self._lock:
                await self._ensure_connected()
                await self._ensure_configured()
        except (MeshSessionError, TimeoutError, OSError) as err:
            _LOGGER.debug("initial connect to %s failed: %s", self.ble_address, err)
            self._refresh_availability()
            return

        await self._probe_power()

    async def _probe_power(self) -> None:
        """Ask once for a power report, to learn whether this model sends them.

        Mains-only fixtures such as the Verge never answer. Platforms use the
        result to decide whether battery sensors are worth creating at all,
        rather than showing a row of permanently unknown values.
        """
        await self.async_refresh_power()
        for _ in range(POWER_PROBE_TICKS):
            if self.state.power:
                return
            await asyncio.sleep(POWER_PROBE_INTERVAL)
        _LOGGER.debug("%s did not report power; no battery sensors", self.ble_address)

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
        """Disconnect and stop reconnect handling."""
        self._closing = True
        while self._unsubscribe:
            self._unsubscribe.pop()()
        async with self._lock:
            await self._teardown()

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
            sequence=self._reserve_sequence(),
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
        """Handle a link drop and line up a reconnect.

        Fixtures and Bluetooth proxies both drop idle links, so a disconnect
        is routine rather than an error. Availability follows whether the
        fixture is in range, not whether we happen to be holding a GATT link -
        otherwise the entity greys out and the user cannot even issue the
        command that would reconnect it.
        """
        self._session = None
        if self._closing:
            return
        _LOGGER.debug("%s disconnected", self.ble_address)
        self._refresh_availability()
        self._schedule_reconnect()

    @callback
    def _on_advertisement(
        self, service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        """Reconnect on hearing the fixture advertise, since it is reachable."""
        self._refresh_availability()
        if self._session is None:
            self._schedule_reconnect()

    @callback
    def _refresh_availability(self) -> None:
        """Available means in range, whether or not a link is currently up."""
        present = bluetooth.async_address_present(
            self.hass, self.ble_address, connectable=True
        )
        self._set_available(present or self._session is not None)

    @callback
    def _schedule_reconnect(self) -> None:
        """Reconnect in the background, at most one attempt at a time."""
        if self._closing or self._reconnecting:
            return
        self._reconnecting = True
        self.hass.async_create_background_task(
            self._async_reconnect(), f"{DOMAIN} reconnect {self.ble_address}"
        )

    async def _async_reconnect(self) -> None:
        try:
            async with self._lock:
                if self._closing or self._session is not None:
                    return
                await self._ensure_connected()
                await self._ensure_configured()
        except (MeshSessionError, TimeoutError, OSError) as err:
            _LOGGER.debug("reconnect to %s failed: %s", self.ble_address, err)
        except Exception as err:  # noqa: BLE001 - a background task must not die
            _LOGGER.debug("reconnect to %s errored: %s", self.ble_address, err)
        finally:
            self._reconnecting = False
            self._refresh_availability()

    @callback
    def _reconnect_tick(self, _now: datetime) -> None:
        """Periodic backstop for when no advertisement arrives."""
        if self._session is None:
            self._schedule_reconnect()
        else:
            self._refresh_availability()

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
        elif command == protocol.Command.SLEEP:
            self.state.is_on = bool(protocol.parse_sleep(params))
        elif command == protocol.Command.GET_POWER:
            self.state.power = protocol.parse_power(params)
            _LOGGER.debug("power report: %s", self.state.power)
        else:
            return

        self.notify()

    async def async_refresh_power(self) -> None:
        """Ask the fixture for a battery/power report.

        Not every fixture answers - mains-only models simply stay silent - so
        this is fire-and-forget and any reply lands via ``_on_mesh_message``.
        """
        try:
            await self.async_send(protocol.get_power())
        except MeshSessionError as err:
            _LOGGER.debug("power query failed: %s", err)

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

    def _reserve_sequence(self) -> int:
        """Claim a block of sequence numbers and return the first of them.

        A mesh node remembers the highest sequence number it has seen from us
        and silently drops anything at or below it. Persisting the counter
        periodically is not enough: a session that sends fewer messages than
        the persist interval stores nothing, so the next session restarts on
        numbers the node has already seen and every command is discarded with
        no error anywhere.

        Reserving up front makes that impossible - the stored value is the
        ceiling we may use, written before the first message goes out, so even
        an unclean shutdown can only ever waste numbers, never repeat them.
        """
        stored = self.entry.data.get(CONF_SEQUENCE, 0)
        if not self.entry.data.get(CONF_SEQUENCE_RESERVED):
            # Migrating off the old lazily-persisted counter: the node may have
            # retired numbers above the stored value, so skip clear of them.
            stored += SEQUENCE_RECOVERY_JUMP
            _LOGGER.debug("migrating sequence counter, skipping to %d", stored)

        start = stored + 1
        self._sequence_ceiling = start + SEQUENCE_BLOCK
        self.hass.config_entries.async_update_entry(
            self.entry,
            data={
                **self.entry.data,
                CONF_SEQUENCE: self._sequence_ceiling,
                CONF_SEQUENCE_RESERVED: True,
            },
        )
        _LOGGER.debug("reserved sequence numbers %d-%d", start, self._sequence_ceiling)
        return start

    def _track_sequence(self, session: MeshSession) -> None:
        """Reserve another block before the current one runs out."""
        if session.sequence >= self._sequence_ceiling - SEQUENCE_HEADROOM:
            self._sequence_ceiling = session.sequence + SEQUENCE_BLOCK
            self.hass.config_entries.async_update_entry(
                self.entry,
                data={**self.entry.data, CONF_SEQUENCE: self._sequence_ceiling},
            )
            _LOGGER.debug("extended sequence reservation to %d", self._sequence_ceiling)

    def _set_available(self, available: bool) -> None:
        if self.state.available != available:
            self.state.available = available
            self.notify()

    def notify(self) -> None:
        """Tell every entity of this fixture to re-read the tracked state."""
        async_dispatcher_send(self.hass, self.signal_update)
