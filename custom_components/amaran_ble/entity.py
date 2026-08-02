"""Shared entity base for amaran fixtures."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity

from .const import CONF_DEVICE_NAME, DOMAIN
from .coordinator import AmaranCoordinator
from .mesh.session import MeshSessionError


class AmaranEntity(Entity):
    """Common device info, availability and update plumbing."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator: AmaranCoordinator, entry: ConfigEntry) -> None:
        """Bind the entity to its coordinator."""
        self._coordinator = coordinator
        self._entry = entry

        product = coordinator.product
        serial = entry.data.get(CONF_DEVICE_NAME, "").split("-")[-1] or None
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.ble_address)},
            identifiers={(DOMAIN, entry.entry_id)},
            manufacturer=product.vendor if product else "amaran",
            model=product.name if product else "amaran fixture",
            name=entry.title,
            serial_number=serial,
        )

    async def async_added_to_hass(self) -> None:
        """Subscribe to coordinator updates."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, self._coordinator.signal_update, self._handle_update
            )
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Whether the fixture is reachable."""
        return self._coordinator.state.available

    async def _send(self, *payloads: bytes) -> None:
        """Send payloads, translating mesh failures into HA errors."""
        try:
            for payload in payloads:
                await self._coordinator.async_send(payload)
        except MeshSessionError as err:
            raise HomeAssistantError(
                f"Failed to control {self.entity_id or 'amaran fixture'}: {err}"
            ) from err
