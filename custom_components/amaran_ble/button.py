"""Button platform: identify and refresh power."""

from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import AmaranConfigEntry
from .amaran import protocol
from .entity import AmaranEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AmaranConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up button entities."""
    coordinator = entry.runtime_data
    async_add_entities(
        [
            AmaranIdentifyButton(coordinator, entry),
            AmaranRefreshPowerButton(coordinator, entry),
        ]
    )


class AmaranIdentifyButton(AmaranEntity, ButtonEntity):
    """Flash the fixture so it can be picked out of a rig."""

    _attr_translation_key = "identify"
    _attr_name = "Identify"
    _attr_device_class = ButtonDeviceClass.IDENTIFY
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry) -> None:
        """Set the unique id."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_identify"

    async def async_press(self) -> None:
        """Run the fixture's "I am here" effect."""
        await self._send(protocol.identify(True))


class AmaranRefreshPowerButton(AmaranEntity, ButtonEntity):
    """Ask the fixture for a fresh battery/power report."""

    _attr_translation_key = "refresh_power"
    _attr_name = "Refresh power"
    _attr_icon = "mdi:refresh"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, entry) -> None:
        """Set the unique id."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_refresh_power"

    async def async_press(self) -> None:
        """Send a power query."""
        await self._coordinator.async_refresh_power()
