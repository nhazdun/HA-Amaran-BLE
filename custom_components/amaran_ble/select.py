"""Select platform: dimming curve."""

from __future__ import annotations

from typing import ClassVar

from homeassistant.components.select import SelectEntity
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
    """Set up select entities."""
    async_add_entities([AmaranDimmingCurve(entry.runtime_data, entry)])


class AmaranDimmingCurve(AmaranEntity, SelectEntity):
    """How the fixture maps a brightness value onto actual output."""

    _attr_translation_key = "dimming_curve"
    _attr_name = "Dimming curve"
    _attr_icon = "mdi:chart-bell-curve-cumulative"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options: ClassVar[list[str]] = list(protocol.DIMMING_CURVE_NAMES)

    def __init__(self, coordinator, entry) -> None:
        """Set the unique id."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_dimming_curve"

    @property
    def current_option(self) -> str | None:
        """Currently selected curve."""
        current = self._coordinator.state.dimming_curve
        for name, value in protocol.DIMMING_CURVE_NAMES.items():
            if value == current:
                return name
        return None

    async def async_select_option(self, option: str) -> None:
        """Apply a dimming curve."""
        curve = protocol.DIMMING_CURVE_NAMES[option]
        await self._send(protocol.dimming_curve(int(curve)))
        self._coordinator.state.dimming_curve = int(curve)
        self.async_write_ha_state()
