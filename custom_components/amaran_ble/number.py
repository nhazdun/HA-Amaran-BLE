"""Number platform: effect speed."""

from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
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
    """Set up number entities."""
    async_add_entities([AmaranEffectSpeed(entry.runtime_data, entry)])


class AmaranEffectSpeed(AmaranEntity, NumberEntity):
    """Frequency field applied to whichever system effect is running."""

    _attr_translation_key = "effect_speed"
    _attr_name = "Effect speed"
    _attr_icon = "mdi:speedometer"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_mode = NumberMode.SLIDER
    _attr_native_min_value = float(protocol.EFFECT_SPEED_MIN)
    _attr_native_max_value = float(protocol.EFFECT_SPEED_MAX)
    _attr_native_step = 1.0

    def __init__(self, coordinator, entry) -> None:
        """Set the unique id."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_effect_speed"

    @property
    def native_value(self) -> float:
        """Current effect speed."""
        return float(self._coordinator.state.effect_speed)

    async def async_set_native_value(self, value: float) -> None:
        """Store the speed and re-send the running effect so it takes hold."""
        state = self._coordinator.state
        state.effect_speed = int(value)

        if state.is_on and state.effect:
            await self._send(
                protocol.build_effect(
                    state.effect,
                    state.intensity,
                    state.kelvin // 10,
                    frq=state.effect_speed,
                )
            )
        self.async_write_ha_state()
