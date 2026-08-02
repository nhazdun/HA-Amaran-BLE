"""Light platform for amaran BLE fixtures."""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_EFFECT,
    ColorMode,
    LightEntity,
    LightEntityFeature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import AmaranConfigEntry
from .amaran import protocol
from .const import (
    CONF_DEVICE_NAME,
    DEFAULT_KELVIN,
    DOMAIN,
    INTENSITY_MAX,
)
from .coordinator import AmaranCoordinator
from .mesh.session import MeshSessionError

_LOGGER = logging.getLogger(__name__)

EFFECT_NONE = "None"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AmaranConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the light for a config entry."""
    async_add_entities([AmaranLight(entry.runtime_data, entry)])


class AmaranLight(LightEntity):
    """A bi-colour amaran fixture controlled over Bluetooth mesh."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_color_mode = ColorMode.COLOR_TEMP
    _attr_supported_color_modes: ClassVar[set[ColorMode]] = {ColorMode.COLOR_TEMP}
    _attr_supported_features = LightEntityFeature.EFFECT

    def __init__(
        self, coordinator: AmaranCoordinator, entry: AmaranConfigEntry
    ) -> None:
        """Bind the entity to its coordinator."""
        self._coordinator = coordinator
        self._attr_unique_id = entry.unique_id or entry.entry_id
        self._attr_min_color_temp_kelvin = coordinator.min_kelvin
        self._attr_max_color_temp_kelvin = coordinator.max_kelvin
        self._attr_effect_list = [EFFECT_NONE, *protocol.VERGE_EFFECTS]

        product = coordinator.product
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.ble_address)},
            identifiers={(DOMAIN, entry.entry_id)},
            manufacturer=product.vendor if product else "amaran",
            model=product.name if product else "amaran fixture",
            name=entry.title,
            serial_number=entry.data.get(CONF_DEVICE_NAME, "").split("-")[-1] or None,
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

    # -- state -------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Whether the fixture is reachable."""
        return self._coordinator.state.available

    @property
    def is_on(self) -> bool:
        """Whether the fixture is on."""
        return self._coordinator.state.is_on

    @property
    def brightness(self) -> int | None:
        """Brightness on Home Assistant's 0-255 scale."""
        return round(self._coordinator.state.intensity * 255 / INTENSITY_MAX)

    @property
    def color_temp_kelvin(self) -> int | None:
        """Current colour temperature."""
        return self._coordinator.state.kelvin

    @property
    def effect(self) -> str:
        """Active effect, or ``None`` when running plain CCT."""
        return self._coordinator.state.effect or EFFECT_NONE

    # -- commands ----------------------------------------------------------

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on, optionally applying brightness, colour temp and effect."""
        state = self._coordinator.state

        if (brightness := kwargs.get(ATTR_BRIGHTNESS)) is not None:
            intensity = round(brightness * INTENSITY_MAX / 255)
        elif state.intensity > 0:
            intensity = state.intensity
        else:
            intensity = INTENSITY_MAX

        kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN, state.kelvin or DEFAULT_KELVIN)
        kelvin = min(
            max(kelvin, self.min_color_temp_kelvin), self.max_color_temp_kelvin
        )

        effect = kwargs.get(ATTR_EFFECT, state.effect or EFFECT_NONE)
        if effect == EFFECT_NONE:
            effect = None

        payloads: list[bytes] = []
        if not state.is_on:
            payloads.append(protocol.sleep(True))

        if effect is None:
            payloads.append(protocol.cct(intensity, kelvin // 10))
        else:
            payloads.append(protocol.build_effect(effect, intensity, kelvin // 10))

        await self._send(payloads)

        state.is_on = True
        state.intensity = intensity
        state.kelvin = kelvin
        state.effect = effect
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the fixture off."""
        await self._send([protocol.sleep(False)])
        self._coordinator.state.is_on = False
        self.async_write_ha_state()

    async def _send(self, payloads: list[bytes]) -> None:
        """Send payloads, translating mesh failures into HA errors."""
        try:
            for payload in payloads:
                await self._coordinator.async_send(payload)
        except MeshSessionError as err:
            raise HomeAssistantError(
                f"Failed to control {self.entity_id or 'amaran light'}: {err}"
            ) from err
