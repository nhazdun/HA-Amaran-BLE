"""Sensor platform: battery and power reporting.

amaran fixtures answer a power query (command 10) only if they have a battery
or can measure their supply; mains-only models stay silent. These sensors
therefore report ``None`` until the fixture actually sends a report.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    UnitOfElectricPotential,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import AmaranConfigEntry
from .entity import AmaranEntity


@dataclass(frozen=True, kw_only=True)
class AmaranSensorDescription(SensorEntityDescription):
    """Describes an amaran power sensor."""

    value_fn: Callable[[dict[str, int]], float | None]


def _scaled(key: str, factor: float) -> Callable[[dict[str, int]], float | None]:
    """Read a key from the power report, scaled, or None when absent."""

    def _get(power: dict[str, int]) -> float | None:
        if key not in power:
            return None
        return power[key] * factor

    return _get


SENSORS: tuple[AmaranSensorDescription, ...] = (
    AmaranSensorDescription(
        key="battery_level",
        name="Battery",
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        value_fn=_scaled("battery_level", 1),
    ),
    AmaranSensorDescription(
        key="battery_voltage",
        name="Battery voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=2,
        value_fn=_scaled("battery_voltage", 0.001),
    ),
    AmaranSensorDescription(
        key="extern_voltage",
        name="Supply voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=2,
        value_fn=_scaled("extern_voltage", 0.001),
    ),
    AmaranSensorDescription(
        key="battery_time",
        name="Runtime remaining",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_scaled("battery_time", 1),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AmaranConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up power sensors."""
    coordinator = entry.runtime_data
    async_add_entities(
        AmaranPowerSensor(coordinator, entry, description) for description in SENSORS
    )


class AmaranPowerSensor(AmaranEntity, SensorEntity):
    """One field of the fixture's power report."""

    entity_description: AmaranSensorDescription

    def __init__(
        self, coordinator, entry, description: AmaranSensorDescription
    ) -> None:
        """Bind the description."""
        super().__init__(coordinator, entry)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

    @property
    def native_value(self) -> float | None:
        """Latest reported value, or None if the fixture has not answered."""
        return self.entity_description.value_fn(self._coordinator.state.power)
