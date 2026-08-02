"""The amaran BLE integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .amaran.products import PRODUCTS
from .const import (
    CONF_ADDRESS,
    CONF_APP_KEY,
    CONF_DEV_KEY,
    CONF_IV_INDEX,
    CONF_NET_KEY,
    CONF_PRODUCT_HEX,
    CONF_UNICAST_ADDRESS,
    PROVISIONER_ADDRESS,
)
from .coordinator import AmaranCoordinator
from .mesh.session import MeshCredentials

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.LIGHT,
    Platform.NUMBER,
    Platform.SELECT,
    Platform.SENSOR,
]

type AmaranConfigEntry = ConfigEntry[AmaranCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: AmaranConfigEntry) -> bool:
    """Set up an amaran fixture from a config entry."""
    try:
        node_address = entry.data[CONF_UNICAST_ADDRESS]
        device_key = bytes.fromhex(entry.data[CONF_DEV_KEY])
        credentials = MeshCredentials(
            net_key=bytes.fromhex(entry.data[CONF_NET_KEY]),
            app_key=bytes.fromhex(entry.data[CONF_APP_KEY]),
            iv_index=entry.data.get(CONF_IV_INDEX, 0),
            provisioner_address=PROVISIONER_ADDRESS,
            device_keys={node_address: device_key},
        )
    except (KeyError, ValueError) as err:
        raise ConfigEntryNotReady(f"malformed config entry: {err}") from err

    coordinator = AmaranCoordinator(
        hass,
        entry,
        credentials,
        node_address=node_address,
        ble_address=entry.data[CONF_ADDRESS],
        product=PRODUCTS.get(entry.data.get(CONF_PRODUCT_HEX, "")),
    )

    await coordinator.async_start()
    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: AmaranConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_stop()
    return unloaded
