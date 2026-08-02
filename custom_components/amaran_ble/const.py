"""Constants for the amaran BLE integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "amaran_ble"

# Config entry keys.
CONF_ADDRESS: Final = "address"
CONF_DEVICE_NAME: Final = "device_name"
CONF_PRODUCT_HEX: Final = "product_hex"
CONF_NET_KEY: Final = "net_key"
CONF_APP_KEY: Final = "app_key"
CONF_DEV_KEY: Final = "dev_key"
CONF_IV_INDEX: Final = "iv_index"
CONF_UNICAST_ADDRESS: Final = "unicast_address"
CONF_ELEMENT_COUNT: Final = "element_count"
CONF_SEQUENCE: Final = "sequence"
CONF_VENDOR_MODELS: Final = "vendor_models"
#: False until the AppKey has been added and bound to the node's vendor models.
#: Provisioning is irreversible, configuration is retryable, so they are tracked
#: separately - see the note in coordinator.async_ensure_configured.
CONF_CONFIGURED: Final = "configured"

# The provisioner (Home Assistant) always takes the first unicast address.
PROVISIONER_ADDRESS: Final = 0x0001
FIRST_NODE_ADDRESS: Final = 0x0002

#: Sequence numbers are persisted lazily; on load we skip ahead by this much so
#: an unclean shutdown can never replay a number the node has already seen.
SEQUENCE_RESTART_MARGIN: Final = 1000
#: Persist the sequence number every N messages.
SEQUENCE_PERSIST_INTERVAL: Final = 64

# Mesh Provisioning Service, advertised by unprovisioned fixtures.
MESH_PROVISIONING_UUID: Final = "00001827-0000-1000-8000-00805f9b34fb"
MESH_PROXY_UUID: Final = "00001828-0000-1000-8000-00805f9b34fb"

# amaran intensity is tenths of a percent.
INTENSITY_MAX: Final = 1000

DEFAULT_KELVIN: Final = 5600
