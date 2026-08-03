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

#: Sequence numbers are reserved in blocks *before* use, never persisted after
#: the fact: a mesh node drops anything at or below the highest number it has
#: already seen from us, so a repeat is silently fatal while a gap is harmless.
SEQUENCE_BLOCK: Final = 2000
#: Reserve the next block once this many numbers of the current one remain.
SEQUENCE_HEADROOM: Final = 200
#: Set once the entry's stored sequence is a reserved ceiling rather than a
#: lazily-persisted counter.
CONF_SEQUENCE_RESERVED: Final = "sequence_reserved"
#: One-time jump applied when migrating an entry off the old scheme. The node
#: may already have retired numbers the old counter never recorded, and the
#: sequence space is 24 bits, so skipping a chunk costs nothing.
SEQUENCE_RECOVERY_JUMP: Final = 100_000

# Mesh Provisioning Service, advertised by unprovisioned fixtures.
MESH_PROVISIONING_UUID: Final = "00001827-0000-1000-8000-00805f9b34fb"
MESH_PROXY_UUID: Final = "00001828-0000-1000-8000-00805f9b34fb"

# amaran intensity is tenths of a percent.
INTENSITY_MAX: Final = 1000

DEFAULT_KELVIN: Final = 5600
