"""Config flow: discover an unprovisioned amaran fixture and provision it."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.core import callback

from .amaran.products import Product, lookup
from .const import (
    CONF_ADDRESS,
    CONF_APP_KEY,
    CONF_DEV_KEY,
    CONF_DEVICE_NAME,
    CONF_ELEMENT_COUNT,
    CONF_IV_INDEX,
    CONF_NET_KEY,
    CONF_PRODUCT_HEX,
    CONF_SEQUENCE,
    CONF_UNICAST_ADDRESS,
    CONF_VENDOR_MODELS,
    DOMAIN,
    FIRST_NODE_ADDRESS,
    MESH_PROVISIONING_UUID,
    PROVISIONER_ADDRESS,
)
from .mesh.crypto import random_bytes
from .mesh.provisioning import Provisioner, ProvisioningData, ProvisioningError
from .mesh.session import MeshCredentials, MeshSession, MeshSessionError

_LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 25.0
#: The node reboots after provisioning; wait and retry before giving up.
CONFIGURE_ATTEMPTS = 3
CONFIGURE_BACKOFF = 2.0


def device_name_from_service_info(info: BluetoothServiceInfoBleak) -> str | None:
    """Extract the fixture name from the Mesh Provisioning service data.

    amaran encodes an ASCII name such as ``400Y5-A1B2C3`` in the 16-byte mesh
    Device UUID, which is the first field of the 0x1827 service data.
    """
    payload = info.service_data.get(MESH_PROVISIONING_UUID)
    if not payload or len(payload) < 16:
        return None

    printable = bytearray()
    for byte in payload[:16]:
        if 32 <= byte <= 126:
            printable.append(byte)
        else:
            break
    return printable.decode("ascii", "ignore").strip() or None


class AmaranConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle discovery and provisioning of amaran fixtures."""

    VERSION = 1

    def __init__(self) -> None:
        """Start with nothing discovered."""
        self._discovery: BluetoothServiceInfoBleak | None = None
        self._device_name: str | None = None
        self._product: Product | None = None
        self._discovered: dict[str, tuple[BluetoothServiceInfoBleak, str, Product]] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle a fixture found by Home Assistant's Bluetooth discovery."""
        name = device_name_from_service_info(discovery_info)
        if name is None:
            return self.async_abort(reason="not_amaran")

        product = lookup(name)
        if product is None:
            _LOGGER.debug("ignoring unknown mesh device %s", name)
            return self.async_abort(reason="not_amaran")

        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        self._discovery = discovery_info
        self._device_name = name
        self._product = product
        self.context["title_placeholders"] = {"name": product.name}
        return await self.async_step_confirm()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user pick from the unprovisioned fixtures in range."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            discovery, name, product = self._discovered[address]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._discovery = discovery
            self._device_name = name
            self._product = product
            return await self.async_step_confirm()

        self._discovered = {}
        current = self._async_current_ids()
        for info in bluetooth.async_discovered_service_info(
            self.hass, connectable=True
        ):
            if info.address in current:
                continue
            name = device_name_from_service_info(info)
            if name is None:
                continue
            if (product := lookup(name)) is None:
                continue
            self._discovered[info.address] = (info, name, product)

        if not self._discovered:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): vol.In(
                        {
                            address: f"{product.name} ({address})"
                            for address, (_, _, product) in self._discovered.items()
                        }
                    )
                }
            ),
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm, then run provisioning."""
        assert self._discovery is not None
        assert self._product is not None

        if user_input is None:
            self._set_confirm_only()
            return self.async_show_form(
                step_id="confirm",
                description_placeholders={
                    "name": self._product.name,
                    "address": self._discovery.address,
                },
            )

        try:
            return await self._async_provision()
        except ProvisioningError as err:
            _LOGGER.error("provisioning failed: %s", err)
            return self.async_abort(reason="provisioning_failed")
        except (MeshSessionError, TimeoutError, OSError) as err:
            _LOGGER.error("could not commission fixture: %s", err)
            return self.async_abort(reason="cannot_connect")

    async def _async_provision(self) -> ConfigFlowResult:
        """Provision the fixture and bind our AppKey to its vendor models."""
        assert self._discovery is not None
        assert self._product is not None
        assert self._device_name is not None

        net_key, app_key, iv_index = self._mesh_network()
        node_address = self._next_unicast_address()

        device = bluetooth.async_ble_device_from_address(
            self.hass, self._discovery.address, connectable=True
        )
        if device is None:
            raise MeshSessionError("fixture went out of range")

        client = await establish_connection(
            BleakClientWithServiceCache,
            device,
            f"{DOMAIN}-provision-{self._discovery.address}",
            timeout=CONNECT_TIMEOUT,
        )

        try:
            provisioner = Provisioner(client)
            result = await provisioner.provision(
                ProvisioningData(
                    net_key=net_key,
                    net_key_index=0,
                    iv_index=iv_index,
                    unicast_address=node_address,
                )
            )
        finally:
            await client.disconnect()

        # The node drops the provisioning link and comes back advertising the
        # Proxy service, so give it a moment and retry the reconnect.
        vendor_models: list[list[int]] = []
        last_error: Exception | None = None
        for attempt in range(CONFIGURE_ATTEMPTS):
            await asyncio.sleep(CONFIGURE_BACKOFF * (attempt + 1))
            try:
                vendor_models = await self._async_configure_node(
                    net_key,
                    app_key,
                    iv_index,
                    result.unicast_address,
                    result.device_key,
                )
            except (MeshSessionError, TimeoutError, OSError) as err:
                last_error = err
                _LOGGER.debug(
                    "post-provision configuration attempt %d/%d failed: %s",
                    attempt + 1,
                    CONFIGURE_ATTEMPTS,
                    err,
                )
            else:
                break
        else:
            raise MeshSessionError(
                f"provisioned, but configuration failed: {last_error}"
            )

        return self.async_create_entry(
            title=f"{self._product.name} ({self._device_name.split('-')[-1]})",
            data={
                CONF_ADDRESS: self._discovery.address,
                CONF_DEVICE_NAME: self._device_name,
                CONF_PRODUCT_HEX: self._product.hex_id,
                CONF_NET_KEY: net_key.hex(),
                CONF_APP_KEY: app_key.hex(),
                CONF_DEV_KEY: result.device_key.hex(),
                CONF_IV_INDEX: iv_index,
                CONF_UNICAST_ADDRESS: result.unicast_address,
                CONF_ELEMENT_COUNT: result.element_count,
                CONF_VENDOR_MODELS: vendor_models,
                CONF_SEQUENCE: 0,
            },
        )

    async def _async_configure_node(
        self,
        net_key: bytes,
        app_key: bytes,
        iv_index: int,
        node_address: int,
        device_key: bytes,
    ) -> list[list[int]]:
        """Add the AppKey and bind it to every model the node exposes."""
        assert self._discovery is not None

        device = bluetooth.async_ble_device_from_address(
            self.hass, self._discovery.address, connectable=True
        )
        if device is None:
            raise MeshSessionError("fixture went out of range after provisioning")

        credentials = MeshCredentials(
            net_key=net_key,
            app_key=app_key,
            iv_index=iv_index,
            provisioner_address=PROVISIONER_ADDRESS,
            device_keys={node_address: device_key},
        )

        client = await establish_connection(
            BleakClientWithServiceCache,
            device,
            f"{DOMAIN}-configure-{self._discovery.address}",
            timeout=CONNECT_TIMEOUT,
        )

        vendor_models: list[list[int]] = []
        try:
            session = MeshSession(client, credentials)
            await session.start()

            composition = await session.get_composition_data(node_address, device_key)
            await session.add_app_key(node_address, device_key)

            for element in composition.elements:
                for company_id, model_id in element.vendor_models:
                    await session.bind_model(
                        node_address,
                        device_key,
                        element.address,
                        model_id,
                        company_id=company_id,
                    )
                    vendor_models.append([company_id, model_id])

            await session.stop()
        finally:
            await client.disconnect()

        if not vendor_models:
            _LOGGER.warning("fixture exposed no vendor models; control may not work")
        return vendor_models

    @callback
    def _mesh_network(self) -> tuple[bytes, bytes, int]:
        """Reuse the existing mesh keys, or mint a new network."""
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            if CONF_NET_KEY in entry.data and CONF_APP_KEY in entry.data:
                return (
                    bytes.fromhex(entry.data[CONF_NET_KEY]),
                    bytes.fromhex(entry.data[CONF_APP_KEY]),
                    entry.data.get(CONF_IV_INDEX, 0),
                )
        return random_bytes(16), random_bytes(16), 0

    @callback
    def _next_unicast_address(self) -> int:
        """Allocate the next free unicast address in the shared network."""
        used = FIRST_NODE_ADDRESS
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            address = entry.data.get(CONF_UNICAST_ADDRESS)
            if address is None:
                continue
            used = max(used, address + entry.data.get(CONF_ELEMENT_COUNT, 1))
        return used
