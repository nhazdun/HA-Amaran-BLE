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
from homeassistant.data_entry_flow import AbortFlow

from .amaran.products import Product, lookup
from .const import (
    CONF_ADDRESS,
    CONF_APP_KEY,
    CONF_CONFIGURED,
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
from .mesh.provisioning import (
    NotUnprovisionedError,
    Provisioner,
    ProvisioningData,
    ProvisioningError,
)
from .mesh.session import MeshCredentials, MeshSession, MeshSessionError

_LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 25.0
#: The node reboots after provisioning; wait and retry before giving up.
CONFIGURE_ATTEMPTS = 3
CONFIGURE_BACKOFF = 5.0

#: Addresses currently being provisioned. Home Assistant's per-unique-id flow
#: guards do not cover this: provisioning is destructive and irreversible, so
#: two flows reaching it for the same fixture would each hand it a different
#: NetKey and leave the surviving config entry holding keys the fixture does
#: not have. Guard the operation itself, not just flow creation.
_PROVISIONING: set[str] = set()


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
            # raise_on_progress must stay True here. The usual Bluetooth
            # boilerplate disables it so a user flow can pre-empt a pending
            # discovery, but provisioning is destructive and not idempotent:
            # two flows racing would provision the fixture twice with different
            # random keys, and whichever entry survives would hold the wrong
            # ones.
            await self.async_set_unique_id(address)
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
        except NotUnprovisionedError as err:
            _LOGGER.error("fixture is not unprovisioned: %s", err)
            return self.async_abort(reason="already_provisioned")
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

        address = self._discovery.address
        if address in _PROVISIONING:
            raise AbortFlow("already_in_progress")

        net_key, app_key, iv_index = self._mesh_network()
        node_address = self._next_unicast_address()

        device = bluetooth.async_ble_device_from_address(
            self.hass, address, connectable=True
        )
        if device is None:
            raise MeshSessionError("fixture went out of range")

        _PROVISIONING.add(address)
        try:
            client = await establish_connection(
                BleakClientWithServiceCache,
                device,
                f"{DOMAIN}-provision-{address}",
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
        finally:
            _PROVISIONING.discard(address)

        # Provisioning is the irreversible half: the fixture now belongs to this
        # mesh and will not answer another Invite. Persist the keys *before*
        # attempting configuration, so a failure here leaves a recoverable entry
        # instead of a fixture orphaned in a network nobody has the keys to.
        vendor_models: list[list[int]] = []
        configured = False
        try:
            vendor_models = await self._async_configure_with_retries(
                net_key, app_key, iv_index, result.unicast_address, result.device_key
            )
        except Exception as err:  # noqa: BLE001 - see below
            # Deliberately broad. Once provisioning has succeeded the fixture
            # is committed to this mesh, so *any* later failure - a Bleak
            # connection error, a stack shutdown, a bug in our own config
            # client - must still produce an entry holding the keys. Letting an
            # exception escape here would strand the fixture and force a
            # factory reset.
            _LOGGER.warning(
                "provisioned 0x%04x, but configuration did not complete (%s: %s); "
                "the integration will retry on setup",
                result.unicast_address,
                type(err).__name__,
                err,
            )
        else:
            configured = True

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
                CONF_CONFIGURED: configured,
                CONF_SEQUENCE: 0,
            },
        )

    async def _async_configure_with_retries(
        self,
        net_key: bytes,
        app_key: bytes,
        iv_index: int,
        node_address: int,
        device_key: bytes,
    ) -> list[list[int]]:
        """Configure the node, retrying while it finishes rebooting."""
        last_error: Exception | None = None
        for attempt in range(CONFIGURE_ATTEMPTS):
            await asyncio.sleep(CONFIGURE_BACKOFF * (attempt + 1))
            try:
                return await self._async_configure_node(
                    net_key, app_key, iv_index, node_address, device_key
                )
            except (MeshSessionError, TimeoutError, OSError) as err:
                last_error = err
                _LOGGER.debug(
                    "post-provision configuration attempt %d/%d failed: %s",
                    attempt + 1,
                    CONFIGURE_ATTEMPTS,
                    err,
                )
        raise MeshSessionError(str(last_error))

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
