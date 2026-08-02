"""PB-GATT provisioner (Mesh Profile 5.4).

Drives an unprovisioned device through invite -> capabilities -> start ->
public key exchange -> confirmation -> random -> data, using the No OOB
authentication method with the FIPS P-256 algorithm. That is the path the
Sidus Link app takes for amaran fixtures, which report no static OOB.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .crypto import (
    PRCK,
    PRDK,
    PRSK,
    PRSN,
    EcdhKeyPair,
    aes_ccm_encrypt,
    aes_cmac,
    k1,
    random_bytes,
    s1,
)
from .pdu import PROXY_TYPE_PROVISIONING
from .proxy import MeshGattBearer

_LOGGER = logging.getLogger(__name__)

# Provisioning PDU types (Mesh Profile 5.4.1).
PDU_INVITE = 0x00
PDU_CAPABILITIES = 0x01
PDU_START = 0x02
PDU_PUBLIC_KEY = 0x03
PDU_INPUT_COMPLETE = 0x04
PDU_CONFIRMATION = 0x05
PDU_RANDOM = 0x06
PDU_DATA = 0x07
PDU_COMPLETE = 0x08
PDU_FAILED = 0x09

ALGORITHM_FIPS_P256 = 0x00
PUBLIC_KEY_NO_OOB = 0x00
AUTH_METHOD_NO_OOB = 0x00

#: No OOB authentication uses an all-zero 16-byte auth value.
AUTH_VALUE_NO_OOB = b"\x00" * 16

PROVISION_TIMEOUT = 60.0
STEP_TIMEOUT = 20.0

FAILURE_REASONS = {
    0x01: "invalid PDU",
    0x02: "invalid format",
    0x03: "unexpected PDU",
    0x04: "confirmation failed",
    0x05: "out of resources",
    0x06: "decryption failed",
    0x07: "unexpected error",
    0x08: "cannot assign address",
}


class ProvisioningError(Exception):
    """Raised when provisioning fails or times out."""


class NotUnprovisionedError(ProvisioningError):
    """The device never answered the invite.

    amaran fixtures keep advertising the Mesh Provisioning Service even after
    they have joined a network, so "discoverable" does not imply
    "provisionable" - a fixture already bound to another mesh (the Sidus Link
    app, or an earlier failed attempt) simply ignores the invite. A factory
    reset is the only way back.
    """


@dataclass(slots=True)
class ProvisioningResult:
    """Outcome of a successful provisioning session."""

    unicast_address: int
    device_key: bytes
    element_count: int


@dataclass(slots=True)
class ProvisioningData:
    """The network parameters handed to the new node."""

    net_key: bytes
    net_key_index: int
    iv_index: int
    unicast_address: int
    key_refresh_flag: int = 0
    iv_update_flag: int = 0

    def to_bytes(self) -> bytes:
        """Serialise the 25-byte provisioning data block."""
        flags = (self.key_refresh_flag & 1) | (self.iv_update_flag & 2)
        return (
            self.net_key
            + self.net_key_index.to_bytes(2, "big")
            + bytes([flags])
            + self.iv_index.to_bytes(4, "big")
            + self.unicast_address.to_bytes(2, "big")
        )


class Provisioner:
    """Runs one PB-GATT provisioning session over a GATT bearer."""

    def __init__(self, client, attention_duration: int = 5) -> None:
        """Prepare a session on an already-connected ``BleakClient``."""
        self._attention = attention_duration
        self._bearer = MeshGattBearer.provisioning(client, self._on_pdu)
        self._inbox: dict[int, asyncio.Future[bytes]] = {}
        self._failure: int | None = None
        self._loop = asyncio.get_running_loop()

        self._keypair = EcdhKeyPair.generate()
        self._invite_params = b""
        self._capabilities = b""
        self._start_params = b""
        self._device_public_key = b""
        self._provisioner_random = b""

    # -- bearer plumbing ---------------------------------------------------

    def _on_pdu(self, msg_type: int, payload: bytes) -> None:
        """Route an inbound provisioning PDU to whoever is awaiting it."""
        if msg_type != PROXY_TYPE_PROVISIONING or not payload:
            return

        pdu_type, params = payload[0], payload[1:]
        _LOGGER.debug("provisioning RX type=0x%02x params=%s", pdu_type, params.hex())

        if pdu_type == PDU_FAILED:
            self._failure = params[0] if params else 0
            for future in self._inbox.values():
                if not future.done():
                    future.set_exception(
                        ProvisioningError(
                            "device rejected provisioning: "
                            + FAILURE_REASONS.get(
                                self._failure, f"code {self._failure}"
                            )
                        )
                    )
            self._inbox.clear()
            return

        future = self._inbox.pop(pdu_type, None)
        if future is not None and not future.done():
            future.set_result(params)

    async def _send(self, pdu_type: int, params: bytes = b"") -> None:
        """Send one provisioning PDU."""
        _LOGGER.debug("provisioning TX type=0x%02x params=%s", pdu_type, params.hex())
        await self._bearer.send(PROXY_TYPE_PROVISIONING, bytes([pdu_type]) + params)

    async def _expect(self, pdu_type: int) -> bytes:
        """Wait for a specific inbound PDU type."""
        future: asyncio.Future[bytes] = self._loop.create_future()
        self._inbox[pdu_type] = future
        try:
            return await asyncio.wait_for(future, STEP_TIMEOUT)
        except TimeoutError as err:
            self._inbox.pop(pdu_type, None)
            raise ProvisioningError(
                f"timed out waiting for provisioning PDU 0x{pdu_type:02x}"
            ) from err

    # -- the state machine -------------------------------------------------

    async def provision(self, data: ProvisioningData) -> ProvisioningResult:
        """Provision the device and return its address and device key."""
        try:
            return await asyncio.wait_for(self._run(data), PROVISION_TIMEOUT)
        except TimeoutError as err:
            raise ProvisioningError("provisioning timed out") from err
        finally:
            await self._bearer.stop()

    async def _run(self, data: ProvisioningData) -> ProvisioningResult:
        await self._bearer.start()

        # 1. Invite.
        self._invite_params = bytes([self._attention])
        await self._send(PDU_INVITE, self._invite_params)

        # 2. Capabilities.
        try:
            self._capabilities = await self._expect(PDU_CAPABILITIES)
        except ProvisioningError as err:
            raise NotUnprovisionedError(
                "the fixture ignored the provisioning invite, which means it is "
                "still joined to another mesh - factory-reset it and retry"
            ) from err
        if len(self._capabilities) < 11:
            raise ProvisioningError("malformed capabilities PDU")
        element_count = self._capabilities[0] or 1

        # 3. Start - No OOB, FIPS P-256.
        self._start_params = bytes(
            [ALGORITHM_FIPS_P256, PUBLIC_KEY_NO_OOB, AUTH_METHOD_NO_OOB, 0x00, 0x00]
        )
        await self._send(PDU_START, self._start_params)

        # 4. Public keys.
        await self._send(PDU_PUBLIC_KEY, self._keypair.public_key_bytes)
        self._device_public_key = await self._expect(PDU_PUBLIC_KEY)
        if len(self._device_public_key) != 64:
            raise ProvisioningError("malformed device public key")

        secret = self._keypair.shared_secret(self._device_public_key)
        confirmation_salt = s1(self._confirmation_inputs())
        confirmation_key = k1(secret, confirmation_salt, PRCK)

        # 5. Confirmation exchange.
        self._provisioner_random = random_bytes(16)
        our_confirmation = aes_cmac(
            confirmation_key, self._provisioner_random + AUTH_VALUE_NO_OOB
        )
        await self._send(PDU_CONFIRMATION, our_confirmation)
        device_confirmation = await self._expect(PDU_CONFIRMATION)

        # 6. Random exchange, then verify the device's confirmation.
        await self._send(PDU_RANDOM, self._provisioner_random)
        device_random = await self._expect(PDU_RANDOM)
        if len(device_random) != 16:
            raise ProvisioningError("malformed device random")

        expected = aes_cmac(confirmation_key, device_random + AUTH_VALUE_NO_OOB)
        if expected != device_confirmation:
            raise ProvisioningError(
                "device confirmation mismatch - the link may be under attack"
            )

        # 7. Session keys and encrypted provisioning data.
        provisioning_salt = s1(
            confirmation_salt + self._provisioner_random + device_random
        )
        session_key = k1(secret, provisioning_salt, PRSK)
        session_nonce = k1(secret, provisioning_salt, PRSN)[3:]
        device_key = k1(secret, provisioning_salt, PRDK)

        encrypted = aes_ccm_encrypt(
            session_key, session_nonce, data.to_bytes(), mic_len=8
        )
        await self._send(PDU_DATA, encrypted)
        await self._expect(PDU_COMPLETE)

        _LOGGER.info(
            "provisioned node at 0x%04x with %d element(s)",
            data.unicast_address,
            element_count,
        )
        return ProvisioningResult(
            unicast_address=data.unicast_address,
            device_key=device_key,
            element_count=element_count,
        )

    def _confirmation_inputs(self) -> bytes:
        """Invite || Capabilities || Start || ProvisionerPubKey || DevicePubKey."""
        return (
            self._invite_params
            + self._capabilities
            + self._start_params
            + self._keypair.public_key_bytes
            + self._device_public_key
        )
