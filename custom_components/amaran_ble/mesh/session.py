"""Mesh proxy session: send and receive access messages over GATT.

Owns the network/transport state for one connection to a proxy node - sequence
numbers, segmentation, reassembly - and provides the small slice of the
Configuration Client needed to commission an amaran fixture.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from .crypto import k4
from .pdu import (
    PROXY_TYPE_CONFIGURATION,
    PROXY_TYPE_NETWORK,
    UNSEGMENTED_ACCESS_MAX,
    NetworkKeys,
    SegmentedMessage,
    decode_access,
    decode_network_pdu,
    encode_access,
    encode_network_pdu,
    lower_segmented_access,
    lower_unsegmented_access,
    segment_ack_pdu,
    upper_decrypt,
    upper_encrypt,
)
from .proxy import MeshGattBearer

_LOGGER = logging.getLogger(__name__)

# Configuration model opcodes (wire form, big-endian).
OP_APPKEY_ADD = 0x00
OP_APPKEY_STATUS = 0x8003
OP_COMPOSITION_DATA_GET = 0x8008
OP_COMPOSITION_DATA_STATUS = 0x02
OP_MODEL_APP_BIND = 0x803D
OP_MODEL_APP_STATUS = 0x803E
OP_NODE_RESET = 0x8049
OP_NODE_RESET_STATUS = 0x804A

# Proxy configuration opcodes (Mesh Profile 6.5).
PROXY_OP_SET_FILTER_TYPE = 0x00
PROXY_OP_ADD_ADDRESSES = 0x01
PROXY_FILTER_WHITELIST = 0x00

DEFAULT_TTL = 7
STATUS_TIMEOUT = 12.0
SEQ_MAX = 0xFFFFFF

MessageHandler = Callable[[int, int, bytes], None]


class MeshSessionError(Exception):
    """Raised when a mesh operation fails or times out."""


@dataclass(slots=True)
class MeshCredentials:
    """Everything needed to talk to a provisioned amaran mesh."""

    net_key: bytes
    app_key: bytes
    net_key_index: int = 0
    app_key_index: int = 0
    iv_index: int = 0
    provisioner_address: int = 0x0001
    #: Per-node device keys, keyed by unicast address.
    device_keys: dict[int, bytes] = field(default_factory=dict)

    def keys(self) -> NetworkKeys:
        """Derive the network key material."""
        return NetworkKeys.derive(self.net_key)

    @property
    def aid(self) -> int:
        """Application key identifier (k4 of the AppKey)."""
        return k4(self.app_key)


def pack_key_indexes(net_key_index: int, app_key_index: int) -> bytes:
    """Pack two 12-bit key indexes into three octets (Mesh Profile 4.3.1.1)."""
    return bytes(
        [
            net_key_index & 0xFF,
            ((net_key_index >> 8) & 0x0F) | ((app_key_index & 0x0F) << 4),
            (app_key_index >> 4) & 0xFF,
        ]
    )


@dataclass(slots=True)
class Element:
    """One element from a Composition Data page 0."""

    address: int
    location: int
    sig_models: list[int]
    vendor_models: list[tuple[int, int]]  # (company_id, model_id)


@dataclass(slots=True)
class CompositionData:
    """Parsed Composition Data page 0."""

    company_id: int
    product_id: int
    version_id: int
    crpl: int
    features: int
    elements: list[Element]


def parse_composition_data(primary_address: int, data: bytes) -> CompositionData:
    """Parse a Composition Data Status payload (page byte already stripped)."""
    if len(data) < 10:
        raise MeshSessionError("composition data too short")

    company_id, product_id, version_id, crpl, features = (
        int.from_bytes(data[i : i + 2], "little") for i in range(0, 10, 2)
    )

    elements: list[Element] = []
    offset = 10
    index = 0
    while offset + 4 <= len(data):
        location = int.from_bytes(data[offset : offset + 2], "little")
        num_sig = data[offset + 2]
        num_vendor = data[offset + 3]
        offset += 4

        sig_models: list[int] = []
        for _ in range(num_sig):
            if offset + 2 > len(data):
                raise MeshSessionError("truncated SIG model list")
            sig_models.append(int.from_bytes(data[offset : offset + 2], "little"))
            offset += 2

        vendor_models: list[tuple[int, int]] = []
        for _ in range(num_vendor):
            if offset + 4 > len(data):
                raise MeshSessionError("truncated vendor model list")
            vendor_models.append(
                (
                    int.from_bytes(data[offset : offset + 2], "little"),
                    int.from_bytes(data[offset + 2 : offset + 4], "little"),
                )
            )
            offset += 4

        elements.append(
            Element(primary_address + index, location, sig_models, vendor_models)
        )
        index += 1

    return CompositionData(company_id, product_id, version_id, crpl, features, elements)


class MeshSession:
    """A live proxy connection to a mesh network."""

    def __init__(
        self,
        client,
        credentials: MeshCredentials,
        sequence: int = 0,
        on_message: MessageHandler | None = None,
    ) -> None:
        """Bind to a connected ``BleakClient`` acting as a proxy node."""
        self._credentials = credentials
        self._keys = credentials.keys()
        self._aid = credentials.aid
        self._sequence = sequence
        self._on_message = on_message
        self._bearer = MeshGattBearer.proxy(client, self._on_pdu)
        self._loop = asyncio.get_running_loop()
        self._pending: dict[tuple[int, int | None], asyncio.Future[bytes]] = {}
        self._reassembly: dict[tuple[int, int], SegmentedMessage] = {}
        self._send_lock = asyncio.Lock()
        # Hold strong references so fire-and-forget acks are not garbage
        # collected before they run.
        self._background: set[asyncio.Task[None]] = set()

    @property
    def sequence(self) -> int:
        """Current sequence number; persist this across restarts."""
        return self._sequence

    async def start(self) -> None:
        """Subscribe to proxy notifications."""
        await self._bearer.start()

    async def stop(self) -> None:
        """Tear down notifications."""
        await self._bearer.stop()

    def _next_seq(self) -> int:
        seq = self._sequence
        self._sequence = (self._sequence + 1) & SEQ_MAX
        return seq

    def _spawn(self, coro) -> None:
        """Run a coroutine in the background, keeping a strong reference."""
        task = self._loop.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    # -- outbound ----------------------------------------------------------

    async def send_access(
        self,
        dst: int,
        opcode: int,
        params: bytes = b"",
        *,
        dev_key: bytes | None = None,
        ttl: int = DEFAULT_TTL,
    ) -> None:
        """Encrypt and send an access message.

        Uses the AppKey unless ``dev_key`` is supplied, in which case the
        message is a Configuration Client message bound to that node.
        """
        access = encode_access(opcode, params)
        key = dev_key if dev_key is not None else self._credentials.app_key
        akf = 0 if dev_key is not None else 1
        aid = 0 if dev_key is not None else self._aid

        async with self._send_lock:
            seq = self._next_seq()
            upper = upper_encrypt(
                key,
                seq=seq,
                src=self._credentials.provisioner_address,
                dst=dst,
                iv_index=self._credentials.iv_index,
                access_payload=access,
                dev_key=dev_key is not None,
            )

            if len(upper) <= UNSEGMENTED_ACCESS_MAX:
                lower_pdus = [lower_unsegmented_access(akf, aid, upper)]
                seqs = [seq]
            else:
                lower_pdus = lower_segmented_access(
                    akf, aid, upper, seq_zero=seq & 0x1FFF
                )
                # The first segment reuses the SeqAuth sequence number.
                seqs = [seq] + [self._next_seq() for _ in lower_pdus[1:]]

            for pdu_seq, lower in zip(seqs, lower_pdus, strict=True):
                await self._send_network(
                    ctl=0, ttl=ttl, seq=pdu_seq, dst=dst, transport_pdu=lower
                )

    async def _send_network(
        self, *, ctl: int, ttl: int, seq: int, dst: int, transport_pdu: bytes
    ) -> None:
        raw = encode_network_pdu(
            self._keys,
            iv_index=self._credentials.iv_index,
            ctl=ctl,
            ttl=ttl,
            seq=seq,
            src=self._credentials.provisioner_address,
            dst=dst,
            transport_pdu=transport_pdu,
        )
        await self._bearer.send(PROXY_TYPE_NETWORK, raw)

    async def set_proxy_filter(self, addresses: list[int]) -> None:
        """Whitelist the addresses we care about on the proxy node."""
        async with self._send_lock:
            for payload in (
                bytes([PROXY_OP_SET_FILTER_TYPE, PROXY_FILTER_WHITELIST]),
                bytes([PROXY_OP_ADD_ADDRESSES])
                + b"".join(a.to_bytes(2, "big") for a in addresses),
            ):
                raw = encode_network_pdu(
                    self._keys,
                    iv_index=self._credentials.iv_index,
                    ctl=1,
                    ttl=0,
                    seq=self._next_seq(),
                    src=self._credentials.provisioner_address,
                    dst=0x0000,
                    transport_pdu=payload,
                )
                await self._bearer.send(PROXY_TYPE_CONFIGURATION, raw)

    async def request(
        self,
        dst: int,
        opcode: int,
        params: bytes,
        response_opcode: int,
        *,
        dev_key: bytes | None = None,
        timeout: float = STATUS_TIMEOUT,
    ) -> bytes:
        """Send a message and wait for its status reply."""
        future: asyncio.Future[bytes] = self._loop.create_future()
        key = (response_opcode, dst)
        self._pending[key] = future
        try:
            await self.send_access(dst, opcode, params, dev_key=dev_key)
            return await asyncio.wait_for(future, timeout)
        except TimeoutError as err:
            raise MeshSessionError(
                f"no reply to opcode 0x{opcode:04x} from 0x{dst:04x}"
            ) from err
        finally:
            self._pending.pop(key, None)

    # -- inbound -----------------------------------------------------------

    def _on_pdu(self, msg_type: int, payload: bytes) -> None:
        """Decode an inbound proxy PDU."""
        if msg_type != PROXY_TYPE_NETWORK:
            return

        network = decode_network_pdu(self._keys, self._credentials.iv_index, payload)
        if network is None:
            return

        if network.ctl:
            # Segment acknowledgements and other control messages: nothing to do.
            return

        self._handle_access_transport(
            network.src, network.dst, network.seq, network.transport_pdu
        )

    def _handle_access_transport(
        self, src: int, dst: int, seq: int, transport: bytes
    ) -> None:
        if not transport:
            return

        segmented = bool(transport[0] & 0x80)
        akf = (transport[0] >> 6) & 1

        if not segmented:
            self._dispatch_upper(src, dst, seq, akf, transport[1:])
            return

        if len(transport) < 4:
            return
        misc = int.from_bytes(transport[1:4], "big")
        szmic = (misc >> 23) & 1
        seq_zero = (misc >> 10) & 0x1FFF
        seg_o = (misc >> 5) & 0x1F
        seg_n = misc & 0x1F

        key = (src, seq_zero)
        message = self._reassembly.get(key)
        if message is None:
            message = SegmentedMessage(
                seq_zero=seq_zero,
                seg_n=seg_n,
                szmic=szmic,
                akf=akf,
                aid=transport[0] & 0x3F,
                # SeqAuth: the sequence number the first segment was sent with.
                seq=(seq & ~0x1FFF) | seq_zero,
            )
            self._reassembly[key] = message
        message.segments[seg_o] = transport[4:]

        if not message.complete:
            return

        self._reassembly.pop(key, None)
        # Acknowledge so the node stops retransmitting.
        ack = segment_ack_pdu(seq_zero, message.block_ack)
        self._spawn(
            self._send_network(
                ctl=1, ttl=DEFAULT_TTL, seq=self._next_seq(), dst=src, transport_pdu=ack
            )
        )
        self._dispatch_upper(
            src, dst, message.seq, akf, message.reassemble(), szmic=szmic
        )

    def _dispatch_upper(
        self, src: int, dst: int, seq: int, akf: int, upper: bytes, szmic: int = 0
    ) -> None:
        """Decrypt an Upper Transport PDU and hand the access message on."""
        candidates: list[tuple[bytes, bool]] = []
        if akf:
            candidates.append((self._credentials.app_key, False))
        else:
            dev_key = self._credentials.device_keys.get(src)
            if dev_key:
                candidates.append((dev_key, True))

        for key, is_dev in candidates:
            try:
                access = upper_decrypt(
                    key,
                    seq=seq,
                    src=src,
                    dst=dst,
                    iv_index=self._credentials.iv_index,
                    upper_pdu=upper,
                    dev_key=is_dev,
                    szmic=szmic,
                )
            except Exception:  # noqa: BLE001 - wrong key or corrupt frame
                continue

            try:
                opcode, params = decode_access(access)
            except ValueError:
                continue

            _LOGGER.debug(
                "mesh RX src=0x%04x opcode=0x%04x params=%s",
                src,
                opcode,
                params.hex(),
            )
            self._resolve(opcode, src, params)
            if self._on_message is not None:
                self._on_message(src, opcode, params)
            return

    def _resolve(self, opcode: int, src: int, params: bytes) -> None:
        """Complete any request waiting on this status message."""
        for key in ((opcode, src), (opcode, None)):
            future = self._pending.get(key)
            if future is not None and not future.done():
                future.set_result(params)
                return

    # -- configuration client ---------------------------------------------

    async def get_composition_data(
        self, address: int, dev_key: bytes, page: int = 0
    ) -> CompositionData:
        """Read Composition Data page 0 from a node."""
        params = await self.request(
            address,
            OP_COMPOSITION_DATA_GET,
            bytes([page]),
            OP_COMPOSITION_DATA_STATUS,
            dev_key=dev_key,
        )
        if not params:
            raise MeshSessionError("empty composition data status")
        return parse_composition_data(address, params[1:])

    async def add_app_key(self, address: int, dev_key: bytes) -> None:
        """Add the network's AppKey to a node."""
        params = (
            pack_key_indexes(
                self._credentials.net_key_index, self._credentials.app_key_index
            )
            + self._credentials.app_key
        )

        status = await self.request(
            address, OP_APPKEY_ADD, params, OP_APPKEY_STATUS, dev_key=dev_key
        )
        _check_status(status, "AppKey Add")

    async def bind_model(
        self,
        address: int,
        dev_key: bytes,
        element_address: int,
        model_id: int,
        company_id: int | None = None,
    ) -> None:
        """Bind the AppKey to a model so it will accept our messages."""
        params = element_address.to_bytes(
            2, "little"
        ) + self._credentials.app_key_index.to_bytes(2, "little")
        if company_id is None:
            params += model_id.to_bytes(2, "little")
        else:
            params += company_id.to_bytes(2, "little") + model_id.to_bytes(2, "little")

        status = await self.request(
            address, OP_MODEL_APP_BIND, params, OP_MODEL_APP_STATUS, dev_key=dev_key
        )
        _check_status(status, "Model App Bind")

    async def reset_node(self, address: int, dev_key: bytes) -> None:
        """Factory-reset a node, removing it from this mesh."""
        try:
            await self.request(
                address,
                OP_NODE_RESET,
                b"",
                OP_NODE_RESET_STATUS,
                dev_key=dev_key,
                timeout=6.0,
            )
        except MeshSessionError:
            # Nodes commonly reset before the status makes it back to us.
            _LOGGER.debug("no Node Reset Status from 0x%04x (usually fine)", address)


def _check_status(params: bytes, what: str) -> None:
    """Raise unless a configuration status reports success (code 0)."""
    if not params:
        raise MeshSessionError(f"{what}: empty status")
    if params[0] != 0x00:
        raise MeshSessionError(f"{what} failed with status 0x{params[0]:02x}")
