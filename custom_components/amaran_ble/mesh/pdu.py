"""Bluetooth SIG Mesh PDU encoding/decoding.

Covers the layers a provisioner + proxy client needs:

* Access layer      - opcode + parameters (Mesh Profile 3.7.3)
* Upper transport   - AppKey/DevKey AES-CCM (3.6.2)
* Lower transport   - (un)segmented access messages and segment acks (3.5.2)
* Network layer     - encryption + obfuscation (3.4.4)
* Proxy             - SAR framing over GATT (6.3.1)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import (
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    aes_ecb,
    application_nonce,
    beacon_key,
    device_nonce,
    identity_key,
    k2,
    network_id,
    network_nonce,
)

# Proxy PDU message types (Mesh Profile 6.3.1).
PROXY_TYPE_NETWORK = 0x00
PROXY_TYPE_BEACON = 0x01
PROXY_TYPE_CONFIGURATION = 0x02
PROXY_TYPE_PROVISIONING = 0x03

SAR_COMPLETE = 0b00
SAR_FIRST = 0b01
SAR_CONTINUATION = 0b10
SAR_LAST = 0b11

UNASSIGNED_ADDRESS = 0x0000
ALL_NODES_ADDRESS = 0xFFFF


def is_unicast(address: int) -> bool:
    """Return True for a unicast address (0x0001-0x7FFF)."""
    return 0 < address < 0x8000


def is_group(address: int) -> bool:
    """Return True for a group address (0xC000-0xFFFF)."""
    return 0xC000 <= address <= 0xFFFF


# --------------------------------------------------------------------------
# Network keys
# --------------------------------------------------------------------------


@dataclass(slots=True)
class NetworkKeys:
    """Key material derived from a NetKey."""

    net_key: bytes
    nid: int
    encryption_key: bytes
    privacy_key: bytes
    network_id: bytes
    beacon_key: bytes
    identity_key: bytes

    @classmethod
    def derive(cls, net_key: bytes) -> NetworkKeys:
        """Derive all per-NetKey material via k2/k3/k1."""
        nid, encryption_key, privacy_key = k2(net_key, b"\x00")
        return cls(
            net_key=net_key,
            nid=nid,
            encryption_key=encryption_key,
            privacy_key=privacy_key,
            network_id=network_id(net_key),
            beacon_key=beacon_key(net_key),
            identity_key=identity_key(net_key),
        )


# --------------------------------------------------------------------------
# Access layer
# --------------------------------------------------------------------------


def opcode_length(first_byte: int) -> int:
    """Return the octet count of an access opcode from its first wire byte."""
    if first_byte & 0x80 == 0x00:
        return 1
    if first_byte & 0xC0 == 0x80:
        return 2
    return 3


def encode_opcode(opcode: int) -> bytes:
    """Serialise an opcode given in wire (big-endian) form.

    ``0x26`` -> ``26``; ``0x8008`` -> ``80 08``; ``0xC0AABB`` -> ``c0 aa bb``.
    """
    if opcode <= 0x7E:
        return bytes([opcode])
    if opcode <= 0xFFFF:
        if (opcode >> 8) & 0xC0 != 0x80:
            raise ValueError(f"invalid 2-octet opcode 0x{opcode:04X}")
        return opcode.to_bytes(2, "big")
    if opcode <= 0xFFFFFF:
        if (opcode >> 16) & 0xC0 != 0xC0:
            raise ValueError(f"invalid 3-octet opcode 0x{opcode:06X}")
        return opcode.to_bytes(3, "big")
    raise ValueError(f"opcode out of range: 0x{opcode:X}")


def encode_access(opcode: int, params: bytes = b"") -> bytes:
    """Build an access payload (opcode || parameters)."""
    return encode_opcode(opcode) + params


def decode_access(payload: bytes) -> tuple[int, bytes]:
    """Split an access payload into ``(opcode, parameters)``."""
    if not payload:
        raise ValueError("empty access payload")
    length = opcode_length(payload[0])
    if len(payload) < length:
        raise ValueError("truncated access opcode")
    return int.from_bytes(payload[:length], "big"), payload[length:]


# --------------------------------------------------------------------------
# Upper transport (application / device key encryption)
# --------------------------------------------------------------------------


def upper_encrypt(
    key: bytes,
    *,
    seq: int,
    src: int,
    dst: int,
    iv_index: int,
    access_payload: bytes,
    dev_key: bool = False,
    szmic: int = 0,
) -> bytes:
    """Encrypt an access payload into an Upper Transport PDU."""
    nonce_fn = device_nonce if dev_key else application_nonce
    nonce = nonce_fn(seq, src, dst, iv_index, szmic)
    return aes_ccm_encrypt(key, nonce, access_payload, mic_len=8 if szmic else 4)


def upper_decrypt(
    key: bytes,
    *,
    seq: int,
    src: int,
    dst: int,
    iv_index: int,
    upper_pdu: bytes,
    dev_key: bool = False,
    szmic: int = 0,
) -> bytes:
    """Decrypt an Upper Transport PDU back to an access payload."""
    nonce_fn = device_nonce if dev_key else application_nonce
    nonce = nonce_fn(seq, src, dst, iv_index, szmic)
    return aes_ccm_decrypt(key, nonce, upper_pdu, mic_len=8 if szmic else 4)


# --------------------------------------------------------------------------
# Lower transport
# --------------------------------------------------------------------------

UNSEGMENTED_ACCESS_MAX = 15
SEGMENT_PAYLOAD_LEN = 12


def lower_unsegmented_access(akf: int, aid: int, upper_pdu: bytes) -> bytes:
    """Build an unsegmented access Lower Transport PDU."""
    if len(upper_pdu) > UNSEGMENTED_ACCESS_MAX:
        raise ValueError("upper transport PDU too long for an unsegmented message")
    return bytes([((akf & 1) << 6) | (aid & 0x3F)]) + upper_pdu


def lower_segmented_access(
    akf: int, aid: int, upper_pdu: bytes, seq_zero: int, szmic: int = 0
) -> list[bytes]:
    """Split an Upper Transport PDU into segmented access Lower Transport PDUs."""
    chunks = [
        upper_pdu[i : i + SEGMENT_PAYLOAD_LEN]
        for i in range(0, len(upper_pdu), SEGMENT_PAYLOAD_LEN)
    ]
    seg_n = len(chunks) - 1
    if seg_n > 31:
        raise ValueError("message too long to segment (>32 segments)")

    pdus = []
    for seg_o, chunk in enumerate(chunks):
        header = 0x80 | ((akf & 1) << 6) | (aid & 0x3F)
        # SZMIC(1) | SeqZero(13) | SegO(5) | SegN(5) == 24 bits
        misc = ((szmic & 1) << 23) | ((seq_zero & 0x1FFF) << 10)
        misc |= ((seg_o & 0x1F) << 5) | (seg_n & 0x1F)
        pdus.append(bytes([header]) + misc.to_bytes(3, "big") + chunk)
    return pdus


@dataclass(slots=True)
class SegmentedMessage:
    """Reassembly buffer for one segmented Upper Transport PDU."""

    seq_zero: int
    seg_n: int
    szmic: int
    akf: int
    aid: int
    seq: int
    segments: dict[int, bytes] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """True once every segment has arrived."""
        return len(self.segments) == self.seg_n + 1

    @property
    def block_ack(self) -> int:
        """Bitfield of received segments, for the Segment Acknowledgement."""
        ack = 0
        for index in self.segments:
            ack |= 1 << index
        return ack

    def reassemble(self) -> bytes:
        """Concatenate the received segments in order."""
        return b"".join(self.segments[i] for i in range(self.seg_n + 1))


def segment_ack_pdu(seq_zero: int, block_ack: int, obo: int = 0) -> bytes:
    """Build a Segment Acknowledgement control message (opcode 0x00)."""
    misc = ((obo & 1) << 15) | ((seq_zero & 0x1FFF) << 2)
    return bytes([0x00]) + misc.to_bytes(2, "big") + block_ack.to_bytes(4, "big")


# --------------------------------------------------------------------------
# Network layer
# --------------------------------------------------------------------------


@dataclass(slots=True)
class NetworkPdu:
    """A decoded network PDU."""

    ivi: int
    nid: int
    ctl: int
    ttl: int
    seq: int
    src: int
    dst: int
    transport_pdu: bytes


def _privacy_xor(
    keys: NetworkKeys, iv_index: int, encrypted: bytes, obfuscated: bytes
) -> bytes:
    """XOR six header bytes with the privacy PECB (Mesh Profile 3.8.7.3)."""
    privacy_random = encrypted[:7]
    pecb_input = b"\x00" * 5 + iv_index.to_bytes(4, "big") + privacy_random
    pecb = aes_ecb(keys.privacy_key, pecb_input)
    return bytes(a ^ b for a, b in zip(obfuscated, pecb[:6], strict=True))


def encode_network_pdu(
    keys: NetworkKeys,
    *,
    iv_index: int,
    ctl: int,
    ttl: int,
    seq: int,
    src: int,
    dst: int,
    transport_pdu: bytes,
) -> bytes:
    """Encrypt and obfuscate a network PDU."""
    mic_len = 8 if ctl else 4
    nonce = network_nonce(ctl, ttl, seq, src, iv_index)
    encrypted = aes_ccm_encrypt(
        keys.encryption_key,
        nonce,
        dst.to_bytes(2, "big") + transport_pdu,
        mic_len=mic_len,
    )

    header = bytes([((ctl & 1) << 7) | (ttl & 0x7F)])
    header += seq.to_bytes(3, "big") + src.to_bytes(2, "big")
    obfuscated = _privacy_xor(keys, iv_index, encrypted, header)

    ivi_nid = bytes([((iv_index & 1) << 7) | (keys.nid & 0x7F)])
    return ivi_nid + obfuscated + encrypted


def decode_network_pdu(
    keys: NetworkKeys, iv_index: int, data: bytes
) -> NetworkPdu | None:
    """Deobfuscate and decrypt a network PDU. Returns ``None`` if it is not ours."""
    if len(data) < 14:
        return None

    ivi = (data[0] >> 7) & 1
    nid = data[0] & 0x7F
    if nid != keys.nid:
        return None

    obfuscated = data[1:7]
    encrypted = data[7:]

    header = _privacy_xor(keys, iv_index, encrypted, obfuscated)
    ctl = (header[0] >> 7) & 1
    ttl = header[0] & 0x7F
    seq = int.from_bytes(header[1:4], "big")
    src = int.from_bytes(header[4:6], "big")

    mic_len = 8 if ctl else 4
    nonce = network_nonce(ctl, ttl, seq, src, iv_index)
    try:
        plaintext = aes_ccm_decrypt(
            keys.encryption_key, nonce, encrypted, mic_len=mic_len
        )
    except Exception:  # noqa: BLE001 - InvalidTag or malformed input
        return None

    return NetworkPdu(
        ivi=ivi,
        nid=nid,
        ctl=ctl,
        ttl=ttl,
        seq=seq,
        src=src,
        dst=int.from_bytes(plaintext[:2], "big"),
        transport_pdu=plaintext[2:],
    )


# --------------------------------------------------------------------------
# Proxy SAR
# --------------------------------------------------------------------------


def proxy_segment(msg_type: int, payload: bytes, mtu: int) -> list[bytes]:
    """Frame a payload into one or more proxy PDUs of at most ``mtu`` bytes."""
    capacity = max(1, mtu - 1)
    if len(payload) <= capacity:
        return [bytes([(SAR_COMPLETE << 6) | msg_type]) + payload]

    chunks = [payload[i : i + capacity] for i in range(0, len(payload), capacity)]
    pdus = []
    for index, chunk in enumerate(chunks):
        if index == 0:
            sar = SAR_FIRST
        elif index == len(chunks) - 1:
            sar = SAR_LAST
        else:
            sar = SAR_CONTINUATION
        pdus.append(bytes([(sar << 6) | msg_type]) + chunk)
    return pdus


class ProxyReassembler:
    """Reassembles inbound proxy PDUs that arrive split across notifications."""

    def __init__(self) -> None:
        """Start with an empty buffer."""
        self._msg_type: int | None = None
        self._buffer = bytearray()

    def push(self, data: bytes) -> tuple[int, bytes] | None:
        """Feed one notification; returns ``(msg_type, payload)`` when complete."""
        if not data:
            return None

        sar = (data[0] >> 6) & 0x03
        msg_type = data[0] & 0x3F
        payload = data[1:]

        if sar == SAR_COMPLETE:
            self._reset()
            return msg_type, payload

        if sar == SAR_FIRST:
            self._msg_type = msg_type
            self._buffer = bytearray(payload)
            return None

        if self._msg_type is None or msg_type != self._msg_type:
            # Continuation without a matching start - drop it.
            self._reset()
            return None

        self._buffer.extend(payload)
        if sar == SAR_LAST:
            result = (self._msg_type, bytes(self._buffer))
            self._reset()
            return result
        return None

    def _reset(self) -> None:
        self._msg_type = None
        self._buffer = bytearray()
