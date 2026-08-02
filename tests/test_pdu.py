"""Tests for the mesh PDU layers."""

from __future__ import annotations

import pytest

from custom_components.amaran_ble.mesh import pdu


def h(value: str) -> bytes:
    return bytes.fromhex(value)


NET_KEY = h("7dd7364cd842ad18c17c2b820c84c3d6")
APP_KEY = h("63964771734fbd76e3b40519d1d94a48")
IV_INDEX = 0x12345678


def test_opcode_round_trip() -> None:
    assert pdu.encode_opcode(0x26) == b"\x26"
    assert pdu.encode_opcode(0x8008) == b"\x80\x08"
    assert pdu.encode_opcode(0x803D) == b"\x80\x3d"
    assert pdu.encode_opcode(0x00) == b"\x00"

    assert pdu.decode_access(b"\x26" + b"\x01" * 10) == (0x26, b"\x01" * 10)
    assert pdu.decode_access(b"\x80\x08\x00") == (0x8008, b"\x00")
    assert pdu.decode_access(b"\x02\xaa") == (0x02, b"\xaa")


def test_opcode_length_boundaries() -> None:
    assert pdu.opcode_length(0x00) == 1
    assert pdu.opcode_length(0x7E) == 1
    assert pdu.opcode_length(0x80) == 2
    assert pdu.opcode_length(0xBF) == 2
    assert pdu.opcode_length(0xC0) == 3
    assert pdu.opcode_length(0xFF) == 3


def test_invalid_opcodes_rejected() -> None:
    with pytest.raises(ValueError):
        pdu.encode_opcode(0x7F)  # reserved
    with pytest.raises(ValueError):
        pdu.encode_opcode(0xC000)  # 2-octet form with 3-octet prefix


def test_network_pdu_round_trip() -> None:
    keys = pdu.NetworkKeys.derive(NET_KEY)
    transport = h("0102030405060708090a0b0c0d0e0f10")

    raw = pdu.encode_network_pdu(
        keys,
        iv_index=IV_INDEX,
        ctl=0,
        ttl=7,
        seq=0x000123,
        src=0x0001,
        dst=0x0002,
        transport_pdu=transport,
    )
    decoded = pdu.decode_network_pdu(keys, IV_INDEX, raw)

    assert decoded is not None
    assert decoded.nid == keys.nid
    assert decoded.ctl == 0
    assert decoded.ttl == 7
    assert decoded.seq == 0x000123
    assert decoded.src == 0x0001
    assert decoded.dst == 0x0002
    assert decoded.transport_pdu == transport


def test_network_pdu_rejects_foreign_nid() -> None:
    ours = pdu.NetworkKeys.derive(NET_KEY)
    theirs = pdu.NetworkKeys.derive(h("00112233445566778899aabbccddeeff"))
    raw = pdu.encode_network_pdu(
        theirs,
        iv_index=IV_INDEX,
        ctl=0,
        ttl=7,
        seq=1,
        src=1,
        dst=2,
        transport_pdu=b"\x00" * 10,
    )
    if theirs.nid != ours.nid:
        assert pdu.decode_network_pdu(ours, IV_INDEX, raw) is None


def test_network_pdu_rejects_tampering() -> None:
    keys = pdu.NetworkKeys.derive(NET_KEY)
    raw = bytearray(
        pdu.encode_network_pdu(
            keys,
            iv_index=IV_INDEX,
            ctl=0,
            ttl=7,
            seq=5,
            src=1,
            dst=2,
            transport_pdu=b"\xaa" * 12,
        )
    )
    raw[-1] ^= 0xFF
    assert pdu.decode_network_pdu(keys, IV_INDEX, bytes(raw)) is None


def test_upper_transport_round_trip_app_key() -> None:
    access = pdu.encode_access(0x26, b"\x01" * 10)
    upper = pdu.upper_encrypt(
        APP_KEY, seq=7, src=0x0001, dst=0x0002, iv_index=IV_INDEX, access_payload=access
    )
    # 11 bytes access + 4 byte TransMIC fits an unsegmented access message exactly.
    assert len(upper) == 15

    out = pdu.upper_decrypt(
        APP_KEY, seq=7, src=0x0001, dst=0x0002, iv_index=IV_INDEX, upper_pdu=upper
    )
    assert out == access


def test_upper_transport_dev_key_uses_different_nonce() -> None:
    access = pdu.encode_access(0x8008, b"\x00")
    as_app = pdu.upper_encrypt(
        APP_KEY, seq=1, src=1, dst=2, iv_index=0, access_payload=access
    )
    as_dev = pdu.upper_encrypt(
        APP_KEY, seq=1, src=1, dst=2, iv_index=0, access_payload=access, dev_key=True
    )
    assert as_app != as_dev


def test_unsegmented_access_header() -> None:
    out = pdu.lower_unsegmented_access(akf=1, aid=0x3A, upper_pdu=b"\x11" * 15)
    assert out[0] == 0x7A  # SEG=0, AKF=1, AID=0x3A
    assert len(out) == 16

    with pytest.raises(ValueError):
        pdu.lower_unsegmented_access(1, 0, b"\x00" * 16)


def test_segmentation_and_reassembly() -> None:
    upper = bytes(range(30))
    segments = pdu.lower_segmented_access(akf=0, aid=0, upper_pdu=upper, seq_zero=0x1AB)

    assert len(segments) == 3  # 12 + 12 + 6
    assert all(seg[0] & 0x80 for seg in segments)

    message = pdu.SegmentedMessage(
        seq_zero=0x1AB, seg_n=2, szmic=0, akf=0, aid=0, seq=0
    )
    for index, seg in enumerate(segments):
        misc = int.from_bytes(seg[1:4], "big")
        assert (misc >> 10) & 0x1FFF == 0x1AB
        assert (misc >> 5) & 0x1F == index
        assert misc & 0x1F == 2
        message.segments[index] = seg[4:]

    assert message.complete
    assert message.reassemble() == upper
    assert message.block_ack == 0b111


def test_segment_ack_layout() -> None:
    ack = pdu.segment_ack_pdu(seq_zero=0x1AB, block_ack=0b111)
    assert ack[0] == 0x00
    assert int.from_bytes(ack[1:3], "big") >> 2 & 0x1FFF == 0x1AB
    assert int.from_bytes(ack[3:7], "big") == 0b111


def test_proxy_sar_round_trip() -> None:
    payload = bytes(range(60))
    pdus = pdu.proxy_segment(pdu.PROXY_TYPE_NETWORK, payload, mtu=20)

    assert len(pdus) == 4  # 19 bytes of payload per PDU
    assert all(len(p) <= 20 for p in pdus)
    assert (pdus[0][0] >> 6) == pdu.SAR_FIRST
    assert (pdus[-1][0] >> 6) == pdu.SAR_LAST

    reassembler = pdu.ProxyReassembler()
    results = [reassembler.push(p) for p in pdus]
    assert results[:-1] == [None, None, None]
    assert results[-1] == (pdu.PROXY_TYPE_NETWORK, payload)


def test_proxy_sar_single_pdu() -> None:
    pdus = pdu.proxy_segment(pdu.PROXY_TYPE_PROVISIONING, b"\x01\x02", mtu=20)
    assert len(pdus) == 1
    assert pdus[0] == bytes([pdu.PROXY_TYPE_PROVISIONING]) + b"\x01\x02"

    assert pdu.ProxyReassembler().push(pdus[0]) == (
        pdu.PROXY_TYPE_PROVISIONING,
        b"\x01\x02",
    )


def test_proxy_reassembler_drops_orphan_continuation() -> None:
    reassembler = pdu.ProxyReassembler()
    assert reassembler.push(bytes([(pdu.SAR_CONTINUATION << 6)]) + b"\xaa") is None


def test_address_helpers() -> None:
    assert pdu.is_unicast(0x0001)
    assert pdu.is_unicast(0x7FFF)
    assert not pdu.is_unicast(0x0000)
    assert not pdu.is_unicast(0xC000)
    assert pdu.is_group(0xC000)
    assert pdu.is_group(0xFFFF)
    assert not pdu.is_group(0x0001)
