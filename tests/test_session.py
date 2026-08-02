"""Tests for mesh session helpers (pure functions, no BLE required)."""

from __future__ import annotations

import pytest

from custom_components.amaran_ble.mesh.session import (
    MeshCredentials,
    MeshSessionError,
    pack_key_indexes,
    parse_composition_data,
)


def test_pack_key_indexes() -> None:
    # Mesh Profile 4.3.1.1: two 12-bit indexes packed into three octets.
    assert pack_key_indexes(0x000, 0x000) == b"\x00\x00\x00"
    assert pack_key_indexes(0x123, 0x456) == bytes([0x23, 0x61, 0x45])
    assert pack_key_indexes(0xFFF, 0xFFF) == bytes([0xFF, 0xFF, 0xFF])


def test_credentials_derive_keys_and_aid() -> None:
    creds = MeshCredentials(
        net_key=bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6"),
        app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
    )
    keys = creds.keys()

    assert len(keys.encryption_key) == 16
    assert len(keys.privacy_key) == 16
    assert 0 <= keys.nid <= 0x7F
    assert 0 <= creds.aid <= 0x3F


def test_parse_composition_data_single_element() -> None:
    data = bytes.fromhex(
        "1102"  # CID
        "2233"  # PID
        "4455"  # VID
        "0800"  # CRPL
        "0300"  # Features
        "0000"  # element Loc
        "03"  # 3 SIG models
        "01"  # 1 vendor model
        "0000"  # Configuration Server
        "0200"  # Health Server
        "0010"  # Generic OnOff Server
        "1102"
        "3412"  # vendor model: company 0x0211, model 0x1234
    )
    comp = parse_composition_data(0x0002, data)

    assert comp.company_id == 0x0211
    assert comp.product_id == 0x3322
    assert len(comp.elements) == 1

    element = comp.elements[0]
    assert element.address == 0x0002
    assert element.sig_models == [0x0000, 0x0002, 0x1000]
    assert element.vendor_models == [(0x0211, 0x1234)]


def test_parse_composition_data_multiple_elements_are_addressed_in_order() -> None:
    data = bytes.fromhex(
        "1102"
        "2233"
        "4455"
        "0800"
        "0300"
        "0000"
        "01"
        "00"
        "0000"  # element 0: one SIG model
        "0000"
        "01"
        "00"
        "0010"  # element 1: one SIG model
    )
    comp = parse_composition_data(0x0005, data)

    assert [e.address for e in comp.elements] == [0x0005, 0x0006]
    assert comp.elements[1].sig_models == [0x1000]


def test_parse_composition_data_rejects_short_payload() -> None:
    with pytest.raises(MeshSessionError):
        parse_composition_data(0x0002, b"\x00" * 4)


def test_parse_composition_data_rejects_truncated_model_list() -> None:
    data = bytes.fromhex(
        "11022233445508000300000002000000"  # claims 2 SIG models, only one present
    )
    with pytest.raises(MeshSessionError):
        parse_composition_data(0x0002, data)
