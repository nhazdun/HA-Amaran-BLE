"""Tests for the amaran vendor payload encoder.

The key test is :func:`java_pack`, a literal transcription of the APK's
``BinaryKit.toBinary`` / ``reverse`` / ``to10ByteArray`` string algorithm. Every
builder is checked against it, which proves the integer-based fast path in
``protocol.pack`` is byte-for-byte equivalent to what the app puts on the wire.
"""

from __future__ import annotations

import pytest

from custom_components.amaran_ble.amaran import protocol as p


def java_pack(fields: list[tuple[int, int]]) -> bytes:
    """Literal port of BinaryKit's bit-string packing used by getSendData()."""
    bits = ""
    for value, width in fields:
        # BinaryKit.toBinary(i, w) -> w-bit MSB-first string, then reverse().
        bits += format(value, f"0{width}b")[::-1]

    assert len(bits) == 80

    # BinaryKit.to10ByteArray: byte i = bit2Byte(reverse(bits[i*8:(i+1)*8]))
    out = bytearray(10)
    for i in range(10):
        out[i] = int(bits[i * 8 : (i + 1) * 8][::-1], 2)
    out[0] = sum(out[1:]) & 0xFF
    return bytes(out)


def test_pack_matches_java_bit_string_algorithm() -> None:
    fields = [
        (0, 8),
        (1, 1),
        (0, 20),
        (0, 13),
        (0, 1),
        (0, 1),
        (0, 1),
        (10, 7),
        (560, 10),
        (180, 10),
        (2, 7),
        (1, 1),
    ]
    assert p.pack(fields) == java_pack(fields)


def test_cct_matches_java_reference() -> None:
    """CCTProtocol(180, 560, 100, 0) - the app's own default preset."""
    expected = java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 20),
            (0, 13),
            (0, 1),  # cct high flag: 5600 K <= 10000
            (0, 1),  # gmFlag
            (0, 1),  # gmHigh
            (10, 7),  # round(100 / 10)
            (560, 10),
            (180, 10),
            (2, 7),
            (1, 1),
        ]
    )
    assert p.cct(180, 560) == expected


def test_payload_is_ten_bytes_with_valid_checksum() -> None:
    payloads = [
        p.cct(1000, 650),
        p.cct(0, 270),
        p.sleep(True),
        p.sleep(False),
        p.brightness(500),
        p.get_power(),
        p.stand_by(1),
    ] + [p.build_effect(name, 750, 560) for name in p.VERGE_EFFECTS]

    for payload in payloads:
        assert len(payload) == p.PAYLOAD_BYTES
        assert p.checksum_valid(payload)


def test_command_and_effect_fields_readable() -> None:
    assert p.command_of(p.cct(500, 560)) == p.Command.CCT
    assert p.command_of(p.sleep(True)) == p.Command.SLEEP
    assert p.command_of(p.brightness(500)) == p.Command.BRIGHTNESS
    assert p.command_of(p.get_power()) == p.Command.GET_POWER

    for name, effect in p.VERGE_EFFECTS.items():
        payload = p.build_effect(name, 500, 560)
        assert p.command_of(payload) == p.Command.SYSTEM_EFFECT
        assert p.effect_of(payload) == effect


def test_sleep_mode_field() -> None:
    assert p.parse_sleep(p.sleep(True)) == 1
    assert p.parse_sleep(p.sleep(False)) == 0


def test_cct_round_trip() -> None:
    payload = p.cct(742, 415)
    parsed = p.parse_cct(payload)

    assert parsed["intensity"] == 742
    assert parsed["cct"] == 415
    assert parsed["gm"] == 100
    assert parsed["sleep_mode"] == 1
    assert parsed["opera_type"] == p.OPTION_WRITE


def test_cct_above_10000_kelvin_uses_carry_bit() -> None:
    # 10500 K -> stored as 50 with the high flag set, decoded back to 1050.
    payload = p.cct(500, 1050)
    assert p.unpack_field(payload, 42, 1) == 1
    assert p.unpack_field(payload, 52, 10) == 50
    assert p.parse_cct(payload)["cct"] == 1050


def test_verge_cct_range_encodes() -> None:
    # amaran Verge: product_cct_min 27 -> 2700 K, product_cct_max 65 -> 6500 K.
    for kelvin in (2700, 4300, 5600, 6500):
        parsed = p.parse_cct(p.cct(1000, kelvin // 10))
        assert parsed["cct"] * 10 == kelvin


def test_effects_match_java_layouts() -> None:
    """Spot-check each effect against its transcribed field list."""
    assert p.effect_lightning(500, 560) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 15),
            (0, 1),
            (0, 1),
            (0, 1),
            (0, 4),  # speed
            (0, 2),  # trigger
            (10, 7),
            (560, 10),
            (5, 4),  # frq
            (500, 10),
            (2, 8),
            (7, 7),
            (1, 1),
        ]
    )

    assert p.effect_tv(500) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 20),
            (0, 11),
            (0, 10),  # cctType
            (5, 4),
            (500, 10),
            (3, 8),
            (7, 7),
            (1, 1),
        ]
    )

    assert p.effect_strobe(500, 560) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 15),
            (0, 1),
            (0, 1),
            (0, 1),
            (0, 2),  # trigger
            (10, 7),
            (560, 10),
            (500, 10),
            (5, 4),  # frq
            (0, 4),  # effectMode = CCT
            (6, 8),
            (7, 7),
            (1, 1),
        ]
    )

    assert p.effect_faulty_bulb(500, 560) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 11),
            (0, 1),
            (0, 1),
            (0, 1),
            (0, 4),  # speed
            (0, 2),  # trigger
            (10, 7),
            (560, 10),
            (500, 10),
            (5, 4),
            (0, 4),
            (8, 8),
            (7, 7),
            (1, 1),
        ]
    )

    assert p.effect_fireworks(500) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 20),
            (0, 13),
            (0, 8),  # type
            (5, 4),
            (500, 10),
            (14, 8),
            (7, 7),
            (1, 1),
        ]
    )


def test_gm_encoding_variants() -> None:
    # gm_flag = 0 stores gm/10.
    assert p.unpack_field(p.cct(500, 560, gm=100, gm_flag=0), 45, 7) == 10
    assert p.unpack_field(p.cct(500, 560, gm=50, gm_flag=0), 45, 7) == 5
    # gm_flag = 1 stores the raw value, carrying >100 in gm_high.
    payload = p.cct(500, 560, gm=130, gm_flag=1)
    assert p.unpack_field(payload, 43, 1) == 1
    assert p.unpack_field(payload, 44, 1) == 1
    assert p.unpack_field(payload, 45, 7) == 30
    assert p.parse_cct(payload)["gm"] == 130


def test_pack_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="does not fit"):
        p.pack([(256, 8), (0, 72)])
    with pytest.raises(ValueError, match="expected 80"):
        p.pack([(0, 8)])
    with pytest.raises(ValueError, match="unsupported effect"):
        p.build_effect("Nope", 500, 560)


def test_intensity_bounds() -> None:
    assert p.checksum_valid(p.cct(0, 270))
    assert p.checksum_valid(p.cct(1000, 650))
    with pytest.raises(ValueError):
        p.cct(1024, 560)  # 10-bit field overflow


def test_dimming_curve_matches_java_reference() -> None:
    for name, curve in p.DIMMING_CURVE_NAMES.items():
        payload = p.dimming_curve(int(curve))
        assert payload == java_pack(
            [(0, 8), (0, 20), (0, 20), (0, 16), (int(curve), 8), (8, 7), (1, 1)]
        ), name
        assert p.command_of(payload) == p.Command.DIMMING_CURVE
        assert p.unpack_field(payload, 64, 8) == int(curve)


def test_identify_matches_java_reference() -> None:
    assert p.identify(True) == java_pack(
        [(0, 8), (0, 1), (0, 20), (0, 20), (0, 13), (1, 2), (16, 8), (7, 7), (1, 1)]
    )
    assert p.command_of(p.identify(True)) == p.Command.SYSTEM_EFFECT
    assert p.effect_of(p.identify(True)) == p.Effect.I_AM_HERE
    assert p.unpack_field(p.identify(False), 62, 2) == 0


def test_effect_speed_lands_in_the_frq_field() -> None:
    # frq sits at a different offset per effect; check via the java reference.
    assert p.build_effect("TV", 500, 560, frq=12) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 20),
            (0, 11),
            (0, 10),
            (12, 4),
            (500, 10),
            (3, 8),
            (7, 7),
            (1, 1),
        ]
    )
    assert p.build_effect("Strobe", 500, 560, frq=9) == java_pack(
        [
            (0, 8),
            (1, 1),
            (0, 15),
            (0, 1),
            (0, 1),
            (0, 1),
            (0, 2),
            (10, 7),
            (560, 10),
            (500, 10),
            (9, 4),
            (0, 4),
            (6, 8),
            (7, 7),
            (1, 1),
        ]
    )


def test_effect_speed_is_clamped_to_the_four_bit_field() -> None:
    for name in p.VERGE_EFFECTS:
        assert p.checksum_valid(p.build_effect(name, 500, 560, frq=99))
        assert p.checksum_valid(p.build_effect(name, 500, 560, frq=-5))


def test_parse_power_round_trip() -> None:
    payload = p.pack(
        [
            (0, 8),
            (0, 12),
            (1, 1),  # powered
            (0, 3),
            (90, 9),  # battery_time (protocol < 42)
            (77, 7),  # battery_level
            (11100, 16),  # battery_voltage, mV
            (19500, 16),  # extern_voltage, mV
            (10, 7),
            (0, 1),
        ]
    )
    power = p.parse_power(payload)
    assert power["powered"] == 1
    assert power["battery_level"] == 77
    assert power["battery_time"] == 90
    assert power["battery_voltage"] == 11100
    assert power["extern_voltage"] == 19500
