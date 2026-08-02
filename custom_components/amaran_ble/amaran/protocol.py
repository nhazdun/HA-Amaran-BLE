"""amaran / Aputure vendor payloads carried inside mesh opcode 0x26.

Every payload is exactly 10 bytes. The Sidus Link app builds them by appending
bit fields to a list and concatenating each field LSB-first
(``BinaryKit.toBinary`` + ``BinaryKit.reverse``), then packing the resulting
80-bit string into bytes LSB-first (``BinaryKit.to10ByteArray``).

That is equivalent to treating the 10 bytes as a little-endian 80-bit integer
in which the first-appended field occupies the lowest bit positions. Byte 0 is
then overwritten with the sum of bytes 1..9 as a checksum.

:func:`pack` takes the fields in the app's append order so each builder below
can be read side-by-side with the decompiled ``getSendData()``.
"""

from __future__ import annotations

from enum import IntEnum

PAYLOAD_BITS = 80
PAYLOAD_BYTES = 10

# Vendor mesh opcode every amaran payload travels under.
VENDOR_OPCODE = 0x26

OPTION_READ = 0
OPTION_WRITE = 1


class Command(IntEnum):
    """Values of the 7-bit command field (``ProtocolConstant.CMD_*``)."""

    GET_VER = 0
    HSI = 1
    CCT = 2
    GEL = 3
    RGBW = 4
    XY = 5
    SYSTEM_EFFECT = 7
    GET_POWER = 10
    SLEEP = 12
    BRIGHTNESS = 15
    STAND_BY = 55


class Effect(IntEnum):
    """System-effect identifiers supported by the amaran Verge."""

    LIGHTNING = 2
    TV = 3
    FIRE = 5
    STROBE = 6
    EXPLOSION = 7
    FAULTY_BULB = 8
    FIREWORKS = 14


#: Effects the Verge / Verge Max firmware advertises in ``fixtureConfig.json``.
VERGE_EFFECTS: dict[str, Effect] = {
    "Lightning": Effect.LIGHTNING,
    "TV": Effect.TV,
    "Fire": Effect.FIRE,
    "Strobe": Effect.STROBE,
    "Explosion": Effect.EXPLOSION,
    "Faulty Bulb": Effect.FAULTY_BULB,
    "Fireworks": Effect.FIREWORKS,
}

# Effect mode selector (``ProtocolConstant.EFFECT_MODE_*``). The Verge is a
# bi-color fixture, so it only ever uses the CCT variant.
EFFECT_MODE_CCT = 0

# Neutral green/magenta shift. gm=100 with gm_flag=0 encodes as 10 in the
# 7-bit field, which is what the app sends for fixtures without GM support.
NEUTRAL_GM = 100

Field = tuple[int, int]


def pack(fields: list[Field]) -> bytes:
    """Pack ``(value, width)`` fields, in app append order, into 10 bytes.

    The first field must be the 8-bit checksum placeholder; byte 0 is
    recomputed as ``sum(bytes[1:]) & 0xFF`` before returning.
    """
    value = 0
    offset = 0
    for raw, width in fields:
        if width <= 0:
            raise ValueError(f"invalid field width {width}")
        if not 0 <= raw < (1 << width):
            raise ValueError(f"value {raw} does not fit in {width} bits")
        value |= raw << offset
        offset += width

    if offset != PAYLOAD_BITS:
        raise ValueError(f"payload is {offset} bits, expected {PAYLOAD_BITS}")

    data = bytearray(value.to_bytes(PAYLOAD_BYTES, "little"))
    data[0] = sum(data[1:]) & 0xFF
    return bytes(data)


def unpack_field(payload: bytes, offset: int, width: int) -> int:
    """Read a bit field back out of a payload (mirrors ``splitAnd2Decimal``)."""
    value = int.from_bytes(payload, "little")
    return (value >> offset) & ((1 << width) - 1)


def command_of(payload: bytes) -> int:
    """Return the 7-bit command type of a received payload."""
    return unpack_field(payload, 72, 7)


def effect_of(payload: bytes) -> int:
    """Return the 8-bit effect type of a received payload."""
    return unpack_field(payload, 64, 8)


def checksum_valid(payload: bytes) -> bool:
    """Return True when byte 0 matches the sum of the remaining bytes."""
    return len(payload) == PAYLOAD_BYTES and payload[0] == sum(payload[1:]) & 0xFF


def _gm_fields(gm: int, gm_flag: int) -> tuple[int, int]:
    """Return ``(gm_high, gm_value)`` exactly as the app encodes them."""
    if gm_flag == 0:
        return 0, round(gm / 10)
    if gm > 100:
        return 1, gm - 100
    return 0, gm


def _cct_split(cct_deci_kelvin: int) -> tuple[int, int]:
    """Return ``(cct_high_flag, encoded_cct)`` for a Kelvin/10 value.

    Values above 10000 K carry the overflow in a separate flag bit, matching
    ``CCTProtocol.getCctValue()``.
    """
    kelvin = cct_deci_kelvin * 10
    high = 0 if kelvin <= 10000 else 1
    if kelvin > 10000:
        kelvin -= 10000
    return high, kelvin // 10


# --------------------------------------------------------------------------
# Core light commands
# --------------------------------------------------------------------------


def cct(
    intensity: int,
    cct_deci_kelvin: int,
    gm: int = NEUTRAL_GM,
    gm_flag: int = 0,
    sleep_mode: int = 1,
) -> bytes:
    """Colour temperature + intensity (``CCTProtocol``, command 2).

    ``intensity`` is tenths of a percent (0-1000) and ``cct_deci_kelvin`` is
    Kelvin/10, so 5600 K at 50 % is ``cct(500, 560)``.
    """
    cct_high, cct_value = _cct_split(cct_deci_kelvin)
    gm_high, gm_value = _gm_fields(gm, gm_flag)
    return pack(
        [
            (0, 8),
            (sleep_mode, 1),
            (0, 20),
            (0, 13),
            (cct_high, 1),
            (gm_flag, 1),
            (gm_high, 1),
            (gm_value, 7),
            (cct_value, 10),
            (intensity, 10),
            (Command.CCT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def sleep(on: bool) -> bytes:
    """Power on/off (``SleepProtocol``, command 12). ``mode`` 1 = on, 0 = off."""
    return pack(
        [
            (0, 8),
            (0, 20),
            (0, 20),
            (0, 16),
            (1 if on else 0, 8),
            (Command.SLEEP, 7),
            (OPTION_WRITE, 1),
        ]
    )


def stand_by(mode: int) -> bytes:
    """Standby control (``StandByProtocol``, command 55)."""
    return pack(
        [
            (0, 8),
            (0, 20),
            (0, 20),
            (0, 16),
            (mode, 8),
            (Command.STAND_BY, 7),
            (OPTION_WRITE, 1),
        ]
    )


def brightness(intensity: int, ratio: int = 0) -> bytes:
    """Intensity-only change (``BrightProtocol``, command 15).

    Note the app sends this with ``operaType = 0``, unlike every other
    command; that is reproduced here verbatim.
    """
    return pack(
        [
            (0, 8),
            (0, 20),
            (0, 20),
            (0, 13),
            (ratio, 1),
            (intensity, 10),
            (Command.BRIGHTNESS, 7),
            (OPTION_READ, 1),
        ]
    )


def get_power() -> bytes:
    """Battery/power query (``GetPowerProtocol``, command 10)."""
    return pack(
        [
            (0, 8),
            (0, 20),
            (0, 20),
            (0, 16),
            (0, 8),
            (Command.GET_POWER, 7),
            (OPTION_READ, 1),
        ]
    )


# --------------------------------------------------------------------------
# System effects (command 7)
# --------------------------------------------------------------------------
#
# Each effect has its own field layout. They are transcribed one-for-one from
# the matching ``*Protocol.getSendData()`` in the APK.


def effect_lightning(
    intensity: int,
    cct_deci_kelvin: int,
    frq: int = 5,
    speed: int = 0,
    trigger: int = 0,
    gm: int = NEUTRAL_GM,
    gm_flag: int = 0,
    sleep_mode: int = 1,
) -> bytes:
    """``LightningProtocol`` - effect 2."""
    cct_high, cct_value = _cct_split(cct_deci_kelvin)
    gm_high, gm_value = _gm_fields(gm, gm_flag)
    return pack(
        [
            (0, 8),
            (sleep_mode, 1),
            (0, 15),
            (cct_high, 1),
            (gm_flag, 1),
            (gm_high, 1),
            (speed, 4),
            (trigger, 2),
            (gm_value, 7),
            (cct_value, 10),
            (frq, 4),
            (intensity, 10),
            (Effect.LIGHTNING, 8),
            (Command.SYSTEM_EFFECT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def _effect_cct_type(effect: Effect, intensity: int, cct_type: int, frq: int) -> bytes:
    """Shared layout for ``TVProtocol`` and ``FireProtocol`` (effects 3 and 5)."""
    return pack(
        [
            (0, 8),
            (1, 1),
            (0, 20),
            (0, 11),
            (cct_type, 10),
            (frq, 4),
            (intensity, 10),
            (effect, 8),
            (Command.SYSTEM_EFFECT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def effect_tv(intensity: int, cct_type: int = 0, frq: int = 5) -> bytes:
    """``TVProtocol`` - effect 3."""
    return _effect_cct_type(Effect.TV, intensity, cct_type, frq)


def effect_fire(intensity: int, cct_type: int = 0, frq: int = 5) -> bytes:
    """``FireProtocol`` - effect 5."""
    return _effect_cct_type(Effect.FIRE, intensity, cct_type, frq)


def _effect_strobe_like(
    effect: Effect,
    intensity: int,
    cct_deci_kelvin: int,
    frq: int,
    trigger: int,
    gm: int,
    gm_flag: int,
    sleep_mode: int,
) -> bytes:
    """Shared CCT-mode layout for ``StrobeProtocol`` / ``ExplosionProtocol``."""
    cct_high, cct_value = _cct_split(cct_deci_kelvin)
    gm_high, gm_value = _gm_fields(gm, gm_flag)
    return pack(
        [
            (0, 8),
            (sleep_mode, 1),
            (0, 15),
            (cct_high, 1),
            (gm_flag, 1),
            (gm_high, 1),
            (trigger, 2),
            (gm_value, 7),
            (cct_value, 10),
            (intensity, 10),
            (frq, 4),
            (EFFECT_MODE_CCT, 4),
            (effect, 8),
            (Command.SYSTEM_EFFECT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def effect_strobe(
    intensity: int,
    cct_deci_kelvin: int,
    frq: int = 5,
    trigger: int = 0,
    gm: int = NEUTRAL_GM,
    gm_flag: int = 0,
    sleep_mode: int = 1,
) -> bytes:
    """``StrobeProtocol`` in CCT mode - effect 6."""
    return _effect_strobe_like(
        Effect.STROBE, intensity, cct_deci_kelvin, frq, trigger, gm, gm_flag, sleep_mode
    )


def effect_explosion(
    intensity: int,
    cct_deci_kelvin: int,
    frq: int = 5,
    trigger: int = 0,
    gm: int = NEUTRAL_GM,
    gm_flag: int = 0,
    sleep_mode: int = 1,
) -> bytes:
    """``ExplosionProtocol`` in CCT mode - effect 7."""
    return _effect_strobe_like(
        Effect.EXPLOSION,
        intensity,
        cct_deci_kelvin,
        frq,
        trigger,
        gm,
        gm_flag,
        sleep_mode,
    )


def effect_faulty_bulb(
    intensity: int,
    cct_deci_kelvin: int,
    frq: int = 5,
    speed: int = 0,
    trigger: int = 0,
    gm: int = NEUTRAL_GM,
    gm_flag: int = 0,
    sleep_mode: int = 1,
) -> bytes:
    """``FaultBulbProtocol`` in CCT mode - effect 8."""
    cct_high, cct_value = _cct_split(cct_deci_kelvin)
    gm_high, gm_value = _gm_fields(gm, gm_flag)
    return pack(
        [
            (0, 8),
            (sleep_mode, 1),
            (0, 11),
            (cct_high, 1),
            (gm_flag, 1),
            (gm_high, 1),
            (speed, 4),
            (trigger, 2),
            (gm_value, 7),
            (cct_value, 10),
            (intensity, 10),
            (frq, 4),
            (EFFECT_MODE_CCT, 4),
            (Effect.FAULTY_BULB, 8),
            (Command.SYSTEM_EFFECT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def effect_fireworks(
    intensity: int, kind: int = 0, frq: int = 5, sleep_mode: int = 1
) -> bytes:
    """``FireworksProtocol`` - effect 14."""
    return pack(
        [
            (0, 8),
            (sleep_mode, 1),
            (0, 20),
            (0, 13),
            (kind, 8),
            (frq, 4),
            (intensity, 10),
            (Effect.FIREWORKS, 8),
            (Command.SYSTEM_EFFECT, 7),
            (OPTION_WRITE, 1),
        ]
    )


def effect_off(intensity: int, cct_deci_kelvin: int) -> bytes:
    """Leave effect mode by re-sending a plain CCT command."""
    return cct(intensity, cct_deci_kelvin)


def build_effect(name: str, intensity: int, cct_deci_kelvin: int) -> bytes:
    """Build the payload for a named Verge effect at the given light settings."""
    effect = VERGE_EFFECTS.get(name)
    if effect is None:
        raise ValueError(f"unsupported effect: {name}")

    if effect is Effect.LIGHTNING:
        return effect_lightning(intensity, cct_deci_kelvin)
    if effect is Effect.TV:
        return effect_tv(intensity)
    if effect is Effect.FIRE:
        return effect_fire(intensity)
    if effect is Effect.STROBE:
        return effect_strobe(intensity, cct_deci_kelvin)
    if effect is Effect.EXPLOSION:
        return effect_explosion(intensity, cct_deci_kelvin)
    if effect is Effect.FAULTY_BULB:
        return effect_faulty_bulb(intensity, cct_deci_kelvin)
    return effect_fireworks(intensity)


# --------------------------------------------------------------------------
# Inbound parsing
# --------------------------------------------------------------------------


def parse_cct(payload: bytes) -> dict[str, int]:
    """Decode a CCT status payload (mirrors ``CCTProtocol.parseData``)."""
    cct_value = unpack_field(payload, 52, 10)
    if unpack_field(payload, 42, 1):
        cct_value += 1000

    gm_flag = unpack_field(payload, 43, 1)
    gm_high = unpack_field(payload, 44, 1)
    gm_raw = unpack_field(payload, 45, 7)

    return {
        "intensity": unpack_field(payload, 62, 10),
        "cct": cct_value,
        "gm": gm_raw * 10 if gm_flag == 0 else gm_high * 100 + gm_raw,
        "sleep_mode": unpack_field(payload, 8, 1),
        "opera_type": unpack_field(payload, 79, 1),
    }


def parse_sleep(payload: bytes) -> int:
    """Decode a sleep-mode status payload. 1 = on, 0 = off."""
    return unpack_field(payload, 64, 8)
