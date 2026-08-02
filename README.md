# amaran BLE for Home Assistant

Control **amaran Verge** and **Verge Max** panels from Home Assistant over
Bluetooth — no cloud, no Sidus Link app, no hardware bridge.

The integration speaks the fixture's native protocol: standard Bluetooth SIG
Mesh for transport, plus amaran's vendor payload format. Both were recovered
from the Sidus Link Android app (`com.sidus.link.amaran`).

> **Status:** the mesh stack and payload encoder are covered by unit tests
> (including a byte-for-byte comparison against the app's own bit-packing
> algorithm). The end-to-end provisioning flow has not yet been run against
> physical hardware — see [Testing status](#testing-status).

---

## Features

| | |
|---|---|
| On / off | `SleepProtocol`, command 12 |
| Brightness | 0–100 % in 0.1 % steps |
| Colour temperature | 2700 K – 6500 K |
| Effects | Lightning, TV, Fire, Strobe, Explosion, Faulty Bulb, Fireworks |
| Transport | Bluetooth SIG Mesh over GATT proxy — local push, no polling |
| Bluetooth proxies | Works through ESPHome Bluetooth proxies |

The Verge is a bi-colour fixture, so the light entity exposes
`ColorMode.COLOR_TEMP`. HSI/RGB commands exist in the protocol module but the
Verge firmware does not advertise support for them.

## Requirements

- Home Assistant 2024.10 or newer
- A Bluetooth adapter or an ESPHome Bluetooth proxy with **active connections**
- An amaran Verge / Verge Max that is **not currently paired** in the Sidus Link app

## Installation

### HACS (custom repository)

1. HACS → ⋮ → **Custom repositories**
2. Add `https://github.com/nhazdun/HA-Amaran-BLE`, category **Integration**
3. Install **amaran BLE**, then restart Home Assistant

### Manual

Copy `custom_components/amaran_ble` into your `config/custom_components/`
directory and restart Home Assistant.

## Setup

An unprovisioned fixture advertises the Mesh Provisioning Service, so Home
Assistant discovers it automatically — look for a notification under
**Settings → Devices & services**. You can also add it manually via
**Add integration → amaran BLE**.

> **Provisioning takes ownership of the fixture.** Home Assistant creates its
> own mesh network and joins the light to it, which removes the light from the
> Sidus Link app. To go back to the app, factory-reset the fixture and re-add
> it there.

If the fixture does not appear, factory-reset it so it advertises as
unprovisioned again (hold the menu/reset control per the fixture manual).

Additional fixtures added later reuse the same mesh keys and are assigned the
next free unicast address, so they all end up on one Home Assistant mesh.

## Testing status

What is verified, and how:

| Layer | Verification |
|---|---|
| Mesh crypto (`s1`, `k2`, `k3`, `k4`) | Bluetooth Mesh Profile v1.0.1 §8.1 sample data |
| `k1`, beacon/identity keys | Definitional tests + cross-checked against `Encipher` in the APK |
| Network PDU encrypt/obfuscate | Round-trip tests; logic compared line-by-line with `NetworkLayerPDU` |
| Segmentation, proxy SAR | Round-trip tests |
| Vendor payloads | Byte-for-byte equality with a literal port of the app's `BinaryKit` packing |
| Provisioning, GATT, live control | **Not yet exercised against hardware** |

Run the suite with:

```bash
python -m pytest tests/ -q
```

## Protocol notes

Everything below was recovered from the decompiled Sidus Link APK. It is
recorded here so the integration can be maintained without re-doing that work.

### Transport

amaran fixtures are **standard Bluetooth SIG Mesh** nodes built on the Telink
mesh SDK. Nothing about the transport is proprietary:

- Provisioning: PB-GATT, service `0x1827`, No OOB, FIPS P-256
- Control: GATT Proxy, service `0x1828`
- Crypto: the usual `s1`/`k1`–`k4`, AES-CMAC, AES-CCM, ECDH P-256
  (`Encipher.java` — note its `aesCmac(message, key)` argument order is
  reversed relative to the spec's notation)

Control messages are sent to the node's unicast address as an access message
with **opcode `0x26`**, AppKey-encrypted, TTL 7, carrying a 10-byte parameter
block. Opcode `0x33` reads the BLE firmware version.

An access payload of 1 opcode byte + 10 parameter bytes + 4-byte TransMIC is
exactly 15 bytes, which is the maximum for an unsegmented access message — so
every light command fits in a single network PDU.

### The 10-byte vendor payload

`getSendData()` builds an 80-bit string by appending fields, each written
LSB-first, then packs it into 10 bytes LSB-first. That is equivalent to a
little-endian 80-bit integer where the *first* field appended occupies the
*lowest* bits.

**Byte 0 is a checksum**: `sum(bytes[1..9]) & 0xFF`.

Common tail for every command:

| Bits | Width | Field |
|---|---|---|
| 0–7 | 8 | Checksum |
| 72–78 | 7 | Command type |
| 79 | 1 | Operation (1 = write, 0 = read) |

#### CCT — command 2

| Bits | Width | Field |
|---|---|---|
| 8 | 1 | Sleep mode (1 = on) |
| 42 | 1 | CCT > 10000 K carry |
| 43 | 1 | GM flag |
| 44 | 1 | GM high |
| 45–51 | 7 | GM |
| 52–61 | 10 | CCT, in Kelvin/10 |
| 62–71 | 10 | Intensity, in 0.1 % (0–1000) |

So 5600 K at 18 % is `intensity=180, cct=560` — the app's own default preset.

#### Sleep (on/off) — command 12

| Bits | Width | Field |
|---|---|---|
| 64–71 | 8 | Mode: 1 = on, 0 = off |

#### System effects — command 7

Bits 64–71 hold the effect id. Verge supports Lightning (2), TV (3), Fire (5),
Strobe (6), Explosion (7), Faulty Bulb (8), Fireworks (14). Each has its own
field layout; see `amaran/protocol.py`, where every builder is transcribed
one-for-one from the matching `*Protocol.getSendData()`.

### Device identification

An unprovisioned fixture puts an ASCII name inside its 16-byte mesh **Device
UUID**, which is the first field of the `0x1827` service data:

```
400Y5-A1B2C3
^^^^^ product code    ^^^^^^ serial
```

The five-character product code maps to the catalogue in
`amaran/products.py`, generated from the app's `fixtureProduct.json` and
`fixtureConfig.json` (96 fixtures). `400Y5` is the Verge, `400Z5` the Verge Max.

Per `fixtureConfig.json`, both report `cct_support: 1`, `hsi_support: 0`,
`rgb_support: 0`, `gm_support: 0`, and a CCT range of 2700–6500 K.

## Repository layout

```
custom_components/amaran_ble/
├── mesh/            # Bluetooth SIG Mesh stack (device-agnostic)
│   ├── crypto.py        s1/k1-k4, AES-CMAC/CCM, ECDH P-256
│   ├── pdu.py           access, transport, network, proxy SAR
│   ├── proxy.py         GATT bearer
│   ├── provisioning.py  PB-GATT provisioner
│   └── session.py       proxy session + configuration client
├── amaran/          # vendor-specific layer
│   ├── protocol.py      10-byte payload builders
│   └── products.py      fixture catalogue from the APK assets
├── config_flow.py   # discovery + provisioning
├── coordinator.py   # connection management, sequence numbers
└── light.py         # the light entity
```

The `mesh/` package has no amaran-specific code and no Home Assistant imports
beyond the GATT bearer, so it can be reused for other SIG Mesh devices.

## Known limitations

- **One-way state.** amaran fixtures do not push status unprompted, so state is
  optimistic: it reflects what was last commanded. Status frames sent by the
  fixture are parsed when they do arrive.
- **Provisioning is exclusive.** A fixture belongs to one mesh at a time; you
  cannot use Home Assistant and the Sidus Link app simultaneously.
- **Bi-colour only.** HSI/RGB/XY payload builders are not wired to the light
  entity, since the Verge does not support them.
- **No group control yet.** Fixtures share a mesh network, so group addressing
  is a natural next step but is not implemented.

## Credits

Protocol recovered from the Sidus Link Android app. amaran, Aputure and Sidus
Link are trademarks of their respective owners; this project is not affiliated
with or endorsed by them.

## License

MIT — see [LICENSE](LICENSE).
