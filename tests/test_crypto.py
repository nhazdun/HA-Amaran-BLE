"""Validate the mesh crypto primitives against Bluetooth Mesh Profile v1.0.1 §8.1."""

from __future__ import annotations

from custom_components.amaran_ble.mesh import crypto


def h(value: str) -> bytes:
    return bytes.fromhex(value)


def test_s1_sample_8_1_1() -> None:
    assert crypto.s1(b"test").hex() == "b73cefbd641ef2ea598c2b6efb62f79c"


def test_k1_matches_spec_definition() -> None:
    """k1(N, SALT, P) = AES-CMAC(AES-CMAC(SALT, N), P).

    This mirrors ``Encipher.k1`` in the Sidus Link APK, which is
    ``aesCmac(P, aesCmac(N, SALT))`` under its reversed ``aesCmac(msg, key)``
    argument order. The CMAC direction itself is pinned by the s1/k2/k3/k4
    tests below, which use real Mesh Profile §8.1 sample data.
    """
    n = h("3216d1509884b533248541792b877f98")
    salt = h("2ba14ca2ea6b8f83d5e0d1a3b1e8e0d5")
    p = h("5a09d60797eeb4478aada59db3352a0d")

    assert crypto.k1(n, salt, p) == crypto.aes_cmac(crypto.aes_cmac(salt, n), p)
    # Argument order must not be silently swappable.
    assert crypto.k1(n, salt, p) != crypto.k1(salt, n, p)


def test_derived_keys_use_k1_like_the_app() -> None:
    """beacon/identity key derivation must match Encipher.generate*Key."""
    net_key = h("7dd7364cd842ad18c17c2b820c84c3d6")

    assert crypto.beacon_key(net_key) == crypto.k1(
        net_key, crypto.s1(b"nkbk"), b"id128\x01"
    )
    assert crypto.identity_key(net_key) == crypto.k1(
        net_key, crypto.s1(b"nkik"), b"id128\x01"
    )


def test_k2_master_sample_8_1_3() -> None:
    nid, enc, priv = crypto.k2(h("f7a2a44f8e8a8029064f173ddc1e2b00"), b"\x00")
    assert nid == 0x7F
    assert enc.hex() == "9f589181a0f50de73c8070c7a6d27f46"
    assert priv.hex() == "4c715bd4a64b938f99b453351653124f"


def test_k3_sample_8_1_5() -> None:
    assert crypto.k3(h("f7a2a44f8e8a8029064f173ddc1e2b00")).hex() == "ff046958233db014"


def test_k4_sample_8_1_6() -> None:
    assert crypto.k4(h("3216d1509884b533248541792b877f98")) == 0x38


def test_network_nonce_layout() -> None:
    # Mesh Profile 3.8.5.1: type || (CTL<<7|TTL) || SEQ(3) || SRC(2) || pad(2) || IVI(4)
    nonce = crypto.network_nonce(
        ctl=0, ttl=4, seq=0x000001, src=0x1201, iv_index=0x12345678
    )
    assert nonce.hex() == "0004000001120100001234 5678".replace(" ", "")
    assert len(nonce) == 13


def test_application_nonce_layout() -> None:
    nonce = crypto.application_nonce(
        seq=0x000006, src=0x1201, dst=0xFFFF, iv_index=0x12345678
    )
    assert nonce.hex() == "010000000612 01ffff12345678".replace(" ", "")
    assert len(nonce) == 13


def test_ecdh_shared_secret_is_symmetric() -> None:
    a = crypto.EcdhKeyPair.generate()
    b = crypto.EcdhKeyPair.generate()
    assert a.shared_secret(b.public_key_bytes) == b.shared_secret(a.public_key_bytes)
    assert len(a.public_key_bytes) == 64


def test_ccm_round_trip() -> None:
    key = crypto.random_bytes(16)
    nonce = crypto.random_bytes(13)
    ct = crypto.aes_ccm_encrypt(key, nonce, b"hello mesh", mic_len=4)
    assert len(ct) == len(b"hello mesh") + 4
    assert crypto.aes_ccm_decrypt(key, nonce, ct, mic_len=4) == b"hello mesh"
