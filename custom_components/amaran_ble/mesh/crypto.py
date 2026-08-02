"""Bluetooth SIG Mesh cryptographic primitives.

Implements the key-derivation and encryption functions from the Bluetooth Mesh
Profile specification v1.0.1, section 3.8 ("Security"). Only the subset needed
by a provisioner + proxy client is implemented.

Everything here is pure ``cryptography`` (a Home Assistant core dependency), so
the integration needs no extra wheels.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

ZERO16 = b"\x00" * 16

# Salt strings from Mesh Profile 5.4.2.5 (provisioning key generation).
PRCK = b"prck"
PRSK = b"prsk"
PRSN = b"prsn"
PRDK = b"prdk"


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC-128 (RFC 4493)."""
    ctx = cmac.CMAC(algorithms.AES(key))
    ctx.update(message)
    return ctx.finalize()


def aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Apply the Mesh ``e`` function: one AES-128 ECB block encryption."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def s1(message: bytes) -> bytes:
    """Salt generation function (Mesh Profile 3.8.2.4)."""
    return aes_cmac(ZERO16, message)


def k1(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive a key with k1 (Mesh Profile 3.8.2.5)."""
    return aes_cmac(aes_cmac(salt, shared_secret), info)


def k2(net_key: bytes, p: bytes) -> tuple[int, bytes, bytes]:
    """Network key material derivation k2 (Mesh Profile 3.8.2.6).

    Returns ``(nid, encryption_key, privacy_key)`` where ``nid`` is 7 bits.
    """
    salt = s1(b"smk2")
    t = aes_cmac(salt, net_key)

    t1 = aes_cmac(t, p + b"\x01")
    t2 = aes_cmac(t, t1 + p + b"\x02")
    t3 = aes_cmac(t, t2 + p + b"\x03")

    # k2 output is (T1 || T2 || T3) mod 2^263; the top byte keeps only the NID.
    nid = t1[15] & 0x7F
    return nid, t2, t3


def k3(net_key: bytes) -> bytes:
    """Network ID derivation k3 (Mesh Profile 3.8.2.7). Returns 8 bytes."""
    salt = s1(b"smk3")
    t = aes_cmac(salt, net_key)
    return aes_cmac(t, b"id64" + b"\x01")[8:]


def k4(app_key: bytes) -> int:
    """AID derivation k4 (Mesh Profile 3.8.2.8). Returns 6 bits."""
    salt = s1(b"smk4")
    t = aes_cmac(salt, app_key)
    return aes_cmac(t, b"id6" + b"\x01")[15] & 0x3F


def aes_ccm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, mic_len: int = 4, aad: bytes = b""
) -> bytes:
    """AES-CCM encrypt, returning ``ciphertext || MIC``."""
    return AESCCM(key, tag_length=mic_len).encrypt(nonce, plaintext, aad or None)


def aes_ccm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, mic_len: int = 4, aad: bytes = b""
) -> bytes:
    """AES-CCM decrypt of ``ciphertext || MIC``. Raises ``InvalidTag`` on failure."""
    return AESCCM(key, tag_length=mic_len).decrypt(nonce, ciphertext, aad or None)


# --------------------------------------------------------------------------
# Network / application nonces (Mesh Profile 3.8.5)
# --------------------------------------------------------------------------


def network_nonce(ctl: int, ttl: int, seq: int, src: int, iv_index: int) -> bytes:
    """Build a network nonce (type 0x00)."""
    return (
        bytes([0x00, ((ctl & 1) << 7) | (ttl & 0x7F)])
        + seq.to_bytes(3, "big")
        + src.to_bytes(2, "big")
        + b"\x00\x00"
        + iv_index.to_bytes(4, "big")
    )


def application_nonce(
    seq: int, src: int, dst: int, iv_index: int, szmic: int = 0
) -> bytes:
    """Build an application nonce (type 0x01)."""
    return (
        bytes([0x01, (szmic & 1) << 7])
        + seq.to_bytes(3, "big")
        + src.to_bytes(2, "big")
        + dst.to_bytes(2, "big")
        + iv_index.to_bytes(4, "big")
    )


def device_nonce(seq: int, src: int, dst: int, iv_index: int, szmic: int = 0) -> bytes:
    """Build a device nonce (type 0x02)."""
    return (
        bytes([0x02, (szmic & 1) << 7])
        + seq.to_bytes(3, "big")
        + src.to_bytes(2, "big")
        + dst.to_bytes(2, "big")
        + iv_index.to_bytes(4, "big")
    )


def proxy_nonce(seq: int, src: int, iv_index: int) -> bytes:
    """Build a proxy nonce (type 0x03)."""
    return (
        b"\x03\x00"
        + seq.to_bytes(3, "big")
        + src.to_bytes(2, "big")
        + b"\x00\x00"
        + iv_index.to_bytes(4, "big")
    )


# --------------------------------------------------------------------------
# Beacon / identity helpers
# --------------------------------------------------------------------------


def beacon_key(net_key: bytes) -> bytes:
    """Derive the beacon key used to authenticate Secure Network Beacons."""
    salt = s1(b"nkbk")
    return k1(net_key, salt, b"id128" + b"\x01")


def identity_key(net_key: bytes) -> bytes:
    """Derive the identity key used for Node Identity advertisements."""
    salt = s1(b"nkik")
    return k1(net_key, salt, b"id128" + b"\x01")


def network_id(net_key: bytes) -> bytes:
    """Compute the 8-byte Network ID advertised by proxy nodes."""
    return k3(net_key)


# --------------------------------------------------------------------------
# ECDH (provisioning)
# --------------------------------------------------------------------------


@dataclass(slots=True)
class EcdhKeyPair:
    """A NIST P-256 key pair in the raw 64-byte form used by mesh provisioning."""

    private_key: ec.EllipticCurvePrivateKey
    public_key_bytes: bytes  # X || Y, 32 bytes each

    @classmethod
    def generate(cls) -> EcdhKeyPair:
        """Generate a fresh ephemeral provisioning key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        raw = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
        return cls(private_key=private_key, public_key_bytes=raw)

    def shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Compute the 32-byte ECDH shared secret from a raw peer public key."""
        if len(peer_public_key_bytes) != 64:
            raise ValueError("peer public key must be 64 bytes (X || Y)")
        peer = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(peer_public_key_bytes[:32], "big"),
            y=int.from_bytes(peer_public_key_bytes[32:], "big"),
            curve=ec.SECP256R1(),
        ).public_key()
        return self.private_key.exchange(ec.ECDH(), peer)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256, used by the mesh v1.1 provisioning algorithm."""
    from cryptography.hazmat.primitives import hmac

    ctx = hmac.HMAC(key, hashes.SHA256())
    ctx.update(message)
    return ctx.finalize()


def random_bytes(length: int) -> bytes:
    """Cryptographically secure random bytes."""
    return os.urandom(length)
