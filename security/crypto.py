"""AES-256-GCM via the `cryptography` library. No custom primitives."""
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


class CryptoError(Exception):
    """Authentication failed: wrong key, or data or associated data was changed."""


def _check(**values):
    for name, value in values.items():
        if type(value) is not bytes:
            raise ValueError(f"{name} must be bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
    """Return (nonce, ciphertext+tag). A fresh random nonce is drawn on every call."""
    _check(key=key, plaintext=plaintext, aad=aad)
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    _check(key=key, nonce=nonce, ciphertext=ciphertext, aad=aad)
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if len(ciphertext) < TAG_LEN:
        raise CryptoError("decryption failed")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise CryptoError("decryption failed") from None
