import pytest

from security.crypto import KEY_LEN, NONCE_LEN, TAG_LEN, CryptoError, decrypt, encrypt

KEY = bytes(range(KEY_LEN))


def test_roundtrip():
    nonce, ct = encrypt(KEY, b"secret data", b"hdr")
    assert len(nonce) == NONCE_LEN
    assert len(ct) == len(b"secret data") + TAG_LEN
    assert decrypt(KEY, nonce, ct, b"hdr") == b"secret data"


def test_empty_plaintext():
    nonce, ct = encrypt(KEY, b"")
    assert decrypt(KEY, nonce, ct) == b""


def test_fresh_nonce_every_call():
    nonces = {encrypt(KEY, b"x")[0] for _ in range(1000)}
    assert len(nonces) == 1000


def test_wrong_key_fails():
    nonce, ct = encrypt(KEY, b"x")
    with pytest.raises(CryptoError):
        decrypt(bytes(KEY_LEN), nonce, ct)


def test_tampered_ciphertext_fails():
    nonce, ct = encrypt(KEY, b"some secret")
    for i in range(len(ct)):
        bad = ct[:i] + bytes([ct[i] ^ 1]) + ct[i + 1 :]
        with pytest.raises(CryptoError):
            decrypt(KEY, nonce, bad)


def test_tampered_nonce_fails():
    nonce, ct = encrypt(KEY, b"x")
    with pytest.raises(CryptoError):
        decrypt(KEY, bytes([nonce[0] ^ 1]) + nonce[1:], ct)


def test_wrong_aad_fails():
    nonce, ct = encrypt(KEY, b"x", b"header-1")
    with pytest.raises(CryptoError):
        decrypt(KEY, nonce, ct, b"header-2")


@pytest.mark.parametrize("n", [0, 1, TAG_LEN - 1])
def test_too_short_ciphertext_fails(n):
    with pytest.raises(CryptoError):
        decrypt(KEY, bytes(NONCE_LEN), bytes(n))


def test_truncated_ciphertext_fails():
    nonce, ct = encrypt(KEY, b"some secret")
    with pytest.raises(CryptoError):
        decrypt(KEY, nonce, ct[:-1])


@pytest.mark.parametrize("key", [b"", b"short", bytes(31), bytes(33), "k" * 32, None])
def test_bad_key(key):
    with pytest.raises(ValueError):
        encrypt(key, b"x")
    with pytest.raises(ValueError):
        decrypt(key, bytes(NONCE_LEN), bytes(TAG_LEN))


@pytest.mark.parametrize("nonce", [b"", bytes(11), bytes(13), None])
def test_bad_nonce(nonce):
    with pytest.raises(ValueError):
        decrypt(KEY, nonce, bytes(TAG_LEN))


def test_error_text_has_no_data():
    nonce, ct = encrypt(KEY, b"TOPSECRET")
    with pytest.raises(CryptoError) as e:
        decrypt(KEY, nonce, ct[:-1] + b"\x00")
    assert "TOPSECRET" not in str(e.value) and e.value.__cause__ is None
