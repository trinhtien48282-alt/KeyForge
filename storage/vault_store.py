"""Versioned vault file: validation, load, save. Format: docs/VAULT_FORMAT.md.

Errors carry fixed text only: never master passwords, keys, or decrypted values.
"""
import base64
import binascii
import json
import os
import tempfile
from pathlib import Path

from security.crypto import NONCE_LEN, TAG_LEN, CryptoError, decrypt, encrypt
from security.key_derivation import (
    ARGON2_VERSION,
    DEFAULT_PARAMS,
    SALT_LEN,
    KdfParams,
    derive_key,
    new_salt,
)

FORMAT_NAME = "keyforge-vault"
VERSION = 1
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 10_000
# field -> (min length, max length) in characters
FIELDS = {
    "id": (1, 64),
    "name": (1, 256),
    "username": (0, 256),
    "password": (0, 1024),
    "url": (0, 2048),
    "notes": (0, 10_000),
}


class VaultError(Exception):
    pass


class VaultFormatError(VaultError):
    """File is damaged, malformed, or not a vault."""


class VaultVersionError(VaultFormatError):
    """Well-formed vault of a version this code does not support."""


class VaultAuthError(VaultError):
    """Wrong master password, or the file was modified or damaged."""


# ---- entries -------------------------------------------------------------

def validate_entries(entries) -> None:
    """Raise ValueError (message never contains field values) if entries are invalid."""
    if type(entries) is not list:
        raise ValueError("entries must be a list")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"too many entries (max {MAX_ENTRIES})")
    seen = set()
    for i, entry in enumerate(entries):
        if type(entry) is not dict or set(entry) != set(FIELDS):
            raise ValueError(f"entry {i}: must be a dict with exactly the fields {sorted(FIELDS)}")
        for name, (lo, hi) in FIELDS.items():
            value = entry[name]
            if type(value) is not str:
                raise ValueError(f"entry {i}: field '{name}' must be a string")
            if not lo <= len(value) <= hi:
                raise ValueError(f"entry {i}: field '{name}' length must be {lo} to {hi}")
        if entry["id"] in seen:
            raise ValueError(f"entry {i}: duplicate id")
        seen.add(entry["id"])


def _serialize(entries: list) -> bytes:
    # ensure_ascii keeps even odd Unicode encodable, so no error can quote a value.
    data = json.dumps({"entries": entries}, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise ValueError("vault too large")
    return data


def _no_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _deserialize(plaintext: bytes) -> list:
    # Authenticated but possibly malformed (a bug, or another program wrote it).
    try:
        doc = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (ValueError, RecursionError):
        raise VaultFormatError("vault contents are invalid") from None
    if type(doc) is not dict or set(doc) != {"entries"}:
        raise VaultFormatError("vault contents are invalid")
    try:
        validate_entries(doc["entries"])
    except ValueError as e:  # messages name fields and indexes, never values
        raise VaultFormatError(f"vault contents are invalid: {e}") from None
    return doc["entries"]


# ---- file envelope -------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value, what: str) -> bytes:
    if type(value) is not str:
        raise VaultFormatError(f"invalid {what}")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise VaultFormatError(f"invalid {what}") from None


def _aad(params: KdfParams, salt: bytes) -> bytes:
    """Header bytes authenticated by GCM. Built from validated values, never from raw
    file text. The nonce is covered by the GCM tag itself."""
    header = {
        "format": FORMAT_NAME,
        "version": VERSION,
        "kdf": _kdf_block(params, salt),
        "cipher": "aes-256-gcm",
    }
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")


def _kdf_block(params: KdfParams, salt: bytes) -> dict:
    return {
        "algorithm": "argon2id",
        "argon2_version": ARGON2_VERSION,
        "time_cost": params.time_cost,
        "memory_kib": params.memory_kib,
        "parallelism": params.parallelism,
        "salt": _b64e(salt),
    }


def _encode(plaintext: bytes, password: str, params: KdfParams) -> bytes:
    salt = new_salt()
    key = derive_key(password, salt, params)
    nonce, ciphertext = encrypt(key, plaintext, _aad(params, salt))
    doc = {
        "format": FORMAT_NAME,
        "version": VERSION,
        "kdf": _kdf_block(params, salt),
        "cipher": {"algorithm": "aes-256-gcm", "nonce": _b64e(nonce)},
        "ciphertext": _b64e(ciphertext),
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("ascii")


def _obj(value, keys: set, what: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise VaultFormatError(f"invalid {what}")
    return value


def _parse(data: bytes):
    """Validate structure only (no decryption). Returns (params, salt, nonce, ciphertext)."""
    if len(data) > MAX_FILE_BYTES:
        raise VaultFormatError("vault file too large")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (ValueError, RecursionError):
        raise VaultFormatError("not a valid vault file") from None
    if type(doc) is not dict or doc.get("format") != FORMAT_NAME:
        raise VaultFormatError("not a valid vault file")
    version = doc.get("version")
    if type(version) is not int:
        raise VaultFormatError("invalid version")
    if version != VERSION:
        raise VaultVersionError(f"unsupported vault version {version}")

    _obj(doc, {"format", "version", "kdf", "cipher", "ciphertext"}, "vault")
    kdf = _obj(
        doc["kdf"],
        {"algorithm", "argon2_version", "time_cost", "memory_kib", "parallelism", "salt"},
        "kdf",
    )
    cipher = _obj(doc["cipher"], {"algorithm", "nonce"}, "cipher")
    if (
        kdf["algorithm"] != "argon2id"
        or type(kdf["argon2_version"]) is not int
        or kdf["argon2_version"] != ARGON2_VERSION
        or cipher["algorithm"] != "aes-256-gcm"
    ):
        raise VaultFormatError("unsupported algorithm")
    try:
        params = KdfParams(kdf["time_cost"], kdf["memory_kib"], kdf["parallelism"])
    except ValueError:
        raise VaultFormatError("invalid kdf parameters") from None

    salt = _b64d(kdf["salt"], "salt")
    nonce = _b64d(cipher["nonce"], "nonce")
    ciphertext = _b64d(doc["ciphertext"], "ciphertext")
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise VaultFormatError("invalid salt or nonce length")
    if not TAG_LEN <= len(ciphertext) <= MAX_PLAINTEXT_BYTES + TAG_LEN:
        raise VaultFormatError("invalid ciphertext length")
    return params, salt, nonce, ciphertext


# ---- files ---------------------------------------------------------------

def _read(path: Path) -> bytes:
    with open(path, "rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise VaultFormatError("vault file too large")
    return data


def _atomic_write(path: Path, data: bytes) -> None:
    """Write beside the target, fsync, then os.replace. On any failure the temp file
    is removed and the original is untouched."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if os.name != "nt":  # best effort: persist the rename itself
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


def _build(entries, password: str, params: KdfParams) -> bytes:
    entries = list(entries)
    validate_entries(entries)
    return _encode(_serialize(entries), password, params)


def create_vault(path, password: str, entries=(), *, kdf_params: KdfParams = DEFAULT_PARAMS) -> None:
    """Write a new vault. Refuses if the path exists."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path} already exists")
    _atomic_write(path, _build(entries, password, kdf_params))


def save_vault(path, password: str, entries, *, kdf_params: KdfParams = DEFAULT_PARAMS) -> None:
    """Replace an existing vault. Refuses to replace anything that is not a supported
    vault. Does not check that `password` opens the current file: callers must pass
    entries obtained from load_vault."""
    path = Path(path)
    _parse(_read(path))
    _atomic_write(path, _build(entries, password, kdf_params))


def load_vault(path, password: str) -> list:
    params, salt, nonce, ciphertext = _parse(_read(Path(path)))
    key = derive_key(password, salt, params)
    try:
        plaintext = decrypt(key, nonce, ciphertext, _aad(params, salt))
    except CryptoError:
        raise VaultAuthError("wrong master password, or the vault file was modified or damaged") from None
    return _deserialize(plaintext)
