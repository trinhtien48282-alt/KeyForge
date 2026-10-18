import base64
import json
import os
from unittest import mock

import pytest

from security.key_derivation import KdfParams
from storage import vault_store
from storage.vault_store import (
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    VaultAuthError,
    VaultFormatError,
    VaultVersionError,
    create_vault,
    load_vault,
    save_vault,
    validate_entries,
)

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
PW = "Sup3r-Secret-MASTER"
SECRET = "ENTRY-SECRET-xyz"


def entry(i=1, **over):
    e = {"id": f"id{i}", "name": f"site{i}", "username": "user", "password": SECRET, "url": "https://x.test", "notes": "n"}
    e.update(over)
    return e


def make(tmp_path, entries=None):
    path = tmp_path / "v.vault"
    create_vault(path, PW, [entry()] if entries is None else entries, kdf_params=FAST)
    return path


def edit(path, fn):
    doc = json.loads(path.read_bytes())
    fn(doc)
    path.write_text(json.dumps(doc))


def flip_b64(text):
    raw = bytearray(base64.b64decode(text))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode()


# ---- round trips ---------------------------------------------------------

def test_roundtrip(tmp_path):
    path = make(tmp_path, [entry(1), entry(2, notes="multi\nline \u00e9 \U0001f600")])
    assert load_vault(path, PW) == [entry(1), entry(2, notes="multi\nline \u00e9 \U0001f600")]


def test_empty_vault(tmp_path):
    path = make(tmp_path, [])
    assert load_vault(path, PW) == []


def test_default_params_roundtrip(tmp_path):
    path = tmp_path / "d.vault"
    create_vault(path, PW, [entry()])
    assert json.loads(path.read_bytes())["kdf"]["memory_kib"] == 65_536
    assert load_vault(path, PW) == [entry()]


def test_save_and_reload(tmp_path):
    path = make(tmp_path)
    save_vault(path, PW, [entry(1), entry(2)], kdf_params=FAST)
    assert load_vault(path, PW) == [entry(1), entry(2)]


def test_every_save_uses_fresh_salt_nonce_ciphertext(tmp_path):
    path = make(tmp_path)
    seen = []
    for _ in range(3):
        save_vault(path, PW, [entry()], kdf_params=FAST)
        d = json.loads(path.read_bytes())
        seen.append((d["kdf"]["salt"], d["cipher"]["nonce"], d["ciphertext"]))
    for column in zip(*seen):
        assert len(set(column)) == 3


def test_file_holds_no_plaintext_or_passwords(tmp_path):
    raw = make(tmp_path).read_bytes()
    for needle in (PW, SECRET, "site1", "user", "x.test"):
        assert needle.encode() not in raw


def test_unicode_master_password_normalization(tmp_path):
    path = tmp_path / "u.vault"
    create_vault(path, "caf\u00e9-pass", [], kdf_params=FAST)
    assert load_vault(path, "cafe\u0301-pass") == []


# ---- wrong password / tampering -----------------------------------------

def test_wrong_password(tmp_path):
    with pytest.raises(VaultAuthError):
        load_vault(make(tmp_path), PW + "x")


@pytest.mark.parametrize("bad", ["", None, 5])
def test_bad_password_type_is_value_error(tmp_path, bad):
    with pytest.raises(ValueError):
        load_vault(make(tmp_path), bad)


def test_tampered_ciphertext(tmp_path):
    path = make(tmp_path)
    edit(path, lambda d: d.update(ciphertext=flip_b64(d["ciphertext"])))
    with pytest.raises(VaultAuthError):
        load_vault(path, PW)


def test_tampered_nonce(tmp_path):
    path = make(tmp_path)
    edit(path, lambda d: d["cipher"].update(nonce=flip_b64(d["cipher"]["nonce"])))
    with pytest.raises(VaultAuthError):
        load_vault(path, PW)


def test_tampered_salt(tmp_path):
    path = make(tmp_path)
    edit(path, lambda d: d["kdf"].update(salt=flip_b64(d["kdf"]["salt"])))
    with pytest.raises(VaultAuthError):
        load_vault(path, PW)


@pytest.mark.parametrize("field,value", [("time_cost", 3), ("memory_kib", 19_457), ("parallelism", 2)])
def test_tampered_kdf_params(tmp_path, field, value):
    path = make(tmp_path)
    edit(path, lambda d: d["kdf"].update({field: value}))
    with pytest.raises(VaultAuthError):
        load_vault(path, PW)


def test_appended_or_dropped_ciphertext_bytes(tmp_path):
    path = make(tmp_path)
    ct = base64.b64decode(json.loads(path.read_bytes())["ciphertext"])
    for changed in (ct[:-1], ct + b"\x00"):
        edit(path, lambda d: d.update(ciphertext=base64.b64encode(changed).decode()))
        with pytest.raises(VaultAuthError):
            load_vault(path, PW)


def test_ciphertext_shorter_than_tag_is_format_error(tmp_path):
    path = make(tmp_path)
    edit(path, lambda d: d.update(ciphertext=base64.b64encode(b"short").decode()))
    with pytest.raises(VaultFormatError):
        load_vault(path, PW)


# ---- truncation / garbage / metadata -------------------------------------

@pytest.mark.parametrize("cut", [0, 1, 50, "half", -3])
def test_truncated_file(tmp_path, cut):
    path = make(tmp_path)
    raw = path.read_bytes()
    n = len(raw) // 2 if cut == "half" else (len(raw) + cut if cut < 0 else cut)
    path.write_bytes(raw[:n])
    with pytest.raises(VaultFormatError):
        load_vault(path, PW)


@pytest.mark.parametrize(
    "raw",
    [
        b"", b"not json", b"[]", b"null", b"123", b'"str"', b"\xff\xfe\x00", b"{}",
        # Explicit short id: pytest would otherwise put all 100,000 bytes in the test ID,
        # which overflows Windows' 32,767-character PYTEST_CURRENT_TEST limit.
        pytest.param(b"[" * 100_000, id="deeply-nested-100k"),
        b'{"format":"keyforge-vault","format":"keyforge-vault"}',
    ],
)
def test_garbage_files(tmp_path, raw):
    path = tmp_path / "g.vault"
    path.write_bytes(raw)
    with pytest.raises(VaultFormatError):
        load_vault(path, PW)


def test_oversized_file(tmp_path):
    path = tmp_path / "big.vault"
    path.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    with pytest.raises(VaultFormatError):
        load_vault(path, PW)


def _del(*keys):
    def f(d):
        t = d
        for k in keys[:-1]:
            t = t[k]
        del t[keys[-1]]
    return f


def _set(*keys, value):
    def f(d):
        t = d
        for k in keys[:-1]:
            t = t[k]
        t[keys[-1]] = value
    return f


B64_8 = base64.b64encode(bytes(8)).decode()
B64_11 = base64.b64encode(bytes(11)).decode()

MUTATIONS = {
    "missing kdf": _del("kdf"),
    "missing ciphertext": _del("ciphertext"),
    "missing nonce": _del("cipher", "nonce"),
    "missing salt": _del("kdf", "salt"),
    "extra top key": _set("extra", value=1),
    "extra kdf key": _set("kdf", "extra", value=1),
    "extra cipher key": _set("cipher", "extra", value=1),
    "wrong format name": _set("format", value="other"),
    "version string": _set("version", value="1"),
    "version bool": _set("version", value=True),
    "version float": _set("version", value=1.0),
    "version none": _set("version", value=None),
    "kdf not dict": _set("kdf", value=[]),
    "cipher not dict": _set("cipher", value="aes"),
    "wrong kdf algorithm": _set("kdf", "algorithm", value="argon2i"),
    "wrong argon2 version": _set("kdf", "argon2_version", value=16),
    "wrong cipher": _set("cipher", "algorithm", value="aes-128-gcm"),
    "memory too big": _set("kdf", "memory_kib", value=10**9),
    "memory too small": _set("kdf", "memory_kib", value=1024),
    "time zero": _set("kdf", "time_cost", value=0),
    "time bool": _set("kdf", "time_cost", value=True),
    "time string": _set("kdf", "time_cost", value="3"),
    "parallelism huge": _set("kdf", "parallelism", value=10**6),
    "salt bad base64": _set("kdf", "salt", value="!!!"),
    "salt wrong size": _set("kdf", "salt", value=B64_8),
    "salt not string": _set("kdf", "salt", value=5),
    "nonce wrong size": _set("cipher", "nonce", value=B64_11),
    "ciphertext empty": _set("ciphertext", value=""),
    "ciphertext not string": _set("ciphertext", value=123),
}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_malformed_metadata(tmp_path, name):
    path = make(tmp_path)
    edit(path, MUTATIONS[name])
    with pytest.raises(VaultFormatError):
        load_vault(path, PW)  # must fail before any key derivation


@pytest.mark.parametrize("v", [0, 2, 99, -1])
def test_unsupported_version(tmp_path, v):
    path = make(tmp_path)
    edit(path, _set("version", value=v))
    before = path.read_bytes()
    with pytest.raises(VaultVersionError):
        load_vault(path, PW)
    with pytest.raises(VaultVersionError):
        save_vault(path, PW, [], kdf_params=FAST)
    assert path.read_bytes() == before


def test_authenticated_but_invalid_contents(tmp_path):
    for plaintext in (b"not json", b"[]", b'{"entries":"x"}', b'{"entries":[],"extra":1}',
                      b'{"entries":[{"id":"x","name":"n","password":"' + SECRET.encode() + b'"}]}'):
        path = tmp_path / "c.vault"
        path.write_bytes(vault_store._encode(plaintext, PW, FAST))
        with pytest.raises(VaultFormatError) as e:
            load_vault(path, PW)
        assert SECRET not in str(e.value) and e.value.__cause__ is None
        path.unlink()


# ---- entry validation (on save) -----------------------------------------

BAD_ENTRY_LISTS = {
    "not a list": {"a": 1},
    "entry not dict": ["x"],
    "missing field": [{k: v for k, v in entry().items() if k != "url"}],
    "extra field": [entry(extra="x")],
    "int field": [entry(name=5)],
    "none field": [entry(notes=None)],
    "empty id": [entry(id="")],
    "empty name": [entry(name="")],
    "id too long": [entry(id="x" * 65)],
    "password too long": [entry(password="x" * 1025)],
    "duplicate id": [entry(1, id="same"), entry(2, id="same")],
    "too many": [entry(i, id=str(i)) for i in range(MAX_ENTRIES + 1)],
    "too big overall": [entry(i, id=str(i), notes="x" * 10_000) for i in range(900)],
}


@pytest.mark.parametrize("name", list(BAD_ENTRY_LISTS))
def test_invalid_entries_rejected_and_nothing_written(tmp_path, name):
    path = tmp_path / "n.vault"
    with pytest.raises(ValueError):
        create_vault(path, PW, BAD_ENTRY_LISTS[name], kdf_params=FAST)
    assert not path.exists() and list(tmp_path.iterdir()) == []


def test_validate_entries_requires_list_but_create_accepts_any_iterable(tmp_path):
    with pytest.raises(ValueError):
        validate_entries((entry(),))
    path = tmp_path / "t.vault"
    create_vault(path, PW, (entry(),), kdf_params=FAST)
    assert load_vault(path, PW) == [entry()]


def test_validate_entries_message_has_no_values():
    with pytest.raises(ValueError) as e:
        validate_entries([entry(password=SECRET * 100)])
    assert SECRET not in str(e.value)


def test_invalid_save_leaves_original(tmp_path):
    path = make(tmp_path)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        save_vault(path, PW, [entry(name=5)], kdf_params=FAST)
    assert path.read_bytes() == before


# ---- overwrite protection and atomicity ---------------------------------

def test_create_refuses_existing(tmp_path):
    path = make(tmp_path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        create_vault(path, PW, [], kdf_params=FAST)
    assert path.read_bytes() == before


def test_save_refuses_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        save_vault(tmp_path / "none.vault", PW, [], kdf_params=FAST)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("raw", [b"", b"garbage", b"[]", b'{"format":"keyforge-vault","version":1}'])
def test_save_refuses_to_overwrite_corrupt_file(tmp_path, raw):
    path = tmp_path / "bad.vault"
    path.write_bytes(raw)
    with pytest.raises(VaultFormatError):
        save_vault(path, PW, [entry()], kdf_params=FAST)
    assert path.read_bytes() == raw


@pytest.mark.parametrize("target", ["os.replace", "os.fsync"])
def test_failed_save_preserves_original_and_cleans_up(tmp_path, target):
    path = make(tmp_path)
    before = path.read_bytes()
    with mock.patch(f"storage.vault_store.{target}", side_effect=OSError("disk gone")):
        with pytest.raises(OSError):
            save_vault(path, PW, [entry(1), entry(2)], kdf_params=FAST)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
    assert load_vault(path, PW) == [entry()]


def test_failed_create_leaves_nothing(tmp_path):
    path = tmp_path / "new.vault"
    with mock.patch("storage.vault_store.os.replace", side_effect=OSError("nope")):
        with pytest.raises(OSError):
            create_vault(path, PW, [], kdf_params=FAST)
    assert list(tmp_path.iterdir()) == []


# ---- errors never leak ---------------------------------------------------

def test_errors_contain_no_secrets(tmp_path):
    path = make(tmp_path)
    errors = []
    try:
        load_vault(path, PW + "wrong")
    except VaultAuthError as e:
        errors.append(e)
    edit(path, lambda d: d.update(ciphertext=flip_b64(d["ciphertext"])))
    try:
        load_vault(path, PW)
    except VaultAuthError as e:
        errors.append(e)
    path.write_bytes(b"junk")
    try:
        load_vault(path, PW)
    except VaultFormatError as e:
        errors.append(e)
    assert len(errors) == 3
    for e in errors:
        for secret in (PW, SECRET, "site1"):
            assert secret not in str(e) and secret not in repr(e)
        assert e.__cause__ is None and e.__suppress_context__
