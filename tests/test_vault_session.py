import pickle
import hashlib
import json
from unittest import mock
from storage import vault_session

import pytest

from security.key_derivation import KdfParams
from storage.vault_session import (
    EntryNotFoundError,
    SessionClosedError,
    SessionLockedError,
    SessionState,
    SessionStateError,
    VaultConflictError,
    VaultSession,
)
from storage.vault_store import VaultAuthError, VaultFormatError, VaultVersionError, load_vault

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
PW = "Sup3r-Secret-MASTER"
SECRET = "ENTRY-SECRET-xyz"


def fields(name="site1", **over):
    f = {"name": name, "username": "user", "password": SECRET, "url": "https://x.test", "notes": "n"}
    f.update(over)
    return f


def new(tmp_path):
    path = tmp_path / "v.vault"
    s = VaultSession(path, kdf_params=FAST)
    s.create(PW)
    return s, path


def open_(path):
    s = VaultSession(path, kdf_params=FAST)
    s.unlock(PW)
    return s


# ---- lifecycle -------------------------------------------------------------

def test_create_unlock_lock_lifecycle(tmp_path):
    path = tmp_path / "v.vault"
    s = VaultSession(path, kdf_params=FAST)
    assert s.state is SessionState.LOCKED and not s.is_unlocked
    s.create(PW)
    assert s.state is SessionState.UNLOCKED and s.list_entries() == []
    eid = s.add_entry(fields())
    s.lock()
    assert s.state is SessionState.LOCKED
    s.unlock(PW)
    assert s.is_unlocked and s.get_entry(eid)["password"] == SECRET


def test_create_refuses_existing_vault(tmp_path):
    s, path = new(tmp_path)
    s.add_entry(fields())
    s.close()
    before = path.read_bytes()
    other = VaultSession(path, kdf_params=FAST)
    with pytest.raises(FileExistsError):
        other.create("another-master")
    assert other.state is SessionState.LOCKED and other._password is None
    assert path.read_bytes() == before


def test_wrong_password_keeps_session_locked_and_retains_nothing(tmp_path):
    s, path = new(tmp_path)
    s.close()
    before = path.read_bytes()
    t = VaultSession(path, kdf_params=FAST)
    with pytest.raises(VaultAuthError):
        t.unlock(PW + "x")
    assert t.state is SessionState.LOCKED
    assert t._password is None and t._entries is None and t._seen is None
    assert path.read_bytes() == before
    t.unlock(PW)  # right password still works afterwards
    assert t.is_unlocked


def test_unlock_missing_corrupt_and_unsupported_files(tmp_path):
    t = VaultSession(tmp_path / "none.vault", kdf_params=FAST)
    with pytest.raises(FileNotFoundError):
        t.unlock(PW)
    bad = tmp_path / "bad.vault"
    bad.write_bytes(b"garbage")
    t = VaultSession(bad, kdf_params=FAST)
    with pytest.raises(VaultFormatError):
        t.unlock(PW)
    assert t.state is SessionState.LOCKED and bad.read_bytes() == b"garbage"
    s, path = new(tmp_path)
    s.close()
    import json
    doc = json.loads(path.read_bytes())
    doc["version"] = 2
    path.write_text(json.dumps(doc))
    t = VaultSession(path, kdf_params=FAST)
    with pytest.raises(VaultVersionError):
        t.unlock(PW)
    assert t.state is SessionState.LOCKED

def test_save_keeps_the_files_kdf_params(tmp_path):
    path = tmp_path / "p.vault"
    strong = KdfParams(time_cost=3, memory_kib=20_000, parallelism=1)
    with VaultSession(path, kdf_params=strong) as s:
        s.create(PW)
    s = VaultSession(path, kdf_params=FAST)  # session default differs from the file
    s.unlock(PW)
    s.add_entry(fields())
    kdf = json.loads(path.read_bytes())["kdf"]
    assert (kdf["time_cost"], kdf["memory_kib"], kdf["parallelism"]) == (3, 20_000, 1)


def test_seen_hash_is_of_written_bytes_not_a_disk_reread(tmp_path):
    s, path = new(tmp_path)
    real = vault_session._hash_file
    calls = []

    def spy(p):
        calls.append(p)
        return real(p)

    with mock.patch("storage.vault_session._hash_file", spy):
        s.add_entry(fields())
    assert len(calls) == 1  # the pre-write check only
    assert s._seen == hashlib.sha256(path.read_bytes()).digest()

def test_unlock_or_create_while_unlocked_rejected(tmp_path):
    s, path = new(tmp_path)
    before = path.read_bytes()
    with pytest.raises(SessionStateError):
        s.unlock(PW)
    with pytest.raises(SessionStateError):
        s.create(PW)
    assert s.is_unlocked and path.read_bytes() == before


def test_multiple_lock_unlock_cycles(tmp_path):
    s, path = new(tmp_path)
    ids = []
    for i in range(5):
        ids.append(s.add_entry(fields(f"site{i}")))
        s.lock()
        assert s._password is None and s._entries is None
        s.lock()  # idempotent
        s.unlock(PW)
        assert [e["id"] for e in s.list_entries()] == ids
    assert len(set(ids)) == 5
    assert [e["name"] for e in load_vault(path, PW)] == [f"site{i}" for i in range(5)]


def test_lock_drops_references_and_empties_containers(tmp_path):
    s, _ = new(tmp_path)
    s.add_entry(fields())
    inner = s._entries[0]
    s.lock()
    assert inner == {} and s._entries is None and s._password is None and s._seen is None


def test_close_is_final_and_idempotent(tmp_path):
    s, path = new(tmp_path)
    s.add_entry(fields())
    s.close()
    s.close()
    s.lock()
    assert s.state is SessionState.CLOSED and s._password is None
    for call in (lambda: s.unlock(PW), lambda: s.create(PW), s.list_entries, lambda: s.add_entry(fields())):
        with pytest.raises(SessionClosedError):
            call()


def test_context_manager_closes(tmp_path):
    path = tmp_path / "c.vault"
    with VaultSession(path, kdf_params=FAST) as s:
        s.create(PW)
        s.add_entry(fields())
    assert s.state is SessionState.CLOSED and s._entries is None


# ---- locked access ---------------------------------------------------------

OPS = {
    "list": lambda s: s.list_entries(),
    "get": lambda s: s.get_entry("x"),
    "add": lambda s: s.add_entry(fields()),
    "update": lambda s: s.update_entry("x", {"name": "n"}),
    "delete": lambda s: s.delete_entry("x"),
}


@pytest.mark.parametrize("op", list(OPS))
def test_locked_session_rejects_operations(tmp_path, op):
    fresh = VaultSession(tmp_path / "none.vault", kdf_params=FAST)
    with pytest.raises(SessionLockedError):
        OPS[op](fresh)
    s, path = new(tmp_path)
    eid = s.add_entry(fields())
    s.lock()
    before = path.read_bytes()
    with pytest.raises(SessionLockedError):
        OPS[op](s)
    with pytest.raises(SessionLockedError):
        s.get_entry(eid)
    assert path.read_bytes() == before


# ---- CRUD and persistence --------------------------------------------------

def test_crud_and_persistence_after_reload(tmp_path):
    s, path = new(tmp_path)
    a = s.add_entry(fields("alpha"))
    b = s.add_entry(fields("beta", notes="multi\nline \u00e9"))
    c = s.add_entry(fields("gamma"))
    updated = s.update_entry(a, {"name": "alpha2", "password": "NEW-SECRET"})
    assert updated["id"] == a and updated["name"] == "alpha2" and updated["username"] == "user"
    s.delete_entry(c)
    s.close()

    t = open_(path)
    assert [e["name"] for e in t.list_entries()] == ["alpha2", "beta"]
    assert t.get_entry(a)["password"] == "NEW-SECRET"
    assert t.get_entry(b)["notes"] == "multi\nline \u00e9"
    with pytest.raises(EntryNotFoundError):
        t.get_entry(c)
    assert load_vault(path, PW) == [t.get_entry(a), t.get_entry(b)]  # engine reads the same data


def test_list_omits_password_and_notes_and_reads_are_copies(tmp_path):
    s, _ = new(tmp_path)
    eid = s.add_entry(fields())
    summary = s.list_entries()[0]
    assert set(summary) == {"id", "name", "username", "url"}
    got = s.get_entry(eid)
    got["password"] = "tampered"
    summary["name"] = "tampered"
    assert s.get_entry(eid)["password"] == SECRET and s.list_entries()[0]["name"] == "site1"


def test_add_defaults_and_generated_ids(tmp_path):
    s, _ = new(tmp_path)
    ids = {s.add_entry({"name": f"n{i}"}) for i in range(5)}
    assert len(ids) == 5 and all(len(i) == 32 and int(i, 16) >= 0 for i in ids)
    assert s.get_entry(next(iter(ids)))["password"] == ""
    assert s.add_entry({"name": "x", "id": "custom-id"}) == "custom-id"


def test_noop_update_does_not_rewrite_file(tmp_path):
    s, path = new(tmp_path)
    eid = s.add_entry(fields())
    before = path.read_bytes()
    s.update_entry(eid, {"name": "site1"})
    s.update_entry(eid, {})
    assert path.read_bytes() == before


def test_unknown_entry(tmp_path):
    s, path = new(tmp_path)
    before = path.read_bytes()
    for call in (lambda: s.get_entry("nope"), lambda: s.update_entry("nope", {"name": "n"}),
                 lambda: s.delete_entry("nope"), lambda: s.get_entry(5)):
        with pytest.raises(EntryNotFoundError):
            call()
    assert path.read_bytes() == before


# ---- validation ------------------------------------------------------------

BAD_ADDS = {
    "missing name": {"username": "u"},
    "empty name": {"name": ""},
    "int field": {"name": 5},
    "none field": {"name": "n", "notes": None},
    "extra field": {"name": "n", "extra": "x"},
    "password too long": {"name": "n", "password": "x" * 1025},
    "id too long": {"name": "n", "id": "x" * 65},
    "empty id": {"name": "n", "id": ""},
}


@pytest.mark.parametrize("case", list(BAD_ADDS))
def test_invalid_add_rejected_and_nothing_changes(tmp_path, case):
    s, path = new(tmp_path)
    s.add_entry(fields())
    before, summary = path.read_bytes(), s.list_entries()
    with pytest.raises(ValueError):
        s.add_entry(BAD_ADDS[case])
    assert path.read_bytes() == before and s.list_entries() == summary


BAD_UPDATES = {
    "empty name": {"name": ""},
    "int value": {"url": 5},
    "too long": {"notes": "x" * 10_001},
    "change id": {"id": "other"},
    "unknown field": {"bogus": "x"},
}


@pytest.mark.parametrize("case", list(BAD_UPDATES))
def test_invalid_update_rejected_and_nothing_changes(tmp_path, case):
    s, path = new(tmp_path)
    eid = s.add_entry(fields())
    before, entry = path.read_bytes(), s.get_entry(eid)
    with pytest.raises(ValueError):
        s.update_entry(eid, BAD_UPDATES[case])
    assert path.read_bytes() == before and s.get_entry(eid) == entry


def test_duplicate_id_rejected(tmp_path):
    s, path = new(tmp_path)
    s.add_entry({"name": "a", "id": "same"})
    before = path.read_bytes()
    with pytest.raises(ValueError):
        s.add_entry({"name": "b", "id": "same"})
    assert path.read_bytes() == before and len(s.list_entries()) == 1


# ---- failed saves and stale sessions --------------------------------------

FAILING = {
    "add": lambda s, eid: s.add_entry(fields("new")),
    "update": lambda s, eid: s.update_entry(eid, {"name": "changed"}),
    "delete": lambda s, eid: s.delete_entry(eid),
}


@pytest.mark.parametrize("op", list(FAILING))
@pytest.mark.parametrize("target", ["os.replace", "os.fsync"])
def test_failed_save_changes_nothing_and_session_recovers(tmp_path, op, target):
    s, path = new(tmp_path)
    eid = s.add_entry(fields())
    before, entry = path.read_bytes(), s.get_entry(eid)
    with mock.patch(f"storage.vault_store.{target}", side_effect=OSError("disk gone")):
        with pytest.raises(OSError):
            FAILING[op](s, eid)
    assert path.read_bytes() == before
    assert s.list_entries() == [{k: entry[k] for k in ("id", "name", "username", "url")}]
    assert s.get_entry(eid) == entry
    assert list(tmp_path.iterdir()) == [path]  # no stray temp file
    s.add_entry(fields("after"))  # session still usable
    assert [e["name"] for e in load_vault(path, PW)] == ["site1", "after"]


def test_stale_session_cannot_overwrite_newer_file(tmp_path):
    s1, path = new(tmp_path)
    s2 = open_(path)
    s1.add_entry(fields("from-s1"))
    after_s1 = path.read_bytes()
    with pytest.raises(VaultConflictError):
        s2.add_entry(fields("from-s2"))
    assert path.read_bytes() == after_s1 and s2.list_entries() == []
    s2.lock()
    s2.unlock(PW)
    assert [e["name"] for e in s2.list_entries()] == ["from-s1"]
    s2.add_entry(fields("from-s2"))
    assert [e["name"] for e in load_vault(path, PW)] == ["from-s1", "from-s2"]


def test_vault_file_removed_mid_session_is_a_conflict_not_a_recreate(tmp_path):
    s, path = new(tmp_path)
    path.unlink()
    with pytest.raises(VaultConflictError):
        s.add_entry(fields())
    assert not path.exists()


def test_replaced_with_corrupt_file_mid_session_not_overwritten(tmp_path):
    s, path = new(tmp_path)
    path.write_bytes(b"corrupt")
    with pytest.raises(VaultConflictError):
        s.add_entry(fields())
    assert path.read_bytes() == b"corrupt"


# ---- no leaks --------------------------------------------------------------

def test_nothing_plaintext_on_disk_and_no_stray_files(tmp_path):
    s, path = new(tmp_path)
    eid = s.add_entry(fields())
    s.update_entry(eid, {"notes": "private note"})
    s.close()
    raw = path.read_bytes()
    for needle in (PW, SECRET, "site1", "private note", "x.test"):
        assert needle.encode() not in raw
    assert list(tmp_path.iterdir()) == [path]


def test_repr_pickle_and_errors_contain_no_secrets(tmp_path):
    s, path = new(tmp_path)
    s.add_entry(fields())
    assert PW not in repr(s) and SECRET not in repr(s) and "unlocked" in repr(s)
    with pytest.raises(TypeError):
        pickle.dumps(s)
    errors = []
    for call in (lambda: s.add_entry({"name": "n", "password": SECRET * 100}),
                 lambda: s.get_entry("nope"), lambda: s.update_entry("nope", {"password": SECRET})):
        try:
            call()
        except Exception as e:
            errors.append(e)
    s.lock()
    try:
        s.get_entry("x")
    except Exception as e:
        errors.append(e)
    t = VaultSession(path, kdf_params=FAST)
    try:
        t.unlock(PW + "-BADPW")
    except Exception as e:
        errors.append(e)
    assert len(errors) == 5
    for e in errors:
        for secret in (PW, SECRET, "BADPW", "site1"):
            assert secret not in str(e) and secret not in repr(e)
