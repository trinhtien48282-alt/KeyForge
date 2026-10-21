"""error_text decides what the user sees. It must never echo a secret."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from security.key_derivation import KdfParams, derive_key, new_salt
from storage.vault_session import VaultSession
from storage.vault_store import MAX_ENTRIES, validate_entries
from ui.vault_page import error_text

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
SECRET = "TOPSECRET-pw-123"


def entry(i=1, **over):
    e = {"id": f"id{i}", "name": f"site{i}", "username": "u", "password": "p", "url": "", "notes": ""}
    e.update(over)
    return e


# ---- nothing unexpected reaches the screen ------------------------------------

LEAKY = {
    "plain ValueError": ValueError(f"bad value {SECRET}"),
    "int parse ValueError": ValueError(f"invalid literal for int() with base 10: '{SECRET}'"),
    "entry lookalike": ValueError(f"entry {SECRET}"),
    "entry index lookalike": ValueError(f"entry 0: field '{SECRET}' must be a string"),
    "master password lookalike": ValueError(f"master password {SECRET}"),
    "UnicodeEncodeError": UnicodeEncodeError("ascii", SECRET, 0, 1, "ordinal not in range"),
    "UnicodeDecodeError": UnicodeDecodeError("utf-8", SECRET.encode(), 0, 1, "invalid start byte"),
    "KeyError": KeyError(SECRET),
    "TypeError": TypeError(SECRET),
    "RuntimeError": RuntimeError(SECRET),
    "OSError": OSError(SECRET),
    "FileNotFoundError": FileNotFoundError(2, SECRET),
    "PermissionError": PermissionError(13, SECRET),
}


@pytest.mark.parametrize("name", list(LEAKY))
def test_unexpected_errors_never_echo_their_message(name):
    e = LEAKY[name]
    text = error_text(e)
    assert text and SECRET not in text and str(e) not in text


def test_unknown_value_error_gets_generic_text():
    assert error_text(ValueError("anything else")) == "Invalid input."


# ---- real validation messages must still reach the user -----------------------

BAD_ENTRY_LISTS = {
    "not a list": {"a": 1},
    "entry not dict": ["x"],
    "missing field": [{k: v for k, v in entry().items() if k != "url"}],
    "int field": [entry(name=5)],
    "empty name": [entry(name="")],
    "password too long": [entry(password="x" * 1025)],
    "duplicate id": [entry(1, id="same"), entry(2, id="same")],
    "too many": [entry(i, id=str(i)) for i in range(MAX_ENTRIES + 1)],
}


@pytest.mark.parametrize("name", list(BAD_ENTRY_LISTS))
def test_validation_messages_pass_through(name):
    with pytest.raises(ValueError) as e:
        validate_entries(BAD_ENTRY_LISTS[name])
    assert str(e.value) and error_text(e.value) == str(e.value)


def test_update_entry_rejection_passes_through(tmp_path):
    with VaultSession(tmp_path / "v.vault", kdf_params=FAST) as s:
        s.create("master-pw-xyz")
        eid = s.add_entry({"name": "n"})
        with pytest.raises(ValueError) as e:
            s.update_entry(eid, {"bogus": "x"})
    assert str(e.value) and error_text(e.value) == str(e.value)


def test_empty_master_password_message_passes_through():
    with pytest.raises(ValueError) as e:
        derive_key("", new_salt(), FAST)
    assert error_text(e.value) == str(e.value)


def test_unencodable_master_password_message_passes_through_without_the_password():
    with pytest.raises(ValueError) as e:
        derive_key("abcSECRET\ud800", new_salt(), FAST)
    text = error_text(e.value)
    assert text == str(e.value) and "SECRET" not in text
