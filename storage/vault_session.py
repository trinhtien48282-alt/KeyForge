"""Unlocked-vault session: lifecycle and credential CRUD over storage.vault_store.

Every change is validated, checked against the file, written with save_vault, and
only then applied in memory, so a failed save leaves memory and the last valid file
untouched. There is no autosave and no dirty state.

The master password is held only while unlocked (each save derives a new key from a
new salt, so the engine needs it again) and released on lock or close. Python cannot
guarantee that strings or dicts are wiped from memory; lock only drops references
and empties the session's own containers. Not thread-safe. Nothing here logs.
"""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import NoReturn, TypedDict

from security.key_derivation import DEFAULT_PARAMS, KdfParams
from storage.vault_store import (
    FIELDS,
    MAX_FILE_BYTES,
    VaultError,
    create_vault,
    load_vault,
    save_vault,
    validate_entries,
    peek_params
)


class Entry(TypedDict):
    id: str
    name: str
    username: str
    password: str
    url: str
    notes: str


class EntrySummary(TypedDict):
    id: str
    name: str
    username: str
    url: str


class SessionState(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CLOSED = "closed"


class SessionStateError(VaultError):
    """Operation not allowed in the session's current state."""


class SessionLockedError(SessionStateError):
    """Operation needs an unlocked vault."""


class SessionClosedError(SessionStateError):
    """Session was closed and cannot be used again."""


class EntryNotFoundError(VaultError):
    pass


class VaultConflictError(VaultError):
    """The vault file changed or disappeared since this session read it."""


_SUMMARY_FIELDS = ("id", "name", "username", "url")
_OPTIONAL_FIELDS = ("username", "password", "url", "notes")


def _hash_file(path: Path) -> bytes:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(MAX_FILE_BYTES + 1)).digest()


class VaultSession:
    def __init__(self, path, *, kdf_params: KdfParams = DEFAULT_PARAMS) -> None:
        self._path = Path(path)
        self._kdf_params = kdf_params  # new vaults only: unlock replaces it with the file's own
        self._state = SessionState.LOCKED
        self._password: str | None = None
        self._entries: list[dict[str, str]] | None = None
        self._seen: bytes | None = None  # hash of the file as this session last saw it

    # ---- lifecycle -------------------------------------------------------

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def is_unlocked(self) -> bool:
        return self._state is SessionState.UNLOCKED

    def create(self, password: str) -> None:
        """Create a new empty vault at the path and leave the session unlocked.
        Refuses to touch an existing file."""
        self._require_locked()
        data = create_vault(self._path, password, [], kdf_params=self._kdf_params)
        self._enter(password, [], hashlib.sha256(data).digest(), self._kdf_params)

    def unlock(self, password: str) -> None:
        """Decrypt the vault. On any failure the session stays locked and keeps nothing."""
        seen = _hash_file(self._path)  # before loading: a racing change then shows as a conflict
        params = peek_params(self._path)
        self._enter(password, load_vault(self._path, password), seen, params)

    def lock(self) -> None:
        """Drop the password and decrypted entries. No-op unless unlocked."""
        if self._state is SessionState.UNLOCKED:
            self._scrub()
            self._state = SessionState.LOCKED

    def close(self) -> None:
        """Lock, then make the session unusable. Safe to call repeatedly."""
        self.lock()
        self._state = SessionState.CLOSED

    def __enter__(self) -> VaultSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<VaultSession {self._state.value}>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("VaultSession cannot be pickled or copied")

    # ---- credentials -----------------------------------------------------

    def list_entries(self) -> list[EntrySummary]:
        """Summaries only: no password and no notes."""
        return [{k: e[k] for k in _SUMMARY_FIELDS} for e in self._live()]  # type: ignore[misc]

    def get_entry(self, entry_id: str) -> Entry:
        """A copy of the full entry; changing it does not change the session."""
        return dict(self._live()[self._index(entry_id)])  # type: ignore[return-value]

    def add_entry(self, fields: Mapping[str, str]) -> str:
        """Add an entry and return its id. A random id is made if none is given;
        username, password, url and notes default to empty."""
        entries = self._live()
        entry = dict(fields)
        entry.setdefault("id", secrets.token_hex(16))
        for name in _OPTIONAL_FIELDS:
            entry.setdefault(name, "")
        self._commit([*entries, entry])
        return entry["id"]

    def update_entry(self, entry_id: str, changes: Mapping[str, str]) -> Entry:
        """Change fields of an entry (never its id) and return the updated copy."""
        entries = self._live()
        i = self._index(entry_id)
        if not set(changes) <= set(FIELDS) - {"id"}:
            raise ValueError(f"changes may only set: {sorted(set(FIELDS) - {'id'})}")
        updated = {**entries[i], **changes}
        if updated != entries[i]:
            self._commit([*entries[:i], updated, *entries[i + 1 :]])
        return dict(updated)  # type: ignore[return-value]

    def delete_entry(self, entry_id: str) -> None:
        entries = self._live()
        i = self._index(entry_id)
        self._commit([*entries[:i], *entries[i + 1 :]])

    # ---- internals -------------------------------------------------------

    def _require_locked(self) -> None:
        if self._state is SessionState.CLOSED:
            raise SessionClosedError("session is closed")
        if self._state is SessionState.UNLOCKED:
            raise SessionStateError("vault is already unlocked")

    def _live(self) -> list[dict[str, str]]:
        if self._state is SessionState.CLOSED:
            raise SessionClosedError("session is closed")
        if self._state is not SessionState.UNLOCKED or self._entries is None:
            raise SessionLockedError("vault is locked")
        return self._entries

    def _index(self, entry_id: str) -> int:
        for i, e in enumerate(self._live()):
            if e["id"] == entry_id:
                return i
        raise EntryNotFoundError("no such entry")

    def _enter(self, password: str, entries: list, seen: bytes, params: KdfParams) -> None:
        self._password, self._entries, self._seen = password, entries, seen
        self._kdf_params = params
        self._state = SessionState.UNLOCKED

    def _scrub(self) -> None:
        if self._entries is not None:
            for e in self._entries:
                e.clear()
            self._entries.clear()
        self._entries = self._password = self._seen = None

    def _commit(self, candidate: list[dict[str, str]]) -> None:
        validate_entries(candidate)
        try:
            current = _hash_file(self._path)
        except FileNotFoundError:
            raise VaultConflictError("vault file is missing") from None
        if current != self._seen:
            raise VaultConflictError("vault file changed since it was unlocked; lock and unlock to reload")
        data = save_vault(self._path, self._password, candidate, kdf_params=self._kdf_params)
        self._entries = candidate  # only after the write succeeded
        self._seen = hashlib.sha256(data).digest()  # the bytes we wrote, not whatever is on disk now
