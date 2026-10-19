# KeyForge

An offline password generator for Windows, built with Python and PySide6. It also contains an experimental encrypted vault engine that has no user interface yet.

## What works in v0.1.0

- Password generator: length 8 to 128, uppercase, lowercase, digits, symbols. Uses Python's `secrets` module, never `random`.
- Desktop window: length slider, character-set checkboxes, Generate, Copy, show/hide password. The password is hidden by default.
- Password analysis: estimated entropy, character types, and warnings. The entropy figure is an estimate, not a security guarantee.
- Best-effort clipboard clearing 30 seconds after Copy, and on exit. It also asks Windows clipboard history and cloud clipboard to skip the copy.
- Command line: run `main.py` with any flag, for example `uv run python main.py -l 24 --no-symbols`.

## Vault engine (library only, no UI)

`security/`, `storage/` and the session layer implement an Argon2id + AES-256-GCM encrypted vault with create, unlock, lock and credential CRUD. There is no window for it. The v0.1.0 executable does not use it. Format details: [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md).

**Do not store real credentials in the vault.** It has not been security audited.

## Run from source

Requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync
uv run python main.py        # desktop app
uv run pytest -v             # tests
```

## Build the Windows executable

See [docs/RELEASE.md](docs/RELEASE.md).

Status: v0.1.0 is not released yet. A local Windows build exists and its SHA-256 is recorded in [docs/RELEASE.md](docs/RELEASE.md#checksums). It has not been tested on a clean machine or offline.

## Known limitations

- Clipboard clearing is best effort. Other programs, clipboard managers and malware can read the clipboard before it is cleared.
- Passwords and keys may stay in process memory after use. KeyForge does not wipe memory.
- No protection against malware, keyloggers or screen capture on your machine.
- The vault has no password recovery and no built-in backup. A forgotten master password means the data is gone.
- No automatic vault locking yet, because the vault has no UI.
- The executable is not code-signed. Windows SmartScreen or antivirus may warn about it.
- Windows only. Tested on Windows 11.
- The symbol set is fixed to ASCII punctuation. Some sites reject some symbols.
- The built-in common-password list is small. Pattern warnings are heuristics.

## License

To be determined.
