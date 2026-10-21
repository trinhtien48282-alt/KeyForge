# KeyForge



An offline password generator and experimental encrypted vault for Windows, built with Python and PySide6.



## What works



- Password generator: length 8 to 128, uppercase, lowercase, digits, symbols. Uses Python's `secrets` module, never `random`.

- Desktop window: length slider, character-set checkboxes, Generate, Copy, show/hide password. The password is hidden by default.

- Password analysis: estimated entropy, character types, and warnings. The entropy figure is an estimate, not a security guarantee.

- Best-effort clipboard clearing 30 seconds after Copy, and on exit. It also asks Windows clipboard history and cloud clipboard to skip the copy.

- Command line: run `main.py` with any flag, for example `uv run python main.py -l 24 --no-symbols`.



## Vault (experimental)



The Vault tab stores credentials in an Argon2id + AES-256-GCM encrypted file.



- Create, unlock and lock a vault. Add, edit, search and delete entries. Copy a username or password.

- Passwords are hidden by default. The clipboard is cleared on lock, and the vault locks when the window closes.

- Auto-lock after 1 to 60 minutes with no clicks, key presses or scrolling in KeyForge (default 5, resets each launch).

- One KeyForge window can have a given vault open at a time. If the file changes on disk while unlocked, saving is refused until you lock and unlock.

- KeyForge remembers the last vault path (not a secret) in the Windows registry.
- When you type a master password for a new vault, KeyForge shows a rough check (entropy estimate and warnings). It is not a guarantee, and it never stops you.



Format details: [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md).



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



Status: v0.3.0 is a pre-release. It has not been tested on a clean Windows machine or offline. The SHA-256 of the zip is in the GitHub release notes.



## Known limitations



- Clipboard clearing is best effort. Other programs, clipboard managers and malware can read the clipboard before it is cleared.

- Passwords and keys may stay in process memory after use. KeyForge does not wipe memory.

- No protection against malware, keyloggers or screen capture on your machine.

- The vault has no password recovery and no built-in backup. A forgotten master password means the data is gone.

- You cannot change the master password yet.

- Unlocking, saving and deleting run Argon2id on the main thread, so the window may pause briefly.

- Another program writing the vault file at the same moment as a save is not fully guarded against.

- Mouse movement does not count as activity for auto-lock.

- The executable is not code-signed. Windows SmartScreen or antivirus may warn about it.

- Windows only. Tested on Windows 11.

- The symbol set is fixed to ASCII punctuation. Some sites reject some symbols.

- The built-in common-password list is small. Pattern warnings are heuristics.



## License



MIT. See [LICENSE](LICENSE).

