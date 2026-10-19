# KeyForge release guide (v0.1.0)

v0.1.0 ships the generator, analyzer and desktop window. The vault engine is library code only and is not reachable from the executable.

PyInstaller is not a cross-compiler: build on Windows.

## 1\. Pre-release checks

```powershell
git status                   # must be clean
uv run pytest -v             # all tests pass
git ls-files | Select-String "\\\\\\\\.vault|\\\\\\\\.env|\\\\\\\\.key|secrets"   # must print nothing
```

## 2\. Build

```powershell
uv add --dev pyinstaller
uv run pyinstaller --noconfirm --windowed --name KeyForge main.py
```

Output: `dist\\\\\\\\KeyForge\\\\\\\\KeyForge.exe` plus its support files. This is a folder build (`--onedir`), which starts faster and triggers fewer antivirus false positives than `--onefile`. `--windowed` hides the console, so command-line flags print nothing in the exe. Use `uv run python main.py -l 24` for the terminal.

`build/`, `dist/` and `\\\\\\\*.spec` are already in `.gitignore`.

## 3\. Package

```powershell
Compress-Archive -Path dist\\\\\\\\KeyForge -DestinationPath dist\\\\\\\\KeyForge-0.1.0-win64.zip
Get-FileHash dist\\\\\\\\KeyForge-v0.1.0-windows-x64 -Algorithm SHA256
```

Publish the SHA-256 next to the zip so people can verify their download.

## 4\. Test on a clean Windows machine

Use a machine or VM that has no Python, no uv, and no copy of this repo. Windows Sandbox works on Pro and Enterprise only.

1. Copy the zip over and extract it.
2. Run `KeyForge.exe`. The window opens with no errors.
3. Generate at several lengths and with each checkbox off. Turn all off: an error shows and no password.
4. Show/hide works. Analysis text appears.
5. Copy, paste elsewhere. After 30 seconds the clipboard is empty.
6. Copy, then copy something else. After 30 seconds the newer clipboard text is untouched.
7. Close the window. Clipboard is cleared if it still held the password.

## 5\. Verify offline

Turn off Wi-Fi and unplug Ethernet (or disable the adapter), then repeat steps 2 to 5 above. Everything must work. KeyForge makes no network calls.

## 6\. Tag

```powershell
git add -A
git commit -m "Release v0.1.0"
git tag -a v0.1.0 -m "KeyForge v0.1.0: generator, analyzer, desktop UI. Vault engine has no UI."
git push --follow-tags
```

Then on GitHub, create a release from the tag, attach the zip, paste the SHA-256, and copy the known limitations from the README into the release notes.

## Checksums

Status: v0.1.0 is not released. The artifact below is an unreleased local build. Clean-machine and offline testing have not been done. The desktop window is generator-only; the vault engine has no usable UI.

|Artifact|Algorithm|Hash|
|-|-|-|
|`KeyForge-v0.1.0-windows-x64.zip` (local build, created with `Compress-Archive` from `dist\\\\\\\\KeyForge`)|SHA-256|`7663CE08260EBFD1F8E53A296DAF7639DAF40C69691638404260EFD56EEAB578`|

The maintainer computed this hash locally with `Get-FileHash .\\\\\\\\KeyForge-v0.1.0-windows-x64.zip -Algorithm SHA256`. Rebuilding or re-zipping changes the hash. Update this table whenever the zip is rebuilt.

To verify a download:

```powershell
Get-FileHash .\\\\\\\\KeyForge-v0.1.0-windows-x64.zip -Algorithm SHA256
```

The output must match the hash above exactly.

## Not done in v0.1.0

* Vault window, so no vault in the executable.
* Automatic vault locking after inactivity. It needs the vault UI.
* Code signing.
* Third-party security audit.
* Test on a second Windows version.

