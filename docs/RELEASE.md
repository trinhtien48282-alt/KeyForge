# KeyForge release guide



Build on Windows: PyInstaller is not a cross-compiler.



No artifact name or checksum is stored in this repo. The version comes from

`pyproject.toml`, and the SHA-256 goes in the GitHub release notes.



## 1. Pre-release checks



```powershell

git status                   # must be clean

uv lock --check              # lock matches pyproject.toml

uv run pytest -v             # all tests pass

git ls-files | Select-String -Pattern '[.](vault|key|env)([.]|$)|secrets'  # must print nothing

git tag                      # the new version must not exist yet

```



Set the version: edit `pyproject.toml` to a clean release version (no `.dev`),

run `uv lock`, and commit both files together.



## 2. Build



```powershell

uv sync --locked

Remove-Item dist, build -Recurse -Force -ErrorAction SilentlyContinue

uv run --no-sync pyinstaller --noconfirm --clean --windowed --name KeyForge main.py

```



Output: `dist/KeyForge/KeyForge.exe` plus support files. This is a folder build

(`--onedir`), which starts faster and triggers fewer antivirus false positives

than `--onefile`. `--windowed` hides the console, so command-line flags print

nothing in the exe. Use `uv run python main.py -l 24` for the terminal.



`build/`, `dist/` and `*.spec` are in `.gitignore`.



## 3. Package



```powershell

$v = (Select-String -Path pyproject.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value

Compress-Archive -Path dist/KeyForge -DestinationPath "dist/KeyForge-$v-win64.zip" -Force

Get-FileHash "dist/KeyForge-$v-win64.zip" -Algorithm SHA256

```



PyInstaller output is not bit-for-bit reproducible, and zip timestamps change the

hash. The hash identifies one specific zip. Rebuilding gives a new hash.



Put the hash in the GitHub release notes. To verify a download:



```powershell

Get-FileHash ./KeyForge-<version>-win64.zip -Algorithm SHA256

```



## 4. Test on a clean Windows machine



Use a machine or VM with no Python, no uv and no copy of this repo. Windows

Sandbox works on Pro and Enterprise only. Use a throwaway vault and password,

never real credentials.



1. Copy the zip over and extract it.

2. Run `KeyForge.exe`. The window opens with no errors.

3. Generator tab: generate at several lengths and with each checkbox off. Turn all

&#x20;  off: an error shows and no password.

4. Show/hide works. Analysis text appears.

5. Copy, paste elsewhere. After 30 seconds the clipboard is empty.

6. Copy, then copy something else. After 30 seconds the newer text is untouched.

7. Vault tab: create a vault in a temp folder. Add an entry. Lock. Unlock with a

&#x20;  wrong password (error, still locked), then the right one.

8. Copy the entry password, then paste it. Open Win+V clipboard history (turn it

&#x20;  on first if needed). The password must not appear there.

9. Set auto-lock to 1 minute, leave KeyForge untouched. It locks.

10. Start a second KeyForge on the same vault file: it reports the vault is open.

11. Close the window with a password on the clipboard. The clipboard is cleared.

12. Delete the test vault.



## 5. Verify offline



Disable Wi-Fi and Ethernet, then repeat steps 2 to 11. KeyForge makes no network

calls.



## 6. Tag and publish



```powershell

git tag -a v<version> -m "KeyForge v<version>"

git push origin main

git push origin v<version>

```



Push the tag by name. Do not use `--follow-tags` or `--tags`: they publish every

local annotated tag. Then on GitHub create a release from the tag, attach the

zip, paste the SHA-256, and copy the known limitations from the README into the

release notes.



## Not done



- Code signing. Windows SmartScreen or antivirus may warn.

- Third-party security audit.

- Test on a second Windows version.

