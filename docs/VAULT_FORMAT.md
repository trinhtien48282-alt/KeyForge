# KeyForge vault format, version 1

Status: experimental. This design has not been security audited and is not
production ready. Do not store real credentials in it until it has been reviewed.

## Overview

A vault is one UTF-8 JSON file. The whole credential list is serialized to JSON,
encrypted with AES-256-GCM, and stored as a single ciphertext. Only the header
(format name, version, KDF parameters, salt, nonce) is readable without the master
password. Neither the master password nor the derived key is ever written to disk.

## File layout

```json
{
  "cipher": {"algorithm": "aes-256-gcm", "nonce": "<base64, 12 bytes>"},
  "ciphertext": "<base64, encrypted credentials + 16-byte GCM tag>",
  "format": "keyforge-vault",
  "kdf": {
    "algorithm": "argon2id",
    "argon2_version": 19,
    "memory_kib": 65536,
    "parallelism": 4,
    "salt": "<base64, 16 bytes>",
    "time_cost": 3
  },
  "version": 1
}
```

Every object has exactly the fields shown. Missing, extra, duplicate, or wrongly
typed fields make the file invalid. Version is checked first, so a future version
is reported as unsupported rather than malformed.

## Plaintext (before encryption)

```json
{"entries": [{"id": "...", "name": "...", "username": "...", "password": "...", "url": "...", "notes": "..."}]}
```

All six fields are required strings. Length limits (characters): id 1-64,
name 1-256, username 0-256, password 0-1024, url 0-2048, notes 0-10000. Ids must be
unique. At most 10,000 entries. Serialized plaintext is at most 8 MiB, the file at
most 16 MiB. These limits are checked on save (so KeyForge never writes a vault it
cannot read back) and again on load.

## Key derivation

- Argon2id, Argon2 version 0x13 (19), via `argon2-cffi` (`hash_secret_raw`).
- Default parameters: time cost 3, memory 65,536 KiB (64 MiB), parallelism 4.
  This is the second recommended profile in RFC 9106.
- Salt: 16 random bytes from `secrets`, new on every save.
- Output: 32 bytes, used directly as the AES-256 key.
- Master password: Unicode NFKC normalized, then UTF-8 encoded. This is part of
  format version 1 and cannot change without a new version. Empty passwords are
  rejected. The engine enforces no other password policy.

KDF parameters are read from the file, which is untrusted input. They are
bounds-checked before any Argon2 work: time cost 2-10, memory 19,456-524,288 KiB
(19 MiB to 512 MiB), parallelism 1-16. Lower bounds stop a file from silently
lowering cost. Upper bounds stop a crafted file from forcing a huge allocation.

## Encryption

- AES-256-GCM from the `cryptography` library. Nothing is hand-rolled.
- Nonce: 12 random bytes from `secrets`, drawn fresh on every encryption.
- A new salt, and so a new key, is also used on every save, so a (key, nonce) pair
  is never reused.
- Associated data (authenticated, not encrypted): canonical JSON of the format
  name, version, the full KDF block (including salt), and the cipher name. The AAD
  is rebuilt from validated values, not copied from file text. The nonce is covered
  by the GCM tag itself.
- In version 1 every AAD field is either a constant or feeds the key, so changing
  it already breaks decryption. The AAD is defense in depth, and matters for future
  versions.

## Loading

1. Reject files over 16 MiB.
2. Parse JSON strictly and validate structure, version, algorithms, parameter
   bounds, base64, and lengths. No key derivation happens yet.
3. Derive the key and decrypt. Any authentication failure raises `VaultAuthError`.
4. Validate the decrypted contents. A failure raises `VaultFormatError`.

A wrong master password and a modified or damaged file are indistinguishable.
AES-GCM cannot tell them apart, so the message covers both.

## Saving

- `create_vault` refuses to touch an existing path.
- `save_vault` refuses to replace anything that is not a structurally valid,
  supported vault, so corrupt or unsupported files are never silently overwritten.
  It does not check that the supplied master password opens the current file.
  Callers must pass entries that came from `load_vault`.
- Writes are atomic: encrypt in memory, write a temp file in the same directory,
  flush and `fsync`, then `os.replace` onto the target. If any step fails, the temp
  file is removed and the original file is untouched.

## Errors

Error messages are fixed text. They never include the master password, keys, or
decrypted values. Validation messages name a field and entry index, never a value.
Underlying exceptions are suppressed so tracebacks cannot carry content.

## Memory handling

KeyForge does not persist the master password or key. It does not claim to erase
them from memory. Python strings and bytes are immutable and may be copied by the
interpreter, the Qt layer, or the OS, so the master password, derived key, and
decrypted entries can remain in process memory after use. Swap files and crash
dumps are out of scope.

## Backup and recovery limitations

- There is no recovery. A forgotten master password means the data is gone.
- There is no built-in backup. Atomic replace keeps the old file only until the
  new one is in place. Copy the vault file somewhere safe yourself.
- A backup is as old as the copy, and opens with the master password in use when
  that copy was saved.
- `fsync` and atomic rename depend on the file system and drive. Some USB drives
  and network shares may not honor them. A power loss during save should leave
  either the old or the new file, but this is not guaranteed on all hardware.
- A crash can leave a stray `<name>.vault.*.tmp` file. It holds only ciphertext and
  can be deleted. Consider adding `*.vault.*.tmp` to `.gitignore`.
- Anyone with a copy of the file can attempt offline guessing of the master
  password. Argon2id slows this down but cannot stop it. A weak master password is
  the main risk.
- Create refuses existing paths with a check-then-write. Another process creating
  the same path in between is not defended against.

## Not covered

No protection from malware on the machine, keyloggers, screen capture, or clipboard
sniffing. No audit has been performed.
