"""Master password -> 32-byte key with Argon2id. Nothing here is persisted."""
import secrets
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

KEY_LEN = 32
SALT_LEN = 16
ARGON2_VERSION = 19  # 0x13, the current Argon2 version

# Accepted range for parameters read from a vault file (untrusted input).
# Lower bounds stop a file from quietly downgrading cost; upper bounds stop a
# crafted file from forcing a huge allocation or a very long run.
BOUNDS = {
    "time_cost": (2, 10),
    "memory_kib": (19_456, 524_288),  # 19 MiB .. 512 MiB
    "parallelism": (1, 16),
}


@dataclass(frozen=True)
class KdfParams:
    # RFC 9106 second recommended profile: t=3, m=64 MiB, p=4.
    time_cost: int = 3
    memory_kib: int = 65_536
    parallelism: int = 4

    def __post_init__(self):
        for name, (lo, hi) in BOUNDS.items():
            value = getattr(self, name)
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError(f"{name} must be an integer between {lo} and {hi}")


DEFAULT_PARAMS = KdfParams()


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


def derive_key(password: str, salt: bytes, params: KdfParams = DEFAULT_PARAMS) -> bytes:
    if type(password) is not str or not password:
        raise ValueError("master password must be a non-empty string")
    if type(salt) is not bytes or len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")
    # NFKC so the same visible password gives the same key on any input method.
    # Part of vault format v1: changing it would lock people out.
    try:
        secret = unicodedata.normalize("NFKC", password).encode("utf-8")
    except UnicodeEncodeError:
        # from None: the codec error text would quote a character of the password.
        raise ValueError("master password is not valid Unicode") from None
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )
