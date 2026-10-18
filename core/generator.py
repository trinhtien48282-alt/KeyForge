import secrets
import string

MIN_LENGTH = 8
MAX_LENGTH = 128

# shortcut: fixed symbol set, some sites reject some symbols; add a custom-symbols option when a real site needs it
SYMBOLS = string.punctuation


def generate_password(
    length: int = 20,
    *,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Return a random password. Raises ValueError on invalid settings."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("length must be an integer")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    sets = [
        chars
        for enabled, chars in (
            (upper, string.ascii_uppercase),
            (lower, string.ascii_lowercase),
            (digits, string.digits),
            (symbols, SYMBOLS),
        )
        if enabled
    ]
    if not sets:
        raise ValueError("enable at least one character set")

    pool = "".join(sets)
    # Rejection sampling: every char uniform over the pool, retry until each
    # enabled set appears. Keeps full entropy, no shuffle or forced slots.
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(c in s for c in pw) for s in sets):
            return pw
