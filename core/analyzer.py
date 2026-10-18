import math
import re
import string
from dataclasses import dataclass

SHORT_LENGTH = 12
# shortcut: 60 bits is a rule of thumb, not a standard; revisit if the threat model changes
LOW_ENTROPY_BITS = 60
# shortcut: tiny built-in list; swap for a real top-10k list when you want better coverage
COMMON = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "111111", "123123", "passw0rd",
    "football", "baseball", "sunshine", "princess", "login", "master", "hello",
    "freedom", "whatever", "trustno1", "shadow",
}
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
POOLS = (
    ("uppercase", string.ascii_uppercase),
    ("lowercase", string.ascii_lowercase),
    ("digits", string.digits),
    ("symbols", string.punctuation),
)


@dataclass(frozen=True)
class Analysis:
    length: int
    classes: tuple  # character types present
    pool_size: int
    entropy_bits: float  # estimate: length * log2(pool), assumes random characters
    warnings: tuple  # plain-English reasons; never contains the password


def _has_sequence(s: str) -> bool:
    for i in range(len(s) - 2):
        a, b, c = s[i : i + 3]
        if (a + b + c).isalnum() and ord(b) - ord(a) == ord(c) - ord(b) in (1, -1):
            return True
    return False


def _has_keyboard_run(s: str) -> bool:
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i : i + 4]
            if chunk in s or chunk[::-1] in s:
                return True
    return False


def analyze(password: str, *, generated: bool = False) -> Analysis:
    """Describe a password. generated=True: it came from core.generator, so
    pattern checks are skipped (a random pick that happens to look patterned is
    no weaker). generated=False: entropy is an upper bound, patterns are checked."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    classes = []
    pool = 0
    for name, chars in POOLS:
        if any(c in chars for c in password):
            classes.append(name)
            pool += len(chars)
    other = {c for c in password if not any(c in chars for _, chars in POOLS)}
    if other:
        classes.append("other")
        pool += len(other)  # shortcut: counts only distinct odd chars seen; true pool is unknown

    bits = len(password) * math.log2(pool)
    warnings = []
    if len(password) < SHORT_LENGTH:
        warnings.append(f"Short: under {SHORT_LENGTH} characters. Longer is the cheapest way to add strength.")
    if bits < LOW_ENTROPY_BITS:
        warnings.append(
            f"Low entropy: about {bits:.0f} bits, under {LOW_ENTROPY_BITS}. "
            "If a site leaks its password hashes, this could be guessed offline."
        )
    if len(classes) == 1:
        warnings.append(f"Only one character type ({classes[0]}). The pool of possible characters is small.")

    if not generated:
        s = password.lower()
        if s in COMMON or s.rstrip(string.digits + string.punctuation) in COMMON:
            warnings.append("Common password: appears in lists attackers try first.")
        if _has_sequence(s):
            warnings.append("Contains a sequence like abc or 321. Attackers try these early.")
        if _has_keyboard_run(s):
            warnings.append("Contains a keyboard run like qwer. Attackers try these early.")
        if re.search(r"(.)\1\1", password):
            warnings.append("Same character 3+ times in a row.")
        if re.fullmatch(r"(.+?)\1+", password):
            warnings.append("A shorter block repeated. Effective length is the block, not the whole.")
        if warnings and any(w.startswith(("Common", "Contains", "Same", "A shorter")) for w in warnings):
            warnings.append("Because of the patterns above, real strength is lower than the entropy figure.")

    return Analysis(len(password), tuple(classes), pool, bits, tuple(warnings))
