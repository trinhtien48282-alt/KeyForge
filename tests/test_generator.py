import inspect
import string

import pytest

from core import generator
from core.generator import MAX_LENGTH, MIN_LENGTH, SYMBOLS, generate_password

CLASSES = {
    "upper": string.ascii_uppercase,
    "lower": string.ascii_lowercase,
    "digits": string.digits,
    "symbols": SYMBOLS,
}


@pytest.mark.parametrize("n", [MIN_LENGTH, 20, MAX_LENGTH])
def test_length(n):
    assert len(generate_password(n)) == n


def test_default_has_every_class():
    for _ in range(300):
        pw = generate_password(MIN_LENGTH)
        assert all(any(c in s for c in pw) for s in CLASSES.values())


@pytest.mark.parametrize("off", list(CLASSES))
def test_disabled_class_absent_others_present(off):
    for _ in range(100):
        pw = generate_password(MIN_LENGTH, **{off: False})
        assert not any(c in CLASSES[off] for c in pw)
        assert all(any(c in s for c in pw) for k, s in CLASSES.items() if k != off)


def test_single_class_only():
    pw = generate_password(30, upper=False, lower=False, symbols=False)
    assert pw.isdigit() and len(pw) == 30


@pytest.mark.parametrize("bad", [0, -1, MIN_LENGTH - 1, MAX_LENGTH + 1, "20", 20.0, None, True])
def test_bad_length(bad):
    with pytest.raises(ValueError):
        generate_password(bad)


def test_no_sets():
    with pytest.raises(ValueError):
        generate_password(20, upper=False, lower=False, digits=False, symbols=False)


def test_no_duplicates_in_1000():
    assert len({generate_password(20) for _ in range(1000)}) == 1000


def test_uses_secrets_not_random():
    src = inspect.getsource(generator)
    assert "import secrets" in src
    assert "import random" not in src and "from random" not in src
