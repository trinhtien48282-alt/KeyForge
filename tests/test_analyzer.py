import math

import pytest

from core.analyzer import analyze
from core.generator import generate_password


def has(a, word):
    return any(word in w for w in a.warnings)


def test_generated_full_set():
    a = analyze(generate_password(20), generated=True)
    assert a.length == 20
    assert a.classes == ("uppercase", "lowercase", "digits", "symbols")
    assert a.pool_size == 94
    assert abs(a.entropy_bits - 20 * math.log2(94)) < 1e-9
    assert a.warnings == ()


def test_generated_weak_settings_warn():
    a = analyze(generate_password(8, upper=False, lower=False, symbols=False), generated=True)
    assert a.classes == ("digits",)
    assert has(a, "Short") and has(a, "Low entropy") and has(a, "Only one")


def test_generated_skips_pattern_checks():
    assert analyze("Abc!xx9Qaaa1Zk#PL2m", generated=True).warnings == ()


@pytest.mark.parametrize(
    "pw,word",
    [
        ("password", "Common"),
        ("Password123!", "Common"),
        ("xk3abcQ9zLm!pV2w", "sequence"),
        ("Zq7!qwerLm4#xPv2", "keyboard"),
        ("Zq7!aaaLm4#xPv2k", "Same character"),
        ("Xk9#Xk9#Xk9#", "shorter block"),
    ],
)
def test_pattern_warnings(pw, word):
    a = analyze(pw)
    assert has(a, word)
    assert has(a, "real strength is lower")


def test_clean_non_generated_has_no_pattern_warnings():
    a = analyze("Xv8#mQ2!rTz5&Lp9")
    assert a.warnings == ()


def test_other_characters():
    assert "other" in analyze("Xv8 mQ2é").classes


def test_warnings_never_contain_password():
    pw = "Password123!"
    assert not any(pw in w for w in analyze(pw).warnings)


@pytest.mark.parametrize("bad", ["", None, 123])
def test_bad_input(bad):
    with pytest.raises(ValueError):
        analyze(bad)
