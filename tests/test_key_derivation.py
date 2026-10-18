import pytest

from security.key_derivation import (
    DEFAULT_PARAMS,
    KEY_LEN,
    SALT_LEN,
    KdfParams,
    derive_key,
    new_salt,
)

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
SALT = bytes(range(SALT_LEN))


def test_defaults_documented_values():
    assert (DEFAULT_PARAMS.time_cost, DEFAULT_PARAMS.memory_kib, DEFAULT_PARAMS.parallelism) == (3, 65_536, 4)


def test_key_length_and_determinism():
    k = derive_key("pw", SALT, FAST)
    assert len(k) == KEY_LEN and k == derive_key("pw", SALT, FAST)


def test_password_salt_params_all_matter():
    base = derive_key("pw", SALT, FAST)
    assert derive_key("pw2", SALT, FAST) != base
    assert derive_key("pw", bytes(SALT_LEN), FAST) != base
    assert derive_key("pw", SALT, KdfParams(3, 19_456, 1)) != base


def test_unicode_normalization():
    composed, decomposed = "caf\u00e9", "cafe\u0301"
    assert derive_key(composed, SALT, FAST) == derive_key(decomposed, SALT, FAST)


def test_new_salt_fresh_and_sized():
    salts = {new_salt() for _ in range(1000)}
    assert len(salts) == 1000 and all(len(s) == SALT_LEN for s in salts)


@pytest.mark.parametrize("bad", ["", None, b"bytes", 123])
def test_bad_password(bad):
    with pytest.raises(ValueError):
        derive_key(bad, SALT, FAST)


def test_unencodable_password_error_does_not_quote_it():
    with pytest.raises(ValueError) as e:
        derive_key("abcSECRET\ud800", SALT, FAST)
    assert "SECRET" not in str(e.value) and e.value.__cause__ is None


@pytest.mark.parametrize("salt", [b"", bytes(15), bytes(17), "s" * 16, None])
def test_bad_salt(salt):
    with pytest.raises(ValueError):
        derive_key("pw", salt, FAST)


@pytest.mark.parametrize(
    "args",
    [(1, 19_456, 1), (11, 19_456, 1), (2, 19_455, 1), (2, 524_289, 1), (2, 19_456, 0), (2, 19_456, 17),
     (True, 19_456, 1), (2.0, 19_456, 1), ("2", 19_456, 1)],
)
def test_params_out_of_bounds(args):
    with pytest.raises(ValueError):
        KdfParams(*args)
