"""Source-level guards for code that handles secrets.

Reads the source with ast (nothing is imported or run). Catches:
  * `random` used anywhere (secrets only, per the roadmap rules)
  * print, logging, traceback, pprint, pdb, breakpoint, direct stdout/stderr writes
    in core/, security/, storage/, ui/ (a debug line could leak a password)
main.py is the CLI and prints the generated password on purpose, so it is only
scanned for `random`.
"""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ("core", "security", "storage", "ui")
RANDOM_SCAN = (*PACKAGES, "main.py")
BANNED_MODULES = {"logging", "traceback", "pprint", "pdb"}
BANNED_CALLS = {"print", "breakpoint"}


def py_files(targets):
    for name in targets:
        path = ROOT / name
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.py"))


def rel(path):
    return path.relative_to(ROOT).as_posix()


def imported_roots(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


def _dynamic_import_of_random(node):
    if not isinstance(node, ast.Call) or not node.args:
        return False
    func = node.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
    arg = node.args[0]
    return (
        name in {"__import__", "import_module"}
        and isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and arg.value.split(".")[0] == "random"
    )


def uses_random(source):
    tree = ast.parse(source)
    return "random" in set(imported_roots(tree)) or any(
        _dynamic_import_of_random(n) for n in ast.walk(tree)
    )


def output_leaks(source):
    tree = ast.parse(source)
    found = sorted(set(imported_roots(tree)) & BANNED_MODULES)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id in BANNED_CALLS:
            found.append(f"{f.id}()")
        elif (
            isinstance(f, ast.Attribute)
            and f.attr == "write"
            and isinstance(f.value, ast.Attribute)
            and f.value.attr in {"stdout", "stderr"}
        ):
            found.append(f"{f.value.attr}.write()")
    return found


def read(path):
    return path.read_text(encoding="utf-8-sig")


RANDOM_FILES = list(py_files(RANDOM_SCAN))
PACKAGE_FILES = list(py_files(PACKAGES))


# ---- the scan itself must not pass vacuously -------------------------------

def test_scan_covers_the_security_modules():
    names = {rel(p) for p in RANDOM_FILES}
    for expected in (
        "core/generator.py",
        "core/analyzer.py",
        "security/crypto.py",
        "security/key_derivation.py",
        "storage/vault_store.py",
        "storage/vault_session.py",
        "ui/vault_page.py",
        "ui/clipboard.py",
        "main.py",
    ):
        assert expected in names, f"{expected} is not being scanned"


@pytest.mark.parametrize(
    "source",
    [
        "import random",
        "import random as r",
        "import os, random",
        "from random import choice",
        "from random import *",
        "import random.foo",
        "__import__('random')",
        "import importlib\nimportlib.import_module('random')",
    ],
)
def test_random_detector_catches(source):
    assert uses_random(source)


@pytest.mark.parametrize(
    "source",
    ["import secrets", "from secrets import token_bytes", "x = 'random'", "import randomish"],
)
def test_random_detector_ignores(source):
    assert not uses_random(source)


@pytest.mark.parametrize(
    "source",
    [
        "print(1)",
        "import logging",
        "from logging import getLogger",
        "import traceback",
        "import pprint",
        "import pdb",
        "breakpoint()",
        "import sys\nsys.stderr.write('x')",
        "import sys\nsys.stdout.write('x')",
    ],
)
def test_output_detector_catches(source):
    assert output_leaks(source)


@pytest.mark.parametrize(
    "source",
    ["x = 1", "def print_all(): pass", "obj.print()", "label.write('x')", "import secrets"],
)
def test_output_detector_ignores(source):
    assert not output_leaks(source)


# ---- the real code ----------------------------------------------------------

@pytest.mark.parametrize("path", RANDOM_FILES, ids=rel)
def test_module_never_uses_random(path):
    assert not uses_random(read(path)), f"{rel(path)} uses `random`; use `secrets`"


@pytest.mark.parametrize("path", PACKAGE_FILES, ids=rel)
def test_module_never_prints_or_logs(path):
    assert output_leaks(read(path)) == [], f"{rel(path)} prints or logs"
