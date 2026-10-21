import string
import subprocess
import sys
from pathlib import Path

import pytest

import main
from core.generator import SYMBOLS

ROOT = Path(main.__file__).resolve().parent

@pytest.fixture(autouse=True)
def gui_must_not_start(monkeypatch):
    def boom():
        raise AssertionError("main() tried to start the GUI")

    monkeypatch.setattr(main, "run_gui", boom)

def run(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    code = main.main()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_no_flags_launches_gui(monkeypatch):
    monkeypatch.setattr(main, "run_gui", lambda: 7)
    monkeypatch.setattr(sys, "argv", ["main.py"])
    assert main.main() == 7


def test_any_flag_stays_in_terminal(monkeypatch, capsys):
    def boom():
        raise AssertionError("GUI must not start when a flag is given")

    monkeypatch.setattr(main, "run_gui", boom)
    code, out, _ = run(monkeypatch, capsys, "-l", "12")
    assert code == 0 and len(out.strip()) == 12


def test_default_length_is_20_and_output_is_only_the_password(monkeypatch, capsys):
    code, out, err = run(monkeypatch, capsys, "--no-symbols")
    assert code == 0 and err == ""
    assert out.endswith("\n") and len(out) == 21 and not any(c.isspace() for c in out[:-1])


@pytest.mark.parametrize("n", [8, 24, 128])
def test_length_flag(monkeypatch, capsys, n):
    code, out, _ = run(monkeypatch, capsys, "-l", str(n))
    assert code == 0 and len(out.strip()) == n


@pytest.mark.parametrize(
    "flag,chars",
    [
        ("--no-upper", string.ascii_uppercase),
        ("--no-lower", string.ascii_lowercase),
        ("--no-digits", string.digits),
        ("--no-symbols", SYMBOLS),
    ],
)
def test_disable_flags_exclude_that_class(monkeypatch, capsys, flag, chars):
    code, out, _ = run(monkeypatch, capsys, "-l", "64", flag)
    assert code == 0 and not any(c in chars for c in out.strip())


@pytest.mark.parametrize("n", [0, 7, 129])
def test_out_of_range_length_exits_2_without_a_password(monkeypatch, capsys, n):
    code, out, err = run(monkeypatch, capsys, "-l", str(n))
    assert code == 2 and out == "" and err.startswith("error:")


def test_all_sets_off_exits_2(monkeypatch, capsys):
    code, out, err = run(
        monkeypatch, capsys, "--no-upper", "--no-lower", "--no-digits", "--no-symbols"
    )
    assert code == 2 and out == "" and "at least one character set" in err


def test_non_integer_length_is_rejected_by_argparse(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "-l", "abc"])
    with pytest.raises(SystemExit) as e:
        main.main()
    assert e.value.code == 2
    assert "invalid int value" in capsys.readouterr().err


def test_script_exit_codes_through_a_real_process():
    # Covers the `sys.exit(main())` wiring that calling main() directly skips.
    ok = subprocess.run(
        [sys.executable, "main.py", "-l", "12"], cwd=ROOT, capture_output=True, text=True, timeout=60
    )
    assert ok.returncode == 0 and len(ok.stdout.strip()) == 12
    bad = subprocess.run(
        [sys.executable, "main.py", "-l", "7"], cwd=ROOT, capture_output=True, text=True, timeout=60
    )
    assert bad.returncode == 2 and bad.stdout == "" and bad.stderr.startswith("error:")