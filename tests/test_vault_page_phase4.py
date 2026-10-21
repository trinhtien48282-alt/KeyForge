import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from security.key_derivation import KdfParams
from storage.vault_store import load_vault
from ui.vault_page import VaultPage

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
PW = "Sup3r-Secret-MASTER"
WEAK = "password123"
GOOD = "Xv8#mQ2!rTz5&Lp9"  # no warnings in tests/test_analyzer.py


def ini(tmp_path):
    return QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app, tmp_path):
    p = VaultPage(settings=ini(tmp_path), kdf_params=FAST)
    yield p
    p.shutdown()


def create(page, tmp_path, password=PW):
    path = tmp_path / "v.vault"
    page.path_edit.setText(str(path))
    page.master.setText(password)
    page.confirm.setText(password)
    page.create()
    return path


def add(page, name="site1"):
    page.new_entry()
    page.fields["name"].setText(name)
    page.fields["password"].setText("ENTRY-SECRET-xyz")
    page.save()


# ---- master password hint ------------------------------------------------------

def test_no_hint_until_confirm_is_typed(page):
    # Unlocking an existing vault never touches the confirm box: no advice there.
    page.master.setText(WEAK)
    assert page.master_hint.text() == ""
    page.confirm.setText(WEAK)
    assert page.master_hint.text() != ""


def test_weak_master_warns_and_never_echoes_the_password(page):
    page.master.setText(WEAK)
    page.confirm.setText(WEAK)
    text = page.master_hint.text()
    assert "Common password" in text and "not a guarantee" in text
    assert WEAK not in text


def test_good_master_gets_no_warning_and_no_praise(page):
    page.master.setText(GOOD)
    page.confirm.setText(GOOD)
    text = page.master_hint.text()
    assert text and "Warning" not in text and "strong" not in text.lower()


def test_hint_follows_the_master_password(page):
    page.master.setText(WEAK)
    page.confirm.setText(WEAK)
    assert "Common password" in page.master_hint.text()
    page.master.setText(GOOD)
    assert "Common password" not in page.master_hint.text()


def test_weak_master_still_creates_the_vault(page, tmp_path):
    path = create(page, tmp_path, WEAK)
    assert page.is_unlocked and path.exists()
    assert load_vault(path, WEAK) == []


def test_hint_cleared_after_create_and_lock(page, tmp_path):
    create(page, tmp_path, WEAK)
    assert page.master_hint.text() == ""
    page.lock()
    page.master.setText(WEAK)
    page.confirm.setText(WEAK)
    assert page.master_hint.text() != ""
    page.lock()
    assert page.master_hint.text() == ""


def test_unlock_flow_shows_no_hint(page, tmp_path):
    create(page, tmp_path)
    page.lock()
    page.master.setText(PW)
    page.unlock()
    assert page.is_unlocked and page.master_hint.text() == ""


# ---- idle lock during the delete confirmation ----------------------------------

def test_lock_while_delete_dialog_is_open_deletes_nothing(page, tmp_path, monkeypatch):
    path = create(page, tmp_path)
    add(page)

    def idle_lock_fires_then_user_clicks_yes(_text):
        page.lock()  # what the idle timer does while the dialog is open
        return True

    monkeypatch.setattr(page, "_confirm", idle_lock_fires_then_user_clicks_yes)
    page.delete()
    assert not page.is_unlocked
    assert [e["name"] for e in load_vault(path, PW)] == ["site1"]
