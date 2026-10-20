import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QEvent, QSettings, Qt
from PySide6.QtGui import QCloseEvent, QKeyEvent
from PySide6.QtWidgets import QApplication, QLineEdit

from security.key_derivation import KdfParams
from storage.vault_store import load_vault, save_vault
from ui.main_window import MainWindow
from ui.vault_page import VaultPage

FAST = KdfParams(time_cost=2, memory_kib=19_456, parallelism=1)
PW = "Sup3r-Secret-MASTER"
SECRET = "ENTRY-SECRET-xyz"


def ini(tmp_path, name="s.ini"):
    return QSettings(str(tmp_path / name), QSettings.Format.IniFormat)


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app, tmp_path):
    p = VaultPage(settings=ini(tmp_path), kdf_params=FAST)
    yield p
    p.shutdown()


def create(page, tmp_path, name="v.vault"):
    path = tmp_path / name
    page.path_edit.setText(str(path))
    page.master.setText(PW)
    page.confirm.setText(PW)
    page.create()
    return path


def add(page, name="site1", **over):
    page.new_entry()
    vals = {"name": name, "url": "https://x.test", "username": "user", "password": SECRET, **over}
    for k, v in vals.items():
        page.fields[k].setText(v)
    page.notes.setPlainText("n")
    page.save()


def test_starts_locked(page):
    assert page.stack.currentIndex() == 0 and not page.is_unlocked


def test_create_add_lock_unlock_roundtrip(page, tmp_path):
    path = create(page, tmp_path)
    assert page.is_unlocked and page.stack.currentIndex() == 1 and path.exists()
    add(page)
    page.lock()
    assert not page.is_unlocked
    page.master.setText(PW)
    page.unlock()
    assert page.is_unlocked and page.listing.count() == 1


def test_wrong_password_stays_locked(page, tmp_path):
    create(page, tmp_path)
    page.lock()
    page.master.setText(PW + "x")
    page.unlock()
    assert not page.is_unlocked
    assert page.lock_error.text().startswith("Wrong master password")
    assert PW not in page.lock_error.text()


def test_create_validation_and_never_overwrites(page, tmp_path):
    path = tmp_path / "n.vault"
    page.path_edit.setText(str(path))
    page.master.setText(PW)
    page.confirm.setText("different")
    page.create()
    assert not page.is_unlocked and page.lock_error.text() and not path.exists()
    page.confirm.setText(PW)
    page.create()
    assert page.is_unlocked
    page.lock()
    before = path.read_bytes()
    page.master.setText(PW)
    page.confirm.setText(PW)
    page.create()
    assert not page.is_unlocked and page.lock_error.text()
    assert path.read_bytes() == before


def test_corrupt_file_safe_error(page, tmp_path):
    bad = tmp_path / "bad.vault"
    bad.write_bytes(b"garbage")
    page.path_edit.setText(str(bad))
    page.master.setText(PW)
    page.unlock()
    assert not page.is_unlocked and "not a valid vault" in page.lock_error.text()
    assert bad.read_bytes() == b"garbage"


def test_search_edit_delete(page, tmp_path, monkeypatch):
    path = create(page, tmp_path)
    add(page, "alpha")
    add(page, "beta", url="https://other.test")
    assert page.listing.count() == 2
    assert all(SECRET not in page.listing.item(i).text() for i in range(2))
    page.search.setText("BETA")
    assert page.listing.count() == 1
    page.search.setText("other.test")
    assert page.listing.count() == 1
    page.search.setText(SECRET)  # passwords are not searchable
    assert page.listing.count() == 0
    page.search.setText("alpha")
    page.listing.setCurrentRow(0)
    assert page.fields["name"].text() == "alpha"
    page.fields["name"].setText("alpha2")
    page.save()
    assert [e["name"] for e in load_vault(path, PW)] == ["alpha2", "beta"]
    monkeypatch.setattr(page, "_confirm", lambda text: True)
    page.delete()
    assert [e["name"] for e in load_vault(path, PW)] == ["beta"]
    assert page.fields["name"].text() == ""


def test_delete_declined(page, tmp_path, monkeypatch):
    path = create(page, tmp_path)
    add(page)
    monkeypatch.setattr(page, "_confirm", lambda text: False)
    page.delete()
    assert len(load_vault(path, PW)) == 1 and page.fields["name"].text() == "site1"


def test_password_masked_reveal_and_reset(page, tmp_path):
    create(page, tmp_path)
    pw = page.fields["password"]
    assert pw.echoMode() == QLineEdit.EchoMode.Password
    page.show_pw.setChecked(True)
    assert pw.echoMode() == QLineEdit.EchoMode.Normal
    page.lock()
    assert pw.echoMode() == QLineEdit.EchoMode.Password and not page.show_pw.isChecked()


def test_lock_clears_ui_state(page, tmp_path):
    create(page, tmp_path)
    add(page)
    page.search.setText("site")
    page.show_pw.setChecked(True)
    page.lock()
    assert page.stack.currentIndex() == 0 and page._session is None
    assert all(w.text() == "" for w in page.fields.values())
    assert page.notes.toPlainText() == "" and page.search.text() == ""
    assert page.listing.count() == 0 and page.master.text() == "" and page._current_id is None
    assert not page.show_pw.isChecked()


def test_locked_page_ignores_actions(page, tmp_path):
    path = create(page, tmp_path)
    add(page)
    page.lock()
    QApplication.clipboard().setText("sentinel")
    page.fields["name"].setText("ghost")
    page.fields["password"].setText(SECRET)
    page.save()
    page.copy_field("password")
    page.delete()
    assert QApplication.clipboard().text() == "sentinel"
    assert [e["name"] for e in load_vault(path, PW)] == ["site1"]


def test_copy_and_clear_on_lock(page, tmp_path):
    create(page, tmp_path)
    add(page)
    page.copy_field("username")
    assert QApplication.clipboard().text() == "user"
    page.copy_field("password")
    assert QApplication.clipboard().text() == SECRET
    page.lock()
    assert QApplication.clipboard().text() == ""


def test_copy_keeps_newer_clipboard_on_lock(page, tmp_path):
    create(page, tmp_path)
    add(page)
    page.copy_field("password")
    QApplication.clipboard().setText("other")
    page.lock()
    assert QApplication.clipboard().text() == "other"


def test_idle_lock(page, tmp_path):
    page.idle_spin.setValue(1)
    create(page, tmp_path)
    assert page._idle.isActive() and page._idle.interval() == 60_000
    page._idle.timeout.emit()
    assert not page.is_unlocked and not page._idle.isActive()


def test_activity_restarts_idle_timer(page, tmp_path):
    create(page, tmp_path)
    page._idle.stop()
    key = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier, "a")
    QApplication.sendEvent(page.search, key)
    assert page._idle.isActive()


def test_failed_save_keeps_typed_form(page, tmp_path):
    path = create(page, tmp_path)
    add(page)
    save_vault(path, PW, [], kdf_params=FAST)  # a foreign writer replaces the file
    page.fields["name"].setText("edited")
    page.save()
    assert "changed on disk" in page.entry_error.text()
    assert page.fields["name"].text() == "edited" and page.fields["password"].text() == SECRET
    assert load_vault(path, PW) == []


def test_invalid_entry_rejected(page, tmp_path):
    path = create(page, tmp_path)
    page.new_entry()
    page.fields["username"].setText("u")
    page.save()
    assert page.entry_error.text() and load_vault(path, PW) == []


def test_second_window_blocked(page, tmp_path):
    path = create(page, tmp_path)
    other = VaultPage(settings=ini(tmp_path, "o.ini"), kdf_params=FAST)
    try:
        other.path_edit.setText(str(path))
        other.master.setText(PW)
        other.unlock()
        assert not other.is_unlocked and "already open" in other.lock_error.text()
    finally:
        other.shutdown()


def test_close_window_locks(page, tmp_path):
    w = MainWindow(vault_page=page)
    create(page, tmp_path)
    add(page)
    page.copy_field("password")
    w.closeEvent(QCloseEvent())
    assert not page.is_unlocked and QApplication.clipboard().text() == ""
    page.setParent(None)  # the window owns the page; detach so teardown can still reach it


def test_last_path_remembered(page, tmp_path):
    path = create(page, tmp_path)
    page._settings.sync()
    again = VaultPage(settings=ini(tmp_path), kdf_params=FAST)
    try:
        assert again.path_edit.text() == str(path)
    finally:
        again.shutdown()