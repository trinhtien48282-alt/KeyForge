import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

import ui.clipboard as clip
from ui.clipboard import ClipboardGuard


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def guard(app):
    g = ClipboardGuard()
    yield g
    g._timer.stop()
    QApplication.clipboard().clear()


def wait_until_fired(guard, seconds=3):
    deadline = time.monotonic() + seconds
    while guard._timer.isActive() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()
    assert not guard._timer.isActive(), "timer never fired"


def test_clear_delay_is_30_seconds():
    assert clip.CLEAR_AFTER_MS == 30_000


def test_copy_arms_a_single_shot_timer(guard):
    guard.copy("secret")
    assert guard._timer.isActive() and guard._timer.isSingleShot()
    assert guard._timer.interval() == clip.CLEAR_AFTER_MS


def test_timer_expiry_clears_our_copy(guard, monkeypatch):
    monkeypatch.setattr(clip, "CLEAR_AFTER_MS", 50)
    guard.copy("secret")
    assert QApplication.clipboard().text() == "secret"
    wait_until_fired(guard)
    assert QApplication.clipboard().text() == ""


def test_timer_expiry_keeps_newer_clipboard(guard, monkeypatch):
    monkeypatch.setattr(clip, "CLEAR_AFTER_MS", 50)
    guard.copy("secret")
    QApplication.clipboard().setText("other")
    wait_until_fired(guard)
    assert QApplication.clipboard().text() == "other"


def test_second_copy_restarts_the_timer(guard, monkeypatch):
    monkeypatch.setattr(clip, "CLEAR_AFTER_MS", 10_000)
    guard.copy("first")
    time.sleep(0.3)
    assert guard._timer.remainingTime() < 9_800
    guard.copy("second")
    assert guard._timer.remainingTime() > 9_800


def test_quit_clears_our_copy(guard, app):
    guard.copy("secret")
    app.aboutToQuit.emit()
    assert QApplication.clipboard().text() == ""


def test_clear_does_nothing_when_we_copied_nothing(guard):
    QApplication.clipboard().setText("user data")
    guard.clear()
    assert QApplication.clipboard().text() == "user data"


def test_copy_asks_windows_to_skip_history_and_cloud(guard):
    guard.copy("secret")
    mime = QApplication.clipboard().mimeData()
    for fmt in clip.NO_HISTORY_FORMATS:
        assert mime.hasFormat(fmt)
        assert bytes(mime.data(fmt)) == b"\x00\x00\x00\x00"