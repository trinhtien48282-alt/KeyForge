import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from ui.generator_page import GeneratorPage


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app):
    return GeneratorPage()


def test_generate_fills_output_hidden_by_default(page):
    page.generate()
    assert len(page.output.text()) == 20
    assert page.output.echoMode() == page.output.EchoMode.Password


def test_no_sets_shows_error_and_no_password(page):
    page.generate()
    for box in page.boxes.values():
        box.setChecked(False)
    page.generate()
    assert page.error.text() and page.output.text() == ""


def test_copy_then_clear(page):
    page.generate()
    page.copy()
    assert QApplication.clipboard().text() == page.output.text()
    page.clear_clipboard()
    assert QApplication.clipboard().text() == ""


def test_clear_keeps_newer_clipboard(page):
    page.generate()
    page.copy()
    QApplication.clipboard().setText("something else")
    page.clear_clipboard()
    assert QApplication.clipboard().text() == "something else"
