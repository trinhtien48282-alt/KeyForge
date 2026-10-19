from PySide6.QtCore import QMimeData, QObject, QTimer
from PySide6.QtWidgets import QApplication

CLEAR_AFTER_MS = 30_000
# Windows formats asking clipboard history and cloud sync to skip this copy (DWORD 0). Best effort.
NO_HISTORY_FORMATS = ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")


class ClipboardGuard(QObject):
    """Copy text, then clear it later only if it is still ours. Best effort."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._copied = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear)
        QApplication.instance().aboutToQuit.connect(self.clear)

    def copy(self, text: str) -> None:
        mime = QMimeData()
        mime.setText(text)
        for fmt in NO_HISTORY_FORMATS:
            mime.setData(fmt, b"\x00\x00\x00\x00")
        QApplication.clipboard().setMimeData(mime)
        self._copied = text
        self._timer.start(CLEAR_AFTER_MS)

    def clear(self) -> None:
        # Only wipe our own copy: never destroy something the user copied since.
        clipboard = QApplication.clipboard()
        if self._copied is not None and clipboard.text() == self._copied:
            clipboard.clear()
        self._copied = None