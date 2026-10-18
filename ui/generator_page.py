from PySide6.QtCore import QMimeData, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from core.generator import MAX_LENGTH, MIN_LENGTH, generate_password

CLEAR_AFTER_MS = 30_000
# Windows formats asking clipboard history and cloud sync to skip this copy (DWORD 0). Best effort.
NO_HISTORY_FORMATS = ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")
SETS = (
    ("upper", "Uppercase (A-Z)"),
    ("lower", "Lowercase (a-z)"),
    ("digits", "Numbers (0-9)"),
    ("symbols", "Symbols (!@#...)"),
)


class GeneratorPage(QWidget):
    def __init__(self):
        super().__init__()
        self._copied = None

        self.slider = QSlider(Qt.Horizontal)
        self.slider.setRange(MIN_LENGTH, MAX_LENGTH)
        self.slider.setValue(20)
        self.length_label = QLabel("20")
        self.slider.valueChanged.connect(lambda v: self.length_label.setText(str(v)))

        self.boxes = {}
        for key, label in SETS:
            self.boxes[key] = QCheckBox(label)
            self.boxes[key].setChecked(True)

        # Hidden by default: nobody over your shoulder sees it.
        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setEchoMode(QLineEdit.Password)
        self.show_box = QCheckBox("Show password")
        self.show_box.toggled.connect(
            lambda on: self.output.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )

        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c0392b;")

        generate_btn = QPushButton("Generate")
        generate_btn.clicked.connect(self.generate)
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy)

        row = QHBoxLayout()
        row.addWidget(QLabel("Length"))
        row.addWidget(self.slider)
        row.addWidget(self.length_label)
        buttons = QHBoxLayout()
        buttons.addWidget(generate_btn)
        buttons.addWidget(copy_btn)

        layout = QVBoxLayout(self)
        layout.addLayout(row)
        for box in self.boxes.values():
            layout.addWidget(box)
        layout.addWidget(self.output)
        layout.addWidget(self.show_box)
        layout.addWidget(self.error)
        layout.addLayout(buttons)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear_clipboard)
        QApplication.instance().aboutToQuit.connect(self.clear_clipboard)

    def generate(self):
        try:
            pw = generate_password(
                self.slider.value(),
                **{key: box.isChecked() for key, box in self.boxes.items()},
            )
        except ValueError as e:
            self.output.clear()
            self.error.setText(str(e))
            return
        self.error.clear()
        self.output.setText(pw)

    def copy(self):
        pw = self.output.text()
        if not pw:
            return
        mime = QMimeData()
        mime.setText(pw)
        for fmt in NO_HISTORY_FORMATS:
            mime.setData(fmt, b"\x00\x00\x00\x00")
        QApplication.clipboard().setMimeData(mime)
        self._copied = pw
        self._timer.start(CLEAR_AFTER_MS)

    def clear_clipboard(self):
        # Only wipe our own copy: never destroy something the user copied since.
        clipboard = QApplication.clipboard()
        if self._copied is not None and clipboard.text() == self._copied:
            clipboard.clear()
        self._copied = None
