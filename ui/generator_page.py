from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from core.analyzer import analyze
from core.generator import MAX_LENGTH, MIN_LENGTH, generate_password
from ui.clipboard import ClipboardGuard


SETS = (
    ("upper", "Uppercase (A-Z)"),
    ("lower", "Lowercase (a-z)"),
    ("digits", "Numbers (0-9)"),
    ("symbols", "Symbols (!@#...)"),
)


class GeneratorPage(QWidget):
    def __init__(self):
        super().__init__()

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

        self.analysis = QLabel()
        self.analysis.setWordWrap(True)

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
        layout.addWidget(self.analysis)
        layout.addWidget(self.error)
        layout.addLayout(buttons)

        self.clipboard = ClipboardGuard(self)

    def generate(self):
        try:
            pw = generate_password(
                self.slider.value(),
                **{key: box.isChecked() for key, box in self.boxes.items()},
            )
        except ValueError as e:
            self.output.clear()
            self.analysis.clear()
            self.error.setText(str(e))
            return
        self.error.clear()
        self.output.setText(pw)
        a = analyze(pw, generated=True)
        lines = [
            f"Length {a.length}. Character types: {', '.join(a.classes)}.",
            f"Estimated entropy: {a.entropy_bits:.0f} bits, assuming random generation. An estimate, not a guarantee.",
            *(f"Warning: {w}" for w in a.warnings),
        ]
        self.analysis.setText("\n".join(lines))

    def copy(self):
        pw = self.output.text()
        if pw:
            self.clipboard.copy(pw)

    def clear_clipboard(self):
        self.clipboard.clear()