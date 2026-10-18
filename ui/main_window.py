from PySide6.QtWidgets import QMainWindow

from ui.generator_page import GeneratorPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeyForge")
        self.setCentralWidget(GeneratorPage())
