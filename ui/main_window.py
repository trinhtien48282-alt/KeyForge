from PySide6.QtWidgets import QMainWindow, QTabWidget

from ui.generator_page import GeneratorPage
from ui.vault_page import VaultPage


class MainWindow(QMainWindow):
    def __init__(self, vault_page=None):
        super().__init__()
        self.setWindowTitle("KeyForge")
        self.generator = GeneratorPage()
        self.vault = vault_page or VaultPage()
        tabs = QTabWidget()
        tabs.addTab(self.generator, "Generator")
        tabs.addTab(self.vault, "Vault")
        self.setCentralWidget(tabs)

    def closeEvent(self, event):
        self.vault.shutdown()  # lock, close session, clear our clipboard copy
        self.generator.clear_clipboard()
        super().closeEvent(event)