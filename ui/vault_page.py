import re

from PySide6.QtCore import QEvent, QSettings, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.analyzer import analyze
from security.key_derivation import DEFAULT_PARAMS
from storage.vault_session import (
    EntryNotFoundError,
    VaultConflictError,
    VaultInUseError,
    VaultSession,
)
from storage.vault_store import VaultAuthError, VaultFormatError, VaultVersionError
from ui.clipboard import ClipboardGuard

DEFAULT_IDLE_MIN = 5
# shortcut: only clicks, keys and wheel count as activity, mouse movement does not; upgrade if users get locked while reading
IDLE_EVENTS = (QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress, QEvent.Type.Wheel)


# Allowlist of ValueError messages that are safe to show (full match). They name
# fields and indexes, never values. Any other ValueError may quote a value (a
# UnicodeError quotes characters), so it gets generic text instead.
_SAFE_VALUE_ERROR = re.compile(
    r"entries must be a list"
    r"|too many entries \(max \d+\)"
    r"|vault too large"
    r"|master password must be a non-empty string"
    r"|master password is not valid Unicode"
    r"|changes may only set: \[[a-z_', ]*\]"
    r"|entry \d+: (?:must be a dict with exactly the fields \[[a-z_', ]*\]"
    r"|field '[a-z]+' (?:must be a string|length must be \d+ to \d+)"
    r"|duplicate id)"
)


def error_text(e: Exception) -> str:
    """Fixed, user-safe text. Vault and crypto errors never carry secrets; ValueError
    messages from validation name fields and indexes, never values."""
    if isinstance(e, VaultAuthError):
        return "Wrong master password, or the vault file was modified or damaged."
    if isinstance(e, VaultVersionError):
        return "This vault was made by a different KeyForge version and cannot be opened."
    if isinstance(e, VaultFormatError):
        return "This is not a valid vault file, or it is damaged."
    if isinstance(e, VaultInUseError):
        return "This vault is already open in another window."
    if isinstance(e, VaultConflictError):
        return "The vault file changed on disk. Lock and unlock to reload it."
    if isinstance(e, EntryNotFoundError):
        return "That entry no longer exists."
    if isinstance(e, FileNotFoundError):
        return "File not found."
    if isinstance(e, FileExistsError):
        return "A file already exists there. KeyForge never overwrites on create."
    if isinstance(e, PermissionError):
        return "Permission denied."
    if isinstance(e, OSError):
        return "Could not read or write the file."
    if isinstance(e, ValueError) and not isinstance(e, UnicodeError):
        msg = str(e)
        return msg if _SAFE_VALUE_ERROR.fullmatch(msg) else "Invalid input."
    return "Something went wrong."


class VaultPage(QWidget):
    def __init__(self, settings=None, kdf_params=DEFAULT_PARAMS):
        super().__init__()
        # Stores only the last vault path (not a secret). On Windows this is the registry.
        self._settings = QSettings("KeyForge", "KeyForge") if settings is None else settings
        self._kdf_params = kdf_params
        self._session = None
        self._current_id = None
        self.clipboard = ClipboardGuard(self)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_locked())
        self.stack.addWidget(self._build_unlocked())
        layout = QVBoxLayout(self)
        layout.addWidget(self.stack)

        self._idle = QTimer(self)
        self._idle.setSingleShot(True)
        self._idle.timeout.connect(self.lock)
        QApplication.instance().installEventFilter(self)

    # ---- building --------------------------------------------------------

    def _build_locked(self) -> QWidget:
        w = QWidget()
        self.path_edit = QLineEdit(str(self._settings.value("vault/last_path", "") or ""))
        self.path_edit.setPlaceholderText("Path to a .vault file")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        self.master = QLineEdit()
        self.master.setEchoMode(QLineEdit.EchoMode.Password)
        self.master.returnPressed.connect(self.unlock)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.master_hint = QLabel()
        self.master_hint.setWordWrap(True)
        self.master.textChanged.connect(self._update_master_hint)
        self.confirm.textChanged.connect(self._update_master_hint)
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.unlock)
        self.create_btn = QPushButton("Create new vault")
        self.create_btn.clicked.connect(self.create)
        self.lock_error = QLabel()
        self.lock_error.setWordWrap(True)
        self.lock_error.setStyleSheet("color: #c0392b;")
        note = QLabel(
            "No password recovery: a forgotten master password means the data is gone. "
            "Back up the vault file yourself. Experimental, not security audited."
        )
        note.setWordWrap(True)

        row = QHBoxLayout()
        row.addWidget(self.path_edit)
        row.addWidget(browse)
        form = QFormLayout()
        form.addRow("Vault file", row)
        form.addRow("Master password", self.master)
        form.addRow("Confirm (new vault only)", self.confirm)
        buttons = QHBoxLayout()
        buttons.addWidget(self.unlock_btn)
        buttons.addWidget(self.create_btn)
        layout = QVBoxLayout(w)
        layout.addWidget(QLabel("Vault locked"))
        layout.addLayout(form)
        layout.addWidget(self.master_hint)
        layout.addLayout(buttons)
        layout.addWidget(self.lock_error)
        layout.addWidget(note)
        layout.addStretch()
        return w

    def _build_unlocked(self) -> QWidget:
        w = QWidget()
        lock_btn = QPushButton("Lock")
        lock_btn.clicked.connect(self.lock)
        self.idle_spin = QSpinBox()
        self.idle_spin.setRange(1, 60)
        self.idle_spin.setValue(DEFAULT_IDLE_MIN)  # shortcut: not persisted, resets each launch
        self.idle_spin.setSuffix(" min")
        self.idle_spin.valueChanged.connect(self._restart_idle)
        top = QHBoxLayout()
        top.addWidget(QLabel("Vault unlocked"))
        top.addStretch()
        top.addWidget(QLabel("Auto-lock after"))
        top.addWidget(self.idle_spin)
        top.addWidget(lock_btn)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, username, URL")
        self.listing = QListWidget()
        self.listing.currentItemChanged.connect(self._select)
        self.search.textChanged.connect(self._refresh)
        new_btn = QPushButton("New entry")
        new_btn.clicked.connect(self.new_entry)
        del_btn = QPushButton("Delete")
        del_btn.clicked.connect(self.delete)
        left_buttons = QHBoxLayout()
        left_buttons.addWidget(new_btn)
        left_buttons.addWidget(del_btn)
        left = QVBoxLayout()
        left.addWidget(self.search)
        left.addWidget(self.listing)
        left.addLayout(left_buttons)

        self.fields = {k: QLineEdit() for k in ("name", "url", "username", "password")}
        self.fields["password"].setEchoMode(QLineEdit.EchoMode.Password)  # hidden by default
        self.notes = QPlainTextEdit()
        self.show_pw = QCheckBox("Show password")
        self.show_pw.toggled.connect(
            lambda on: self.fields["password"].setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
            )
        )
        form = QFormLayout()
        form.addRow("Name", self.fields["name"])
        form.addRow("URL", self.fields["url"])
        form.addRow("Username", self.fields["username"])
        form.addRow("Password", self.fields["password"])
        form.addRow("", self.show_pw)
        form.addRow("Notes", self.notes)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save)
        copy_user = QPushButton("Copy username")
        copy_user.clicked.connect(lambda: self.copy_field("username"))
        copy_pw = QPushButton("Copy password")
        copy_pw.clicked.connect(lambda: self.copy_field("password"))
        right_buttons = QHBoxLayout()
        for b in (save_btn, copy_user, copy_pw):
            right_buttons.addWidget(b)
        self.entry_error = QLabel()
        self.entry_error.setWordWrap(True)
        self.entry_error.setStyleSheet("color: #c0392b;")
        right = QVBoxLayout()
        right.addLayout(form)
        right.addLayout(right_buttons)
        right.addWidget(self.entry_error)

        body = QHBoxLayout()
        body.addLayout(left, 1)
        body.addLayout(right, 2)
        layout = QVBoxLayout(w)
        layout.addLayout(top)
        layout.addLayout(body)
        return w

    # ---- lifecycle -------------------------------------------------------

    @property
    def is_unlocked(self) -> bool:
        return self._session is not None and self._session.is_unlocked

    def _path(self) -> str:
        return self.path_edit.text().strip().strip('"')

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Vault file", self._path(), "Vault (*.vault);;All files (*)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if path:
            self.path_edit.setText(path)

    def create(self):
        path, pw = self._path(), self.master.text()
        if not path:
            return self.lock_error.setText("Choose a vault file path.")
        if not pw:
            return self.lock_error.setText("Enter a master password.")
        if pw != self.confirm.text():
            return self.lock_error.setText("Passwords do not match.")
        self._open(lambda s: s.create(pw), path)

    def unlock(self):
        path, pw = self._path(), self.master.text()
        if not path:
            return self.lock_error.setText("Choose a vault file path.")
        if not pw:
            return self.lock_error.setText("Enter a master password.")
        self._open(lambda s: s.unlock(pw), path)

    def _open(self, action, path: str):
        session = VaultSession(path, kdf_params=self._kdf_params)
        self._set_busy(True)
        try:
            action(session)
        except Exception as e:
            session.close()
            self.lock_error.setText(error_text(e))
            return
        finally:
            self._set_busy(False)
        self._session = session
        self._settings.setValue("vault/last_path", path)
        self.master.clear()
        self.confirm.clear()
        self.lock_error.clear()
        self._refresh()
        self.stack.setCurrentIndex(1)
        self._restart_idle()

    def _update_master_hint(self, *_):
        """Advice while choosing a master password. Shown only once the confirm box
        has text (unlocking never uses it) and it never blocks creating the vault.
        analyze() warnings never contain the password."""
        pw = self.master.text()
        if not pw or not self.confirm.text():
            self.master_hint.clear()
            return
        a = analyze(pw)
        lines = [
            f"Length {a.length}. Rough estimate: up to {a.entropy_bits:.0f} bits. "
            "A rough check, not a guarantee.",
            *(f"Warning: {w}" for w in a.warnings),
        ]
        self.master_hint.setText("\n".join(lines))

    def _set_busy(self, on: bool):
        # shortcut: Argon2 runs on the GUI thread (VaultSession is not thread-safe); a hostile
        # vault at the KDF upper bounds can freeze the window for many seconds
        for b in (self.unlock_btn, self.create_btn):
            b.setEnabled(not on)
        if on:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
        else:
            QApplication.restoreOverrideCursor()

    def lock(self):
        """Drop the session and wipe every sensitive widget. Safe to call when locked."""
        self._idle.stop()
        if self._session is not None:
            self._session.close()
            self._session = None
        self._current_id = None
        self.listing.blockSignals(True)
        self.listing.clear()
        self.listing.blockSignals(False)
        self.search.clear()
        self._clear_form()
        self.master.clear()
        self.confirm.clear()
        self.clipboard.clear()
        self.stack.setCurrentIndex(0)

    def shutdown(self):
        """Window closing: lock, release the vault, stop watching events."""
        self.lock()
        QApplication.instance().removeEventFilter(self)

    # ---- idle lock -------------------------------------------------------

    def _restart_idle(self, *_):
        if self.is_unlocked:
            self._idle.start(self.idle_spin.value() * 60_000)

    def eventFilter(self, obj, event):
        if event.type() in IDLE_EVENTS:
            self._restart_idle()
        return False

    # ---- entries ---------------------------------------------------------

    def _form(self) -> dict:
        data = {k: w.text() for k, w in self.fields.items()}
        data["notes"] = self.notes.toPlainText()
        return data

    def _clear_form(self):
        for w in self.fields.values():
            w.clear()
        self.notes.clear()
        self.show_pw.setChecked(False)  # cancels any reveal
        self.entry_error.clear()

    def _refresh(self, *_):
        self.listing.blockSignals(True)
        self.listing.clear()
        if self.is_unlocked:
            q = self.search.text().strip().lower()
            for s in self._session.list_entries():  # summaries: no password, no notes
                if q and not any(q in s[k].lower() for k in ("name", "username", "url")):
                    continue
                item = QListWidgetItem(f"{s['name']}  ({s['username']})" if s["username"] else s["name"])
                item.setData(Qt.ItemDataRole.UserRole, s["id"])
                self.listing.addItem(item)
                if s["id"] == self._current_id:
                    self.listing.setCurrentItem(item)
        self.listing.blockSignals(False)

    # shortcut: picking another entry replaces unsaved form edits without asking; add a dirty check if it bites
    def _select(self, item, _prev=None):
        if item is None or not self.is_unlocked:
            return
        entry_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            e = self._session.get_entry(entry_id)
        except Exception as ex:
            self.entry_error.setText(error_text(ex))
            return
        self._current_id = entry_id
        for k, w in self.fields.items():
            w.setText(e[k])
        self.notes.setPlainText(e["notes"])
        self.entry_error.clear()

    def new_entry(self):
        self._current_id = None
        self.listing.blockSignals(True)
        self.listing.setCurrentRow(-1)
        self.listing.blockSignals(False)
        self._clear_form()
        self.fields["name"].setFocus()

    def save(self):
        if not self.is_unlocked:
            return
        data = self._form()
        try:
            if self._current_id is None:
                self._current_id = self._session.add_entry(data)
            else:
                self._session.update_entry(self._current_id, data)
        except Exception as e:
            self.entry_error.setText(error_text(e))  # form left as typed: nothing is lost
            return
        self.entry_error.setText("Saved.")
        self._refresh()

    def _confirm(self, text: str) -> bool:
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        return QMessageBox.question(self, "KeyForge", text, yes | no, no) == yes

    def delete(self):
        if not self.is_unlocked or self._current_id is None:
            return
        if not self._confirm("Delete this entry? This cannot be undone."):
            return
        if not self.is_unlocked:  # the idle timer can fire while the dialog is open
            return
        try:
            self._session.delete_entry(self._current_id)
        except Exception as e:
            self.entry_error.setText(error_text(e))
            return
        self._current_id = None
        self._clear_form()
        self._refresh()

    def copy_field(self, key: str):
        text = self.fields[key].text()
        if self.is_unlocked and text:
            self.clipboard.copy(text)