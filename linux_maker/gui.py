"""Lumen's native Qt desktop. All long operations run in isolated CLI processes."""
from __future__ import annotations

import argparse
import codecs
import datetime
import json
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QFrame, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
    QListWidget, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar,
    QPushButton, QScrollArea, QSizePolicy, QSplitter, QStackedWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import __version__
from .gui_i18n import default_language, translate
from .gui_state import WizardState, json_result
from .paths import ROOT, directories


STEPS = ("Introduction", "Check this PC", "Build the Mac setup", "Your BIOS steps", "Create the macOS stick", "Done")


def cli_command(operation: str, **values) -> list[str]:
    """Single desktop-to-CLI contract. Arguments are never interpreted by a shell."""
    request = {"action": operation}
    if operation == "check": request["action"] = "status"
    elif operation == "scan":
        request["scan"] = str(values["out"])
    elif operation == "build":
        request.update(scan=str(Path(values["report"]).parent), build=str(values["out"]), macos=values["macos"])
        for key in ("experimental", "persistent_nvram", "new_identity", "boot_logs", "stopped_at"):
            if key in values: request[key] = values[key]
    elif operation == "guide":
        request["scan"] = str(Path(values["report"]).parent)
        if values.get("config"): request["build"] = str(Path(values["config"]).parent.parent.parent)
        request["bios_only"] = bool(values.get("prerequisites"))
        request["macos"] = values.get("macos", "24")
    elif operation == "write":
        request.update(disk=values["identity"], confirmed=True, build=str(values["build"]), macos=values["macos"],
                       scan=str(Path(values["report"]).parent), recovery_dir=values.get("recovery_dir") or None,
                       allow_large=bool(values.get("allow_large")), erase_os=bool(values.get("erase_os")))
    elif operation == "doctor":
        request.update(action="efi-check", path=str(values["root"]), fix=bool(values.get("fix")))
        if values.get("report"): request["report"] = str(values["report"])
        request["boot_logs"] = list(map(str, values.get("boot_logs", [])))
        request["stopped_at"] = values.get("stopped_at", "")
    elif operation == "diagnose":
        request.update(logs=list(map(str, values.get("logs", []))), stopped_at=values.get("stopped", ""))
        if values.get("report"): request["report"] = str(values["report"])
    elif operation == "update-drivers":
        request.update(action="update-driver", roots=list(map(str, values.get("destinations", []))))
    elif operation in ("update", "update-check"):
        request["action"] = "update-app" if operation == "update" else "check-update"
        if values.get("source"): request["source"] = values["source"]
        for key in ("archive", "sha256", "expected_version", "expected_sha256"):
            if values.get(key): request[key] = str(values[key])
    elif operation == "export-logs":
        request.update(path=str(values["out"]), files=list(map(str, values.get("files", []))))
    else:
        request.update(values)
    return [sys.executable, "-B", "-u", "-m", "linux_maker", "--request", json.dumps(request, ensure_ascii=False, default=str)]


class CommandWorker(QThread):
    output = Signal(str)
    completed = Signal(int, str, bool)

    def __init__(self, command, environment, parent=None, *, cleanup_timeout=30):
        super().__init__(parent)
        self.command = command
        self.environment = environment
        self._process = None
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self.cleanup_timeout = cleanup_timeout

    def run(self):
        collected, size, code = [], 0, 1
        process = None
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = ""
        try:
            with self._lock:
                if self._cancelled.is_set():
                    self.completed.emit(130, "", True)
                    return
                self._process = subprocess.Popen(self.command, cwd=str(ROOT), env=self.environment,
                                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                 stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
                process = self._process
            while True:
                data = process.stdout.read(8192)
                if not data: break
                text = decoder.decode(data)
                pending += text
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    self.emit_line(line)
                collected.append(text)
                size += len(text)
                while size > 16 * 1024 * 1024 and len(collected) > 1:
                    size -= len(collected.pop(0))
            tail = decoder.decode(b"", final=True)
            if tail:
                collected.append(tail)
                pending += tail
            if pending: self.emit_line(pending)
            code = process.wait()
        except Exception as error:
            text = f"{type(error).__name__}: {error}\n"
            self.output.emit(text)
            collected.append(text)
        finally:
            if process is not None and process.stdout:
                process.stdout.close()
            with self._lock:
                self._process = None
        self.completed.emit(code, "".join(collected), self._cancelled.is_set())

    def emit_line(self, line):
        try: event = json.loads(line)
        except ValueError: self.output.emit(line + "\n"); return
        if not isinstance(event, dict) or "event" not in event:
            if isinstance(event, dict) and "done" in event and "total" in event:
                self.output.emit(f"PROGRESS {event.get('done') or 0} {event.get('total') or 0} {event.get('message', '')}\n")
                return
            self.output.emit(line + "\n"); return
        if event["event"] == "log": self.output.emit(str(event.get("text", "")) + "\n")
        elif event["event"] == "progress":
            self.output.emit(f"PROGRESS {event.get('done', 0)} {event.get('total', 0)} {event.get('phase', '')}\n")
        elif event["event"] == "result":
            if event.get("error"): self.output.emit(str(event["error"]) + "\n")
            data = event.get("data")
            if isinstance(data, dict):
                summary = {k: v for k, v in data.items() if k not in ("hardware", "raw_hardware", "transcript", "report", "profile", "files", "decisions")}
                if summary: self.output.emit(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n")

    def cancel(self):
        if self._cancelled.is_set(): return
        self._cancelled.set()
        with self._lock:
            process = self._process
        if not process or process.poll() is not None: return
        # Only interrupt the worker. Its SIGTERM handler raises KeyboardInterrupt,
        # allowing the bounded privileged helper call and its finally cleanup to
        # finish. Sending SIGTERM to the group would kill mkfs/pkexec underneath it.
        try: process.send_signal(signal.SIGTERM)
        except (ProcessLookupError, PermissionError): return

        def reap():
            try: process.wait(timeout=self.cleanup_timeout)
            except subprocess.TimeoutExpired:
                self.output.emit("Cancellation cleanup deadline exceeded. Inspect unfinished USB sessions before retrying.\n")
                try: os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try: process.kill()
                    except OSError: pass
        threading.Thread(target=reap, daemon=True).start()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Lumen", "Installer")
        self.language = self.settings.value("language", default_language())
        self.dark = self.settings.value("dark", True, type=bool)
        self.paths = directories()
        self.state = WizardState(build_dir=self.paths["build"])
        self.worker = None
        self.operation = None
        self.operation_callback = None
        self.pending_close = False
        self._labels = []
        self._buttons = []
        self._dialogs = []
        self.disk_records = []
        self._last_doctor = None
        self.setMinimumSize(820, 640)
        self.resize(1100, 820)
        self._make_ui()
        self._make_menu()
        self.apply_theme()
        self.retranslate()
        self.restore_session()
        self.go(0)

    def tr(self, text):
        return translate(text, self.language)

    def label(self, text, *, title=False):
        widget = QLabel(self.tr(text))
        widget.setWordWrap(True)
        widget.setTextFormat(Qt.TextFormat.PlainText)
        if title: widget.setObjectName("sectionTitle")
        self._labels.append((widget, text))
        return widget

    def button(self, text, callback, *, primary=False):
        widget = QPushButton(self.tr(text))
        widget.clicked.connect(callback)
        if primary: widget.setObjectName("primary")
        self._buttons.append((widget, text))
        return widget

    def check(self, text):
        widget = QCheckBox(self.tr(text))
        self._buttons.append((widget, text))
        return widget

    def page(self, subtitle):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(16)
        layout.addWidget(self.label(subtitle))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(container)
        self.pages.addWidget(scroll)
        return layout

    def _make_ui(self):
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        header = QFrame()
        header.setObjectName("header")
        h = QHBoxLayout(header)
        h.setContentsMargins(24, 16, 24, 16)
        brand = QLabel("LUMEN")
        brand.setObjectName("brand")
        h.addWidget(brand)
        h.addWidget(self.label("Linux edition · based on 1401"))
        h.addStretch()
        self.lang = QComboBox()
        self.lang.addItem("中文", "zh-CN")
        self.lang.addItem("English", "en")
        self.lang.setCurrentIndex(0 if self.language.startswith("zh") else 1)
        self.lang.currentIndexChanged.connect(self.change_language)
        h.addWidget(self.lang)
        self.theme = self.button("Light" if self.dark else "Dark", self.toggle_theme)
        h.addWidget(self.theme)
        outer.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Vertical)
        main = QWidget()
        main_layout = QHBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setFixedWidth(218)
        self.navigation.setSpacing(4)
        self.navigation.currentRowChanged.connect(self._nav_changed)
        main_layout.addWidget(self.navigation)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.heading = QLabel()
        self.heading.setObjectName("pageTitle")
        self.heading.setContentsMargins(26, 24, 26, 0)
        right_layout.addWidget(self.heading)
        self.pages = QStackedWidget()
        right_layout.addWidget(self.pages)
        main_layout.addWidget(right, 1)
        splitter.addWidget(main)

        self._intro_page()
        self._scan_page()
        self._build_page()
        self._guide_page()
        self._write_page()
        self._done_page()

        log_area = QWidget()
        log_layout = QVBoxLayout(log_area)
        log_layout.setContentsMargins(18, 8, 18, 10)
        toolbar = QHBoxLayout()
        toolbar.addWidget(self.label("Operation log"))
        toolbar.addStretch()
        toolbar.addWidget(self.button("Copy", lambda: QApplication.clipboard().setText(self.log.toPlainText())))
        toolbar.addWidget(self.button("Save log…", self.save_log))
        toolbar.addWidget(self.button("Clear view", lambda: self.log.clear()))
        log_layout.addLayout(toolbar)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(10000)
        self.log.setFont(QFont("monospace", 10))
        self.log.setMinimumHeight(110)
        log_layout.addWidget(self.log)
        splitter.addWidget(log_area)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([570, 180])
        outer.addWidget(splitter, 1)

        footer = QFrame()
        footer.setObjectName("footer")
        f = QHBoxLayout(footer)
        f.setContentsMargins(24, 12, 24, 12)
        self.status = QLabel(self.tr("Ready"))
        f.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(170)
        self.progress.setVisible(False)
        f.addWidget(self.progress)
        f.addStretch()
        self.cancel_button = self.button("Cancel task", self.cancel_task)
        self.cancel_button.setVisible(False)
        f.addWidget(self.cancel_button)
        self.back = self.button("Back", lambda: self.go(self.pages.currentIndex() - 1))
        self.next = self.button("Continue", self.on_next, primary=True)
        f.addWidget(self.back)
        f.addWidget(self.next)
        outer.addWidget(footer)
        self.setCentralWidget(root)

    def _intro_page(self):
        layout = self.page("Lumen reads your hardware, builds an OpenCore configuration, and prepares a macOS recovery USB. The recovery environment downloads macOS from Apple during installation.")
        layout.addWidget(self.label("Run the check on the PC that will run macOS. You can also import a report and ACPI tables from that PC. Hardware and driver compatibility depend on the target machine."))
        layout.addWidget(self.label("You will need", title=True))
        layout.addWidget(self.label("An erasable USB drive (4 GB or larger), an internet connection, and time to review the generated BIOS instructions."))
        layout.addWidget(self.label("Your files stay in the local workspace. Diagnostics are exported or sent only when you request it."))
        row = QHBoxLayout()
        row.addWidget(self.button("Check requirements", lambda: self.run_cli("check")))
        row.addWidget(self.button("OpenCore installation guide", lambda: QDesktopServices.openUrl(QUrl("https://dortania.github.io/OpenCore-Install-Guide/"))))
        row.addStretch()
        layout.addLayout(row)
        layout.addStretch()

    def _scan_page(self):
        layout = self.page("Read processor, board, graphics, displays, network, audio, storage and ACPI tables. Privileged reads may request authentication.")
        row = QHBoxLayout()
        self.scan_button = self.button("Scan hardware", self.scan, primary=True)
        row.addWidget(self.scan_button)
        row.addWidget(self.button("Import report + ACPI", self.import_report))
        row.addStretch()
        layout.addLayout(row)
        self.report_label = self.label("No hardware report selected")
        layout.addWidget(self.report_label)
        self.facts = QTableWidget(0, 2)
        self.facts.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.facts.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.facts.verticalHeader().setVisible(False)
        self.facts.horizontalHeader().setStretchLastSection(True)
        self.facts.setColumnWidth(0, 150)
        self.facts.setMinimumHeight(200)
        layout.addWidget(self.facts)
        self.scan_paths = QLabel()
        self.scan_paths.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.scan_paths.setWordWrap(True)
        layout.addWidget(self.scan_paths)

    def _build_page(self):
        layout = self.page("The selected report, ACPI tables, options and verified dependencies determine the EFI. Changing an option requires a new build.")
        row = QHBoxLayout()
        row.addWidget(self.label("Target macOS"))
        self.macos = QComboBox()
        self.macos.addItem("macOS 15 Sequoia", "24")
        self.macos.addItem("macOS 26 Tahoe", "25")
        self.macos.currentIndexChanged.connect(self.options_changed)
        row.addWidget(self.macos)
        row.addStretch()
        layout.addLayout(row)
        self.experimental = self.check("Include experimental drivers")
        self.experimental.setToolTip(self.tr("Experimental drivers may affect Wi-Fi, AMD RDNA 4 graphics, USB and power management. They are disabled by default."))
        self.persistent = self.check("Persistent NVRAM on AMD (experimental)")
        self.new_identity = self.check("Generate a new SMBIOS identity")
        for widget in (self.experimental, self.persistent, self.new_identity):
            widget.toggled.connect(self.options_changed)
            layout.addWidget(widget)
        row = QHBoxLayout()
        row.addWidget(self.button("Use previous boot logs", self.select_build_logs))
        self.build_logs_label = QLabel("0")
        row.addWidget(self.build_logs_label)
        row.addStretch()
        layout.addLayout(row)
        self.stopped = QLineEdit()
        self.stopped.setMaxLength(500)
        self.stopped.textChanged.connect(self.options_changed)
        layout.addWidget(self.stopped)
        row = QHBoxLayout()
        self.build_button = self.button("Build", self.build, primary=True)
        row.addWidget(self.build_button)
        row.addWidget(self.button("Open build folder", lambda: self.open_path(self.state.build_dir)))
        row.addStretch()
        layout.addLayout(row)
        self.build_summary = QLabel()
        self.build_summary.setWordWrap(True)
        self.build_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.build_summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.build_summary)
        layout.addStretch()

    def _guide_page(self):
        layout = self.page("Review this PC's BIOS instructions before writing the installer. Firmware menu names can vary by board revision.")
        row = QHBoxLayout()
        row.addWidget(self.button("Generate guide", self.generate_guide, primary=True))
        row.addWidget(self.button("Open guide in browser", self.open_guide))
        row.addWidget(self.button("Firmware prerequisites", self.prerequisite_guide))
        layout.addLayout(row)
        self.guide_summary = QPlainTextEdit()
        self.guide_summary.setReadOnly(True)
        self.guide_summary.setMinimumHeight(180)
        layout.addWidget(self.guide_summary)
        layout.addWidget(self.label("The full guide opens in your browser so its layout and interactive steps remain available."))
        self.reviewed = self.check("I have reviewed the BIOS instructions")
        self.reviewed.toggled.connect(self.update_navigation)
        layout.addWidget(self.reviewed)

    def _write_page(self):
        layout = self.page("The selected drive will be erased. The backend checks its identity and system-disk protection again immediately before writing.")
        layout.addWidget(self.label("USB drive", title=True))
        row = QHBoxLayout()
        self.devices = QComboBox()
        self.devices.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.devices.addItem(self.tr("Refresh to list USB drives"), None)
        row.addWidget(self.devices, 1)
        row.addWidget(self.button("Refresh devices", self.refresh_disks))
        layout.addLayout(row)
        row = QHBoxLayout()
        authorization = self.button("Authorize device check", lambda: self.refresh_disks(authorized=True))
        authorization.setToolTip(self.tr("Authorization can read the boot partition identity when Linux restricts firmware variables. It does not erase or format any device."))
        row.addWidget(authorization)
        row.addWidget(self.button("Unfinished USB sessions", self.sessions_dialog))
        row.addStretch()
        layout.addLayout(row)
        self.disk_detail = QLabel()
        self.disk_detail.setWordWrap(True)
        self.disk_detail.setTextFormat(Qt.TextFormat.PlainText)
        self.devices.currentIndexChanged.connect(self.selected_disk_changed)
        layout.addWidget(self.disk_detail)
        layout.addWidget(self.label("Local recovery folder (optional)"))
        row = QHBoxLayout()
        self.recovery = QLineEdit()
        row.addWidget(self.recovery, 1)
        row.addWidget(self.button("Browse…", self.select_recovery))
        layout.addLayout(row)
        self.allow_large = self.check("Allow a drive larger than 256 GiB")
        self.erase_os = self.check("Allow erasing existing OS partitions on the selected USB drive")
        layout.addWidget(self.allow_large)
        layout.addWidget(self.erase_os)
        layout.addWidget(self.label("These options never permit erasing the running system or its boot devices."))
        row = QHBoxLayout()
        self.write_button = self.button("Erase and create", self.write, primary=True)
        row.addWidget(self.write_button)
        row.addWidget(self.button("Export installer image", self.export_image))
        row.addStretch()
        layout.addLayout(row)
        layout.addStretch()

    def _done_page(self):
        layout = self.page("The write and verification completed. Restart the target PC, follow the BIOS guide, and choose the USB drive from its UEFI boot menu.")
        layout.addWidget(self.label("In OpenCore, select the macOS recovery installer. Once macOS is installed, open the supplied Mac companion app if your setup needs its NVIDIA driver."))
        layout.addWidget(self.label("Keep the OpenCore USB connected for startup until you deliberately set up another boot device."))
        row = QHBoxLayout()
        row.addWidget(self.button("Open guide in browser", self.open_guide))
        row.addWidget(self.button("Create another installer", self.another_installer))
        row.addStretch()
        layout.addLayout(row)
        self.done_detail = QLabel()
        self.done_detail.setWordWrap(True)
        layout.addWidget(self.done_detail)
        layout.addStretch()

    def _make_menu(self):
        self.menuBar().clear()
        tools = self.menuBar().addMenu(self.tr("Tools"))
        for title, slot in (
            ("Check requirements", lambda: self.run_cli("check")),
            ("Check / repair an EFI", self.doctor_dialog),
            ("Diagnose startup logs", self.diagnose_dialog),
            ("Scan USB for startup logs", self.find_logs),
            ("Update NVIDIA package", self.update_driver),
            ("Update Lumen", self.update_dialog),
            ("Export diagnostics", self.export_logs),
            ("Send a diagnostic archive", self.upload_logs),
            ("Export installer image", self.export_image),
            ("Unfinished USB sessions", self.sessions_dialog),
            ("Open workspace", lambda: self.open_path(self.paths["home"])),
            ("Credits and licenses", self.credits),
        ):
            action = QAction(self.tr(title), self)
            action.triggered.connect(slot)
            tools.addAction(action)

    def retranslate(self):
        self.setWindowTitle(f"{self.tr('Lumen Installer')} · {__version__}")
        self.lang.blockSignals(True)
        self.lang.setCurrentIndex(0 if self.language.startswith("zh") else 1)
        self.lang.blockSignals(False)
        for widget, text in self._labels:
            widget.setText(self.tr(text))
        for widget, text in self._buttons:
            widget.setText(self.tr(text))
        self.theme.setText(self.tr("Light" if self.dark else "Dark"))
        if self.devices.count() == 1 and self.devices.itemData(0) is None:
            self.devices.setItemText(0, self.tr("No eligible USB drives found" if getattr(self, "_disks_discovered", False) else "Refresh to list USB drives"))
        self.stopped.setPlaceholderText(self.tr("Last line visible when boot stopped (optional)"))
        self.facts.setHorizontalHeaderLabels([self.tr("Property"), self.tr("Observed value")])
        current = self.pages.currentIndex()
        self.navigation.blockSignals(True)
        self.navigation.clear()
        for i, name in enumerate(STEPS): self.navigation.addItem(f"{i + 1:02d}   {self.tr(name)}")
        self.navigation.setCurrentRow(current)
        self.navigation.blockSignals(False)
        self.heading.setText(self.tr(STEPS[max(0, current)]))
        if not self.worker: self.status.setText(self.tr("Ready"))
        self._make_menu()
        if self.state.report: self.load_facts()
        self.update_navigation()

    def restore_session(self):
        path = self.paths["home"] / "desktop-session.json"
        if not path.exists(): return
        try:
            restored = WizardState.load(path)
        except (OSError, ValueError, TypeError): return
        self.state = restored
        for widget in (self.macos, self.experimental, self.persistent, self.new_identity, self.stopped): widget.blockSignals(True)
        self.macos.setCurrentIndex(1 if restored.options["macos"] == "25" else 0)
        self.experimental.setChecked(bool(restored.options["experimental"]))
        self.persistent.setChecked(bool(restored.options["persistent_nvram"]))
        self.new_identity.setChecked(bool(restored.options["new_identity"]))
        self.stopped.setText(restored.options["stopped_at"])
        for widget in (self.macos, self.experimental, self.persistent, self.new_identity, self.stopped): widget.blockSignals(False)
        self.build_logs_label.setText(str(len(restored.options["boot_logs"])))
        self.load_facts()
        if restored.build_current(): self.build_summary.setText(self.tr("Build completed and bound to these inputs."))
        self.reviewed.setChecked(False)

    def save_session(self):
        try: self.state.save(self.paths["home"] / "desktop-session.json")
        except OSError as error: self.append_log(f"Session could not be saved: {error}\n")

    def change_language(self):
        self.language = self.lang.currentData()
        self.settings.setValue("language", self.language)
        self.retranslate()

    def toggle_theme(self):
        self.dark = not self.dark
        self.settings.setValue("dark", self.dark)
        self.apply_theme()
        self.theme.setText(self.tr("Light" if self.dark else "Dark"))

    def apply_theme(self):
        bg, panel, fg, muted, edge, input_bg = ("#10151f", "#17202d", "#e7eef8", "#94a6bd", "#2b3a50", "#0d1420") if self.dark else ("#f5f7fb", "#ffffff", "#1b2940", "#64748b", "#d8e1ec", "#ffffff")
        self.setStyleSheet(f"""
            QWidget {{ background: {bg}; color: {fg}; font-size: 13px; }}
            QMenuBar, QMenu {{ background: {panel}; }}
            QMenu::item:selected {{ background: #3869ad; color: white; }}
            QFrame#header, QFrame#footer {{ background: {panel}; border-bottom: 1px solid {edge}; }}
            QFrame#header QLabel, QFrame#footer QLabel {{ background: transparent; }}
            QLabel#brand {{ font-size: 23px; font-weight: 800; letter-spacing: 3px; color: #6aa9ef; }}
            QLabel#pageTitle {{ font-size: 26px; font-weight: 700; }}
            QLabel#sectionTitle {{ font-size: 17px; font-weight: 650; }}
            QListWidget#navigation {{ background: {panel}; border: 0; border-right: 1px solid {edge}; padding: 16px 10px; }}
            QListWidget#navigation::item {{ padding: 15px 9px; border-radius: 7px; color: {muted}; }}
            QListWidget#navigation::item:selected {{ background: #284c77; color: #f0f7ff; }}
            QPushButton {{ background: {panel}; border: 1px solid {edge}; padding: 8px 14px; border-radius: 6px; }}
            QPushButton:hover {{ border-color: #70a9e8; }}
            QPushButton:pressed {{ background: #284c77; color: white; }}
            QPushButton#primary {{ background: #397ac4; color: white; border-color: #397ac4; font-weight: 600; }}
            QPushButton#primary:hover {{ background: #488bd5; }}
            QPushButton:disabled, QCheckBox:disabled {{ color: {muted}; }}
            QLineEdit, QComboBox, QPlainTextEdit, QTableWidget {{ background: {input_bg}; border: 1px solid {edge}; border-radius: 5px; padding: 7px; selection-background-color: #3869ad; }}
            QComboBox::drop-down {{ border: 0; width: 24px; }}
            QHeaderView::section {{ background: {panel}; color: {muted}; border: 0; padding: 7px; }}
            QTableWidget {{ gridline-color: {edge}; }}
            QCheckBox {{ spacing: 9px; padding: 4px 0; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; }}
            QProgressBar {{ background: {input_bg}; border: 1px solid {edge}; border-radius: 4px; text-align: center; }}
            QProgressBar::chunk {{ background: #397ac4; }}
            QSplitter::handle {{ background: {edge}; height: 2px; }}
            QToolTip {{ background: {panel}; color: {fg}; border: 1px solid {edge}; padding: 6px; }}
        """)

    def _nav_changed(self, index):
        if index < 0: return
        if self.worker:
            self.navigation.blockSignals(True)
            self.navigation.setCurrentRow(self.pages.currentIndex())
            self.navigation.blockSignals(False)
            return
        allowed = index <= 1 or (index in (2, 3) and self.state.report) or (index == 4 and self.state.build_current()) or (index == 5 and self.state.written)
        if allowed: self.go(index)
        else:
            self.navigation.blockSignals(True)
            self.navigation.setCurrentRow(self.pages.currentIndex())
            self.navigation.blockSignals(False)

    def go(self, index):
        index = max(0, min(5, index))
        self.pages.setCurrentIndex(index)
        self.navigation.blockSignals(True)
        self.navigation.setCurrentRow(index)
        self.navigation.blockSignals(False)
        self.heading.setText(self.tr(STEPS[index]))
        self.update_navigation()

    def update_navigation(self, *_):
        if not hasattr(self, "next"): return
        page = self.pages.currentIndex()
        busy = self.worker is not None
        self.back.setEnabled(not busy and 0 < page < 5)
        enabled = page == 0 or (page == 1 and self.state.report is not None) or (page == 2 and self.state.built_fingerprint is not None) or (page == 3 and self.state.guide is not None and self.reviewed.isChecked()) or (page == 4 and self.state.written) or page == 5
        self.next.setEnabled(bool(enabled and not busy))
        self.next.setText(self.tr("Close" if page == 5 else "Continue"))
        self.scan_button.setEnabled(not busy)
        self.build_button.setEnabled(not busy and self.state.report is not None)
        self.write_button.setEnabled(not busy and bool(self.state.built_fingerprint))
        self.pages.setEnabled(not busy)
        self.menuBar().setEnabled(not busy)
        self.navigation.setEnabled(not busy)
        self.cancel_button.setVisible(busy)
        self.cancel_button.setEnabled(busy)
        self.lang.setEnabled(not busy)

    def on_next(self):
        page = self.pages.currentIndex()
        if page == 5: self.close(); return
        if page in (2, 3, 4) and not self.state.build_current():
            self.state.invalidate()
            self.update_navigation()
            self.error("Build is missing or changed", "Build the EFI again before writing. The selected input or output files no longer match the completed build.")
            return
        self.go(page + 1)
        if page == 2 and not self.state.guide: self.generate_guide()
        elif page == 3: self.refresh_disks()

    def append_log(self, text):
        cursor = self.log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self.log.setTextCursor(cursor)
        self.log.ensureCursorVisible()
        for line in text.splitlines():
            if line.startswith("PROGRESS "):
                pieces = line.split()
                try:
                    done, total = int(pieces[1]), int(pieces[2])
                    if total > 0:
                        self.progress.setRange(0, 1000)
                        self.progress.setValue(min(1000, int(1000 * done / total)))
                except (IndexError, ValueError): pass

    def run_cli(self, operation, callback=None, **values):
        if self.worker:
            self.error("A task is running", "Wait for the current task to finish before starting another.")
            return False
        command = cli_command(operation, **values)
        self.operation, self.operation_callback = operation, callback
        self.append_log(f"\n━━ {datetime.datetime.now().strftime('%H:%M:%S')} · {operation} ━━\n")
        env = os.environ.copy()
        env["A1401_LANG"] = self.language
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # The helper can take 240 s to complete its current operation and another
        # 240 s to clean up a prepared session. Allow both bounded operations.
        cleanup_timeout = 540 if operation in {"write", "sessions", "close-session", "disks", "scan"} else 30
        self.worker = CommandWorker(command, env, self, cleanup_timeout=cleanup_timeout)
        self.worker.output.connect(self.append_log)
        self.worker.completed.connect(self.task_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.status.setText(self.tr("Working…"))
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        self.update_navigation()
        self.worker.start()
        return True

    def task_finished(self, code, output, cancelled):
        operation, callback = self.operation, self.operation_callback
        parsed = json_result(output)
        inspection = operation == "doctor" and isinstance(parsed, dict) and "would_fix" in parsed and not parsed.get("error")
        self.worker = None
        self.operation = self.operation_callback = None
        self.progress.setVisible(False)
        self.status.setText(self.tr("Task cancelled" if cancelled else "Task completed" if code == 0 or inspection else "Task failed"))
        if operation == "write" and (cancelled or code): self.state.written = False
        if cancelled and operation == "write":
            self.append_log(self.tr("Task stopped. Use Unfinished USB sessions if the helper reported that cleanup is still required.") + "\n")
        try:
            from . import reports
            report = reports.save(operation, "cancelled" if cancelled else "ok" if code == 0 else "failed", output.splitlines(), None if code == 0 else f"exit {code}")
            self.append_log(f"\n{self.tr('Log saved locally')}: {report}\n")
        except Exception as error:
            self.append_log(f"\nCould not save local operation report: {error}\n")
        if callback and not cancelled:
            try: callback(code, output, parsed)
            except Exception as error:
                if operation == "write": self.state.written = False
                self.append_log(f"\n{type(error).__name__}: {error}\n")
                self.error("Error", str(error))
        self.update_navigation()
        self.save_session()
        if self.pending_close:
            self.pending_close = False
            QTimer.singleShot(0, self.close)
        elif code and not cancelled and not inspection:
            self.error("Task failed", "The operation did not finish successfully. Review the log below. No installer is marked ready.")

    def cancel_task(self):
        if not self.worker: return
        if self.operation == "write" and QMessageBox.question(self, self.tr("Cancel the write?"), self.tr("Interrupting a write leaves the USB incomplete. Cancel this operation?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.cancel_button.setEnabled(False)
        self.status.setText(self.tr("Cancel requested; waiting for safe cleanup…"))
        self.worker.cancel()

    def error(self, title, message):
        QMessageBox.warning(self, self.tr(title), self.tr(message))

    def scan(self):
        def complete(code, output, result):
            if code: return
            scan_dir = self.paths["scan"]
            if isinstance(result, dict) and result.get("scan"): scan_dir = Path(result["scan"])
            report, acpi = scan_dir / "Report.json", scan_dir / "ACPI"
            self.accept_report(report, acpi, imported=False)
        self.run_cli("scan", complete, out=self.paths["scan"])

    def import_report(self):
        report, _ = QFileDialog.getOpenFileName(self, self.tr("Select Report.json"), str(self.paths["home"]), "JSON (*.json)")
        if not report: return
        candidate = Path(report).parent / "ACPI"
        acpi = QFileDialog.getExistingDirectory(self, self.tr("Select ACPI directory"), str(candidate if candidate.is_dir() else Path(report).parent))
        if not acpi: return
        source = Path(report)
        tables = Path(acpi)
        # Normalize both separately selected inputs into one immutable import folder.
        # The shared backend consumes a Report.json plus ACPI sibling contract.
        try:
            from .gui_state import input_fingerprint
            fingerprint = input_fingerprint(source, tables, {})
            imported = self.paths["home"] / "imports" / fingerprint[:24]
            if not imported.exists():
                import tempfile, shutil
                imported.parent.mkdir(parents=True, exist_ok=True)
                temporary = Path(tempfile.mkdtemp(prefix=".import-", dir=imported.parent))
                try:
                    (temporary / "ACPI").mkdir()
                    shutil.copyfile(source, temporary / "Report.json")
                    for table in tables.rglob("*"):
                        if table.is_file() and table.suffix.lower() in (".aml", ".dat"):
                            if table.is_symlink(): raise ValueError("ACPI tables must be regular files")
                            target = temporary / "ACPI" / table.relative_to(tables)
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(table, target)
                    (temporary / "import-source.json").write_text(json.dumps({'kind':'imported_report','live_identity':'unverified', 'sha256':hashlib.sha256((temporary / 'Report.json').read_bytes()).hexdigest()}) + '\n')
                    temporary.rename(imported)
                finally: shutil.rmtree(temporary, ignore_errors=True)
            self.accept_report(imported / "Report.json", imported / "ACPI", imported=True)
        except (OSError, ValueError) as error:
            self.error("Invalid hardware report", str(error))

    def accept_report(self, report, acpi, *, imported):
        try:
            value = json.loads(report.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict): raise ValueError("Report is not a JSON object")
            from .gui_state import input_fingerprint
            input_fingerprint(report, acpi, {})
            self.state.select_report(report.resolve(), acpi.resolve(), imported=imported)
            self.reviewed.setChecked(False)
            self.build_summary.clear()
            self.guide_summary.clear()
            self.load_facts()
            self.update_navigation()
        except (OSError, ValueError) as error:
            self.error("Invalid hardware report", self.tr("The report must be a JSON object and ACPI must contain AML/DAT files.") + "\n\n" + str(error))

    def load_facts(self):
        try:
            value = json.loads(self.state.report.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError): return
        self.report_label.setText(self.tr("Imported report — describes the selected target, not a fresh scan of this PC." if self.state.imported else "Local scan"))
        self.scan_paths.setText(f"{self.tr('Report')}: {self.state.report}\n{self.tr('ACPI tables')}: {self.state.acpi}")
        unknown = self.tr("Unknown / unavailable")
        def name(section):
            data = value.get(section)
            if not isinstance(data, dict): return str(data or unknown)
            return str(data.get("Name") or data.get("Processor Name") or ", ".join(str(k) for k in data) or unknown)
        bios = value.get("BIOS") or {}
        facts = [("Board", name("Motherboard")), ("CPU", name("CPU")), ("Graphics", name("GPU")),
                 ("Firmware", str(bios.get("Firmware Type") or unknown)), ("Secure Boot", str(bios.get("Secure Boot") or unknown)),
                 ("Network", name("Network")), ("Storage", name("Storage Drives") if value.get("Storage Drives") else name("Storage Controllers"))]
        self.facts.setRowCount(len(facts))
        for row, (key, item) in enumerate(facts):
            self.facts.setItem(row, 0, QTableWidgetItem(self.tr(key)))
            self.facts.setItem(row, 1, QTableWidgetItem(item))
        self.facts.resizeRowsToContents()

    def options_changed(self, *_):
        if not hasattr(self, "stopped"): return
        values = {"macos": self.macos.currentData(), "experimental": self.experimental.isChecked(),
                  "persistent_nvram": self.persistent.isChecked(), "new_identity": self.new_identity.isChecked(),
                  "boot_logs": self.state.options.get("boot_logs", []), "stopped_at": self.stopped.text()}
        if values != self.state.options:
            self.state.options = values
            self.state.invalidate()
            self.build_summary.clear()
            self.reviewed.setChecked(False)
            self.update_navigation()

    def select_build_logs(self):
        files, _ = QFileDialog.getOpenFileNames(self, self.tr("Select startup logs"), str(self.paths["home"]), "Logs (*.txt *.log *.panic);;All files (*)")
        if files:
            self.state.options["boot_logs"] = files
            self.state.invalidate()
            self.build_logs_label.setText(str(len(files)))
            self.build_summary.clear()
            self.reviewed.setChecked(False)
            self.update_navigation()

    def build(self):
        try: fingerprint = self.state.current_fingerprint()
        except (OSError, ValueError) as error: self.error("Error", str(error)); return
        self.state.invalidate()
        self.reviewed.setChecked(False)
        def complete(code, output, result):
            if code or (isinstance(result, dict) and result.get("ok") is False): return
            self.state.record_build(fingerprint)
            summary = self.tr("Build completed and bound to these inputs.")
            if isinstance(result, dict):
                for key in ("macos_version", "smbios", "needs_oclp"):
                    if key in result: summary += f"\n{key}: {result[key]}"
                for note in result.get("notices", []) or []: summary += "\n" + str(note)
            self.build_summary.setText(summary)
        self.run_cli("build", complete, report=self.state.report, acpi=self.state.acpi, out=self.state.build_dir, **self.state.options)

    def generate_guide(self):
        if not self.state.build_current():
            self.error("Build is missing or changed", "Build the EFI again before writing. The selected input or output files no longer match the completed build.")
            return
        target = self.paths["home"] / "guide.html"
        def complete(code, output, result):
            path = Path(result.get("path", target)) if isinstance(result, dict) else target
            if code or not path.is_file(): return
            self.state.guide = path
            if isinstance(result, dict) and result.get("text"):
                self.guide_summary.setPlainText(result["text"])
                return
            self.guide_summary.setPlainText(self.tr("The full guide opens in your browser so its layout and interactive steps remain available."))
        self.run_cli("guide", complete, report=self.state.report, config=self.state.build_dir / "EFI/OC/config.plist", out=target, macos=self.state.options["macos"])

    def prerequisite_guide(self):
        if not self.state.report: return
        target = self.paths["home"] / "firmware.html"
        self.run_cli("guide", lambda code, *_: self.open_path(target) if code == 0 and target.is_file() else None,
                     report=self.state.report, out=target, prerequisites=True)

    def open_guide(self):
        if self.state.guide and self.state.guide.is_file(): self.open_path(self.state.guide)
        elif self.state.build_current(): self.generate_guide()

    def refresh_disks(self, _checked=False, *, authorized=False):
        def complete(code, output, result):
            if code: return
            records = result.get("disks", []) if isinstance(result, dict) else result
            if not isinstance(records, list): raise ValueError("Disk discovery returned no structured device list")
            self.disk_records = [d for d in records if isinstance(d, dict) and str(d.get("tran") or d.get("BusType") or "").lower() == "usb"]
            self._disks_discovered = True
            self.devices.clear()
            for record in self.disk_records:
                device = str(record.get("path") or record.get("device") or record.get("Path") or "")
                name = str(record.get("model") or record.get("name") or record.get("FriendlyName") or "USB")
                size = int(record.get("size") or record.get("Size") or 0)
                text = f"{device}  ·  {name}  ·  {size / (1 << 30):.1f} GiB"
                self.devices.addItem(text, record)
            if not self.disk_records: self.devices.addItem(self.tr("No eligible USB drives found"), None)
            self.selected_disk_changed()
        self.run_cli("disks", complete, authorized=authorized)

    def sessions_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Unfinished USB sessions"))
        dialog.resize(720, 300)
        layout = QVBoxLayout(dialog)
        layout.addWidget(self.label("This synchronizes and unmounts the unfinished installer. It does not resume the installation or erase another disk."))
        sessions = QComboBox()
        layout.addWidget(sessions)
        details = QLabel()
        details.setWordWrap(True)
        details.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(details)
        row = QHBoxLayout()
        close = self.button("Close selected session", lambda: None)
        close.setEnabled(False)
        def selected(*_):
            value = sessions.currentData()
            close.setEnabled(isinstance(value, dict) and isinstance(value.get("token"), str))
            details.setText(json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, dict) else "")
        sessions.currentIndexChanged.connect(selected)
        def refresh():
            def complete(code, output, result):
                if code or not isinstance(result, dict): return
                sessions.clear()
                for session in result.get("sessions", []):
                    if not isinstance(session, dict): continue
                    sessions.addItem(str(session.get("mountpoint", "")) + " · " + str(session.get("phase", "")), session)
                if sessions.count() == 0: sessions.addItem(self.tr("No unfinished USB sessions"), None)
                selected()
            self.run_cli("sessions", complete)
        def close_selected():
            value = sessions.currentData()
            if not isinstance(value, dict) or not value.get("token"): return
            if QMessageBox.question(dialog, self.tr("Close this unfinished USB session?"),
                                    self.tr("This synchronizes and unmounts the unfinished installer. It does not resume the installation or erase another disk.") + "\n\n" + str(value.get("mountpoint", "")),
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
            close.setEnabled(False)
            def complete(code, output, result):
                if code == 0: QTimer.singleShot(0, refresh)
                else: selected()
            self.run_cli("close-session", complete, token=value["token"])
        close.clicked.disconnect()
        close.clicked.connect(close_selected)
        row.addWidget(self.button("Refresh sessions", refresh, primary=True))
        row.addWidget(close)
        row.addWidget(self.button("Close", dialog.close))
        layout.addLayout(row)
        self._dialogs.append(dialog)
        dialog.show()
        refresh()

    def selected_disk_changed(self, *_):
        record = self.devices.currentData()
        if not isinstance(record, dict): self.disk_detail.clear(); return
        lines = []
        for key in ("serial", "wwn", "tran", "mountpoints", "protected", "reasons", "eligible"):
            if key in record: lines.append(f"{key}: {record[key]}")
        lines.append(self.tr("Full disk identity and size are rechecked by the privileged writer."))
        self.disk_detail.setText("\n".join(lines))

    def select_recovery(self):
        directory = QFileDialog.getExistingDirectory(self, self.tr("Select recovery folder"), self.recovery.text() or str(self.paths["recovery"]))
        if directory: self.recovery.setText(directory)

    def write(self):
        if not self.state.build_current():
            self.error("Build is missing or changed", "Build the EFI again before writing. The selected input or output files no longer match the completed build.")
            return
        if not self.reviewed.isChecked() or not self.state.guide:
            self.error("Error", "Review the BIOS guide first"); return
        record = self.devices.currentData()
        if not isinstance(record, dict): self.error("Error", "Choose a USB drive first"); return
        if record.get("reasons") or record.get("protected"):
            self.error("Error", "\n".join(map(str, record.get("reasons") or ["This disk is protected"])))
            return
        if record.get("requires_large_confirmation") and not self.allow_large.isChecked():
            self.error("Error", "Allow a drive larger than 256 GiB"); return
        if record.get("requires_os_confirmation") and not self.erase_os.isChecked():
            self.error("Error", "Allow erasing existing OS partitions on the selected USB drive"); return
        device = str(record.get("path") or record.get("device") or record.get("Path") or "")
        if not device.startswith("/dev/"): self.error("Error", "Choose a USB drive first"); return
        prompt = self.tr("Everything on this device will be deleted. Type ERASE to continue:") + "\n\n" + self.devices.currentText()
        answer, ok = QInputDialog.getText(self, self.tr("Confirm erase"), prompt)
        if not ok or answer != "ERASE": return
        self.state.written = False
        def complete(code, output, result):
            if code: return
            if not isinstance(result, dict) or result.get("verified") is not True or result.get("unmounted") is not True:
                raise ValueError("The USB writer did not confirm successful readback and unmount; the installer is not marked ready.")
            self.state.written = True
            self.done_detail.setText(f"{self.tr('Selected disk')}: {device}")
            self.go(5)
        self.run_cli("write", complete, device=device, build=self.state.build_dir, macos=self.state.options["macos"],
                     report=self.state.report, recovery_dir=self.recovery.text().strip(), identity=record,
                     allow_large=self.allow_large.isChecked(), erase_os=self.erase_os.isChecked())

    def export_image(self):
        if not self.state.build_current():
            self.error("Build is missing or changed", "Build the EFI again before writing. The selected input or output files no longer match the completed build.")
            return
        destination, _ = QFileDialog.getSaveFileName(self, self.tr("Select installer image destination"),
                                                    str(self.paths["home"] / "lumen-installer.img"), "Disk image (*.img)")
        if not destination: return
        def complete(code, output, result):
            if code: return
            if not isinstance(result, dict) or result.get("verified") is not True:
                raise ValueError("Image export returned no verification receipt.")
            self.status.setText(self.tr("Installer image exported"))
            self.append_log(self.tr("An image was exported; no physical USB drive was written.") + "\n")
        self.run_cli("export-image", complete, path=destination, scan=str(self.state.report.parent),
                     build=str(self.state.build_dir), macos=self.state.options["macos"],
                     recovery_dir=self.recovery.text().strip() or None)

    def another_installer(self):
        self.state.written = False
        self.go(4)
        self.refresh_disks()

    def doctor_dialog(self):
        folder = QFileDialog.getExistingDirectory(self, self.tr("Select EFI folder"), str(self.paths["home"]))
        if not folder: return
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Check / repair an EFI"))
        dialog.resize(620, 240)
        layout = QVBoxLayout(dialog)
        name = QLabel(folder)
        name.setWordWrap(True)
        layout.addWidget(name)
        layout.addWidget(self.label("Review the inspection output before applying fixes. A backup is created by the EFI doctor."))
        row = QHBoxLayout()
        apply = self.button("Apply repairs", lambda: None)
        apply.setEnabled(False)
        inspected = {"fingerprint": None}
        def digest():
            from p1401.efidoctor import find_oc
            import hashlib
            selected = find_oc(folder)
            if not selected: raise ValueError("No OpenCore config.plist found in the selected folder")
            path = Path(selected)
            return hashlib.sha256(path.read_bytes()).hexdigest()
        def inspect():
            try: before = digest()
            except Exception as error: self.error("Error", str(error)); return
            def complete(code, output, result):
                if code in (0, 1) and isinstance(result, dict) and digest() == before:
                    inspected["fingerprint"] = before
                    apply.setEnabled(True)
            self.run_cli("doctor", complete, root=folder, report=self.state.report,
                         boot_logs=self.state.options["boot_logs"], stopped_at=self.state.options["stopped_at"])
        def fix():
            try:
                if not inspected["fingerprint"] or digest() != inspected["fingerprint"]:
                    apply.setEnabled(False)
                    inspect()
                    return
            except Exception as error: self.error("Error", str(error)); return
            if QMessageBox.question(dialog, self.tr("Apply repairs"), self.tr("Apply the displayed fixes to this EFI?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                apply.setEnabled(False)
                self.run_cli("doctor", root=folder, report=self.state.report, fix=True,
                             boot_logs=self.state.options["boot_logs"], stopped_at=self.state.options["stopped_at"])
        apply.clicked.disconnect()
        apply.clicked.connect(fix)
        row.addWidget(self.button("Inspect EFI", inspect, primary=True))
        row.addWidget(apply)
        row.addWidget(self.button("Close", dialog.close))
        layout.addLayout(row)
        self._dialogs.append(dialog)
        dialog.show()
        inspect()

    def diagnose_dialog(self):
        files, _ = QFileDialog.getOpenFileNames(self, self.tr("Select startup logs"), str(self.paths["home"]), "Logs (*.txt *.log *.panic);;All files (*)")
        if not files: return
        stopped, ok = QInputDialog.getText(self, self.tr("Diagnose startup logs"), self.tr("Last line visible when boot stopped (optional)"))
        if not ok: return
        self.state.options["boot_logs"] = files
        self.state.options["stopped_at"] = stopped[:500]
        self.state.invalidate()
        self.build_logs_label.setText(str(len(files)))
        self.stopped.setText(stopped[:500])
        self.run_cli("diagnose", logs=files, report=self.state.report, stopped=stopped[:500])

    def find_logs(self):
        root = QFileDialog.getExistingDirectory(self, self.tr("Select USB mount directory"), "/run/media")
        if not root: return
        def complete(code, output, result):
            if code or not isinstance(result, dict): return
            files = result.get("files") or []
            if not files:
                self.error("Diagnose startup logs", "No startup logs found in the selected directory")
                return
            self.state.options["boot_logs"] = list(map(str, files))
            self.state.invalidate()
            self.reviewed.setChecked(False)
            self.build_logs_label.setText(str(len(files)))
            self.append_log(self.tr("Selected logs") + ":\n" + "\n".join(files) + "\n")
            QTimer.singleShot(0, lambda: self.run_cli("diagnose", logs=files, report=self.state.report, stopped=self.stopped.text()))
        self.run_cli("find-logs", complete, roots=[root])

    def update_driver(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Update NVIDIA driver"))
        layout = QVBoxLayout(dialog)
        layout.addWidget(self.label("Updated driver and Mac companion packages will be used for future installers."))
        row = QHBoxLayout()
        def download():
            dialog.close()
            self.run_cli("update-drivers", destinations=[])
        def existing_usb():
            directory = QFileDialog.getExistingDirectory(dialog, self.tr("Select USB mount directory"), "/run/media")
            if directory:
                dialog.close()
                self.run_cli("update-drivers", destinations=[directory])
        row.addWidget(self.button("Download for future installers", download, primary=True))
        row.addWidget(self.button("Also update an existing USB", existing_usb))
        row.addWidget(self.button("Close", dialog.close))
        layout.addLayout(row)
        self._dialogs.append(dialog)
        dialog.show()

    def update_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Update Lumen"))
        dialog.resize(680, 230)
        layout = QVBoxLayout(dialog)
        layout.addWidget(self.label("Use only a release channel you trust. Lumen verifies the declared package hash before staging an update."))
        source = QLineEdit(str(self.settings.value("update_source", "")))
        source.setPlaceholderText("https://…/releases.json")
        layout.addWidget(self.label("Update manifest URL"))
        layout.addWidget(source)
        def run(action):
            value = source.text().strip()
            self.settings.setValue("update_source", value)
            if action == "update":
                def checked(code, output, result):
                    if code or not isinstance(result, dict) or not result.get("available"): return
                    text = self.tr("Install this release on the next start?") + "\n\n" + str(result.get("version", "")) + "\n" + str(result.get("url", "")) + "\nSHA256: " + str(result.get("sha256", ""))
                    if QMessageBox.question(dialog, self.tr("Update Lumen"), text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                        QTimer.singleShot(0, lambda: self.run_cli("update", source=value,
                                                                expected_version=result.get("version"), expected_sha256=result.get("sha256")))
                self.run_cli("update-check", checked, source=value)
            else: self.run_cli(action, source=value)
        row = QHBoxLayout()
        row.addWidget(self.button("Check for updates", lambda: run("update-check")))
        row.addWidget(self.button("Download and stage update", lambda: run("update"), primary=True))
        row.addWidget(self.button("Close", dialog.close))
        layout.addLayout(row)
        row = QHBoxLayout()
        def local():
            archive, _ = QFileDialog.getOpenFileName(dialog, self.tr("Select a Lumen release archive"), str(self.paths["updates"]), "Gzip archive (*.tar.gz *.tgz)")
            if not archive: return
            digest, ok = QInputDialog.getText(dialog, self.tr("Expected SHA-256"), self.tr("Expected SHA-256"))
            if not ok: return
            if QMessageBox.question(dialog, self.tr("Update Lumen"), self.tr("Install this release on the next start?") + "\n\n" + archive + "\nSHA256: " + digest.strip(),
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self.run_cli("update", archive=archive, sha256=digest.strip().lower())
        def rollback():
            if QMessageBox.question(dialog, self.tr("Roll back the previous update"), self.tr("Switch to the previously installed release on next start?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self.run_cli("rollback")
        row.addWidget(self.button("Install local release archive", local))
        row.addWidget(self.button("Roll back the previous update", rollback))
        layout.addLayout(row)
        self._dialogs.append(dialog)
        dialog.show()

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save diagnostics archive"), str(self.paths["home"] / "lumen-diagnostics.zip"), "ZIP (*.zip)")
        if path:
            files = list(self.state.options.get("boot_logs", []))
            self.run_cli("export-logs", out=path, files=files)

    def upload_logs(self):
        archive, _ = QFileDialog.getOpenFileName(self, self.tr("Select a diagnostic archive"), str(self.paths["home"]), "ZIP (*.zip)")
        if not archive: return
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Send a diagnostic archive"))
        dialog.resize(640, 220)
        layout = QVBoxLayout(dialog)
        layout.addWidget(self.label("Review the exported ZIP before sending. The selected archive is sent to the endpoint below only after confirmation."))
        selected = QLabel(archive)
        selected.setWordWrap(True)
        layout.addWidget(selected)
        layout.addWidget(self.label("HTTPS report endpoint"))
        endpoint = QLineEdit(str(self.settings.value("report_endpoint", "")))
        endpoint.setPlaceholderText("https://…/reports")
        layout.addWidget(endpoint)
        row = QHBoxLayout()
        def send():
            value = endpoint.text().strip()
            if QMessageBox.question(dialog, self.tr("Send a diagnostic archive"), self.tr("Send this archive to the selected server?") + "\n\n" + archive + "\n" + value,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
            self.settings.setValue("report_endpoint", value)
            dialog.close()
            self.run_cli("upload-logs", path=archive, endpoint=value, confirmed=True)
        row.addWidget(self.button("Send a diagnostic archive", send, primary=True))
        row.addWidget(self.button("Close", dialog.close))
        layout.addLayout(row)
        self._dialogs.append(dialog)
        dialog.show()

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save operation log"), str(self.paths["home"] / "operation-log.txt"), "Text (*.txt)")
        if path:
            try:
                from .reports import clean
                Path(path).write_text(clean(self.log.toPlainText()), encoding="utf-8")
                self.status.setText(self.tr("Saved"))
            except OSError as error: self.error("Error", str(error))

    def credits(self):
        dialog = QMessageBox(self)
        dialog.setWindowTitle(self.tr("Credits and licenses"))
        dialog.setText(self.tr("Lumen is an independent Linux adaptation of 1401. Copyright notices and third-party licenses remain with their authors. NVIDIA driver packages and the Mac companion application are upstream components."))
        license_button = dialog.addButton(self.tr("Open license"), QMessageBox.ButtonRole.ActionRole)
        notices_button = dialog.addButton(self.tr("Open component notices"), QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Close)
        dialog.exec()
        if dialog.clickedButton() == license_button: self.open_path(ROOT / "LICENSE")
        elif dialog.clickedButton() == notices_button: self.open_path(ROOT / "NOTICE.md")

    def open_path(self, path):
        if path: QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).resolve())))

    def closeEvent(self, event):
        if self.worker:
            message = "Interrupting a write leaves the USB incomplete. Cancel the write and close?" if self.operation == "write" else "Cancel the running task and close?"
            if QMessageBox.question(self, self.tr("A task is running"), self.tr(message), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self.pending_close = True
                self.cancel_button.setEnabled(False)
                self.status.setText(self.tr("Cancel requested; waiting for safe cleanup…"))
                self.worker.cancel()
            event.ignore()
            return
        self.settings.setValue("geometry", self.saveGeometry())
        self.save_session()
        event.accept()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="lumen-gui")
    parser.add_argument("--language", choices=("en", "zh-CN"))
    parser.add_argument("--smoke-test", action="store_true", help="Construct all pages and quit without hardware or disk access")
    parser.add_argument("--screenshot", help="Save a screenshot during the smoke test")
    args = parser.parse_args(argv)
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName("Lumen")
    app.setOrganizationName("Lumen")
    app.setApplicationVersion(__version__)
    window = MainWindow()
    if args.language:
        window.language = args.language
        window.lang.blockSignals(True)
        window.lang.setCurrentIndex(0 if args.language == "zh-CN" else 1)
        window.lang.blockSignals(False)
        window.retranslate()
    if not args.smoke_test:
        saved = window.settings.value("geometry")
        if saved: window.restoreGeometry(saved)
    window.show()
    if args.smoke_test:
        def finish():
            if args.screenshot: window.grab().save(args.screenshot)
            app.quit()
        QTimer.singleShot(200, finish)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
