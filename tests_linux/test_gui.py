"""State transitions must never enable writing a stale or changed EFI."""
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from linux_maker.gui_state import WizardState, input_fingerprint, json_result


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root / "Report.json"
        self.report.write_text('{"CPU":{"Name":"fixture"}}')
        self.acpi = self.root / "ACPI"
        self.acpi.mkdir()
        (self.acpi / "DSDT.aml").write_bytes(b"test ACPI")
        build = self.root / "build"
        for file in ("EFI/BOOT/BOOTx64.efi", "EFI/OC/OpenCore.efi", "EFI/OC/config.plist"):
            target = build / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"fixture")
        self.state = WizardState(build_dir=build)
        self.state.select_report(self.report, self.acpi, imported=True)

    def build(self):
        self.state.record_build(self.state.current_fingerprint())
        self.assertTrue(self.state.build_current())

    def test_changed_report_or_table_invalidates_build(self):
        self.build()
        self.report.write_text('{"CPU":{"Name":"another"}}')
        self.assertFalse(self.state.build_current())
        self.build()
        (self.acpi / "SSDT.aml").write_bytes(b"new table")
        self.assertFalse(self.state.build_current())

    def test_policy_and_output_changes_invalidate_build(self):
        self.build()
        self.state.options["macos"] = "25"
        self.assertFalse(self.state.build_current())
        self.build()
        (self.state.build_dir / "EFI/OC/OpenCore.efi").write_bytes(b"tampered")
        self.assertFalse(self.state.build_current())

    def test_no_success_without_boot_files(self):
        (self.state.build_dir / "EFI/BOOT/BOOTx64.efi").unlink()
        with self.assertRaises(ValueError): self.state.record_build(self.state.current_fingerprint())
        self.assertFalse(self.state.build_current())

    def test_mid_build_input_change_refuses_receipt(self):
        before = self.state.current_fingerprint()
        self.state.options["experimental"] = True
        with self.assertRaises(ValueError): self.state.record_build(before)

    def test_restore_rechecks_built_files_and_never_restores_written_state(self):
        self.build()
        self.state.written = True
        path = self.root / "session.json"
        self.state.save(path)
        restored = WizardState.load(path)
        self.assertTrue(restored.build_current())
        self.assertFalse(restored.written)
        (self.state.build_dir / "EFI/OC/config.plist").write_bytes(b"changed after session")
        restored = WizardState.load(path)
        self.assertFalse(restored.build_current())
        self.assertIsNone(restored.guide)

    def test_local_scan_receipt_cannot_survive_another_boot(self):
        self.build()
        self.state.imported = False
        self.state.scan_boot_id = "a different boot"
        self.assertFalse(self.state.build_current())

    def test_boot_log_content_change_invalidates_a_build(self):
        log = self.root / "opencore-boot.txt"
        log.write_text("original boot")
        self.state.options["boot_logs"] = [str(log)]
        self.build()
        log.write_text("a different boot")
        self.assertFalse(self.state.build_current())

    def test_json_after_progress(self):
        self.assertEqual(json_result('STEP scanning\n{\n"ok":true,\n"data":[1,2]\n}\n'), {"ok":True,"data":[1,2]})
        self.assertEqual(json_result('working\nRESULT {"ok": true}\n'), {"ok":True})
        self.assertEqual(json_result('{"event":"log","text":"hello"}\n{"event":"result","ok":true,"data":{"disks":[]}}\n'), {"disks":[]})
        self.assertIsNone(json_result('not json'))


try:
    import PySide6
except ImportError:
    PySide6 = None


@unittest.skipIf(PySide6 is None, "Qt desktop dependency is not installed")
class QtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_all_pages_construct_and_language_switch(self):
        from linux_maker.gui import MainWindow
        with tempfile.TemporaryDirectory() as folder:
            from unittest.mock import patch
            with patch.dict(os.environ, {"LUMEN_HOME":folder}):
                window = MainWindow()
                self.assertEqual(window.pages.count(), 6)
                self.assertFalse(window.state.written)
                self.assertFalse(window.build_button.isEnabled())
                self.assertFalse(window.write_button.isEnabled())
                window.language = "zh-CN"
                window.retranslate()
                self.assertEqual(window.heading.text(), "开始")
                window.close()

    def test_command_arguments_keep_paths_literal(self):
        from linux_maker.gui import cli_command
        path = '/tmp/a folder/$(echo should-not-run)/Report.json'
        cmd = cli_command("build", report=path, acpi="/tmp/ACPI", out="/tmp/build", macos="24")
        request = json.loads(cmd[-1])
        self.assertEqual(request["scan"], str(Path(path).parent))
        self.assertNotIn("shell", cmd)

    def test_authorized_inventory_and_session_contracts(self):
        from linux_maker.gui import cli_command
        inventory = json.loads(cli_command("disks", authorized=True)[-1])
        self.assertEqual(inventory, {"action":"disks", "authorized":True})
        self.assertEqual(json.loads(cli_command("sessions")[-1]), {"action":"sessions"})
        self.assertEqual(json.loads(cli_command("close-session", token="test-token")[-1]), {"action":"close-session", "token":"test-token"})

    def test_cancel_only_signals_worker_and_preserves_cleanup_budget(self):
        from linux_maker.gui import CommandWorker
        from unittest.mock import Mock, patch
        worker = CommandWorker(["unused"], {}, cleanup_timeout=540)
        process = Mock()
        process.poll.return_value = None
        worker._process = process
        class ImmediateThread:
            def __init__(self, target, daemon): self.target = target
            def start(self): self.target()
        with patch("linux_maker.gui.threading.Thread", ImmediateThread), patch("linux_maker.gui.os.killpg") as kill_group:
            worker.cancel()
            worker.cancel()  # repeated close requests must not interrupt cleanup again
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=540)
        kill_group.assert_not_called()

    def test_worker_cancellation_allows_finally_to_finish(self):
        from linux_maker.gui import CommandWorker
        from PySide6.QtCore import QEventLoop, QTimer
        import time
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "cleanup"
            source = '''import signal,time,pathlib
def interrupt(*args): raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, interrupt)
print("ready",flush=True)
try:
    while True: time.sleep(0.02)
except KeyboardInterrupt:
    time.sleep(0.1)
finally:
    pathlib.Path(__import__('sys').argv[1]).write_text('clean')
'''
            worker = CommandWorker([sys.executable, "-u", "-c", source, str(marker)], os.environ.copy(), cleanup_timeout=2)
            loop = QEventLoop()
            result = []
            worker.output.connect(lambda text: worker.cancel() if "ready" in text else None)
            worker.completed.connect(lambda *values: (result.append(values), loop.quit()))
            timer = QTimer(); timer.setSingleShot(True); timer.timeout.connect(loop.quit); timer.start(5000)
            worker.start(); loop.exec(); worker.wait(3000)
            if worker.isRunning(): worker.cancel(); worker.wait(3000)
            self.assertTrue(result)
            self.assertTrue(result[0][2])
            self.assertEqual(marker.read_text(), "clean")

    def test_write_success_requires_verification_and_unmount_receipt(self):
        from linux_maker.gui import MainWindow
        from unittest.mock import Mock, patch
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"LUMEN_HOME":folder}):
            window = MainWindow()
            window.state.build_dir = Path(folder)
            window.state.report = Path(folder) / "Report.json"
            window.state.guide = Path(folder) / "guide.html"
            window.state.build_current = Mock(return_value=True)
            window.reviewed.setChecked(True)
            disk = {"path":"/dev/fake", "fingerprint":"fingerprint", "reasons":[], "protected":False}
            window.devices.clear(); window.devices.addItem("fixture device", disk)
            callbacks = []
            window.run_cli = lambda action, callback=None, **values: callbacks.append(callback)
            with patch("linux_maker.gui.QInputDialog.getText", return_value=("ERASE", True)):
                window.write()
            self.assertEqual(len(callbacks), 1)
            with self.assertRaises(ValueError): callbacks[0](0, "", {"verified":True, "unmounted":False})
            self.assertFalse(window.state.written)
            callbacks[0](0, "", {"verified":True, "unmounted":True})
            self.assertTrue(window.state.written)
            self.assertEqual(window.pages.currentIndex(), 5)
            window.close()


if __name__ == "__main__":
    unittest.main()
