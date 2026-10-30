"""Linux guide instructions must not claim Windows-only actions happened."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linux_maker import guides, service
from p1401 import guide as upstream, loc, scan_evidence


REPORT = {"Motherboard":{"Name":"DELL fixture","Platform":"Desktop"}, "CPU":{"Manufacturer":"Intel","Processor Name":"Intel fixture"},
          "GPU":{"Intel UHD":{"Manufacturer":"Intel","Device Type":"Integrated GPU"}}, "BIOS":{"Firmware Type":"UEFI","Secure Boot":"Disabled"}}
CONFIG = {"Kernel":{"Quirks":{"AppleXcpmCfgLock":True,"DisableIoMapper":True}}}


class LinuxGuides(unittest.TestCase):
    def test_linux_steps_do_not_offer_windows_buttons_or_automatic_bitlocker(self):
        for language in ("en", "zh-CN"):
            with self.subTest(language=language), patch.object(loc, "_FORCED", language):
                text = upstream.render_text(guides.build_guide(REPORT, CONFIG))
                for forbidden in ("Then the app pauses BitLocker", "Click **Restart", "Windows is installed in Legacy", "bcdedit", "mbr2gpt", "应用会在接下来的几次重启中暂停 BitLocker", "Windows 重启后直接进入"):
                    self.assertNotIn(forbidden, text)
                self.assertIn("LUKS", text)
                self.assertIn("BitLocker", text)
                self.assertIn("If Windows is installed" if language == "en" else "如果目标电脑安装了 Windows", text)
                self.assertIn("Lumen does not suspend or resume BitLocker" if language == "en" else "Lumen 不会暂停或恢复 BitLocker", text)
                self.assertIn("desktop's normal power menu" if language == "en" else "桌面的正常电源菜单", text)

    def test_legacy_mode_does_not_infer_windows_installation(self):
        report = deepcopy(REPORT); report["BIOS"]["Firmware Type"] = "BIOS"
        with patch.object(loc, "_FORCED", "en"):
            text = upstream.render_text(guides.build_guide(report, CONFIG))
        self.assertIn("does not establish whether Windows is installed", text)
        self.assertNotIn("Windows is installed in Legacy", text)
        self.assertNotIn("mbr2gpt", text)

    def test_retains_exact_upstream_bios_rule_results_and_disabled_gpu_selection(self):
        for language in ("en", "zh-CN"):
            with patch.object(loc, "_FORCED", language):
                actual = [setting for step in guides.build_guide(REPORT, CONFIG, disabled_devices={}) for setting in step.settings]
                expected = upstream.bios_settings(REPORT, CONFIG, {})
                self.assertEqual(list(map(asdict, actual)), list(map(asdict, expected)))

    def test_storage_prerequisite_does_not_offer_generic_windows_migration(self):
        report = deepcopy(REPORT); report["Storage Controllers"] = {"Intel VMD RAID controller":{}}
        with patch.object(loc, "_FORCED", "en"):
            for steps in (guides.build_guide(report, CONFIG), guides.build_prerequisite_guide(report)):
                text = upstream.render_text(steps)
                self.assertIn("Their names do not prove which drive", text)
                self.assertIn("every installed operating system", text)
                self.assertNotIn("bcdedit", text)

    def test_import_receipt_takes_precedence_and_changed_bytes_lose_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Report.json"
            report = deepcopy(REPORT); report["Linux Scan"] = {"schema":"lumen-linux-scan/1","boot_id":"current"}
            path.write_text(json.dumps(report))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            (path.parent / "import-source.json").write_text(json.dumps({"kind":"imported_report","sha256":digest}))
            (path.parent / scan_evidence.RECEIPT).write_text(json.dumps({"schema":scan_evidence.SCHEMA,"report_sha256":digest,"scan_status":"complete","phase":"complete","run_id":"a"*32}))
            with patch("linux_maker.hardware.boot_identity", return_value={"boot_id":"current"}):
                self.assertEqual(guides.provenance(path), "imported")
                path.write_text(json.dumps({**report,"Changed":True}))
                self.assertEqual(guides.provenance(path), "saved")

    def test_current_local_provenance_needs_hash_and_boot_receipts(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Report.json"
            path.write_text(json.dumps({**REPORT,"Linux Scan":{"schema":"lumen-linux-scan/1","boot_id":"boot"}}))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            receipt = {"schema":scan_evidence.SCHEMA,"report_sha256":digest,"scan_status":"complete","phase":"complete","run_id":"a"*32}
            (path.parent / scan_evidence.RECEIPT).write_text(json.dumps(receipt))
            with patch("linux_maker.hardware.boot_identity", return_value={"boot_id":"boot"}): self.assertEqual(guides.provenance(path), "local")
            with patch("linux_maker.hardware.boot_identity", return_value={"boot_id":"next"}): self.assertEqual(guides.provenance(path), "saved")
            for change in ({"phase":"inventory"}, {"scan_status":"failed"}, {"run_id":""}):
                (path.parent / scan_evidence.RECEIPT).write_text(json.dumps({**receipt, **change}))
                with patch("linux_maker.hardware.boot_identity", return_value={"boot_id":"boot"}): self.assertEqual(guides.provenance(path), "saved")

    def test_html_independent_brand_translation_and_hostile_report_escaping(self):
        report = deepcopy(REPORT); report["Motherboard"]["Name"] = 'DELL <script>alert("x")</script>'
        for language in ("en", "zh-CN"):
            with patch.object(loc, "_FORCED", language):
                page = guides.render_html(report, guides.build_guide(report, CONFIG, source="imported"))
            self.assertIn('<html lang="' + language + '">', page)
            self.assertIn("<title>Lumen", page)
            self.assertNotIn("<title>1401", page)
            self.assertNotIn('<script>alert("x")', page)
            self.assertIn("&lt;script&gt;", page)
            self.assertNotIn('src="http', page)
            self.assertIn("Content-Security-Policy", page)
            self.assertIn("© 2026 NullMoth Systems", page)
            self.assertIn("explicitly imported" if language == "en" else "明确导入", page)

    def test_service_uses_linux_adapter_and_returns_same_steps_as_html(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"LUMEN_HOME":folder}), patch.object(loc, "_FORCED", "en"):
            scan = Path(folder) / "source"; scan.mkdir()
            (scan / "Report.json").write_text(json.dumps(REPORT))
            result = service.guide({"scan":str(scan),"bios_only":True})
            page = Path(result["path"]).read_text()
            self.assertIn("Lumen firmware prerequisites", page)
            self.assertIn("Lumen does not suspend or resume BitLocker", result["text"])
            self.assertNotIn("Protect Windows before changing storage", result["text"])

    def test_guide_uses_verified_efi_macos_instead_of_caller_default(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"LUMEN_HOME":folder}), patch.object(loc, "_FORCED", "en"):
            scan = Path(folder) / "source"; scan.mkdir()
            (scan / "Report.json").write_text(json.dumps(REPORT))
            with patch("p1401.guide.load", return_value=(REPORT, CONFIG)), patch("p1401.machine_handoff.verified", return_value={"macos_version":"25.99.99", "disabled_devices":{}}):
                result = service.guide({"scan":str(scan),"macos":"24"})
            self.assertIn("macOS Tahoe 26", result["text"])
            self.assertNotIn("macOS Sequoia 15", result["text"])
            with patch("p1401.guide.load", return_value=(REPORT, CONFIG)), patch("p1401.machine_handoff.verified", return_value={}):
                with self.assertRaisesRegex(RuntimeError, "macOS target"):
                    service.guide({"scan":str(scan),"macos":"24"})


if __name__ == "__main__": unittest.main()
