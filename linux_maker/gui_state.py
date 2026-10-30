"""The wizard's state rules, independent of Qt and disk access."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import json
import os


def input_fingerprint(report: Path, acpi: Path, options: dict) -> str:
    """Bind a successful build to its exact hardware input and policy choices."""
    digest = hashlib.sha256()
    digest.update(report.read_bytes())
    digest.update(json.dumps(options, sort_keys=True, ensure_ascii=True).encode())
    if not acpi.is_dir():
        raise ValueError("Select an ACPI directory")
    tables = sorted(p for p in acpi.rglob("*") if p.is_file() and p.suffix.lower() in (".aml", ".dat"))
    if not tables:
        raise ValueError("The ACPI directory contains no AML/DAT tables")
    for path in tables:
        digest.update(str(path.relative_to(acpi)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def json_result(output: str):
    """Accept machine output, including a JSON document after progress lines."""
    decoder = json.JSONDecoder()
    candidates = []
    for index, line in enumerate(output.splitlines(keepends=True)):
        try:
            event = json.loads(line)
            if isinstance(event, dict) and event.get("event") == "result":
                if event.get("ok") is False:
                    data = event.get("data")
                    return {**(data if isinstance(data, dict) else {}), "ok": False, "error": event.get("error")}
                return event.get("data")
        except ValueError:
            pass
        if line.startswith("RESULT "):
            try:
                return json.loads(line[7:])
            except ValueError:
                pass
    for offset, char in enumerate(output):
        if char not in "[{":
            continue
        try:
            result, end = decoder.raw_decode(output, offset)
            if not output[end:].strip():
                candidates.append(result)
        except ValueError:
            continue
    return candidates[0] if candidates else None


@dataclass
class WizardState:
    report: Path | None = None
    acpi: Path | None = None
    imported: bool = False
    build_dir: Path | None = None
    options: dict = field(default_factory=lambda: {
        "macos": "24", "experimental": False, "persistent_nvram": False,
        "new_identity": False, "boot_logs": [], "stopped_at": "",
    })
    built_fingerprint: str | None = None
    built_files: dict[str, str] = field(default_factory=dict)
    guide: Path | None = None
    written: bool = False
    scan_boot_id: str | None = None

    def invalidate(self):
        self.built_fingerprint = None
        self.built_files = {}
        self.guide = None
        self.written = False

    def select_report(self, report: Path, acpi: Path, *, imported: bool):
        self.report, self.acpi, self.imported = report, acpi, imported
        self.scan_boot_id = None if imported else boot_id()
        self.invalidate()

    def current_fingerprint(self) -> str:
        if not self.report or not self.acpi:
            raise ValueError("Check this PC or import a hardware report first")
        options = dict(self.options)
        options["boot_log_hashes"] = {
            str(path): hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for path in self.options.get("boot_logs", [])
        }
        return input_fingerprint(self.report, self.acpi, options)

    def record_build(self, fingerprint: str):
        if not self.build_dir:
            raise ValueError("No build directory")
        required = ("EFI/BOOT/BOOTx64.efi", "EFI/OC/OpenCore.efi", "EFI/OC/config.plist")
        if any(not (self.build_dir / name).is_file() for name in required):
            raise ValueError("The build did not produce a complete EFI")
        if self.current_fingerprint() != fingerprint:
            raise ValueError("The hardware report or selected options changed during the build")
        self.built_files = {
            str(path.relative_to(self.build_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (self.build_dir / "EFI").rglob("*") if path.is_file()
        }
        self.built_fingerprint = fingerprint
        self.written = False

    def build_current(self) -> bool:
        try:
            if not self.imported and self.scan_boot_id and self.scan_boot_id != boot_id():
                return False
            if not self.built_fingerprint or self.built_fingerprint != self.current_fingerprint() or not self.build_dir:
                return False
            actual = {
                str(path.relative_to(self.build_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (self.build_dir / "EFI").rglob("*") if path.is_file()
            }
            return actual == self.built_files and bool(actual)
        except (OSError, ValueError):
            return False

    def save(self, path: Path):
        data = {
            "schema": "lumen-gui-session/1", "report": str(self.report) if self.report else None,
            "acpi": str(self.acpi) if self.acpi else None, "imported": self.imported,
            "build": str(self.build_dir) if self.build_dir else None, "options": self.options,
            "fingerprint": self.built_fingerprint, "files": self.built_files,
            "guide": str(self.guide) if self.guide else None, "scan_boot_id": self.scan_boot_id,
        }
        temporary = path.with_name(path.name + ".tmp")
        path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(data, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)

    @classmethod
    def load(cls, path: Path):
        """A receipt can restore a completed build only if every bound file still matches."""
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Invalid session file")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema") != "lumen-gui-session/1":
            raise ValueError("Invalid session schema")
        state = cls()
        for key, field_name in (("report", "report"), ("acpi", "acpi"), ("build", "build_dir"), ("guide", "guide")):
            value = data.get(key)
            if value is not None:
                if not isinstance(value, str) or len(value) > 8192 or not Path(value).is_absolute():
                    raise ValueError("Invalid session path")
                setattr(state, field_name, Path(value))
        options = data.get("options")
        if not isinstance(options, dict) or options.get("macos") not in ("24", "25"):
            raise ValueError("Invalid session policy")
        if not isinstance(options.get("boot_logs"), list) or len(options["boot_logs"]) > 100 or any(not isinstance(p, str) for p in options["boot_logs"]):
            raise ValueError("Invalid startup log list")
        if not isinstance(options.get("stopped_at"), str) or len(options["stopped_at"]) > 500:
            raise ValueError("Invalid stopped line")
        if any(type(options.get(key)) is not bool for key in ("experimental", "persistent_nvram", "new_identity")):
            raise ValueError("Invalid policy switches")
        state.options.update({key: options[key] for key in state.options if key in options})
        state.imported = data.get("imported") is True
        state.scan_boot_id = data.get("scan_boot_id")
        state.built_fingerprint = data.get("fingerprint")
        state.built_files = data.get("files") if isinstance(data.get("files"), dict) else {}
        if not state.report or not state.report.is_file() or not state.acpi or not state.acpi.is_dir():
            raise ValueError("Saved hardware inputs are no longer present")
        if not state.build_current(): state.invalidate()
        if state.guide and not state.guide.is_file(): state.guide = None
        return state


def boot_id():
    try: return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError: return None
