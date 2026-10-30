"""Shared operations for the desktop and CLI. Each invocation owns one process."""
import contextlib
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import sys
import traceback
from .paths import ROOT, directories, atomic_json, prepare_engine, helper_status
from . import reports


class LineSink(io.TextIOBase):
    def __init__(self, callback, lines): self.callback, self.lines, self.pending = callback, lines, ''
    def write(self, text):
        self.pending += text
        while '\n' in self.pending:
            line, self.pending = self.pending.split('\n', 1)
            self.lines.append(line)
            if len(self.lines) > 10000: del self.lines[:1000]
            self.callback({'event': 'log', 'text': line})
        return len(text)
    def flush(self):
        if self.pending:
            self.lines.append(self.pending); self.callback({'event': 'log', 'text': self.pending}); self.pending = ''


def dependency_status():
    required = {'lspci': 'pciutils', 'lsusb': 'usbutils', 'lsblk': 'util-linux', 'findmnt': 'util-linux',
                'sfdisk': 'util-linux', 'mkfs.fat': 'dosfstools', 'mcopy': 'mtools', 'pkexec': 'polkit'}
    commands = {key: {'path': shutil.which(key), 'package': package} for key,package in required.items()}
    return {'platform': platform.platform(), 'architecture': platform.machine(), 'python': platform.python_version(),
            'commands': commands, 'missing': [key for key,value in commands.items() if not value['path']],
            'privileged_helper': Path('/usr/libexec/lumen-helper').is_file(), 'helper_status': helper_status(),
            'home': str(directories()['home']), 'project': str(ROOT)}


def _scan_path(request):
    selected = request.get('scan')
    if not selected:
        receipt = directories()['home'] / 'active-scan.json'
        if receipt.is_file(): selected = json.loads(receipt.read_text()).get('path')
    return Path(selected or directories()['scan']).expanduser().resolve()
def _build_path(request): return Path(request.get('build') or directories()['build']).expanduser().resolve()


def build(request):
    from p1401 import engine, scan, machine_handoff
    prepare_engine()
    scan_dir, output = _scan_path(request), _build_path(request)
    report = scan_dir / 'Report.json'
    issues = scan.check(str(scan_dir))
    if issues: raise RuntimeError('; '.join(issues))
    # Imported reports deliberately remain identified as saved observations by scan_evidence.
    policy = engine.Policy(macos=str(request.get('macos', '24')), boot_logs=request.get('boot_logs', []),
                           stopped_at=str(request.get('stopped_at', ''))[:500],
                           new_identity=bool(request.get('new_identity', False)),
                           experimental_drivers=bool(request.get('experimental', False)),
                           persistent_nvram_amd=bool(request.get('persistent_nvram', False)), boot_logo=False)
    result = engine.build(str(report), str(scan_dir / 'ACPI'), str(output), policy, echo=True,
                          download=not request.get('plan', False))
    data = dataclasses.asdict(result)
    atomic_json(output / 'build-result.json', data)
    if result.ok and not request.get('plan'):
        machine_handoff.verified(str(output), str(report))
        data['guide'] = guide({**request, 'scan': str(scan_dir), 'build': str(output)})['path']
    data.update({'build': str(output), 'scan': str(scan_dir)})
    return data


def guide(request):
    from p1401 import guide as renderer, machine_handoff
    from . import guides
    scan_dir, output = _scan_path(request), _build_path(request)
    report_path = scan_dir / 'Report.json'
    source = guides.provenance(report_path)
    if request.get('bios_only'):
        report, bound = renderer.load_prerequisite(str(report_path))
        steps = guides.build_prerequisite_guide(report, source=source)
        page = guides.render_html(report, steps, prerequisites=True)
    else:
        report, cfg = renderer.load(str(report_path), str(output / 'EFI/OC/config.plist'))
        profile = machine_handoff.verified(str(output), str(report_path))
        disabled = profile.get('disabled_devices', {})
        mac = renderer.macos_name(str(profile.get('macos_version', '')))
        if not mac:
            raise RuntimeError('The verified EFI has no recognized macOS target. Rebuild before generating its guide.')
        steps = guides.build_guide(report, cfg, macos=mac, disabled_devices=disabled, source=source)
        page = guides.render_html(report, steps, mac)
    target = directories()['home'] / ('firmware.html' if request.get('bios_only') else 'guide.html')
    target.write_text(page, encoding='utf-8')
    return {'ok': True, 'path': str(target), 'text': renderer.render_text(steps)}


def import_scan(request):
    from p1401 import scan
    source = Path(request['source']).expanduser().resolve()
    if source.is_file(): source = source.parent
    errors = scan.check(str(source))
    if errors: raise ValueError('Cannot import hardware report: ' + '; '.join(errors))
    import uuid
    target = directories()['home'] / 'imports' / uuid.uuid4().hex
    target.parent.mkdir(parents=True, exist_ok=True)
    if source != target:
        import tempfile
        temporary = Path(tempfile.mkdtemp(prefix='.scan-import-', dir=target.parent))
        try:
            shutil.copy2(source / 'Report.json', temporary / 'Report.json')
            shutil.copytree(source / 'ACPI', temporary / 'ACPI')
            if target.exists():
                backup = target.with_name('scan-previous')
                if backup.exists(): shutil.rmtree(backup)
                target.rename(backup)
            temporary.rename(target)
        finally: shutil.rmtree(temporary, ignore_errors=True)
    atomic_json(target / 'import-source.json', {'kind': 'imported_report', 'live_identity': 'unverified',
                                               'sha256': hashlib.sha256((target / 'Report.json').read_bytes()).hexdigest()})
    atomic_json(directories()['home'] / 'active-scan.json', {'path': str(target)})
    report = json.loads((target / 'Report.json').read_text(encoding='utf-8-sig'))
    return {'ok': True, 'scan': str(target), 'report': report, 'imported': True}


def stage_payload(request, emit):
    """Download and verify everything before authorizing an erase."""
    from p1401 import machine_handoff
    from . import writer
    build_dir = _build_path(request)
    profile = machine_handoff.verified(str(build_dir), str(_scan_path(request) / 'Report.json'))
    def progress(event):
        emit({'event': 'progress', **event, 'phase': event.get('message', '')})
    root = writer.prepare_payload(str(build_dir), darwin=int(request.get('macos', 24)),
                                  recovery_dir=request.get('recovery_dir') or str(directories()['recovery']),
                                  assets_dir=str(ROOT / 'assets'), progress=progress)
    manifest = writer.load_manifest(root)
    return {'ok': True, 'root': str(root), 'files': manifest['files'],
            'bytes': sum(record['size'] for record in manifest['files'].values()), 'profile': profile}


def dispatch(request, emit=lambda event: None):
    action = request.get('action')
    if action == 'status': return dependency_status()
    if action == 'import-scan': return import_scan(request)
    if action == 'scan':
        from p1401 import scan
        import uuid
        parent = Path(request.get('scan') or directories()['scan']).expanduser().resolve()
        target = parent / ('attempt-' + uuid.uuid4().hex)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            scan.scan(str(target))
        except Exception as error:
            raise RuntimeError(str(error) + '\nPartial scan evidence: ' + str(target)) from error
        atomic_json(directories()['home'] / 'active-scan.json', {'path': str(target)})
        return {'ok': True, 'scan': str(target), 'report': json.loads((target / 'Report.json').read_text())}
    if action in ('build','plan'): return build({**request, 'plan': action == 'plan'})
    if action == 'guide': return guide(request)
    if action == 'disks':
        from . import disks
        if request.get('authorized'):
            from .writer import authorized_disks
            return {'disks': authorized_disks()}
        return {'disks': disks.list_disks()}
    if action == 'sessions':
        from .writer import _helper
        return _helper({'action': 'sessions'})
    if action == 'close-session':
        from .writer import close_session
        return close_session(request['token'])
    if action == 'prepare': return stage_payload(request, emit)
    if action == 'write':
        from . import writer
        if not request.get('confirmed'): raise ValueError('Disk erasure requires explicit confirmation.')
        if not writer.HELPER.is_file(): raise RuntimeError('Install the Lumen privileged helper first: sudo python3 tools/install_linux.py')
        if not helper_status()['matches_app']:
            raise RuntimeError('The installed privileged helper differs from this app. Update it from this version: sudo python3 tools/install_linux.py')
        payload = stage_payload(request, emit)
        disk = request['disk']
        try:
            return writer.write_usb(disk['path'], disk['fingerprint'], payload['root'],
                                    allow_large=bool(request.get('allow_large')), erase_os=bool(request.get('erase_os')),
                                    progress=lambda event: emit({'event': 'progress', **event, 'phase': event.get('message', '')}))
        finally:
            shutil.rmtree(payload['root'], ignore_errors=True)
    if action == 'export-image':
        from . import writer
        payload = stage_payload(request, emit)
        try:
            return writer.export_image(payload['root'], request['path'],
                                       progress=lambda event: emit({'event': 'progress', **event, 'phase': event.get('message', '')}))
        finally:
            shutil.rmtree(payload['root'], ignore_errors=True)
    if action == 'efi-check':
        from p1401 import efidoctor
        prepare_engine()
        return efidoctor.check(request['path'], request.get('report'), request.get('boot_logs', []),
                               bool(request.get('fix')), str(request.get('stopped_at', ''))[:500])
    if action == 'diagnose':
        from p1401 import diagnose
        hw = json.loads(Path(request['report']).read_text()) if request.get('report') else None
        from p1401 import bootfix
        result = diagnose.diagnose(bootfix.read_logs(request.get('logs', [])), str(request.get('stopped_at', ''))[:500], hw)
        # Preserve upstream findings while making their instructions usable in
        # this Linux application and with its LUMEN-labelled recovery volume.
        def local_text(value):
            if isinstance(value, str):
                return value.replace('1401 on Windows', 'Lumen on Linux').replace('1401 entry', 'LUMEN entry').replace('entry named 1401', 'entry named LUMEN').replace('with 1401', 'with Lumen')
            if isinstance(value, list): return [local_text(item) for item in value]
            if isinstance(value, dict): return {key: local_text(item) for key, item in value.items()}
            return value
        return local_text(result)
    if action == 'find-logs':
        roots = request.get('roots', [])
        return {'files': list(map(str, reports.discover(roots))), 'local': list(map(str, directories()['logs'].glob('*.json')))}
    if action == 'export-logs': return {'path': reports.export(request['path'], request.get('files', []))}
    if action == 'upload-logs':
        if not request.get('confirmed'): raise ValueError('Explicit consent is required to upload reports.')
        return reports.upload(request['path'], request['endpoint'])
    if action == 'update-driver':
        from .updates import update_driver
        return update_driver(request.get('roots', []))
    if action == 'check-update':
        from .updates import check
        return check(request.get('source'))
    if action == 'update-app':
        from .updates import update_app
        return update_app(request.get('source'), request.get('archive'), request.get('sha256'),
                          request.get('expected_version'), request.get('expected_sha256'))
    if action == 'rollback':
        from .updates import rollback
        return rollback()
    raise ValueError('Unknown operation: ' + str(action))


@contextlib.contextmanager
def operation_lock(action):
    """Serialize operations that mutate a user's shared workspace."""
    if action in {'status', 'disks', 'find-logs', 'check-update', 'sessions', 'close-session'}:
        yield
        return
    import fcntl
    with (directories()['home'] / '.operation.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Another Lumen task is using this workspace. Wait for it to finish.') from None
        try: yield
        finally: fcntl.flock(lock, fcntl.LOCK_UN)


def run(request, emit):
    lines = []
    sink = LineSink(emit, lines)
    action = request.get('action', 'unknown')
    outcome, error = None, None
    try:
        with operation_lock(action), contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            outcome = dispatch(request, emit)
        sink.flush()
        ok = not isinstance(outcome, dict) or outcome.get('ok', True)
    except (Exception, KeyboardInterrupt) as exc:
        sink.flush()
        error = 'Task cancelled; the installer is incomplete.' if isinstance(exc, KeyboardInterrupt) else str(exc)
        lines.extend(traceback.format_exc().splitlines())
        ok = False
    log = None
    if action not in ('status', 'disks', 'find-logs'):
        try: log = str(reports.save(action, outcome, lines, error))
        except OSError as exc: emit({'event': 'log', 'text': 'Could not save local report: ' + str(exc)})
    event = {'event': 'result', 'ok': bool(ok), 'data': outcome, 'error': error, 'log': log}
    emit(event)
    return 0 if ok else 1
