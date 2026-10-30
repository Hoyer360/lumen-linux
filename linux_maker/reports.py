"""Local, redacted diagnostic records. Upload is an explicit separate operation."""
import datetime
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import urllib.parse
import urllib.request
import uuid
import zipfile
from .paths import directories, atomic_json

SENSITIVE = re.compile(r'(serialnumber|systemuuid|\bmlb\b|\brom\b|mac.address|ip.address|password|passwd|secret|token|cookie|authorization)', re.I)


def clean(value):
    if isinstance(value, dict):
        return {str(k): '<redacted>' if SENSITIVE.search(str(k)) else clean(v) for k,v in value.items()}
    if isinstance(value, (list, tuple)): return [clean(v) for v in value]
    if not isinstance(value, str): return value
    value = value.replace(str(Path.home()), '<home>')
    for literal, replacement in ((socket.gethostname(), '<host>'), (getpass.getuser(), '<user>')):
        if literal: value = re.sub(r'(?<![\w])' + re.escape(literal) + r'(?![\w])', replacement, value)
    value = re.sub(r'(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+', r'\1 <redacted>', value)
    value = re.sub(r'(?i)(SystemSerialNumber|SystemUUID|MLB|ROM|SerialNumber|password|passwd|secret|token|cookie|authorization)([\s"\x27:=]+)(?:"[^"]*"|\x27[^\x27]*\x27|[^\s,;<]+)', r'\1\2<redacted>', value)
    value = re.sub(r'(?<![\w:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:])', '<mac>', value)
    def address(match):
        try: ipaddress.ip_address(match.group(0).split('%',1)[0]); return '<address>'
        except ValueError: return match.group(0)
    value = re.sub(r'(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[\w.-]+)?(?![\w:])', address, value)
    value = re.sub(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', address, value)
    return value


def save(action, outcome, lines, error=None):
    from . import __version__
    path = directories()['logs'] / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8] + '.json')
    atomic_json(path, clean({'schema': 'lumen-operation/1', 'version': __version__, 'action': action,
                            'result': outcome, 'error': error, 'output': lines[-10000:]}))
    return path


def discover(roots):
    found = []
    patterns = ('opencore-*.txt', 'panic-*.txt', 'ApplePanic*', '*.panic')
    for raw in roots:
        root = Path(raw).expanduser()
        if not root.is_dir(): continue
        for folder in (root, root / 'EFI/OC', root / 'NullMoth', root / 'NullMoth/sent-logs'):
            for pattern in patterns:
                for path in folder.glob(pattern):
                    if path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 * 1024 * 1024:
                        found.append(path.resolve())
    return sorted(set(found), key=lambda p: p.stat().st_mtime, reverse=True)[:100]


def export(destination, files=()):
    destination = Path(destination).expanduser().absolute()
    if destination.is_symlink(): raise ValueError('The export destination must not be a symbolic link.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = list(directories()['logs'].glob('*.json')) + [Path(p) for p in files]
    for path in records:
        if path.resolve() == destination.resolve() or (path.exists() and destination.exists() and os.path.samefile(path, destination)):
            raise ValueError('The export destination is an input report. Choose a different filename.')
    fd, temporary = tempfile.mkstemp(prefix='.diagnostics-', suffix='.zip', dir=destination.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('README.txt', 'Lumen diagnostic export. Hardware observations do not establish macOS compatibility.\n')
            total = 0
            for n, path in enumerate(records[:200]):
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024: continue
                data = path.read_text(encoding='utf-8', errors='replace')
                try: data = json.dumps(clean(json.loads(data)), ensure_ascii=False, indent=2)
                except ValueError: data = clean(data)
                data = data.encode('utf-8')
                total += len(data)
                if total > 32 * 1024 * 1024: raise ValueError('Selected reports exceed the 32 MiB export limit.')
                archive.writestr(f'report-{n:03d}.txt', data)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return str(destination)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Report uploads do not follow redirects. Configure the final HTTPS endpoint.')


def upload(bundle, endpoint):
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('A configured HTTPS report endpoint is required.')
    bundle = Path(bundle)
    if bundle.stat().st_size > 32 * 1024 * 1024: raise ValueError('Diagnostic bundle is larger than 32 MiB.')
    request = urllib.request.Request(endpoint, data=bundle.read_bytes(), method='POST',
                                     headers={'Content-Type': 'application/zip', 'User-Agent': 'Lumen/0.1'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        result = json.loads(response.read(1024 * 1024))
    if not isinstance(result, dict) or not result.get('report_id'):
        raise RuntimeError('The server did not return a report_id.')
    return result
