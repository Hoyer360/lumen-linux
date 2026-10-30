"""One writable workspace per user; engine sources stay in the installation."""
import hashlib
import json
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent


def helper_status():
    """An app update cannot silently keep using an obsolete privileged writer."""
    installed = Path('/usr/libexec/lumen-helper').is_file()
    result = {'installed': installed, 'matches_app': False, 'changed': []}
    if not installed:
        return result
    for name in ('__init__.py', 'disks.py', 'privileged.py', 'hardware.py'):
        deployed = Path('/usr/lib/lumen/linux_maker') / name
        try:
            if hashlib.sha256(deployed.read_bytes()).digest() != hashlib.sha256((ROOT / 'linux_maker' / name).read_bytes()).digest():
                result['changed'].append(name)
        except OSError:
            result['changed'].append(name)
    result['matches_app'] = not result['changed']
    return result


def home():
    override = os.environ.get('LUMEN_HOME')
    return Path(override).expanduser().resolve() if override else Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'lumen'


def cache():
    return Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache'))) / 'lumen'


def directories():
    base = home()
    values = {'home': base, 'scan': base / 'scan', 'build': base / 'build', 'logs': base / 'logs',
              'recovery': base / 'recovery', 'payload': base / 'payload', 'updates': base / 'updates', 'cache': cache()}
    for p in values.values():
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return values


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, default=str)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def prepare_engine():
    """Give legacy upstream tools their own writable, versioned source directory."""
    from p1401 import engine, validate
    source = ROOT / 'upstream/OpCore-Simplify'
    pins = json.loads((ROOT / 'LINUX-TOOLS.json').read_text())
    for name, record in pins.items():
        path = source / 'Scripts' / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise RuntimeError('Bundled Linux tool failed verification: ' + name)
    records = []
    for path in sorted(source.rglob('*')):
        if path.is_file() and not any(part in {'__pycache__', 'OCK_Files', 'Results'} for part in path.parts):
            records.append((str(path.relative_to(source)), hashlib.sha256(path.read_bytes()).hexdigest()))
    stamp = hashlib.sha256(json.dumps(records).encode()).hexdigest()[:16]
    parent = cache() / 'engines'
    target = parent / stamp
    if not target.exists():
        parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        temporary = Path(tempfile.mkdtemp(prefix='.engine-', dir=parent))
        try:
            shutil.copytree(source, temporary, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('__pycache__', 'OCK_Files', 'Results'))
            for name in ('iasl', 'iasl-stable', 'iasl-dev', 'macserial.linux'):
                tool = temporary / 'Scripts' / name
                if tool.is_file(): tool.chmod(0o755)
            try: temporary.rename(target)
            except FileExistsError: shutil.rmtree(temporary)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    engine.UPSTREAM = str(target)
    engine.OCK_CACHE = str(cache() / 'OCK_Files')
    validate.CACHE = str(cache() / 'downloads')
    return target
