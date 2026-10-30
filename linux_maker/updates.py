"""Verified portable releases and explicit driver updates."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid
from .paths import directories, home, atomic_json
from . import __version__

MAX_PACKAGE = 1024 ** 3


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https': raise ValueError('Update redirects require HTTPS.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Updates require a valid HTTPS URL without credentials.')
    from p1401 import tls
    tls.install()
    return urllib.request.build_opener(SecureRedirect()).open(
        urllib.request.Request(url, headers={'User-Agent': 'Lumen/0.1'}), timeout=60)


def fetch(url, destination, expected=None):
    digest = hashlib.sha256()
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.part')
    try:
        with _open(url) as response, temporary.open('wb') as output:
            total = 0
            for block in iter(lambda: response.read(1024 * 1024), b''):
                total += len(block)
                if total > MAX_PACKAGE: raise ValueError('Downloaded package exceeds 1 GiB.')
                digest.update(block); output.write(block)
            output.flush(); os.fsync(output.fileno())
        if expected and digest.hexdigest() != expected: raise ValueError('Downloaded archive SHA256 mismatch.')
        temporary.replace(destination)
    finally: temporary.unlink(missing_ok=True)
    return digest.hexdigest()


def get(url):
    with _open(url) as response: data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024: raise ValueError('Update metadata is too large.')
    return data


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,6}\.\d{1,6}\.\d{1,6}', value):
        raise ValueError('Expected a semantic release version.')
    return tuple(map(int, value.split('.')))


def check(source=None):
    settings = home() / 'settings.json'
    config = json.loads(settings.read_text()) if settings.exists() else {}
    source = source or config.get('update_url')
    if not source:
        return {'configured': False, 'current': __version__, 'available': False,
                'message': 'No Linux release service has been published. You can install a verified local release archive.'}
    metadata = json.loads(get(source))
    if metadata.get('schema') != 'lumen-release/1' or metadata.get('platform') != 'linux-x86_64':
        raise ValueError('This is not a Lumen Linux x86_64 release.')
    version(metadata.get('version'))
    if not re.fullmatch('[0-9a-f]{64}', metadata.get('sha256', '')): raise ValueError('Release SHA256 is missing.')
    if urllib.parse.urlsplit(metadata.get('url', '')).scheme != 'https': raise ValueError('Invalid release URL.')
    return {**metadata, 'configured': True, 'current': __version__, 'available': version(metadata['version']) > version(__version__)}


def safe_name(name):
    if not isinstance(name,str): return False
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and all(p not in ('','..','.') for p in name.split('/')) and '\\' not in name


def verify_tree(root, expected_manifest=None):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): raise ValueError('Release directory must not be a link.')
    manifest_path = root / 'RELEASE-MANIFEST.json'
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Invalid package manifest.')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema') != 'lumen-package/1' or manifest.get('platform') != 'linux-x86_64':
        raise ValueError('Package schema or platform mismatch.')
    version(manifest.get('version'))
    if expected_manifest is not None and manifest != expected_manifest: raise ValueError('Installed package manifest changed.')
    files = manifest.get('files')
    if not isinstance(files, dict) or not all(p in files for p in ('linux_maker/__init__.py','linux_maker/__main__.py','lumen')):
        raise ValueError('Release entrypoints are missing.')
    observed = set()
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()): raise ValueError('Unsafe installed release file.')
        if path.is_file(): observed.add(path.relative_to(root).as_posix())
    if observed != set(files) | {'RELEASE-MANIFEST.json'}: raise ValueError('Unlisted release files.')
    for name, digest in files.items():
        if not safe_name(name) or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):
            raise ValueError('Invalid package file record.')
        with (root / name).open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest() != digest: raise ValueError('Package file hash mismatch: ' + name)
    tree = ast.parse((root / 'linux_maker/__init__.py').read_text())
    declared = [node.value.value for node in tree.body if isinstance(node,ast.Assign) and
                any(isinstance(t,ast.Name) and t.id=='__version__' for t in node.targets) and
                isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)]
    if declared != [manifest['version']]: raise ValueError('Package code version differs from manifest.')
    return manifest


def install_archive(archive, expected, expected_version=None):
    archive = Path(archive)
    if not re.fullmatch('[0-9a-f]{64}', expected or ''): raise ValueError('An expected SHA256 is required for local updates.')
    if archive.stat().st_size > MAX_PACKAGE: raise ValueError('Release archive exceeds 1 GiB.')
    with archive.open('rb') as stream: actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != expected: raise ValueError('Release archive hash mismatch.')
    releases = home() / 'releases'; releases.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.install-', dir=releases))
    try:
        with tarfile.open(archive, 'r:gz') as tar:
            members=[];names=set();total=0
            for member in tar:
                total += member.size
                if total > 2 * 1024 ** 3 or len(members) >= 12000: raise ValueError('Release exceeds extraction limits.')
                if not safe_name(member.name) or member.name in names or not (member.isfile() or member.isdir()):
                    raise ValueError('Release contains unsafe or duplicate entries.')
                names.add(member.name);members.append(member)
            tar.extractall(temporary, members=members, filter='data')
        manifest = verify_tree(temporary)
        release_version = manifest['version']
        if expected_version and release_version != expected_version: raise ValueError('Downloaded release version changed.')
        destination = releases / (release_version + '-' + expected[:12])
        if destination.exists() or destination.is_symlink(): verify_tree(destination, manifest)
        else: temporary.rename(destination)
        (destination / 'lumen').chmod(0o755)
        current = home() / 'current'
        previous = str(current.resolve()) if current.is_symlink() else None
        if previous != str(destination):
            if previous:
                old = Path(previous)
                if not old.is_relative_to(releases.resolve()): raise ValueError('Current release points outside the release directory.')
                old_manifest = verify_tree(old)
                atomic_json(home() / 'previous-release.json', {'path':previous,'manifest':old_manifest})
            else:
                atomic_json(home() / 'previous-release.json', {'baseline':True})
        pointer = home() / ('.current-' + uuid.uuid4().hex)
        pointer.symlink_to(destination, target_is_directory=True); pointer.replace(current)
        return {'version': release_version, 'path': str(destination), 'restart_required': True, 'previous': previous or 'original launcher'}
    finally: shutil.rmtree(temporary, ignore_errors=True)


def rollback():
    data = json.loads((home() / 'previous-release.json').read_text())
    if data.get('baseline'):
        (home() / 'current').unlink(missing_ok=True)
        return {'path':'original launcher','restart_required':True}
    target = Path(data['path']).absolute()
    if not target.is_relative_to((home() / 'releases').absolute()): raise ValueError('Previous release is outside the releases directory.')
    verify_tree(target, data.get('manifest'))
    pointer = home() / ('.rollback-' + uuid.uuid4().hex)
    pointer.symlink_to(target,target_is_directory=True);pointer.replace(home()/'current')
    return {'path':str(target),'restart_required':True}


def update_app(source=None, archive=None, sha256=None, expected_version=None, expected_sha256=None):
    if archive: return install_archive(archive,sha256,expected_version)
    info=check(source)
    if not info['configured'] or not info['available']:return info
    if not expected_version or not expected_sha256:
        raise ValueError('Check the release first and confirm its version and SHA256 before updating.')
    if info['version']!=expected_version or info['sha256']!=expected_sha256:
        raise ValueError('Release metadata changed after confirmation. Check and confirm the update again.')
    destination=directories()['updates']/('lumen-'+info['version']+'.tar.gz')
    fetch(info['url'],destination,info['sha256'])
    return install_archive(destination,info['sha256'],info['version'])


def update_driver(roots=()):
    from p1401 import nullmoth
    rel=nullmoth.latest_release(lambda u:json.loads(get(u)),lambda u:get(u).decode('utf-8'))
    driver, companion=rel.get('driver'),rel.get('mac')
    if not companion or not driver or nullmoth._PKG_RE.fullmatch(driver[0]).group(1)!=nullmoth._MAC_RE.fullmatch(companion[0]).group(1):
        raise ValueError('Driver and Mac companion release versions do not match.')
    destinations=[str(directories()['payload'])]
    destinations += [str(Path(p).expanduser().resolve()/'NullMoth') for p in roots]
    lines=nullmoth.update(destinations,rel,lambda url,path:fetch(url,path))
    atomic_json(directories()['payload']/'driver-release.json',rel)
    return {'release':rel,'output':lines,'destinations':destinations}
