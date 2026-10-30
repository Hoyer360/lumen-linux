"""Stage a verified installer, export a disk image, or write a confirmed USB.

All downloads and copies run as the desktop user. Only fixed partition/mount
operations cross the installed polkit helper boundary. No write occurs on import.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile

from .disks import DiskError, GIB, PART_CAP, list_disks, select_disk, tool

MANIFEST = '.lumen-payload.json'
HELPER = Path('/usr/libexec/lumen-helper')
MAC_PACKAGE = ('1401-Mac-2.6.4.zip', '1d75ff4b45afe01d0c0047139f42e8d0f5de2fd89cb37d6ce1ec62c8e9607062')
FAT_MAX_FILE = (1 << 32) - 1


def _event(progress, message, done=None, total=None):
    if progress:
        progress({'message': message, 'done': done, 'total': total})


def sha256(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise DiskError('Installer payload must be a real directory.')
    result = {}
    for folder, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            if (Path(folder) / name).is_symlink():
                raise DiskError('Installer payload contains a directory link.')
        for name in names:
            path = Path(folder) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise DiskError('Installer payload contains a link or special file: ' + relative)
            if info.st_size > FAT_MAX_FILE:
                raise DiskError('FAT32 cannot store this file (larger than 4 GiB): ' + relative)
            if relative == MANIFEST:
                continue
            result[relative] = {'sha256': sha256(path), 'size': info.st_size}
    return dict(sorted(result.items()))


def _safe_name(value):
    parts = value.split('/') if isinstance(value, str) else []
    return bool(parts) and all(part not in {'', '.', '..'} and '\\' not in part and ':' not in part and '\0' not in part for part in parts)


def load_manifest(payload):
    root = Path(payload)
    path = root / MANIFEST
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * (1 << 20):
        raise DiskError('Invalid installer payload manifest.')
    data = json.loads(path.read_text())
    if data.get('schema') != 1 or not isinstance(data.get('files'), dict) or not data['files']:
        raise DiskError('Unsupported installer payload manifest.')
    for name, record in data['files'].items():
        if not _safe_name(name) or not isinstance(record, dict) or not isinstance(record.get('size'), int) or record['size'] < 0:
            raise DiskError('Unsafe installer payload manifest entry.')
    if 'EFI/BOOT/BOOTx64.efi' not in data['files'] or 'EFI/OC/config.plist' not in data['files']:
        raise DiskError('Installer payload has no complete OpenCore configuration.')
    if 'com.apple.recovery.boot/BaseSystem.dmg' not in data['files']:
        raise DiskError('Installer payload has no Apple recovery image.')
    return data


def verify_payload(payload, root=None, *, progress=None):
    manifest = load_manifest(payload)
    root = Path(root or payload)
    expected = manifest['files']
    actual = inventory(root)
    if actual != expected:
        differences = sorted(key for key in set(actual) | set(expected) if actual.get(key) != expected.get(key))
        raise DiskError('Written installer differs from its verified payload: ' + ', '.join(differences[:8]))
    from p1401 import apple
    chunklist = root / 'com.apple.recovery.boot/BaseSystem.chunklist'
    image = root / 'com.apple.recovery.boot/BaseSystem.dmg'
    chunks = apple.parse_chunklist(chunklist.read_bytes())
    bad = apple.verify_written(str(image), chunks)
    if bad:
        raise DiskError('Recovery image failed its Apple chunklist check: ' + ', '.join(map(str, bad[:8])))
    _event(progress, 'Installer files and Apple recovery signature verified')
    return manifest


def prepare_payload(build_dir, darwin=24, recovery_dir=None, assets_dir=None, progress=None, release=None):
    from p1401 import apple, machine_handoff, netsupport, nullmoth, usbwriter
    build = Path(build_dir).resolve(strict=True)
    profile = machine_handoff.verified(str(build))
    if int(str(profile.get('macos_version', '')).split('.')[0]) != int(darwin):
        raise DiskError('The selected macOS version differs from this EFI build. Rebuild before writing.')
    assets = Path(assets_dir or Path(__file__).resolve().parents[1] / 'assets')
    # The user-selected verified driver update must apply to the next installer,
    # not only a stick that happened to be connected during Update driver.
    if release is None:
        from .paths import directories
        updated = directories()['payload']
        selected_manifest = updated / 'driver-release.json'
        if selected_manifest.exists():
            record = selected_manifest.lstat()
            if not stat.S_ISREG(record.st_mode) or record.st_size > 65536:
                raise DiskError('Selected driver release manifest is invalid.')
            release = json.loads(selected_manifest.read_text())
            assets = updated
    selected = None
    if release is not None:
        if not isinstance(release, dict):
            raise DiskError('Invalid selected driver release.')
        selected = {}
        versions = []
        for key, expression in (('driver', r'nullmoth-nvidia-(\d+\.\d+\.\d+)\.tar\.gz'), ('mac', r'1401-Mac-(\d+\.\d+\.\d+)\.zip')):
            item = release.get(key)
            if not isinstance(item, (list, tuple)) or len(item) != 3 or not all(isinstance(value, str) for value in item):
                raise DiskError('Selected release must include a matching driver and Mac companion.')
            name, url, expected = item
            match = re.fullmatch(expression, name)
            if not match or not re.fullmatch('[0-9a-f]{64}', expected):
                raise DiskError('Selected release filename or hash is invalid.')
            source = assets / name
            if source.is_symlink() or not source.is_file() or sha256(source) != expected:
                raise DiskError('Selected release package is missing or changed: ' + name)
            versions.append(match.group(1))
            selected[key] = (source, expected)
        if versions[0] != versions[1]:
            raise DiskError('Driver and Mac companion versions do not match.')
    info = apple.local_image(str(recovery_dir)) if recovery_dir else None
    if netsupport.needs_local_image(str(build)) and not info:
        raise DiskError('This EFI has no supported recovery network adapter; select a local recovery image first.')
    if info is None:
        _event(progress, 'Requesting the selected recovery image from Apple')
        info = apple.image_info(int(darwin))
    root = Path(tempfile.mkdtemp(prefix='lumen-payload-'))
    try:
        # The existing engine verifies signed chunks during either download or local copy.
        def transfer(done, total, *_):
            _event(progress, 'Preparing Apple recovery', done, total)
        got = (apple.copy_local if info.get('local') else apple.download)(info, str(root), transfer)
        # Apple has used both BaseSystem and RecoveryImage asset names. OpenCore
        # accepts the recovery pair; a stable name also makes payload validation
        # and exported media consistent regardless of the CDN basename.
        for key, filename in (('image', 'BaseSystem.dmg'), ('chunklist', 'BaseSystem.chunklist')):
            original = Path(got[key])
            wanted = root / 'com.apple.recovery.boot' / filename
            if original != wanted:
                original.rename(wanted)
        if machine_handoff.verified(str(build)) != profile:
            raise DiskError('The EFI changed while preparing recovery. Rebuild before writing.')
        # efi_hashes above rejects links; verify again after copying to catch changes.
        shutil.copytree(build / 'EFI', root / 'EFI')
        usbwriter.verify_efi_copy(str(build / 'EFI'), str(root / 'EFI'))
        machine_handoff.copy_to_installer(profile, str(root))
        destination = root / 'NullMoth'
        destination.mkdir(exist_ok=True)
        if usbwriter.needs_nullmoth(str(build)):
            if selected:
                source, expected = selected['driver']
                shutil.copyfile(source, destination / source.name)
                if sha256(destination / source.name) != expected:
                    raise DiskError('Selected driver changed while staging.')
            else:
                source = assets / nullmoth.PACKAGE['name']
                cache = root / '.driver-cache'
                cache.mkdir()
                if source.is_file() and sha256(source) == nullmoth.PACKAGE['sha256']:
                    shutil.copyfile(source, cache / source.name)
                nullmoth.stage(str(root), str(cache), fetch=usbwriter._fetch)
                shutil.rmtree(cache)
        # Companion is also useful for EFI and USB setup without NVIDIA graphics.
        companion, companion_hash = selected['mac'] if selected else (assets / MAC_PACKAGE[0], MAC_PACKAGE[1])
        if not companion.is_file() or sha256(companion) != companion_hash:
            raise DiskError('The pinned Mac companion package is missing or failed verification: ' + str(companion))
        shutil.copyfile(companion, destination / companion.name)
        if sha256(destination / companion.name) != companion_hash:
            raise DiskError('Mac companion changed while staging.')
        (root / 'LUMEN-README.txt').write_text('Lumen Linux installer, derived from 1401 2.6.4.\n'
            'Boot this USB through UEFI and choose macOS recovery. Recovery normally needs internet.\n'
            'After installation, the unmodified upstream Mac companion is in NullMoth/.\n'
            'Lumen is an independent project, not an official NullMoth release.\n')
        files = inventory(root)
        (root / MANIFEST).write_text(json.dumps({'schema': 1, 'macos': int(darwin), 'files': files}, indent=2) + '\n')
        verify_payload(root, progress=progress)
        return root
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


def copy_payload(payload, root, progress=None):
    manifest = load_manifest(payload)
    source, destination = Path(payload), Path(root)
    if source.resolve() == destination.resolve():
        raise DiskError('Payload and target must be different directories.')
    if not destination.is_dir() or destination.is_symlink():
        raise DiskError('Installer target is not a real mounted directory.')
    total = sum(r['size'] for r in manifest['files'].values())
    if shutil.disk_usage(destination).free < total + 32 * (1 << 20):
        raise DiskError('Installer volume has insufficient free space.')
    done = 0
    for relative, expected in manifest['files'].items():
        src, dst = source / relative, destination / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            raise DiskError('New installer volume unexpectedly contains: ' + relative)
        # O_NOFOLLOW blocks a source swap to a link; hashes catch modifications.
        handle = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
        digest = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(handle, 'rb') as inp, open(dst, 'xb') as out:
                if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
                    raise DiskError('Payload source changed into a special file.')
                while block := inp.read(1 << 20):
                    digest.update(block)
                    out.write(block)
                    copied += len(block)
                    done += len(block)
                    _event(progress, 'Writing ' + relative, done, total)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            dst.unlink(missing_ok=True)
            raise
        if copied != expected['size'] or digest.hexdigest() != expected['sha256']:
            raise DiskError('Payload changed during copy: ' + relative)
    with open(destination / MANIFEST, 'xb') as out:
        out.write((source / MANIFEST).read_bytes())
        out.flush()
        os.fsync(out.fileno())
    return manifest


def _helper(request):
    if not HELPER.is_file():
        raise DiskError('Install the Lumen system helper before writing USB devices. Image export works without it.')
    pkexec = tool('pkexec')
    # A cancellation must not kill a privileged partitioning process halfway
    # through a command and lose its session. Let that bounded request finish,
    # then close its mount and propagate cancellation to the worker.
    child = subprocess.Popen([pkexec, str(HELPER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    cancelled = None
    try:
        stdout, stderr = child.communicate(json.dumps(request), timeout=240)
    except KeyboardInterrupt as error:
        cancelled = error
        try:
            stdout, stderr = child.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                stdout, stderr = child.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill(); stdout, stderr = child.communicate()
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            stdout, stderr = child.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill(); stdout, stderr = child.communicate()
        raise DiskError('Administrative operation timed out. Use unfinished-session cleanup before retrying.') from None
    try:
        result = json.loads(stdout)
    except ValueError:
        raise DiskError('Administrative helper failed or authorization was canceled: ' + stderr.strip()[-800:]) from None
    if cancelled:
        if request.get('action') == 'prepare' and result.get('ok') and result.get('token'):
            _helper({'action': 'close', 'token': result['token']})
        raise cancelled
    if child.returncode or not result.get('ok'):
        raise DiskError(result.get('error') or 'Administrative operation failed.')
    return result


def authorized_disks():
    """Root observation can read BootCurrent on kernels that restrict EFI variables."""
    return _helper({'action': 'disks'})['disks']


def close_session(token):
    return _helper({'action': 'close', 'token': token})


def revalidate_selection(device, fingerprint, payload):
    """Merge root-only observations while preserving local source protection."""
    choices = list_disks(protected_paths=(str(payload),))
    selected = next((disk for disk in choices if disk['path'] == device), None)
    if selected is None:
        return choices
    needs_authorization = selected['fingerprint'] != fingerprint or any(
        'cannot identify the EFI partition' in reason for reason in selected['reasons'])
    if not needs_authorization:
        return choices
    elevated = next((disk for disk in authorized_disks() if disk['path'] == device), None)
    if elevated is None or elevated['identity'] != selected['identity']:
        return choices
    # Root blkid can fill missing filesystem/partition types without changing
    # the disk. Mount or partition extent changes are never treated this way.
    def layout(disk):
        keys = ('path', 'major_minor', 'size', 'type', 'mountpoints')
        return (disk['mountpoints'], [{key: part.get(key) for key in keys} for part in disk['partitions']])
    if layout(elevated) != layout(selected):
        return choices
    if elevated['fingerprint'] != fingerprint:
        raise DiskError('Administrative inspection found additional disk metadata. Refresh with Authorize device check and confirm the device again.')
    local_reasons = [reason for reason in selected['reasons'] if 'cannot identify the EFI partition' not in reason]
    merged = {**elevated, 'reasons': sorted(set(local_reasons + elevated['reasons']))}
    merged['eligible'] = not merged['reasons']
    merged['protected'] = bool(selected['protected'] or elevated['protected'])
    return [merged if disk['path'] == device else disk for disk in choices]


def write_usb(device, fingerprint, payload_dir, *, allow_large=False, erase_os=False, progress=None):
    payload = Path(payload_dir).resolve(strict=True)
    manifest = verify_payload(payload, progress=progress)
    choices = revalidate_selection(device, fingerprint, payload)
    disk = select_disk(device, fingerprint, allow_large=allow_large, erase_os=erase_os, inventory=choices)
    available = min(disk['size'] - 64 * (1 << 20), PART_CAP)
    needed = sum(r['size'] for r in manifest['files'].values())
    if needed + 64 * (1 << 20) > available:
        raise DiskError('The verified installer payload does not fit on this USB.')
    _event(progress, 'Requesting authorization to erase the selected USB')
    session = _helper({'action': 'prepare', 'device': device, 'fingerprint': fingerprint, 'confirm': 'ERASE',
                       'allow_large': bool(allow_large), 'erase_os': bool(erase_os)})
    token = session['token']
    try:
        copy_payload(payload, session['mountpoint'], progress=progress)
        _event(progress, 'Synchronizing the USB and reopening it read-only for verification')
        checked = _helper({'action': 'readback', 'token': token})
        if not checked.get('geometry_verified') or not checked.get('read_only'):
            raise DiskError('Helper did not verify the USB partition and FAT32 geometry.')
        verify_payload(payload, checked['mountpoint'], progress=progress)
    except BaseException:
        try:
            close_session(token)
        except Exception as cleanup:
            _event(progress, 'Session cleanup requires attention: ' + str(cleanup))
        raise
    closed = close_session(token)
    if closed.get('sync_warning'):
        raise DiskError('USB was unmounted, but final synchronization failed: ' + closed['sync_warning'])
    _event(progress, 'Installer verified and safely unmounted', 1, 1)
    return {'device': device, 'verified': True, 'unmounted': True, 'bytes': needed}


def partition_layout(size_bytes, sector_size=512):
    if sector_size != 512:
        raise DiskError('Portable image export currently uses 512-byte sectors.')
    if size_bytes < 4 * GIB or size_bytes > 2 * (1 << 40):
        raise DiskError('Image size must be between 4 GiB and 2 TiB.')
    start = (1 << 20) // sector_size
    length = min(size_bytes - 64 * (1 << 20), PART_CAP) // sector_size
    return start, length


def mbr(start, length):
    if not 0 < start <= 0xffffffff or not 0 < length <= 0xffffffff:
        raise DiskError('Partition exceeds MBR addressing.')
    block = bytearray(512)
    # LBA FAT32, active; saturated CHS avoids geometry assumptions on UEFI hosts.
    block[446:462] = struct.pack('<B3sB3sII', 0x80, b'\xfe\xff\xff', 0x0c, b'\xfe\xff\xff', start, length)
    block[510:512] = b'\x55\xaa'
    return bytes(block)


def _execute(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise DiskError(Path(args[0]).name + ': ' + (result.stderr or result.stdout).strip()[-1600:])
    return result.stdout


def export_image(payload_dir, output, *, size_bytes=None, progress=None):
    payload = Path(payload_dir).resolve(strict=True)
    manifest = verify_payload(payload, progress=progress)
    mkfs, mcopy = tool('mkfs.fat'), tool('mcopy')
    total = sum(r['size'] for r in manifest['files'].values())
    minimum = max(4 * GIB, ((total + 256 * (1 << 20) + GIB - 1) // GIB) * GIB)
    size = int(size_bytes or minimum)
    start, length = partition_layout(size)
    if total + 64 * (1 << 20) > length * 512:
        raise DiskError('Installer payload does not fit in the image FAT32 partition.')
    target = Path(output).absolute()
    if target.exists() or target.is_symlink():
        raise DiskError('Image output already exists; choose a new filename.')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.lumen-image-', dir=target.parent) as temporary:
        temp = Path(temporary)
        partition = temp / 'partition.img'
        _event(progress, 'Creating FAT32 installer image')
        _execute([mkfs, '-C', '-F', '32', '-n', 'LUMEN', str(partition), str(length // 2)])
        for item in sorted(payload.iterdir()):
            _execute([mcopy, '-s', '-i', str(partition), str(item), '::/'])
        # Verify files through mtools, not via an OS mount or privilege escalation.
        readback = temp / 'readback'
        readback.mkdir()
        _execute([mcopy, '-s', '-i', str(partition), '::*', str(readback)])
        verify_payload(payload, readback, progress=progress)
        # Create sparse full disk image; copying in blocks also supports filesystems
        # without SEEK_DATA/SEEK_HOLE. Zero blocks remain holes in the destination.
        completed = temp / 'completed.img'
        with open(completed, 'xb') as out, open(partition, 'rb') as inp:
            out.write(mbr(start, length))
            out.seek(start * 512)
            while block := inp.read(1 << 20):
                if block.count(0) == len(block):
                    out.seek(len(block), os.SEEK_CUR)
                else:
                    out.write(block)
            out.truncate(size)
            out.flush()
            os.fsync(out.fileno())
        # Atomic publication must not replace an existing output selected while
        # export was running. A hard link on this same filesystem is no-replace.
        os.link(completed, target)
        folder_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
    _event(progress, 'Installer disk image exported', 1, 1)
    return {'path': str(target), 'size': size, 'payload_bytes': total, 'verified': True}
