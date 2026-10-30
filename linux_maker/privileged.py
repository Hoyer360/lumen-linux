"""Installed, root-owned block-device helper. Fixed JSON actions, never a shell.

Run only through /usr/libexec/lumen-helper. This module deliberately refuses a
user-writable source checkout even when launched through sudo/pkexec.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import time

INSTALL_ROOT = Path('/usr/lib/lumen')
RUNTIME = Path('/run/lumen')
BLKGETSIZE64 = 0x80081272


class HelperError(RuntimeError):
    pass


def trusted_install():
    path = Path(__file__).absolute()
    if path != INSTALL_ROOT / 'linux_maker/privileged.py':
        raise HelperError('Install Lumen and its root-owned helper before writing USB devices.')
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise HelperError(f'Unsafe helper path: {entry} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}); requires root ownership, no group/other write permission, and no symbolic link.')
    package_root = INSTALL_ROOT / 'linux_maker'
    if package_root.is_symlink():
        raise HelperError('Privileged package directory cannot be a symbolic link.')
    for folder, dirs, files in os.walk(INSTALL_ROOT / 'linux_maker', followlinks=False):
        for name in dirs + files:
            item = Path(folder) / name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise HelperError(f'Unsafe helper module: {item} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}); requires root ownership, no group/other write permission, and no symbolic link.')


def caller_uid():
    if os.geteuid() != 0:
        raise HelperError('Administrative authorization is required.')
    value = os.environ.get('PKEXEC_UID') or os.environ.get('SUDO_UID')
    if not value or not value.isdecimal() or int(value) <= 0:
        raise HelperError('An authenticated, non-root desktop user is required.')
    uid = int(value)
    pwd.getpwuid(uid)
    return uid


def command(args, *, data=None, timeout=60, pass_fds=()):
    binary = shutil.which(args[0], path='/usr/sbin:/usr/bin:/sbin:/bin')
    if not binary:
        raise HelperError('Required system tool is missing: ' + args[0])
    result = subprocess.run([binary, *args[1:]], input=data, text=True, capture_output=True,
                            timeout=timeout, pass_fds=pass_fds,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise HelperError(args[0] + ': ' + (result.stderr or result.stdout).strip()[-1600:])
    return result.stdout


def runtime_root():
    for parent in RUNTIME.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise HelperError('Unsafe helper runtime parent directory.')
    RUNTIME.mkdir(mode=0o711, exist_ok=True)
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise HelperError('Unsafe helper runtime directory.')
    return RUNTIME


def _state_path(token):
    if not isinstance(token, str) or not re.fullmatch('[a-f0-9]{48}', token):
        raise HelperError('Invalid write session.')
    return runtime_root() / token / 'state.json'


def save_state(state):
    path = _state_path(state['token'])
    with open(path.with_suffix('.tmp'), 'w', encoding='utf-8', opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path.with_suffix('.tmp'), path)


def load_state(token, uid):
    path = _state_path(token)
    info = path.lstat()
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16384:
        raise HelperError('Unsafe write-session state.')
    value = json.loads(path.read_text())
    if value.get('mountpoint') != str(RUNTIME / token / 'media'):
        raise HelperError('Invalid saved mountpoint.')
    if value.get('uid') != uid or value.get('token') != token:
        raise HelperError('This write session belongs to a different user.')
    if value.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise HelperError('This write session belongs to a prior system boot.')
    return value


def check_device(identity, path=None):
    selected = path or identity['path']
    info = os.stat(selected, follow_symlinks=False)
    if not stat.S_ISBLK(info.st_mode):
        raise HelperError('Target is no longer a block device.')
    major_minor = f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
    expected = identity.get('major_minor')
    if path is None and major_minor != expected:
        raise HelperError('Target device identity changed.')
    if path is None:
        sysfs = Path('/sys/dev/block') / major_minor
        if str(sysfs.resolve()) != identity['sysfs_path'] or (sysfs / 'diskseq').read_text().strip() != identity['diskseq']:
            raise HelperError('Target was disconnected or replaced; write stopped.')
    return info


def _unmount_target(disk):
    mountpoints = set(disk.get('mountpoints') or [])
    for part in disk.get('partitions') or []:
        mountpoints.update(part.get('mountpoints') or [])
    for mount in sorted(mountpoints, key=len, reverse=True):
        if mount and mount != '[SWAP]':
            command(['umount', '--', mount])


def descriptor_matches(fd, path, expected_mm=None):
    have = os.fstat(fd)
    current = os.stat(path, follow_symlinks=False)
    if not stat.S_ISBLK(have.st_mode) or have.st_rdev != current.st_rdev:
        raise HelperError('Block device changed while it was being opened.')
    mm = f'{os.major(have.st_rdev)}:{os.minor(have.st_rdev)}'
    if expected_mm is not None and mm != expected_mm:
        raise HelperError('Opened block device has a different partition identity.')
    return mm


def validate_geometry_bytes(mbr, bpb, state):
    if len(mbr) != 512 or mbr[510:512] != b'\x55\xaa':
        raise HelperError('Written MBR boot signature is invalid.')
    entry = mbr[446:462]
    start, length = struct.unpack_from('<II', entry, 8)
    if entry[0] != 0x80 or entry[4] != 0x0c or (start, length) != (state['start'], state['length']):
        raise HelperError('Written MBR partition geometry differs from the intended installer layout.')
    if any(mbr[462:510]):
        raise HelperError('Unexpected extra MBR partition entries.')
    if bpb is not None:
        if len(bpb) != 512 or bpb[510:512] != b'\x55\xaa':
            raise HelperError('FAT32 boot signature is invalid.')
        sector = state['identity']['logical_sector']
        bytes_per_sector = struct.unpack_from('<H', bpb, 11)[0]
        sectors = struct.unpack_from('<I', bpb, 32)[0]
        hidden = struct.unpack_from('<I', bpb, 28)[0]
        reserved = struct.unpack_from('<H', bpb, 14)[0]
        fat_size = struct.unpack_from('<I', bpb, 36)[0]
        sectors_per_cluster = bpb[13]
        # mkfs.fat may round the usable extent down to track alignment (eight
        # sectors on the fixture). It may never overrun the partition.
        if bytes_per_sector != sector or not 0 <= length - sectors < 2048 or sectors <= 0 or hidden != start or not reserved or not fat_size or not sectors_per_cluster or sectors_per_cluster & (sectors_per_cluster - 1) or bpb[16] not in (1, 2) or bpb[82:90] != b'FAT32   ':
            raise HelperError('FAT32 geometry differs from the intended installer partition.')
        clusters = (sectors - reserved - bpb[16] * fat_size) // sectors_per_cluster
        root_cluster = struct.unpack_from('<I', bpb, 44)[0]
        if not 65525 <= clusters < 0x0ffffff5 or not 2 <= root_cluster < clusters + 2 or fat_size * sector < (clusters + 2) * 4:
            raise HelperError('FAT32 cluster geometry is invalid.')


def verify_geometry(state, *, formatted=True):
    """Verify the actual MBR, kernel partition extent and FAT32 BPB."""
    identity = state['identity']
    check_device(identity)
    partition = _partition(identity)
    if partition != state['partition']:
        raise HelperError('Installer partition path changed.')
    disk_fd = os.open(identity['path'], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    part_fd = os.open(partition, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        descriptor_matches(disk_fd, identity['path'], identity['major_minor'])
        mm = descriptor_matches(part_fd, partition, state.get('partition_major_minor'))
        mbr = os.pread(disk_fd, 512, 0)
        bpb = os.pread(part_fd, 512, 0) if formatted else None
        validate_geometry_bytes(mbr, bpb, state)
        sysfs = Path('/sys/dev/block') / mm
        sector = identity['logical_sector']
        if int((sysfs / 'start').read_text()) * 512 != state['start'] * sector or int((sysfs / 'size').read_text()) * 512 != state['length'] * sector:
            raise HelperError('Kernel partition extent differs from the written MBR.')
        check_device(identity)
        return mm
    finally:
        os.close(part_fd)
        os.close(disk_fd)


def _partition(identity):
    data = json.loads(command(['lsblk', '--json', '--paths', '--output', 'NAME,TYPE,MAJ:MIN,PKNAME', identity['path']]))
    children = data.get('blockdevices', [{}])[0].get('children') or []
    parts = [p for p in children if p.get('type') == 'part']
    if len(parts) != 1:
        raise HelperError('Expected exactly one newly created FAT32 partition.')
    path = parts[0]['name']
    if not path.startswith('/dev/') or not re.fullmatch(r'\d+:\d+', str(parts[0].get('maj:min'))):
        raise HelperError('Invalid partition identity.')
    check_device(identity, path)
    sysfs = (Path('/sys/dev/block') / parts[0]['maj:min']).resolve()
    if str(sysfs.parent) != identity['sysfs_path']:
        raise HelperError('New partition belongs to another device.')
    return path


def prepare(request, uid, disks):
    if request.get('confirm') != 'ERASE':
        raise HelperError('Explicit erase confirmation is required.')
    required = ('sfdisk', 'wipefs', 'mkfs.fat', 'mount', 'umount', 'blockdev', 'lsblk')
    for name in required:
        if not shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin'):
            raise HelperError('Required system tool is missing: ' + name)
    disk = disks.select_disk(request.get('device', ''), request.get('fingerprint', ''),
                             allow_large=request.get('allow_large') is True, erase_os=request.get('erase_os') is True)
    identity = disk['identity']
    runtime_root()
    for entry in RUNTIME.glob('*/state.json'):
        try:
            other = json.loads(entry.read_text())
            if other.get('identity', {}).get('major_minor') == identity['major_minor']:
                raise HelperError('This device already has an unfinished Lumen write session. Close that session first.')
        except (OSError, ValueError):
            continue
    check_device(identity)
    _unmount_target(disk)
    check_device(identity)
    # Unmount changes the selection fingerprint, so compare the pinned identity
    # while rerunning every system/swap/holder protection independently.
    fresh = [d for d in disks.list_disks() if d['identity'] == identity]
    if len(fresh) != 1 or fresh[0]['reasons']:
        raise HelperError('Device became protected or ambiguous after unmount: ' + '; '.join(fresh[0]['reasons'] if fresh else ['identity unavailable']))
    if any(p.get('mountpoints') for p in fresh[0]['partitions']) or fresh[0]['mountpoints']:
        raise HelperError('Device was automatically remounted; close programs using it and retry.')
    flags = os.O_RDWR | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(identity['path'], flags)
    session = None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        descriptor_matches(fd, identity['path'], identity['major_minor'])
        size = int.from_bytes(fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)), sys.byteorder)
        if size != identity['size']:
            raise HelperError('Device capacity changed before the erase.')
        sector = identity['logical_sector']
        start = (1 << 20) // sector
        length = min(size - 64 * (1 << 20), disks.PART_CAP) // sector
        if length <= 0 or start + length >= size // sector:
            raise HelperError('Invalid partition geometry.')
        # The inherited descriptor pins the kernel device through its erase.
        fdpath = f'/proc/self/fd/{fd}'
        check_device(identity)
        command(['wipefs', '--all', '--force', '--', fdpath], pass_fds=(fd,))
        script = f'label: dos\nunit: sectors\n\nstart={start}, size={length}, type=c, bootable\n'
        command(['sfdisk', '--no-reread', '--no-tell-kernel', '--wipe', 'always', '--wipe-partitions', 'always', fdpath], data=script, pass_fds=(fd,))
        os.fsync(fd)
        check_device(identity)
    finally:
        os.close(fd)
    # Our O_EXCL descriptor intentionally makes sfdisk's preliminary re-read
    # return EBUSY. Write only while it is held, close it, then ask the kernel
    # to publish the partition table explicitly.
    check_device(identity)
    command(['blockdev', '--rereadpt', identity['path']])
    # Udev may need time to publish the new partition; no fixed sleep is necessary
    # where udevadm is available. Re-identify every time before a destructive step.
    if shutil.which('udevadm', path='/usr/sbin:/usr/bin:/sbin:/bin'):
        command(['udevadm', 'settle', '--timeout=10'], timeout=15)
    for attempt in range(20):
        check_device(identity)
        try:
            partition = _partition(identity)
            break
        except HelperError:
            if attempt == 19:
                raise
            time.sleep(0.1)
    check_device(identity)
    partition_mm = f'{os.major(os.stat(partition, follow_symlinks=False).st_rdev)}:{os.minor(os.stat(partition, follow_symlinks=False).st_rdev)}'
    geometry = {'identity': identity, 'partition': partition, 'partition_major_minor': partition_mm, 'start': start, 'length': length}
    verify_geometry(geometry, formatted=False)
    partition_fd = os.open(partition, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        check_device(identity)
        descriptor_matches(partition_fd, partition, partition_mm)
        # mkfs.fat opens its target O_EXCL itself. Keep a pinned nonexclusive
        # descriptor; holding our own O_EXCL would make its open fail EBUSY.
        fcntl.flock(partition_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        command(['mkfs.fat', '-F', '32', '-S', str(sector), '-h', str(start), '-n', 'LUMEN', '--', f'/proc/self/fd/{partition_fd}'], timeout=120, pass_fds=(partition_fd,))
        os.fsync(partition_fd)
        check_device(identity)
    finally:
        os.close(partition_fd)
    verify_geometry(geometry)
    token = secrets.token_hex(24)
    session = RUNTIME / token
    session.mkdir(mode=0o711)
    root = session / 'media'
    root.mkdir(mode=0o700)
    state = {**geometry, 'token': token, 'uid': uid, 'mountpoint': str(root),
             'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'phase': 'prepared'}
    save_state(state)
    try:
        mount_installer(state)
        state['phase'] = 'mounted'
        save_state(state)
        return {'token': token, 'mountpoint': str(root), 'device': identity['path']}
    except BaseException:
        if not os.path.ismount(root):
            root.rmdir()
            _state_path(token).unlink(missing_ok=True)
            session.rmdir()
        raise


def mount_installer(state, *, readonly=False):
    identity, partition = state['identity'], state['partition']
    check_device(identity)
    if _partition(identity) != partition:
        raise HelperError('Installer partition changed before mount.')
    uid = state['uid']
    gid = pwd.getpwuid(uid).pw_gid
    options = f'uid={uid},gid={gid},fmask=0077,dmask=0077,nodev,nosuid,noexec'
    if readonly:
        options = 'ro,' + options
    fd = os.open(partition, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        descriptor_matches(fd, partition, state['partition_major_minor'])
        check_device(identity)
        command(['mount', '-t', 'vfat', '-o', options, '--', f'/proc/self/fd/{fd}', state['mountpoint']], pass_fds=(fd,))
        check_device(identity)
    finally:
        os.close(fd)


def remount_readonly(state):
    check_device(state['identity'])
    root = state['mountpoint']
    if not os.path.ismount(root):
        raise HelperError('The installer volume is no longer mounted.')
    command(['sync', '-f', root])
    command(['umount', '--', root])
    state['phase'] = 'unmounted'
    save_state(state)
    check_device(state['identity'])
    if _partition(state['identity']) != state['partition']:
        raise HelperError('Installer partition changed.')
    # Flush/invalidate buffers after unmount; refusal is fatal, never a cached-read pass.
    command(['blockdev', '--flushbufs', state['partition']])
    command(['blockdev', '--flushbufs', state['identity']['path']])
    verify_geometry(state)
    check_device(state['identity'])
    mount_installer(state, readonly=True)
    state['phase'] = 'readback'
    save_state(state)
    return {'token': state['token'], 'mountpoint': root, 'read_only': True, 'geometry_verified': True}


def close(state):
    root = Path(state['mountpoint'])
    if root != RUNTIME / state['token'] / 'media' or root.is_symlink():
        raise HelperError('Unsafe session mountpoint.')
    sync_error = None
    if os.path.ismount(root):
        try:
            command(['sync', '-f', str(root)])
        except HelperError as error:
            # A removed USB can fail sync, but cleanup must still attempt the
            # private mount's ordinary unmount (never lazy/force unmount).
            sync_error = str(error)
        command(['umount', '--', str(root)])
    # Removal is deliberately non-recursive: user payload must be on the volume,
    # and an unexpected directory below /run cannot be followed or deleted.
    root.rmdir()
    _state_path(state['token']).unlink()
    root.parent.rmdir()
    return {'closed': True, 'sync_warning': sync_error}


def dispatch(request, uid, disks):
    action = request.get('action')
    if action == 'acpi':
        from linux_maker import hardware
        return {'bundle': hardware.acpi_bundle()}
    if action == 'disks':
        return {'disks': disks.list_disks()}
    if action == 'prepare':
        return prepare(request, uid, disks)
    if action in {'readback', 'close'}:
        state = load_state(request.get('token'), uid)
        return remount_readonly(state) if action == 'readback' else close(state)
    if action == 'sessions':
        found = []
        for entry in runtime_root().glob('*/state.json'):
            try:
                state = load_state(entry.parent.name, uid)
                found.append({**{key: state[key] for key in ('token', 'mountpoint', 'phase')}, 'device': state['identity']['path']})
            except (OSError, ValueError, HelperError):
                continue
        return {'sessions': found}
    raise HelperError('Unknown helper action.')


def main():
    try:
        trusted_install()
        uid = caller_uid()
        # Only the already checked, root-owned installation participates in imports.
        sys.path.insert(0, str(INSTALL_ROOT))
        from linux_maker import disks
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise HelperError('Request exceeds the limit.')
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise HelperError('Request must be a JSON object.')
        # Once a fixed operation has begun, a dying UI cannot interrupt the
        # helper between erase/format/mount and its persisted session receipt.
        # Every subprocess still has its own bounded timeout.
        import signal
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        # Serialize inventory/revalidation and session mutation across clients.
        runtime_root()
        with open(RUNTIME / 'helper.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = dispatch(request, uid, disks)
        print(json.dumps({'ok': True, **result}))
        return 0
    except Exception as error:
        print(json.dumps({'ok': False, 'error': f'{type(error).__name__}: {error}'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
