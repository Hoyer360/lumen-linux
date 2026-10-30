"""Linux block-device inventory and fail-closed installer-target checks.

Discovery never writes a block device. The privileged helper repeats these checks
immediately before opening a target; a /dev name by itself is never an identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

GIB = 1 << 30
MIN_DISK = 4 * GIB
MAX_DISK = 256 * GIB
PART_CAP = 16 * GIB
EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
OS_TYPES = {
    "7c3457ef-0000-11aa-aa11-00306543ecac", "48465300-0000-11aa-aa11-00306543ecac",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac", "0fc63daf-8483-4772-8e79-3d69d8477de4",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "e6d6d379-f507-44c2-a23c-238f2a3df928",
    "a19d880f-05fc-4d3b-a006-743f0f84911e", "83", "82", "8e", "fd", "af", "a5", "a6",
}
OS_FILESYSTEMS = {"apfs", "hfs", "hfsplus", "ntfs", "ntfs3", "ext2", "ext3", "ext4", "xfs",
                  "btrfs", "zfs_member", "crypto_luks", "lvm2_member", "linux_raid_member", "swap", "f2fs", "bcachefs"}


class DiskError(RuntimeError):
    pass


def run(command, *, timeout=15, input=None):
    """No shell expansion, inherited stdin, or interactive password prompt."""
    process = subprocess.run(command, input=input, stdin=subprocess.DEVNULL if input is None else None,
                             capture_output=True, text=True, timeout=timeout, env={**os.environ, "LC_ALL": "C"})
    if process.returncode:
        raise DiskError(f"{Path(command[0]).name}: {(process.stderr or process.stdout).strip()[-1200:]}")
    return process.stdout


def tool(name):
    path = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not path:
        raise DiskError(f"Required system tool is missing: {name}")
    return path


def _text(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return ""


def _bool(value):
    return value is True or value == 1 or str(value).lower() in {"true", "1"}


def _flatten(rows):
    for row in rows:
        yield row
        yield from _flatten(row.get("children") or [])


def _system_mount(target):
    if not target:
        return False
    # External automounts are candidates; /mnt/wsl and live boot mounts remain protected.
    if target.startswith(("/media/", "/run/media/")):
        return False
    if target.startswith("/mnt/") and not target.startswith(("/mnt/wsl", "/mnt/live")):
        return False
    return True


def _boot_partuuid(efivars=Path("/sys/firmware/efi/efivars")):
    """Return the GPT partition in the current EFI load option, when available."""
    guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    try:
        current = (efivars / f"BootCurrent-{guid}").read_bytes()
        number = int.from_bytes(current[4:6], "little")
        option = (efivars / f"Boot{number:04X}-{guid}").read_bytes()[4:]
        length = int.from_bytes(option[4:6], "little")
        off = 6
        while off + 2 <= len(option) and option[off:off + 2] != b"\0\0":
            off += 2
        off += 2
        end = min(len(option), off + length)
        while off + 4 <= end:
            size = int.from_bytes(option[off + 2:off + 4], "little")
            if size < 4 or off + size > end:
                break
            node = option[off:off + size]
            if node[0:2] == b"\x04\x01" and size >= 42 and node[41] == 2:
                return str(uuid.UUID(bytes_le=node[24:40]))
            off += size
    except (OSError, ValueError):
        pass
    return None


def _identity(node):
    return {key: node.get(key) for key in ("path", "major_minor", "size", "model", "serial", "wwn", "sysfs_path", "diskseq", "logical_sector")}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_inventory(blocks, mounts, *, sysfs=Path("/sys"), swaps=(), protected_devices=(),
                    boot_partuuid=None, boot_unknown=False, protected_paths=(), topology_failure=None):
    """Pure lsblk/findmnt graph parser, apart from optional sysfs evidence.

    Pass sysfs=None for fixture tests. Unknown root backing fails every write.
    """
    nodes, parents, children = {}, {}, {}
    by_path = {}
    for row in _flatten(blocks.get("blockdevices") or []):
        key = str(row.get("maj:min") or "")
        if not re.fullmatch(r"\d+:\d+", key):
            continue
        path = str(row.get("name") or "")
        if not path.startswith("/dev/"):
            path = "/dev/" + path
        node = nodes.setdefault(key, {"path": path, "major_minor": key, "mountpoints": []})
        for name in ("type", "tran", "model", "serial", "wwn", "fstype", "parttype", "partuuid", "pkname"):
            node[name] = str(row.get(name) or "").strip()
        node['metadata_error'] = row.get('_metadata_error')
        node.update(size=int(row.get("size") or 0), read_only=_bool(row.get("ro")),
                    removable=_bool(row.get("rm")), logical_sector=int(row.get("log-sec") or 512))
        for mount in row.get("mountpoints") or []:
            if mount and mount not in node["mountpoints"]:
                node["mountpoints"].append(mount)
        by_path[path] = key
        parents.setdefault(key, set())
        children.setdefault(key, set())
    def edge(child, parent):
        if child in nodes and parent in nodes and child != parent:
            parents[child].add(parent)
            children[parent].add(child)
    def row_edges(rows, parent=None):
        for row in rows:
            key = str(row.get("maj:min") or "")
            if parent:
                edge(key, parent)
            row_edges(row.get("children") or [], key)
    row_edges(blocks.get("blockdevices") or [])
    for key, node in nodes.items():
        pk = node["pkname"]
        edge(key, by_path.get(pk if pk.startswith("/dev/") else "/dev/" + pk))
        node["sysfs_path"], node["diskseq"] = "", ""
        if sysfs is not None:
            entry = Path(sysfs) / "dev/block" / key
            try:
                resolved = entry.resolve(strict=True)
                node["sysfs_path"] = str(resolved)
                node["diskseq"] = _text(resolved / "diskseq")
                if any(re.fullmatch(r"usb\d+", part) for part in resolved.parts):
                    node["tran"] = "usb"
                for slave in (resolved / "slaves").glob("*"):
                    edge(key, _text(slave / "dev"))
            except OSError:
                pass
    def ancestors(key):
        found, todo = set(), [key]
        while todo:
            current = todo.pop()
            if current in found:
                continue
            found.add(current)
            todo.extend(parents.get(current, ()))
        return found
    def descendants(key):
        found, todo = set(), [key]
        while todo:
            current = todo.pop()
            if current in found:
                continue
            found.add(current)
            todo.extend(children.get(current, ()))
        return found
    protected = set()
    reasons = {}
    def protect(key, why):
        for parent in ancestors(key):
            protected.add(parent)
            reasons.setdefault(parent, set()).add(why)
    root_seen = False
    root_resolved = False
    for mount in _flatten(mounts.get("filesystems") or []):
        key, target = str(mount.get("maj:min") or ""), str(mount.get("target") or "")
        if target == "/":
            root_seen = True
            root_resolved = key in nodes and any(nodes.get(parent, {}).get('type') == 'disk' for parent in ancestors(key))
        if key in nodes:
            if target not in nodes[key]["mountpoints"]:
                nodes[key]["mountpoints"].append(target)
            if _system_mount(target):
                protect(key, f"contains active system mount {target}")
    for key, node in nodes.items():
        for target in node["mountpoints"]:
            if target == "[SWAP]" or _system_mount(target):
                protect(key, f"contains active system mount {target}")
        if node["path"] in swaps or key in protected_devices:
            protect(key, "is used by the running system or its swap")
        if boot_partuuid and node["partuuid"].lower() == boot_partuuid.lower():
            protect(key, "contains the EFI partition used for this boot")
        if node["type"] not in {"disk", "part", "rom", "loop"} and parents[key]:
            for parent in parents[key]:
                protect(parent, "has an active device-mapper or RAID holder")
    # Protect mounted OS installations even when their mountpoint was manually
    # placed below /mnt. Only blank/FAT installer media is auto-unmounted.
    for key, node in nodes.items():
        if node['mountpoints'] and node['fstype'].lower() in OS_FILESYSTEMS:
            protect(key, 'contains a mounted operating-system or encrypted filesystem')
    # All devices in an active system Btrfs filesystem must be protected, not just lsblk's first member.
    system_btrfs = any(m.get("fstype") == "btrfs" and _system_mount(str(m.get("target") or ""))
                      for m in _flatten(mounts.get("filesystems") or []))
    if system_btrfs and sysfs is not None:
        for dev in (Path(sysfs) / "fs/btrfs").glob("*/devices/*/dev"):
            if _text(dev) in nodes:
                protect(_text(dev), "member of a mounted system Btrfs filesystem")
    topology_error = None if root_seen and root_resolved else "cannot resolve the running root filesystem to physical block devices"
    if topology_failure:
        topology_error = topology_failure
    if boot_unknown:
        topology_error = "cannot identify the EFI partition used for the current boot"
    disks = []
    for key, node in nodes.items():
        if node["type"] != "disk":
            continue
        related = [nodes[k] for k in sorted(descendants(key))]
        partitions = [{k: n.get(k) for k in ("path", "major_minor", "size", "type", "fstype", "parttype", "partuuid", "mountpoints")}
                      for n in related if n is not node]
        os_parts = [n["path"] for n in related if n["fstype"].lower() in OS_FILESYSTEMS or n["parttype"].lower().removeprefix("0x") in OS_TYPES]
        blocked = sorted(reasons.get(key, ()))
        if node["read_only"]:
            blocked.append("device is read-only")
        if node["tran"].lower() != "usb":
            blocked.append("device is not connected through USB")
        if node["size"] < MIN_DISK:
            blocked.append("device is smaller than the required 4 GiB")
        if node["logical_sector"] not in {512, 4096}:
            blocked.append("unsupported logical sector size")
        if sysfs is not None and (not node["sysfs_path"] or not node["diskseq"]):
            blocked.append("kernel disk sequence identity is unavailable")
        if any(n.get('metadata_error') for n in related):
            blocked.append('filesystem and partition metadata could not be inspected; administrative refresh is required')
        if topology_error:
            blocked.append(topology_error)
        value = {**node, "partitions": partitions, "os_partitions": os_parts,
                 "protected": key in protected, "reasons": blocked,
                 "requires_large_confirmation": node["size"] > MAX_DISK,
                 "requires_os_confirmation": bool(os_parts)}
        value["identity"] = _identity(node)
        value["fingerprint"] = fingerprint({"identity": value["identity"], "partitions": partitions,
                                             "fstype": node["fstype"], "mountpoints": node["mountpoints"]})
        value["eligible"] = not blocked
        disks.append(value)
    return sorted(disks, key=lambda d: d["path"])


def probe_missing_metadata(blocks):
    """udev-less/live systems need direct read-only probing before erase."""
    if os.geteuid() != 0:
        return
    executable = tool('blkid')
    for row in _flatten(blocks.get('blockdevices') or []):
        if row.get('type') not in {'disk', 'part'}:
            continue
        if row.get('fstype') and (row.get('type') == 'disk' or row.get('parttype')):
            continue
        path = str(row.get('name') or '')
        if not path.startswith('/dev/'):
            row['_metadata_error'] = True
            continue
        result = subprocess.run([executable, '-p', '-o', 'export', '--', path],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if result.returncode not in (0, 2):
            row['_metadata_error'] = True
            continue
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        row['fstype'] = row.get('fstype') or fields.get('TYPE')
        row['parttype'] = row.get('parttype') or fields.get('PART_ENTRY_TYPE')
        row['partuuid'] = row.get('partuuid') or fields.get('PART_ENTRY_UUID')


def list_disks(*, protected_paths=()):
    columns = "NAME,KNAME,TYPE,TRAN,SIZE,RO,RM,MODEL,SERIAL,WWN,MAJ:MIN,PKNAME,FSTYPE,MOUNTPOINTS,PARTTYPE,PARTUUID,LOG-SEC"
    blocks = json.loads(run([tool("lsblk"), "--json", "--bytes", "--paths", "--output", columns]))
    probe_missing_metadata(blocks)
    mounts = json.loads(run([tool("findmnt"), "--json", "--output", "SOURCE,TARGET,FSTYPE,MAJ:MIN"]))
    swaps = []
    protected = []
    for line in _text("/proc/swaps").splitlines()[1:]:
        parts = line.split()
        if parts:
            swaps.append(parts[0])
            if parts[1:2] == ["file"]:
                protected_paths = (*protected_paths, parts[0])
    # Active loop images may back a Live root filesystem. Their physical disk must
    # not become eligible just because the loop node itself has no lsblk parent.
    loop_failure = None
    for row in _flatten(blocks.get('blockdevices') or []):
        if row.get('type') != 'loop':
            continue
        name = Path(str(row.get('name') or '')).name
        backing = _text(Path('/sys/class/block') / name / 'loop/backing_file')
        if not backing:
            loop_failure = 'cannot resolve the backing file of an active loop device'
            continue
        try:
            value = json.loads(run([tool('findmnt'), '--json', '--target', backing, '--output', 'MAJ:MIN']))
            keys = [str(m.get('maj:min')) for m in value.get('filesystems') or []]
            if not keys:
                raise ValueError('missing backing device')
            protected.extend(keys)
        except (DiskError, ValueError):
            loop_failure = 'cannot resolve the physical disk backing an active loop device'
    # Protect the application, current directory and any caller-specified source payload.
    for path in (os.getcwd(), __file__, *protected_paths):
        try:
            value = json.loads(run([tool("findmnt"), "--json", "--target", str(path), "--output", "MAJ:MIN"]))
            protected.extend(str(m.get("maj:min")) for m in value.get("filesystems") or [])
        except (DiskError, ValueError):
            # Root resolution below still protects system devices. A selected source
            # that cannot be resolved is explicitly rejected by the prepare helper.
            pass
    boot_uuid = _boot_partuuid()
    boot_unknown = Path("/sys/firmware/efi").is_dir() and boot_uuid is None
    return parse_inventory(blocks, mounts, swaps=swaps, protected_devices=protected,
                           boot_partuuid=boot_uuid, boot_unknown=boot_unknown, topology_failure=loop_failure)


def select_disk(path, expected_fingerprint, *, allow_large=False, erase_os=False, protected_paths=(), inventory=None):
    """Repeat inventory, require the entire displayed identity, and enforce policy."""
    choices = list_disks(protected_paths=protected_paths) if inventory is None else inventory
    matches = [disk for disk in choices if disk["path"] == path and disk["fingerprint"] == expected_fingerprint]
    if len(matches) != 1:
        raise DiskError("The selected device changed or disappeared. Refresh the disk list and select it again.")
    disk = matches[0]
    reasons = list(disk["reasons"])
    if disk["requires_large_confirmation"] and not allow_large:
        reasons.append("large disks require an additional explicit confirmation")
    if disk["requires_os_confirmation"] and not erase_os:
        reasons.append("existing operating-system or encrypted partitions require explicit erase confirmation")
    if reasons:
        raise DiskError("Refusing to erase " + path + ": " + "; ".join(reasons))
    return disk
