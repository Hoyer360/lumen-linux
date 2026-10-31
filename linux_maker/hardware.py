"""Read-only Linux hardware facts and the Hardware Sniffer platform adapter.

No firmware setting is changed. Unreadable facts retain their failure state. The
ACPI bundle format lets a fixed privileged helper read firmware tables while the
unprivileged process owns all output paths.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import time

MAX_TABLE = 8 * 1024 * 1024
MAX_TABLES = 256
MAX_ACPI_BYTES = 32 * 1024 * 1024
BUNDLE_SCHEMA = 'lumen-acpi/1'
VENDORS = {'8086': 'Intel', '1002': 'AMD', '10DE': 'NVIDIA'}


def measured(value, source):
    return {'status': 'measured', 'source': source, 'value': value}


def unavailable(error, source):
    return {'status': 'unavailable', 'source': source, 'error': str(error)[:300]}


def read_text(path, default='', maximum=1024 * 1024):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            return default
        return data.decode('utf-8', 'replace').strip()
    except OSError:
        return default


def read_int(path, default=None):
    try:
        return int(read_text(path), 0)
    except ValueError:
        return default


def parse_cpu_list(value):
    """Parse kernel CPU ranges, rejecting pathological allocations."""
    out = set()
    for part in value.split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?', part):
            raise ValueError('invalid CPU list')
        start, _, end = part.partition('-')
        lo, hi = int(start), int(end or start)
        if not 0 <= lo <= hi <= 65535 or hi - lo > 4096:
            raise ValueError('CPU list exceeds limits')
        out.update(range(lo, hi + 1))
        if len(out) > 4096:
            raise ValueError('too many logical processors')
    return sorted(out)


def cpu_topology(root=Path('/sys/devices/system/cpu')):
    root = Path(root)
    try:
        online = parse_cpu_list(read_text(root / 'online'))
        cores, packages, caches = {}, set(), {}
        types = {}
        for cpu in online:
            path = root / ('cpu%d' % cpu)
            package = read_int(path / 'topology/physical_package_id')
            core = read_int(path / 'topology/core_id')
            if package is None or core is None or package < 0 or core < 0:
                raise ValueError('kernel did not expose physical core/package identity')
            packages.add(package)
            cores.setdefault((package, core), []).append(cpu)
            kind = read_int(path / 'topology/core_type')
            if kind is not None:
                types[cpu] = kind
            for entry in sorted((path / 'cache').glob('index[0-9]*'))[:32]:
                shared = read_text(entry / 'shared_cpu_list')
                level, typ = read_int(entry / 'level'), read_text(entry / 'type')
                size = read_text(entry / 'size')
                key = (level, typ, shared)
                caches[key] = {'level': level, 'type': typ.lower(), 'size': size,
                               'shared_cpu_list': shared}
        return measured({'packages': len(packages), 'cores': len(cores),
                         'logical_processors': len(online), 'online_cpu_ids': online,
                         'core_map': [{'package': p, 'core': c, 'logical': len(ids), 'cpu_ids': ids}
                                      for (p, c), ids in sorted(cores.items())],
                         'core_types': types, 'hybrid': len(set(types.values())) > 1 if types else None,
                         'caches': list(caches.values()),
                         'logical_address_format': 'Linux CPU number'},
                        'Linux sysfs CPU topology (online processors)')
    except (OSError, ValueError) as error:
        return unavailable(error, 'Linux sysfs CPU topology')


def secure_boot(efi=Path('/sys/firmware/efi')):
    efi = Path(efi)
    source = 'efivarfs SecureBoot (4-byte attributes + one-byte value)'
    if not efi.is_dir():
        return unavailable('EFI runtime is not exposed by this boot; firmware capability is unknown', source)
    path = efi / 'efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    try:
        data = path.read_bytes()
        if len(data) != 5 or data[4] not in (0, 1):
            raise ValueError('invalid SecureBoot EFI variable length or value')
        return measured(bool(data[4]), source)
    except (OSError, ValueError) as error:
        return unavailable(type(error).__name__ + ': ' + str(error), source)


def is_wsl():
    return 'microsoft' in read_text('/proc/sys/kernel/osrelease').lower() or 'WSL_INTEROP' in os.environ


def boot_identity(proc=Path('/proc')):
    proc = Path(proc)
    token = read_text(proc / 'sys/kernel/random/boot_id', maximum=128)
    if not re.fullmatch(r'[0-9a-f-]{36}', token):
        token = None
    booted = None
    for line in read_text(proc / 'stat').splitlines():
        if line.startswith('btime '):
            try:
                booted = int(line.split()[1])
            except (ValueError, IndexError):
                pass
    return {'boot_id': token, 'boot_time': booted}


def pci_paths(device):
    """Derive PciRoot from firmware _UID, never from the PCI domain number."""
    device = Path(device)
    result = {}
    acpi = read_text(device / 'firmware_node/path')
    if acpi.startswith('\\_SB_.'):
        acpi = '\\_SB.' + acpi[6:]
    if re.fullmatch(r'\\?_SB(?:\.[A-Z0-9_]+)+', acpi):
        result['ACPI Path'] = acpi
    real = device.resolve()
    parts, root_uid = [], None
    current = Path('/')
    for component in real.parts[1:]:
        current /= component
        if re.fullmatch(r'pci[0-9a-fA-F]{4}:[0-9a-fA-F]{2}', component):
            uid = read_text(current / 'firmware_node/uid')
            try:
                root_uid = int(uid, 0) if uid.lower().startswith('0x') else int(uid)
            except ValueError:
                root_uid = None
        match = re.fullmatch(r'[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:([0-9a-fA-F]{2})\.([0-7])', component)
        if match:
            parts.append('Pci(0x%x,0x%x)' % (int(match[1], 16), int(match[2], 16)))
    if root_uid is not None and 0 <= root_uid <= 0xffffffff and parts:
        result['PCI Path'] = 'PciRoot(0x%x)/%s' % (root_uid, '/'.join(parts))
    return result


def pci_inventory(root=Path('/sys/bus/pci/devices')):
    out = []
    for device in sorted(Path(root).glob('*'))[:1024]:
        vendor, product, cls = (read_int(device / key) for key in ('vendor', 'device', 'class'))
        if vendor is None or product is None or cls is None:
            continue
        record = {'address': device.name, 'device_id': '%04X-%04X' % (vendor, product),
                  'class_code': '%06X' % cls, 'path': str(device), **pci_paths(device)}
        subvendor, subdevice = (read_int(device / key) for key in ('subsystem_vendor', 'subsystem_device'))
        if subvendor is not None and subdevice is not None:
            record['subsystem_id'] = '%04X%04X' % (subdevice, subvendor)
        if (device / 'driver').is_symlink():
            record['driver'] = (device / 'driver').resolve().name
            record['driver_version'] = read_text(device / 'driver/module/version') or None
        resources = []
        for index, line in enumerate(read_text(device / 'resource', maximum=16384).splitlines()[:32]):
            try:
                start, end, flags = [int(value, 16) for value in line.split()]
                if start and end >= start:
                    resources.append({'index': index, 'start': start, 'end': end,
                                      'size': end - start + 1, 'flags': flags})
            except ValueError:
                continue
        record['resources'] = resources
        out.append(record)
    return out


def display_inventory(root=Path('/sys/class/drm')):
    out = []
    for connector in sorted(Path(root).glob('card*-*'))[:128]:
        status = read_text(connector / 'status')
        if not status:
            continue
        record = {'connector': connector.name, 'status': status,
                  'enabled': read_text(connector / 'enabled'),
                  'modes': read_text(connector / 'modes').splitlines()[:64]}
        device = connector / 'device'
        if device.exists():
            record['device'] = device.resolve().name
        try:
            data = (connector / 'edid').read_bytes()[:4096]
            if data:
                record['edid_sha256'] = hashlib.sha256(data).hexdigest()
                record['edid_blocks_valid'] = len(data) % 128 == 0 and all(
                    sum(data[i:i + 128]) % 256 == 0 for i in range(0, len(data), 128))
        except OSError:
            pass
        out.append(record)
    return out


def system_tool(name):
    """Use only administrator-owned system directories, not the caller's PATH."""
    for directory in ('/usr/bin', '/usr/sbin', '/bin', '/sbin'):
        path = Path(directory) / name
        try:
            resolved = path.resolve(strict=True)
            st = resolved.stat()
            if resolved.is_file() and st.st_uid == 0 and not st.st_mode & 0o022 and os.access(resolved, os.X_OK):
                return str(resolved)
        except OSError:
            continue
    return None


def run_tool(name, arguments, timeout=5):
    executable = system_tool(name)
    if not executable:
        raise FileNotFoundError(name + ' is not installed in a trusted system directory')
    env = {'PATH': '/usr/bin:/usr/sbin:/bin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
    proc = subprocess.run([executable, *arguments], capture_output=True, text=True,
                          timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    if proc.returncode:
        raise OSError('%s exited %d: %s' % (name, proc.returncode, proc.stderr[-200:]))
    if len(proc.stdout) > 2 * 1024 * 1024:
        raise ValueError(name + ' output exceeds limit')
    return proc.stdout


def storage_drives():
    data = json.loads(run_tool('lsblk', ['--json', '--bytes', '--output', 'NAME,TYPE,SIZE,MODEL,TRAN,ROTA,MOUNTPOINTS']))
    rows = []
    def mounted(node):
        return any(p in ('/', '/boot', '/boot/efi', '/efi', '[SWAP]')
                   for p in (node.get('mountpoints') or [])) or any(mounted(c) for c in node.get('children', []))
    def visit(node):
        if node.get('type') == 'disk':
            rows.append({'Number': node.get('name'), 'Model': (node.get('model') or node.get('name') or '').strip(),
                         'BusType': str(node.get('tran') or 'unknown').upper(), 'Size': int(node.get('size') or 0),
                         'MediaType': 'HDD' if node.get('rota') else 'SSD/Flash', 'IsSystem': mounted(node)})
        for child in node.get('children', []):
            visit(child)
    for node in data.get('blockdevices', []):
        visit(node)
    return rows


VENDOR_LIBRARY_DIRS = ('/usr/lib/x86_64-linux-gnu', '/usr/lib64', '/usr/lib',
                       '/lib/x86_64-linux-gnu', '/lib64', '/lib', '/usr/lib/wsl/lib')
VENDOR_LIBRARY_NAMES = {'nvml': 'libnvidia-ml.so.1', 'cuda': 'libcuda.so.1'}


def _trusted_vendor_file(candidate):
    """Resolve distro library links, checking the file and every owning directory."""
    try:
        path = Path(candidate).resolve(strict=True)
        if not any(path.is_relative_to(root) for root in ('/usr/lib', '/usr/lib64', '/lib', '/lib64')):
            return None
        for index, node in enumerate((path, *path.parents)):
            info = node.stat()
            kind = stat.S_ISREG(info.st_mode) if index == 0 else stat.S_ISDIR(info.st_mode)
            if not kind or info.st_uid != 0 or info.st_mode & 0o022:
                return None
        return path
    except (OSError, RuntimeError):
        return None


def open_vendor_library(vendor):
    """Only administrator-installed Linux driver libraries; never search PATH/cwd."""
    filename = VENDOR_LIBRARY_NAMES.get(vendor)
    if not filename:
        return None, 'unsupported vendor library'
    if any(os.environ.get(key) for key in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT')):
        return None, 'dynamic loader overrides are present; installed-library provenance cannot be established'
    failures = []
    for directory in VENDOR_LIBRARY_DIRS:
        path = _trusted_vendor_file(Path(directory) / filename)
        if path is None:
            continue
        try:
            return ctypes.CDLL(str(path), mode=os.RTLD_LOCAL | os.RTLD_NOW), str(path)
        except OSError as error:
            failures.append(type(error).__name__)
    return None, filename + (' could not be loaded: ' + ', '.join(failures) if failures else ' is not present in trusted system directories')


def _nvidia_summary():
    source = 'NVIDIA installed nvidia-smi, read-only query (NVML)'
    try:
        text = run_tool('nvidia-smi', ['--query-gpu=pci.bus_id,name,driver_version,memory.total', '--format=csv,noheader,nounits'])
        rows = []
        for line in text.splitlines()[:64]:
            fields = [part.strip() for part in line.split(',')]
            if len(fields) == 4:
                rows.append({'pci_address': fields[0], 'name': fields[1], 'driver_version': fields[2],
                             'memory_mib': int(fields[3]) if fields[3].isdigit() else None})
        return {'status': 'measured', 'source': source, 'devices': rows}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {'status': 'unavailable', 'source': source, 'error': str(error)[:300], 'devices': []}


def _nvidia_views(records):
    """Join only an unambiguous, complete PCI domain:bus:device.function."""
    from p1401 import hwcapture
    groups = {}
    for index, (vendor, device) in enumerate(records):
        pci = (device.get('pci') or {}).get('value')
        address = None
        if pci and all(pci.get(key) is not None for key in ('domain', 'bus', 'device', 'function')):
            address = hwcapture._pci_key(*(pci[key] for key in ('domain', 'bus', 'device', 'function')))
        groups.setdefault(address or 'unavailable:%04d' % index, []).append((vendor, device, address))
    views = []
    for group in groups.values():
        duplicate = any(sum(v == vendor for v, _, _ in group) > 1 for vendor in VENDOR_LIBRARY_NAMES)
        batches = [[item] for item in group] if duplicate else [group]
        for batch in batches:
            address = batch[0][2]
            view = {vendor: data for vendor, data, _ in batch}
            view.update(pci_address=address, identity_status='ambiguous duplicate PCI function' if duplicate else
                        'complete PCI function' if address else 'unavailable full PCI function; not joined')
            for name in ('tensor_cores', 'rt_cores'):
                view[name] = unavailable(hwcapture.NOT_EXPOSED, 'none')
            views.append(view)
    return views


def nvidia_inventory(checkpoint=None):
    """Read installed NVML/CUDA APIs inside hwcapture's isolated, timed worker."""
    from p1401 import hwcapture
    result = {'status': 'unavailable', 'source': 'Installed Linux NVIDIA driver APIs; read-only queries',
              'nvml': 'not queried', 'cuda': 'not queried', 'devices': [], 'libraries': {}}
    records, succeeded = [], []
    def saved():
        if checkpoint:
            checkpoint(result)
    result['summary'] = _nvidia_summary()
    saved()
    for vendor, getter in (('nvml', hwcapture.nvml_devices), ('cuda', hwcapture.cuda_devices)):
        try:
            library, source = open_vendor_library(vendor)
            if library is None:
                result[vendor] = source
            else:
                result['libraries'][vendor] = source
                records.extend((vendor, device) for device in getter(library))
                succeeded.append(vendor)
                result[vendor] = 'ok'
        except Exception as error:
            result[vendor] = type(error).__name__ + ': ' + str(error)[:200]
        result['devices'] = _nvidia_views(records)
        result['status'] = 'measured' if len(succeeded) == 2 else 'partial' if succeeded else 'unavailable'
        saved()
    if not succeeded and result['summary']['status'] == 'measured':
        result['status'] = 'partial'
    return result


def peripheral_inventory():
    usb = []
    for device in sorted(Path('/sys/bus/usb/devices').glob('*'))[:512]:
        vendor, product = read_text(device / 'idVendor'), read_text(device / 'idProduct')
        if re.fullmatch(r'[0-9a-fA-F]{4}', vendor) and re.fullmatch(r'[0-9a-fA-F]{4}', product):
            usb.append({'device_id': (vendor + '-' + product).upper(), 'product': read_text(device / 'product'),
                        'class': read_text(device / 'bDeviceClass'), 'speed_mbps': read_text(device / 'speed')})
    audio = [{'card': p.name, 'id': read_text(p / 'id')} for p in sorted(Path('/sys/class/sound').glob('card[0-9]*'))[:64]]
    wireless = []
    for phy in sorted(Path('/sys/class/ieee80211').glob('*'))[:64]:
        wireless.append({'phy': phy.name, 'device': (phy / 'device').resolve().name})
    return measured({'usb': usb, 'audio': audio, 'wifi': wireless,
                     'not_observed': ['microphone audio', 'input events', 'Wi-Fi credentials', 'port connector routing']},
                    'Linux USB, ALSA and ieee80211 sysfs metadata')


def cpu_native(root=None):
    """Run the packaged, hash-verified helper as an unprivileged bounded subprocess."""
    source = 'Linux CPUID allow-list; group*64+bit is the Linux logical CPU number'
    root = Path(root) if root else Path(__file__).resolve().parents[1] / 'bin'
    binary, pin = root / 'lumen-cpuinfo', root / 'cpu-helper-linux.json'
    try:
        if binary.is_symlink() or pin.is_symlink() or not binary.is_file() or not pin.is_file():
            raise ValueError('packaged CPUID helper or pin is missing')
        if binary.stat().st_size > 4 * 1024 * 1024 or pin.stat().st_size > 4096:
            raise ValueError('helper or metadata exceeds bounds')
        metadata = json.loads(pin.read_text())
        expected = metadata.get('sha256')
        if metadata.get('schema') != 'lumen-cpu-helper/1' or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('invalid CPUID helper pin')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != expected:
            raise ValueError('CPUID helper hash mismatch')
        proc = subprocess.run([str(binary)], stdin=subprocess.DEVNULL, capture_output=True, timeout=5.5,
                              env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, start_new_session=True)
        if proc.returncode or len(proc.stdout) > 1024 * 1024:
            raise ValueError('CPUID helper failed or exceeded its output limit')
        payload = json.loads(proc.stdout)
        from p1401.cpunative import validate
        if not validate(payload):
            raise ValueError('CPUID output schema refused')
        record = measured(payload, source)
        sample = payload['per_logical_processor']
        if payload['truncated'] or sample.get('stopped') not in (None, 'complete') or sample.get('affinity_refused') or sample.get('location_unavailable') or sample.get('affinity_restored') is False:
            record['status'] = 'partial'
            record['error'] = 'One or more processors could not be sampled; inspect per-processor statuses'
        return record
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return unavailable(error, source)


def inventory(report=None, checkpoint=None):
    """Capture in stages so a hung vendor query cannot discard earlier evidence."""
    out = {}
    device_map = {'qualification': 'Linux observations; macOS support not assessed', 'stages_completed': []}
    out['device_map'] = device_map
    def saved():
        if checkpoint:
            checkpoint(out)
    def stage(name, function, source):
        try:
            value = function()
        except Exception as error:
            value = unavailable(type(error).__name__ + ': ' + str(error), source)
        device_map[name] = value
        device_map['stages_completed'].append(name)
        saved()
        return value

    out['cpu_topology'] = cpu_topology()
    saved()
    pci = pci_inventory()
    gpu_pci = [p for p in pci if p['class_code'].startswith('03')]
    stage('platform_role', lambda: measured(read_text('/sys/class/dmi/id/chassis_type') or 'unknown', 'DMI chassis type'), 'DMI')
    stage('devices', lambda: measured({'nodes': pci}, 'Linux PCI sysfs'), 'Linux PCI')
    stage('display_paths', lambda: measured(display_inventory(), 'Linux DRM connectors'), 'Linux DRM')
    stage('graphics', lambda: measured(gpu_pci, 'Linux PCI display class; D3D12 capability is not a Linux observation'), 'Linux PCI')
    stage('gpu_drivers', lambda: measured([{'address': p['address'], 'driver': p.get('driver'), 'version': p.get('driver_version')}
                                          for p in gpu_pci], 'Linux bound PCI drivers'), 'Linux drivers')
    stage('pci_resources', lambda: measured([{'address': p['address'], 'resources': p['resources']} for p in pci], 'Linux PCI allocated resources'), 'Linux PCI')
    stage('secure_boot', secure_boot, 'efivarfs SecureBoot')
    stage('peripheral_caps', peripheral_inventory, 'Linux peripheral sysfs')

    def firmware_attributes():
        attributes = []
        for root in sorted(Path('/sys/class/firmware-attributes').glob('*/attributes'))[:8]:
            for attribute in sorted(root.iterdir())[:256]:
                # Select before reading to avoid credential-bearing OEM properties.
                if not re.search(r'secure.?boot|resiz|above.?4g|csm|virtual|sata|storage', attribute.name, re.I):
                    continue
                current = read_text(attribute / 'current_value', maximum=4096)
                if current:
                    attributes.append({'name': attribute.name, 'value': current[:256]})
        return measured(attributes, 'Linux firmware-attributes sysfs (read only)') if attributes else unavailable(
            'no generic Linux interface exposes all OEM BIOS settings', 'Linux firmware attributes')
    stage('bios_settings', firmware_attributes, 'Linux firmware attributes')
    # Potentially slow owned subprocesses run only after cheap evidence is durable.
    stage('cpu_native', cpu_native, 'Linux CPUID')
    def nvidia_saved(value):
        device_map['nvidia_detail'] = value
        out['nvidia'] = value
        saved()
    stage('nvidia_detail', lambda: nvidia_inventory(checkpoint=nvidia_saved), 'Linux NVML/CUDA driver APIs')
    out['nvidia'] = device_map['nvidia_detail']
    saved()
    return out


def validate_table(data):
    if not isinstance(data, bytes) or not 8 <= len(data) <= MAX_TABLE:
        raise ValueError('ACPI table length outside limits')
    sig = data[:4]
    if not re.fullmatch(rb'[A-Z0-9_]{4}', sig):
        raise ValueError('invalid ACPI signature')
    declared = struct.unpack_from('<I', data, 4)[0]
    if declared != len(data):
        raise ValueError('ACPI length does not match header')
    if sig == b'FACS':
        if len(data) < 64:
            raise ValueError('truncated FACS')
    elif len(data) < 36 or sum(data) & 0xff:
        raise ValueError('invalid ACPI header or checksum')
    return sig.decode('ascii')


def acpi_bundle(root=Path('/sys/firmware/acpi/tables')):
    """Read a fixed firmware location; returned data contains no caller-controlled paths."""
    root = Path(root)
    if not root.is_dir():
        raise OSError('ACPI tables are not exposed; use a native x86_64 Linux boot or import a report and ACPI')
    files = sorted(root.iterdir()) + sorted((root / 'dynamic').glob('*'))
    records, total = [], 0
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as stream:
            data = stream.read(MAX_TABLE + 1)
        signature = validate_table(data)
        total += len(data)
        if total > MAX_ACPI_BYTES or len(records) >= MAX_TABLES:
            raise ValueError('ACPI bundle exceeds bounds')
        records.append({'signature': signature, 'sha256': hashlib.sha256(data).hexdigest(),
                        'data': base64.b64encode(data).decode('ascii')})
    if not any(record['signature'] == 'DSDT' for record in records):
        raise ValueError('firmware did not expose a DSDT')
    return {'schema': BUNDLE_SCHEMA, 'tables': records}


def write_acpi_bundle(bundle, destination):
    """Validate the whole bundle before atomically writing into a fresh directory."""
    if not isinstance(bundle, dict) or bundle.get('schema') != BUNDLE_SCHEMA:
        raise ValueError('invalid ACPI bundle schema')
    records = bundle.get('tables')
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_TABLES:
        raise ValueError('invalid ACPI table count')
    decoded, total, counts = [], 0, {}
    for record in records:
        data = base64.b64decode(record['data'], validate=True)
        sig = validate_table(data)
        if sig != record.get('signature') or hashlib.sha256(data).hexdigest() != record.get('sha256'):
            raise ValueError('ACPI signature or hash mismatch')
        total += len(data)
        if total > MAX_ACPI_BYTES:
            raise ValueError('ACPI bundle exceeds size limit')
        index = counts.get(sig, 0)
        counts[sig] = index + 1
        name = '%s%s.aml' % (sig, '' if index == 0 else str(index))
        decoded.append((name, data))
    if counts.get('DSDT') != 1:
        raise ValueError('ACPI bundle must contain exactly one DSDT')
    destination = Path(destination)
    if destination.exists() and (destination.is_symlink() or any(destination.iterdir())):
        raise ValueError('ACPI destination must be a fresh directory')
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in decoded:
        path = destination / name
        with path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    return len(decoded)


def dump_acpi(destination):
    try:
        bundle = acpi_bundle()
    except PermissionError as error:
        # The installed broker returns bytes only; it never receives an output path.
        helper = Path('/usr/libexec/lumen-helper')
        if not helper.is_file():
            raise PermissionError('Reading ACPI needs the installed Lumen privileged helper. Install the helper or import an existing ACPI dump.') from error
        executable = system_tool('pkexec')
        if not executable:
            raise PermissionError('polkit/pkexec is not installed') from error
        result = subprocess.run([executable, str(helper)], input=b'{"action":"acpi"}',
                                capture_output=True, timeout=90)
        if result.returncode:
            detail = result.stderr.decode('utf-8', 'replace').strip()
            if not detail:
                try:
                    detail = json.loads(result.stdout).get('error', '')
                except (ValueError, AttributeError):
                    pass
            detail = str(detail or f'helper exited with status {result.returncode}')[-300:]
            raise PermissionError('ACPI authorization/read failed: ' + detail)
        if len(result.stdout) > MAX_ACPI_BYTES * 2:
            raise ValueError('privileged ACPI response exceeds limit')
        response = json.loads(result.stdout)
        if not response.get('ok'):
            raise PermissionError(response.get('error') or 'ACPI helper failed')
        bundle = response['bundle']
    return write_acpi_bundle(bundle, destination)


def configure_sniffer(sniffer, progress=None):
    """Fix Linux gaps in the adapter, leaving the pinned upstream tree unchanged."""
    hardware = sniffer.hardware_info
    raw_read = hardware.utils.read_file
    def safe_read(path):
        try:
            return raw_read(path)
        except (OSError, UnicodeError):
            return None
    hardware.utils.read_file = safe_read
    hardware.utils.head = lambda *args, **kwargs: None
    hardware.get_device_location_paths = pci_paths

    def board():
        from Scripts.datasets import chipset_data
        root = Path('/sys/class/dmi/id')
        vendor = read_text(root / 'board_vendor') or read_text(root / 'sys_vendor')
        model = read_text(root / 'board_name') or read_text(root / 'product_name')
        name = ' '.join(x for x in (vendor, model) if x).strip() or 'Unknown motherboard'
        chassis = read_int(root / 'chassis_type')
        kind = 'Laptop' if chassis in (8, 9, 10, 14, 30, 31, 32) else 'Desktop'
        chipset = 'Unknown'
        for device in hardware.devices_by_class.get('ISA bridge', []):
            chipset = chipset_data.chipset_controllers.get(device.get('Device ID'), chipset)
        for candidate in chipset_data.amd_chipsets:
            if candidate in name.upper():
                chipset = candidate
                break
        return {'Name': name.upper(), 'Chipset': chipset, 'Platform': kind}
    hardware.motherboard = board

    def bios():
        sb = secure_boot()
        result = {'Version': read_text('/sys/class/dmi/id/bios_version') or 'Unknown',
                  'Release Date': read_text('/sys/class/dmi/id/bios_date') or 'Unknown',
                  'Firmware Type': 'UEFI' if Path('/sys/firmware/efi').is_dir() else 'BIOS'}
        if sb['status'] == 'measured':
            result['Secure Boot'] = 'Enabled' if sb['value'] else 'Disabled'
        # The engine adapter permits omission of this informational field when unavailable.
        resources = pci_inventory()
        if any(r['start'] >= 2**32 and r['flags'] & 0x200 for p in resources for r in p['resources']):
            result['Above 4G Decoding'] = 'Enabled'
        return result
    hardware.bios = bios

    original_cpu = hardware.cpu
    def cpu():
        result = original_cpu() or {}
        topology = cpu_topology()
        if result and topology['status'] == 'measured':
            value = topology['value']
            result['Core Count'] = '%02d' % value['cores']
            result['CPU Count'] = '%02d' % value['packages']
            result['Thread Count'] = str(value['logical_processors'])
        # Linux reports SSE3 as pni, not sse3. Token matching avoids SSE4a/SSE4.1 confusion.
        flags = set()
        for line in read_text('/proc/cpuinfo').splitlines():
            if line.startswith('flags'):
                flags = set(line.partition(':')[2].split())
                break
        names = [('SSE', 'sse'), ('SSE2', 'sse2'), ('SSE3', 'pni'), ('SSSE3', 'ssse3'),
                 ('SSE4.1', 'sse4_1'), ('SSE4.2', 'sse4_2'), ('SSE4a', 'sse4a'),
                 ('AVX', 'avx'), ('AVX2', 'avx2')]
        if result and flags:
            result['SIMD Features'] = ', '.join(name for name, flag in names if flag in flags)
        return result
    hardware.cpu = cpu

    def gpu():
        out = {}
        for device in pci_inventory():
            if not device['class_code'].startswith('03'):
                continue
            classification = hardware.classify_gpu(device['device_id'])
            props = {'Manufacturer': classification.get('Manufacturer', VENDORS.get(device['device_id'][:4], 'Unknown')),
                     'Codename': classification.get('Codename', 'Unknown'),
                     'Device Type': classification.get('Device Type', 'Unknown'),
                     'Bus Type': 'PCI', 'Device ID': device['device_id'], 'Device Path': device['path'],
                     **{k: device[k] for k in ('PCI Path', 'ACPI Path') if k in device}}
            if 'subsystem_id' in device:
                props['Subsystem ID'] = device['subsystem_id']
            # A large BAR proves its current size, not the firmware Resizable BAR toggle.
            name, _ = hardware.get_pci_device_name_and_class(device['address'])
            if name == 'Unknown':
                name = '%s PCI %s' % (props['Manufacturer'], device['device_id'])
            out[hardware.utils.get_unique_key(name, out)] = props
        return out
    hardware.gpu = gpu

    original_network = hardware.network
    def network():
        result = original_network() or {}
        seen = {d.get('Device ID') for d in result.values()}
        for device in pci_inventory():
            if not device['class_code'].startswith('02') or device['device_id'] in seen:
                continue
            name, _ = hardware.get_pci_device_name_and_class(device['address'])
            entry = {'Bus Type': 'PCI', 'Device ID': device['device_id'],
                     **{k: device[k] for k in ('PCI Path', 'ACPI Path') if k in device}}
            if 'subsystem_id' in device:
                entry['Subsystem ID'] = device['subsystem_id']
            result[hardware.utils.get_unique_key(name, result)] = entry
        return result
    hardware.network = network

    steps = [('pci_devices', None), ('motherboard', 'Motherboard'), ('bios', 'BIOS'), ('cpu', 'CPU'),
             ('gpu', 'GPU'), ('monitor', 'Monitor'), ('network', 'Network'), ('sound', 'Sound'),
             ('usb_controllers', 'USB Controllers'), ('input', 'Input'), ('storage_controllers', 'Storage Controllers'),
             ('biometric', 'Biometric'), ('bluetooth', 'Bluetooth'), ('sd_controller', 'SD Controller'),
             ('system_devices', 'System Devices')]
    def collect():
        hardware.result = {}
        failures = []
        for index, (method, section) in enumerate(steps, 1):
            print('STEP %d/%d %s' % (index, len(steps), section or 'PCI devices'), flush=True)
            try:
                value = getattr(hardware, method)()
                if section:
                    hardware.result[section] = value or {}
            except Exception as error:
                if section:
                    hardware.result[section] = {}
                failures.append({'section': section or method, 'error': type(error).__name__ + ': ' + str(error)[:200]})
                print('NOTE unavailable %s: %s' % (section or method, str(error)[:200]), flush=True)
            if progress:
                progress(hardware.result)
        hardware.result['Linux Scan'] = {'schema': 'lumen-linux-scan/1', **boot_identity(),
                                         'failures': failures, 'source': 'Linux sysfs/procfs + Hardware Sniffer',
                                         'secure_boot': secure_boot()}
    hardware.hardware_collector = collect
    sniffer.dump_acpi_tables = lambda: dump_acpi(Path(sniffer.result_dir) / 'ACPI')


def allow_unavailable_secure_boot():
    """Missing firmware observations are not fabricated to satisfy the old schema.

    This changes only the optionality of the informational Secure Boot field; an
    observed value still has to be Enabled/Disabled. No compatibility rule is relaxed.
    """
    from Scripts import report_validator
    cls = report_validator.ReportValidator
    if getattr(cls, '_lumen_secure_boot', False):
        return
    original = cls.__init__
    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.SCHEMA['schema']['BIOS']['schema']['Secure Boot']['required'] = False
    cls.__init__ = initialize
    cls._lumen_secure_boot = True


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--acpi-bundle', action='store_true')
    args = parser.parse_args()
    print(json.dumps(acpi_bundle() if args.acpi_bundle else inventory(), ensure_ascii=False))
