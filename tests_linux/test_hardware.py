"""Linux hardware parsing, firmware transport and scan failure evidence."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linux_maker import hardware as hw
from p1401 import engine, scan, scan_evidence


def table(sig=b'DSDT', payload=b'\x00' * 8):
    data = bytearray(sig + struct.pack('<I', 36 + len(payload)) + bytes(28) + payload)
    data[9] = -sum(data) & 255
    return bytes(data)


def bundle(*tables):
    return {'schema': hw.BUNDLE_SCHEMA, 'tables': [
        {'signature': data[:4].decode(), 'sha256': hashlib.sha256(data).hexdigest(),
         'data': base64.b64encode(data).decode()} for data in tables]}


class Firmware(unittest.TestCase):
    def test_secure_boot_is_binary_after_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            var = root / 'efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
            var.parent.mkdir()
            for value in (0, 1):
                var.write_bytes(struct.pack('<I', 7) + bytes([value]))
                result = hw.secure_boot(root)
                self.assertEqual(result['status'], 'measured')
                self.assertIs(result['value'], bool(value))
            for bad in (b'1', b'\x07\x00\x00\x00\x02', b''):
                var.write_bytes(bad)
                self.assertEqual(hw.secure_boot(root)['status'], 'unavailable')
            var.unlink()
            self.assertEqual(hw.secure_boot(root)['status'], 'unavailable')

    def test_acpi_repeated_ssdts_are_preserved_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'ACPI'
            self.assertEqual(hw.write_acpi_bundle(bundle(table(), table(b'SSDT'), table(b'SSDT', b'xx')), target), 3)
            self.assertEqual({p.name for p in target.iterdir()}, {'DSDT.aml', 'SSDT.aml', 'SSDT1.aml'})
            with self.assertRaises(ValueError):
                hw.write_acpi_bundle(bundle(table()), target)

    def test_acpi_invalid_table_leaves_no_partial_directory(self):
        good = table()
        invalid = bytearray(table(b'SSDT'))
        invalid[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'ACPI'
            with self.assertRaises(ValueError):
                hw.write_acpi_bundle(bundle(good, bytes(invalid)), target)
            self.assertFalse(target.exists())
            with self.assertRaises(ValueError):
                hw.write_acpi_bundle(bundle(good, good), target)
            self.assertFalse(target.exists())

    def test_acpi_bundle_reads_fixed_flat_and_dynamic_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dynamic').mkdir()
            (root / 'DSDT').write_bytes(table())
            (root / 'SSDT1').write_bytes(table(b'SSDT'))
            (root / 'dynamic/SSDT2').write_bytes(table(b'SSDT', b'xx'))
            records = hw.acpi_bundle(root)['tables']
            self.assertEqual(len(records), 3)
            (root / 'DSDT').unlink()
            with self.assertRaises(ValueError):
                hw.acpi_bundle(root)

    def test_pci_root_uses_acpi_uid_instead_of_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'pci0000:40'
            device = root / '0000:40:01.0' / '0000:41:00.1'
            device.mkdir(parents=True)
            (root / 'firmware_node').mkdir()
            (root / 'firmware_node/uid').write_text('7')
            self.assertEqual(hw.pci_paths(device)['PCI Path'], 'PciRoot(0x7)/Pci(0x1,0x0)/Pci(0x0,0x1)')
            (root / 'firmware_node/uid').unlink()
            self.assertNotIn('PCI Path', hw.pci_paths(device))


class Cpu(unittest.TestCase):
    def test_topology_counts_cores_not_threads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'online').write_text('0-3')
            for cpu, core in enumerate((0, 0, 1, 1)):
                topo = root / ('cpu%d' % cpu) / 'topology'
                topo.mkdir(parents=True)
                (topo / 'physical_package_id').write_text('0')
                (topo / 'core_id').write_text(str(core))
            result = hw.cpu_topology(root)
            self.assertEqual(result['status'], 'measured')
            self.assertEqual(result['value']['cores'], 2)
            self.assertEqual(result['value']['logical_processors'], 4)
            (root / 'cpu1/topology/core_id').unlink()
            self.assertEqual(hw.cpu_topology(root)['status'], 'unavailable')

    def test_cpu_list_bounds(self):
        self.assertEqual(hw.parse_cpu_list('0-3,6,8-9'), [0, 1, 2, 3, 6, 8, 9])
        for bad in ('', '-1', '4-2', '0-999999', 'a'):
            with self.assertRaises(ValueError):
                hw.parse_cpu_list(bad)



    def test_slow_vendor_stage_cannot_erase_earlier_checkpoints(self):
        saved = []
        def checkpoint(value):
            saved.append(json.loads(json.dumps(value)))
        def failure(**_kwargs):
            raise OSError('vendor query failed')
        with patch.object(hw, 'pci_inventory', return_value=[]), patch.object(hw, 'display_inventory', return_value=[]), \
             patch.object(hw, 'peripheral_inventory', return_value=hw.measured({}, 'fixture')), \
             patch.object(hw, 'cpu_native', side_effect=failure), patch.object(hw, 'nvidia_inventory', side_effect=failure):
            result = hw.inventory(checkpoint=checkpoint)
        self.assertGreater(len(saved), 6)
        self.assertIn('cpu_topology', saved[0])
        self.assertEqual(result['device_map']['cpu_native']['status'], 'unavailable')
        self.assertEqual(result['device_map']['devices']['status'], 'measured')
        self.assertTrue(any('devices' in value['device_map'] and 'cpu_native' not in value['device_map'] for value in saved))

    def test_native_helper_pin_is_enforced_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lumen-cpuinfo').write_bytes(b'not an executable')
            (root / 'cpu-helper-linux.json').write_text(json.dumps({'schema': 'lumen-cpu-helper/1', 'sha256': 'a' * 64}))
            with patch.object(hw.subprocess, 'run', side_effect=AssertionError('must not execute')):
                result = hw.cpu_native(root)
            self.assertEqual(result['status'], 'unavailable')
            self.assertIn('hash mismatch', result['error'])

    def test_compiled_linux_cpuid_uses_existing_validated_schema(self):
        root = Path(__file__).resolve().parents[1]
        if not (root / 'bin/lumen-cpuinfo').is_file():
            self.skipTest('build the Linux CPUID helper to execute its integration check')
        result = hw.cpu_native()
        self.assertIn(result['status'], ('measured', 'partial'), result)
        self.assertEqual(result['value']['schema'], 'nm-cpuinfo/1')
        sample = result['value']['per_logical_processor']
        self.assertGreater(sample['visited'], 0)
        self.assertTrue(sample['affinity_restored'])

    def test_imported_reports_do_not_bind_to_host_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'Report.json'
            report.write_text('{}')
            with patch.object(engine.sys, 'platform', 'linux'), patch.object(engine, 'boot_epoch', return_value=99999999999):
                self.assertIsNone(engine.stale_scan_message(str(report)))

    def test_linux_scan_boot_identity_prevents_stale_use(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'Report.json'
            report.write_text(json.dumps({'Linux Scan': {'boot_id': 'earlier'}}))
            with patch.object(engine.sys, 'platform', 'linux'), patch.object(hw, 'boot_identity', return_value={'boot_id': 'now'}):
                self.assertIn('earlier boot', engine.stale_scan_message(str(report)))

    def test_wsl_refusal_retains_failed_scan_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(scan.platform, 'system', return_value='Linux'), patch.object(hw, 'is_wsl', return_value=True):
                self.assertEqual(scan._child(directory), 1)
            receipt = json.loads((Path(directory) / scan_evidence.RECEIPT).read_text())
            self.assertEqual(receipt['scan_status'], 'failed')
            self.assertEqual(receipt['failure_type'], 'wsl_virtual_hardware')
            self.assertFalse((Path(directory) / 'Report.json').exists())


class Nvidia(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cc'):
            raise unittest.SkipTest('A C compiler is needed for real vendor ABI fixture tests')
        root = Path(__file__).resolve().parents[1]
        if not all((root / 'tests/native' / ('fake_' + vendor + '.c')).is_file() for vendor in ('nvml', 'cuda')):
            raise unittest.SkipTest('Run ABI fixture tests from the development checkout with tests/native')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.libraries = {}
        for vendor in ('nvml', 'cuda'):
            destination = Path(cls.temporary.name) / ('libfake_' + vendor + '.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-o', str(destination),
                            str(root / 'tests/native' / ('fake_' + vendor + '.c'))],
                           check=True, capture_output=True, timeout=30)
            cls.libraries[vendor] = ctypes.CDLL(str(destination))

    @classmethod
    def tearDownClass(cls):
        cls.libraries.clear()
        cls.temporary.cleanup()

    def test_linux_adapter_joins_real_abi_results_and_never_reads_uuid(self):
        saved = []
        with patch.object(hw, 'open_vendor_library', side_effect=lambda vendor: (self.libraries[vendor], '/fixture/' + vendor)), \
             patch.object(hw, '_nvidia_summary', return_value={'status': 'unavailable', 'devices': []}):
            result = hw.nvidia_inventory(checkpoint=lambda value: saved.append(json.loads(json.dumps(value))))
        self.assertEqual(result['status'], 'measured')
        devices = {device['pci_address']: device for device in result['devices']}
        self.assertEqual(set(devices), {'0000:01:00.0', '0000:2a:00.0', '0000:05:00.0'})
        first = devices['0000:01:00.0']
        self.assertEqual(first['cuda']['multiprocessor_count']['value'], 82)
        self.assertEqual(first['nvml']['vram_bytes']['value'], 25769803776)
        self.assertEqual(first['tensor_cores']['status'], 'unavailable')
        self.assertEqual(ctypes.c_int.in_dll(self.libraries['nvml'], 'uuid_calls').value, 0)
        self.assertEqual(saved[1]['nvml'], 'ok')
        self.assertEqual(saved[1]['cuda'], 'not queried')
        self.assertEqual(len(saved[1]['devices']), 3)

    def test_cuda_failure_preserves_nvml_observations(self):
        from p1401 import hwcapture
        with patch.object(hw, 'open_vendor_library', side_effect=lambda vendor: (self.libraries[vendor], '/fixture/' + vendor)), \
             patch.object(hw, '_nvidia_summary', return_value={'status': 'unavailable', 'devices': []}), \
             patch.object(hwcapture, 'cuda_devices', side_effect=OSError('driver unavailable')):
            result = hw.nvidia_inventory()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['nvml'], 'ok')
        self.assertIn('driver unavailable', result['cuda'])
        self.assertEqual(len(result['devices']), 3)
        self.assertTrue(all('nvml' in device and 'cuda' not in device for device in result['devices']))


class NvidiaLoader(unittest.TestCase):
    def test_missing_libraries_remain_unavailable(self):
        with patch.object(hw, 'open_vendor_library', return_value=(None, 'not installed')), \
             patch.object(hw, '_nvidia_summary', return_value={'status': 'unavailable', 'devices': []}):
            result = hw.nvidia_inventory()
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['devices'], [])

    def test_loader_refuses_overrides_and_unknown_library_names(self):
        with patch.object(hw.ctypes, 'CDLL', side_effect=AssertionError('must not load')), \
             patch.dict(os.environ, {'LD_LIBRARY_PATH': '/untrusted'}):
            self.assertIsNone(hw.open_vendor_library('cuda')[0])
            self.assertIsNone(hw.open_vendor_library('../other')[0])

    def test_loader_refuses_library_outside_system_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'libcuda.so.1'
            path.write_bytes(b'fixture')
            path.chmod(0o555)
            self.assertIsNone(hw._trusted_vendor_file(path))

    def test_loader_refuses_writable_or_user_owned_parent(self):
        library = Path('/usr/lib/vendor/libcuda.so.1')
        def info(path):
            mode = stat.S_IFREG | 0o644 if path == library else stat.S_IFDIR | 0o755
            return SimpleNamespace(st_mode=mode, st_uid=0)
        with patch.object(Path, 'resolve', return_value=library), patch.object(Path, 'stat', autospec=True, side_effect=info):
            self.assertEqual(hw._trusted_vendor_file(library), library)
        for bad in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000)):
            with patch.object(Path, 'resolve', return_value=library), \
                 patch.object(Path, 'stat', autospec=True, side_effect=lambda path: bad if path == library.parent else info(path)):
                self.assertIsNone(hw._trusted_vendor_file(library))


if __name__ == '__main__':
    unittest.main()
