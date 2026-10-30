"""Cross-module regressions from the independent implementation review."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from linux_maker import reports, service, updates
from p1401 import engine, scan_evidence


def archive(path, version='0.2.0', platform='linux-x86_64'):
    files = {'linux_maker/__init__.py': f'__version__ = "{version}"\n'.encode(),
             'linux_maker/__main__.py': b'print("fixture")\n', 'lumen': b'#!/bin/sh\nexit 0\n'}
    manifest = {'schema': 'lumen-package/1', 'platform': platform, 'version': version,
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    files['RELEASE-MANIFEST.json'] = json.dumps(manifest).encode()
    with tarfile.open(path, 'w:gz') as output:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            output.addfile(item, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest(), files


class ReviewRegressions(unittest.TestCase):
    def test_password_bearer_and_ipv6_are_removed_from_log_strings(self):
        cleaned = reports.clean('password=hunter2 IPv6 2001:db8::1234 Authorization: Bearer abcDEF123')
        for secret in ('hunter2', '2001:db8::1234', 'abcDEF123'):
            self.assertNotIn(secret, cleaned)

    def test_export_does_not_overwrite_an_input_report(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            path = Path(folder) / 'selected.log'
            path.write_text('original report')
            with self.assertRaises((ValueError, OSError)):
                reports.export(path, [path])
            self.assertEqual(path.read_text(), 'original report')

    def test_archive_platform_is_checked(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            path = Path(folder) / 'wrong-platform.tar.gz'
            digest, _ = archive(path, platform='windows-x86_64')
            with self.assertRaises(ValueError):
                updates.install_archive(path, digest)
            self.assertFalse((Path(folder) / 'current').exists())

    def test_reinstall_does_not_activate_modified_existing_release(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            path = Path(folder) / 'release.tar.gz'
            digest, files = archive(path)
            first = updates.install_archive(path, digest)
            installed = Path(first['path'])
            (installed / 'lumen').write_text('modified after initial verification')
            try:
                updates.install_archive(path, digest)
            except ValueError:
                return  # Rejecting tampered cache is also a safe supported outcome.
            self.assertEqual((installed / 'lumen').read_bytes(), files['lumen'])

    def test_first_update_can_return_to_original_launcher(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            path = Path(folder) / 'release.tar.gz'
            digest, _ = archive(path)
            updates.install_archive(path, digest)
            updates.install_archive(path, digest)
            self.assertTrue((Path(folder) / 'current').is_symlink())
            self.assertEqual(updates.rollback()['path'], 'original launcher')
            self.assertFalse((Path(folder) / 'current').exists())

    def test_changed_online_release_never_downloads_after_confirmation(self):
        info = {'configured': True, 'available': True, 'version': '0.3.0', 'sha256': 'a'*64, 'url':'https://example.com/release.tar.gz'}
        with patch.object(updates, 'check', return_value=info), patch.object(updates, 'fetch') as fetch:
            with self.assertRaisesRegex(ValueError, 'changed'):
                updates.update_app('https://example.com/release.json', expected_version='0.2.0', expected_sha256='a'*64)
            fetch.assert_not_called()

    def test_repeated_scan_uses_new_attempt_not_existing_receipt(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            def fixture_scan(directory):
                root = Path(directory)
                token = scan_evidence.begin(root)
                (root / 'Report.json').write_text(json.dumps({'CPU': {'fixture': True}}))
                scan_evidence.finish(root, token, True)
                return str(root)
            with patch('p1401.scan.scan', side_effect=fixture_scan):
                first = service.dispatch({'action': 'scan'})
                second = service.dispatch({'action': 'scan'})
            self.assertTrue(Path(first['scan']).is_dir())
            self.assertTrue(Path(second['scan']).is_dir())

    def test_imported_linux_scan_is_usable_as_offline_input(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LUMEN_HOME': folder}):
            source = Path(folder) / 'original'
            source.mkdir()
            (source / 'ACPI').mkdir()
            (source / 'ACPI/DSDT.aml').write_bytes(b'DSDT' + bytes(40))
            original = {'CPU': {'fixture': True}, 'GPU': {'fixture': True}, 'Motherboard': {'fixture': True},
                        'Linux Scan': {'boot_id': 'different-machine'}}
            (source / 'Report.json').write_text(json.dumps(original))
            imported = service.import_scan({'source': str(source)})
            with patch.object(engine.sys, 'platform', 'linux'):
                self.assertIsNone(engine.stale_scan_message(str(Path(imported['scan']) / 'Report.json')))


if __name__ == '__main__':
    unittest.main()
