import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
from linux_maker import writer, privileged
from linux_maker.disks import DiskError, GIB


class WriterTests(unittest.TestCase):
    def test_root_metadata_revalidation_keeps_local_source_protection(self):
        local = {'path': '/dev/fixture', 'fingerprint': 'unprivileged', 'identity': {'diskseq': '10'},
                 'mountpoints': [], 'partitions': [{'path': '/dev/fixture1', 'size': 123, 'fstype': ''}],
                 'protected': True, 'reasons': ['contains source payload', 'cannot identify the EFI partition used for the current boot']}
        elevated = {**local, 'fingerprint': 'authorized', 'protected': False, 'reasons': [],
                    'partitions': [{'path': '/dev/fixture1', 'size': 123, 'fstype': 'vfat'}]}
        with mock.patch.object(writer, 'list_disks', return_value=[local]), mock.patch.object(writer, 'authorized_disks', return_value=[elevated]):
            merged = writer.revalidate_selection('/dev/fixture', 'authorized', '/payload')[0]
            self.assertEqual(merged['fingerprint'], 'authorized')
            self.assertEqual(merged['reasons'], ['contains source payload'])
            self.assertTrue(merged['protected'])
            self.assertFalse(merged['eligible'])
            elevated['identity'] = {'diskseq': '11'}
            self.assertEqual(writer.revalidate_selection('/dev/fixture', 'authorized', '/payload')[0]['fingerprint'], 'unprivileged')

    def test_mbr_layout_contains_bootable_fat32_and_correct_lba(self):
        start, length = writer.partition_layout(4 * GIB)
        data = writer.mbr(start, length)
        self.assertEqual(len(data), 512)
        self.assertEqual(data[510:], b'\x55\xaa')
        self.assertEqual(data[446], 0x80)
        self.assertEqual(data[450], 0x0c)
        self.assertEqual(struct.unpack_from('<II', data, 454), (2048, length))
        self.assertLess(start + length, 4 * GIB // 512)

    def test_image_partition_is_capped_and_small_images_refused(self):
        self.assertEqual(writer.partition_layout(64 * GIB)[1] * 512, 16 * GIB)
        with self.assertRaises(DiskError):
            writer.partition_layout(1 * GIB)

    def test_payload_rejects_symbolic_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(DiskError, 'link or special'):
                writer.inventory(root)

    def test_manifest_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / writer.MANIFEST).write_text(json.dumps({'schema': 1, 'files': {'../escape': {'size': 1}}}))
            with self.assertRaisesRegex(DiskError, 'Unsafe'):
                writer.load_manifest(root)

    def test_copy_hash_detects_payload_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            src, dst = root / 'src', root / 'dst'
            src.mkdir(); dst.mkdir()
            files = {'EFI/BOOT/BOOTx64.efi': b'boot', 'EFI/OC/config.plist': b'config',
                     'com.apple.recovery.boot/BaseSystem.dmg': b'image'}
            for name, content in files.items():
                path = src / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            (src / writer.MANIFEST).write_text(json.dumps({'schema': 1, 'files': writer.inventory(src)}))
            (src / 'EFI/BOOT/BOOTx64.efi').write_bytes(b'evil')
            with self.assertRaisesRegex(DiskError, 'changed during copy'):
                writer.copy_payload(src, dst)

    def test_copy_cannot_overwrite_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            src, dst = root / 'src', root / 'dst'
            src.mkdir(); dst.mkdir()
            files = {'EFI/BOOT/BOOTx64.efi': b'boot', 'EFI/OC/config.plist': b'config',
                     'com.apple.recovery.boot/BaseSystem.dmg': b'image'}
            for name, content in files.items():
                path = src / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            (src / writer.MANIFEST).write_text(json.dumps({'schema': 1, 'files': writer.inventory(src)}))
            (dst/'EFI/BOOT').mkdir(parents=True); (dst/'EFI/BOOT/BOOTx64.efi').write_bytes(b'old')
            with self.assertRaisesRegex(DiskError, 'unexpectedly contains'):
                writer.copy_payload(src, dst)
            self.assertEqual((dst/'EFI/BOOT/BOOTx64.efi').read_bytes(), b'old')

    def test_recoveryimage_asset_names_normalize_to_basesystem(self):
        from p1401 import apple, machine_handoff, netsupport, usbwriter
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); build = root / 'build'; assets = root / 'assets'
            (build / 'EFI/OC').mkdir(parents=True); assets.mkdir()
            (build / 'EFI/OC/config.plist').write_bytes(b'fixture')
            companion = assets / writer.MAC_PACKAGE[0]; companion.write_bytes(b'fixture companion')
            profile = {'macos_version': '24.99.99'}
            def recovery(info, target, progress):
                folder = Path(target) / 'com.apple.recovery.boot'; folder.mkdir()
                image, chunklist = folder / 'RecoveryImage.dmg', folder / 'RecoveryImage.chunklist'
                image.write_bytes(b'image'); chunklist.write_bytes(b'chunklist')
                return {'image': str(image), 'chunklist': str(chunklist)}
            with mock.patch.object(machine_handoff, 'verified', return_value=profile), mock.patch.object(machine_handoff, 'copy_to_installer'), mock.patch.object(netsupport, 'needs_local_image', return_value=False), mock.patch.object(apple, 'image_info', return_value={}), mock.patch.object(apple, 'download', side_effect=recovery), mock.patch.object(usbwriter, 'verify_efi_copy'), mock.patch.object(usbwriter, 'needs_nullmoth', return_value=False), mock.patch.object(writer, 'MAC_PACKAGE', (companion.name, writer.sha256(companion))), mock.patch.object(writer, 'verify_payload'):
                payload = writer.prepare_payload(build, assets_dir=assets)
                try:
                    self.assertEqual((payload / 'com.apple.recovery.boot/BaseSystem.dmg').read_bytes(), b'image')
                    self.assertFalse((payload / 'com.apple.recovery.boot/RecoveryImage.dmg').exists())
                finally:
                    import shutil
                    shutil.rmtree(payload)

    def test_updated_driver_and_companion_must_be_matching_verified_release(self):
        from p1401 import machine_handoff
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); build = root / 'build'; assets = root / 'assets'
            build.mkdir(); assets.mkdir()
            driver = assets / 'nullmoth-nvidia-2.6.5.tar.gz'; driver.write_bytes(b'driver')
            mac = assets / '1401-Mac-2.6.4.zip'; mac.write_bytes(b'mac')
            release = {'driver': [driver.name, 'https://example/driver', writer.sha256(driver)],
                       'mac': [mac.name, 'https://example/mac', writer.sha256(mac)]}
            with mock.patch.object(machine_handoff, 'verified', return_value={'macos_version': '24'}):
                with self.assertRaisesRegex(DiskError, 'versions do not match'):
                    writer.prepare_payload(build, assets_dir=assets, release=release)
                release['driver'][2] = '0' * 64
                with self.assertRaisesRegex(DiskError, 'missing or changed'):
                    writer.prepare_payload(build, assets_dir=assets, release=release)

    def test_selected_driver_update_is_read_for_future_media(self):
        from p1401 import machine_handoff
        from linux_maker import paths
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); build = root / 'build'; assets = root / 'selected'
            build.mkdir(); assets.mkdir()
            driver = assets / 'nullmoth-nvidia-2.6.5.tar.gz'; driver.write_bytes(b'driver')
            mac = assets / '1401-Mac-2.6.4.zip'; mac.write_bytes(b'mac')
            release = {'driver': [driver.name, 'https://example/driver', writer.sha256(driver)],
                       'mac': [mac.name, 'https://example/mac', writer.sha256(mac)]}
            (assets / 'driver-release.json').write_text(json.dumps(release))
            with mock.patch.object(machine_handoff, 'verified', return_value={'macos_version': '24'}), mock.patch.object(paths, 'directories', return_value={'payload': assets}):
                with self.assertRaisesRegex(DiskError, 'versions do not match'):
                    writer.prepare_payload(build)

    def test_real_image_tools_round_trip_fixture_payload(self):
        import os
        tools = Path(os.environ.get('LUMEN_TEST_IMAGE_TOOLS', '/nonexistent'))
        if not (tools / 'mkfs.fat').is_file() or not (tools / 'mcopy').is_file():
            self.skipTest('Set LUMEN_TEST_IMAGE_TOOLS to explicit mkfs.fat/mcopy fixture executables')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); payload = root / 'payload'; payload.mkdir()
            files = {'EFI/BOOT/BOOTx64.efi': b'fixture boot', 'EFI/OC/config.plist': b'fixture config',
                     'com.apple.recovery.boot/BaseSystem.dmg': b'fixture recovery',
                     'com.apple.recovery.boot/BaseSystem.chunklist': b'fixture chunklist'}
            for name, content in files.items():
                path = payload / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            (payload / writer.MANIFEST).write_text(json.dumps({'schema': 1, 'files': writer.inventory(payload)}))
            def fixture_verify(payload, root=None, **kwargs):
                manifest = writer.load_manifest(payload)
                self.assertEqual(manifest['files'], writer.inventory(root or payload))
                return manifest
            # Fixtures intentionally have no Apple signature; only this file-format
            # integration test substitutes signature checking, never production.
            with mock.patch.object(writer, 'tool', side_effect=lambda name: str(tools / name)), mock.patch.object(writer, 'verify_payload', side_effect=fixture_verify):
                output = root / 'installer.img'
                result = writer.export_image(payload, output)
                self.assertTrue(result['verified'])
                self.assertEqual(output.stat().st_size, 4 * GIB)
                with output.open('rb') as stream:
                    self.assertEqual(stream.read(512)[510:], b'\x55\xaa')

    def test_geometry_detects_bad_partition_and_fat_sector_size(self):
        start, length = 2048, 131072
        state = {'start': start, 'length': length, 'identity': {'logical_sector': 512}}
        bpb = bytearray(512)
        bpb[510:512] = b'\x55\xaa'; bpb[82:90] = b'FAT32   '; bpb[13] = 1; bpb[16] = 2
        struct.pack_into('<H', bpb, 11, 512); struct.pack_into('<H', bpb, 14, 32)
        struct.pack_into('<I', bpb, 28, start); struct.pack_into('<I', bpb, 32, length); struct.pack_into('<I', bpb, 36, 1024); struct.pack_into('<I', bpb, 44, 2)
        privileged.validate_geometry_bytes(writer.mbr(start, length), bytes(bpb), state)
        with self.assertRaisesRegex(privileged.HelperError, 'partition geometry'):
            privileged.validate_geometry_bytes(writer.mbr(start + 1, length), bytes(bpb), state)
        struct.pack_into('<H', bpb, 11, 4096)
        with self.assertRaisesRegex(privileged.HelperError, 'FAT32 geometry'):
            privileged.validate_geometry_bytes(writer.mbr(start, length), bytes(bpb), state)

    def test_cancellation_during_prepare_closes_returned_session(self):
        child = mock.Mock()
        child.communicate.side_effect = [KeyboardInterrupt(), (json.dumps({'ok': True, 'token': 'test-token'}), '')]
        child.returncode = 0
        cleanup = mock.Mock()
        cleanup.communicate.return_value = (json.dumps({'ok': True, 'closed': True}), '')
        cleanup.returncode = 0
        with mock.patch.object(writer.HELPER.__class__, 'is_file', return_value=True), mock.patch.object(writer, 'tool', return_value='/usr/bin/pkexec'), mock.patch.object(writer.subprocess, 'Popen', side_effect=[child, cleanup]):
            with self.assertRaises(KeyboardInterrupt):
                writer._helper({'action': 'prepare'})
            self.assertEqual(json.loads(cleanup.communicate.call_args.args[0]), {'action': 'close', 'token': 'test-token'})

    def test_source_checkout_cannot_run_privileged(self):
        with self.assertRaisesRegex(privileged.HelperError, 'Install Lumen'):
            privileged.trusted_install()

    def test_helper_unknown_action_is_rejected(self):
        with self.assertRaisesRegex(privileged.HelperError, 'Unknown'):
            privileged.dispatch({'action': 'shell', 'command': 'id'}, 1000, None)

    def test_helper_erase_requires_explicit_confirmation(self):
        with self.assertRaisesRegex(privileged.HelperError, 'Explicit erase'):
            privileged.prepare({'action': 'prepare'}, 1000, None)

    def test_helper_token_rejects_traversal(self):
        with self.assertRaisesRegex(privileged.HelperError, 'Invalid write session'):
            privileged._state_path('../etc/passwd')


if __name__ == '__main__':
    unittest.main()
