import unittest
from unittest import mock
from linux_maker import disks


def node(path, mm, **kwargs):
    return {'name': path, 'maj:min': mm, 'type': 'disk', 'size': 8 * disks.GIB,
            'log-sec': 512, 'mountpoints': [], 'serial': 'serial-' + mm, **kwargs}


def root_mount(mm='8:1'):
    return {'filesystems': [{'source': '/dev/sda1', 'target': '/', 'maj:min': mm, 'fstype': 'ext4'}]}


def parse(rows, mounts=None, **kwargs):
    return disks.parse_inventory({'blockdevices': rows}, mounts or root_mount(), sysfs=None, **kwargs)


def system():
    return node('/dev/sda', '8:0', children=[node('/dev/sda1', '8:1', type='part', fstype='ext4', mountpoints=['/'])])


class DiskTests(unittest.TestCase):
    def test_usb_ssd_does_not_require_removable_bit(self):
        disk = parse([system(), node('/dev/sdb', '8:16', tran='usb', rm=False)])[1]
        self.assertTrue(disk['eligible'])
        self.assertFalse(disk['removable'])

    def test_root_disk_is_protected_even_when_usb(self):
        disk = parse([node('/dev/sda', '8:0', tran='usb', children=[node('/dev/sda1', '8:1', type='part')])])[0]
        self.assertTrue(disk['protected'])
        self.assertFalse(disk['eligible'])

    def test_luks_lvm_root_protects_physical_parent(self):
        root = node('/dev/dm-1', '253:1', type='lvm')
        crypt = node('/dev/dm-0', '253:0', type='crypt', children=[root])
        part = node('/dev/sda2', '8:2', type='part', children=[crypt])
        disk = parse([node('/dev/sda', '8:0', tran='usb', children=[part])], root_mount('253:1'))[0]
        self.assertTrue(disk['protected'])
        self.assertFalse(disk['eligible'])

    def test_raid_root_protects_all_members(self):
        md = node('/dev/md0', '9:0', type='raid1')
        rows = [node('/dev/sda', '8:0', tran='usb', children=[md]), node('/dev/sdb', '8:16', tran='usb', children=[dict(md)])]
        self.assertTrue(all(d['protected'] for d in parse(rows, root_mount('9:0'))))

    def test_swap_protects_device(self):
        disk = parse([system(), node('/dev/sdb', '8:16', tran='usb')], swaps=['/dev/sdb'])[1]
        self.assertFalse(disk['eligible'])

    def test_unresolved_overlay_root_refuses_all_devices(self):
        disk = parse([node('/dev/sdb', '8:16', tran='usb')], root_mount('0:99'))[0]
        self.assertFalse(disk['eligible'])
        self.assertIn('cannot resolve', ';'.join(disk['reasons']))

    def test_external_automount_can_be_unmounted_but_system_mount_cannot(self):
        disk = node('/dev/sdb', '8:16', tran='usb', children=[node('/dev/sdb1', '8:17', type='part', mountpoints=['/run/media/alice/USB'])])
        self.assertTrue(parse([system(), disk])[1]['eligible'])
        disk['children'][0]['mountpoints'] = ['/run/live/medium']
        self.assertFalse(parse([system(), disk])[1]['eligible'])

    def test_encrypted_or_os_volume_needs_separate_confirmation(self):
        disk = parse([system(), node('/dev/sdb', '8:16', tran='usb', children=[node('/dev/sdb1', '8:17', type='part', fstype='crypto_LUKS')])])[1]
        self.assertTrue(disk['eligible'])
        self.assertTrue(disk['requires_os_confirmation'])
        with mock.patch.object(disks, 'list_disks', return_value=[disk]):
            with self.assertRaisesRegex(disks.DiskError, 'existing operating-system'):
                disks.select_disk(disk['path'], disk['fingerprint'])
            self.assertEqual(disks.select_disk(disk['path'], disk['fingerprint'], erase_os=True), disk)

    def test_readonly_is_never_overridable(self):
        disk = parse([system(), node('/dev/sdb', '8:16', tran='usb', ro=True)])[1]
        with mock.patch.object(disks, 'list_disks', return_value=[disk]):
            with self.assertRaisesRegex(disks.DiskError, 'read-only'):
                disks.select_disk(disk['path'], disk['fingerprint'], allow_large=True, erase_os=True)

    def test_replacement_same_path_and_size_is_not_accepted(self):
        original = node('/dev/sdb', '8:16', tran='usb', serial='first')
        disk = parse([system(), original])[1]
        replacement = parse([system(), {**original, 'serial': 'second'}])[1]
        with mock.patch.object(disks, 'list_disks', return_value=[replacement]):
            with self.assertRaisesRegex(disks.DiskError, 'changed or disappeared'):
                disks.select_disk(disk['path'], disk['fingerprint'])

    def test_partition_changes_invalidate_selection(self):
        original = node('/dev/sdb', '8:16', tran='usb')
        before = parse([system(), original])[1]
        after = parse([system(), {**original, 'children': [node('/dev/sdb1', '8:17', type='part')]}])[1]
        self.assertNotEqual(before['fingerprint'], after['fingerprint'])

    def test_current_efi_partition_protects_its_disk(self):
        uuid = '12345678-1234-1234-1234-123456789abc'
        rows = [system(), node('/dev/sdb', '8:16', tran='usb', children=[node('/dev/sdb1', '8:17', type='part', partuuid=uuid)])]
        self.assertTrue(parse(rows, boot_partuuid=uuid)[1]['protected'])

    def test_unknown_efi_boot_disk_refuses_write(self):
        self.assertFalse(parse([system(), node('/dev/sdb', '8:16', tran='usb')], boot_unknown=True)[1]['eligible'])

    def test_root_probes_missing_udev_filesystem_metadata(self):
        import subprocess
        blocks = {'blockdevices': [node('/dev/sdb1', '8:17', type='part')]}
        response = subprocess.CompletedProcess([], 0, 'TYPE=crypto_LUKS\nPART_ENTRY_TYPE=0x83\nPART_ENTRY_UUID=abcd-01\n', '')
        with mock.patch.object(disks.os, 'geteuid', return_value=0), mock.patch.object(disks, 'tool', return_value='/usr/bin/blkid'), mock.patch.object(disks.subprocess, 'run', return_value=response):
            disks.probe_missing_metadata(blocks)
        row = blocks['blockdevices'][0]
        self.assertEqual(row['fstype'], 'crypto_LUKS')
        self.assertEqual(row['parttype'], '0x83')

    def test_unreadable_filesystem_metadata_is_not_a_blank_disk(self):
        import subprocess
        blocks = {'blockdevices': [system(), node('/dev/sdb', '8:16', tran='usb')]}
        with mock.patch.object(disks.os, 'geteuid', return_value=0), mock.patch.object(disks, 'tool', return_value='/usr/bin/blkid'), mock.patch.object(disks.subprocess, 'run', return_value=subprocess.CompletedProcess([], 4, '', 'permission denied')):
            disks.probe_missing_metadata(blocks)
        parsed = disks.parse_inventory(blocks, root_mount(), sysfs=None)
        self.assertFalse(parsed[1]['eligible'])
        self.assertIn('metadata could not be inspected', '; '.join(parsed[1]['reasons']))

    def test_large_capacity_confirmation(self):
        disk = parse([system(), node('/dev/sdb', '8:16', tran='usb', size=512*disks.GIB)])[1]
        self.assertTrue(disk['requires_large_confirmation'])
        with mock.patch.object(disks, 'list_disks', return_value=[disk]):
            with self.assertRaisesRegex(disks.DiskError, 'large disks'):
                disks.select_disk(disk['path'], disk['fingerprint'])


if __name__ == '__main__':
    unittest.main()
