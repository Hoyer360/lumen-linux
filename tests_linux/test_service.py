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


class Services(unittest.TestCase):
    def test_diagnosis_preserves_top_level_findings_and_linux_instructions(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'opencore.txt'
            log.write_text('OC: Driver HfsPlus.efi at 0 cannot be found\n')
            result = service.dispatch({'action': 'diagnose', 'logs': [str(log)]})
        self.assertIsInstance(result['findings'], list)
        self.assertEqual(result['findings'][0]['id'], 'hfsplus-missing')
        self.assertIn('Lumen on Linux', ' '.join(result['findings'][0]['steps']))
        self.assertIn('cpu', result)

    def test_redaction_preserves_pci_but_removes_identity(self):
        value=reports.clean({'SystemSerialNumber':'SECRET123','GPU':'10DE-2D05','path':str(Path.home())+'/file', 'log':'ip 192.168.1.1 mac aa:bb:cc:dd:ee:ff'})
        self.assertEqual(value['SystemSerialNumber'],'<redacted>')
        self.assertEqual(value['GPU'],'10DE-2D05')
        self.assertNotIn(str(Path.home()),value['path'])
        self.assertNotIn('192.168.1.1',value['log'])
        self.assertNotIn('aa:bb',value['log'])

    def test_write_requires_confirmation_before_preparation(self):
        with patch('linux_maker.service.stage_payload') as stage:
            with self.assertRaisesRegex(ValueError,'confirmation'):
                service.dispatch({'action':'write'})
            stage.assert_not_called()

    def test_write_refuses_outdated_privileged_helper_before_preparation(self):
        with patch('linux_maker.writer.HELPER', Path(__file__)), patch('linux_maker.service.helper_status', return_value={'matches_app': False}), patch('linux_maker.service.stage_payload') as stage:
            with self.assertRaisesRegex(RuntimeError, 'differs from this app'):
                service.dispatch({'action': 'write', 'confirmed': True})
            stage.assert_not_called()

    def test_upload_requires_explicit_consent(self):
        with patch('linux_maker.reports.upload') as upload:
            with self.assertRaisesRegex(ValueError,'consent'):
                service.dispatch({'action':'upload-logs','path':'x','endpoint':'https://example.com'})
            upload.assert_not_called()

    def test_failure_event_retains_local_report(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'LUMEN_HOME':folder}):
            events=[]
            code=service.run({'action':'does-not-exist'},events.append)
            self.assertEqual(code,1)
            result=events[-1]
            self.assertFalse(result['ok'])
            self.assertTrue(Path(result['log']).is_file())
            self.assertIn('Unknown operation',result['error'])

    def test_updates_do_not_default_to_windows(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'LUMEN_HOME':folder}):
            value=updates.check()
            self.assertFalse(value['configured'])
            self.assertFalse(value['available'])

    def test_update_rejects_archive_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'LUMEN_HOME':folder}):
            for linked in (False,True):
                archive=Path(folder)/'evil.tar.gz'
                with tarfile.open(archive,'w:gz') as output:
                    member=tarfile.TarInfo('link' if linked else '../escape')
                    if linked: member.type=tarfile.SYMTYPE;member.linkname='/tmp'
                    output.addfile(member)
                digest=hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError,'unsafe'):
                    updates.install_archive(archive,digest)
            self.assertFalse((Path(folder)/'current').exists())

    def test_upload_refuses_credentials_and_plain_http(self):
        for endpoint in ('http://example.com','https://user:pass@example.com'):
            with self.assertRaises(ValueError):reports.upload('missing',endpoint)


if __name__=='__main__':unittest.main()
