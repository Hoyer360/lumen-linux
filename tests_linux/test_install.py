"""Installer permissions must satisfy the privileged helper under common umasks."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from linux_maker import privileged

ROOT = Path(__file__).resolve().parents[1]

class InstallPermissions(unittest.TestCase):
    def install(self, root, mask=0o022):
        return subprocess.run([sys.executable, str(ROOT/'tools/install_linux.py'), '--destdir', str(root)],
                              capture_output=True, text=True, umask=mask)

    def test_fresh_install_has_exact_modes_under_common_umasks(self):
        for mask in (0o022, 0o002, 0o077):
            with self.subTest(umask=mask), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                result=self.install(root,mask)
                self.assertEqual(result.returncode,0,result.stderr)
                for name in ('usr/lib/lumen','usr/lib/lumen/linux_maker','usr/libexec','usr/share/polkit-1/actions'):
                    self.assertEqual(stat.S_IMODE((root/name).stat().st_mode),0o755)
                self.assertEqual(stat.S_IMODE((root/'usr/lib/lumen/linux_maker/privileged.py').stat().st_mode),0o644)

    def test_reinstall_repairs_app_directories_without_changing_system_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            package=root/'usr/lib/lumen/linux_maker'
            package.mkdir(parents=True)
            for path in (package, package.parent):path.chmod(0o777)
            (root/'usr/lib').chmod(0o750)
            result=self.install(root)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(stat.S_IMODE(package.stat().st_mode),0o755)
            self.assertEqual(stat.S_IMODE(package.parent.stat().st_mode),0o755)
            self.assertEqual(stat.S_IMODE((root/'usr/lib').stat().st_mode),0o750)

    def test_symlink_install_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);outside=root/'outside';outside.mkdir();outside.chmod(0o700)
            (root/'usr/lib').mkdir(parents=True)
            (root/'usr/lib/lumen').symlink_to(outside,target_is_directory=True)
            result=self.install(root)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('installation directory',result.stderr)
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode),0o700)
            self.assertEqual(list(outside.iterdir()),[])

    def test_helper_accepts_root_0755_rejects_writable_or_user_owned(self):
        installed=Path('/usr/lib/lumen/linux_maker/privileged.py')
        target=Path('/usr/lib/lumen')
        for mode,uid,accepted in ((0o755,0,True),(0o750,0,True),(0o775,0,False),(0o777,0,False),(0o755,1000,False)):
            def metadata(path):
                return SimpleNamespace(st_mode=(stat.S_IFREG|0o644) if path==installed else stat.S_IFDIR|(mode if path==target else 0o755),st_uid=uid if path==target else 0)
            with self.subTest(mode=mode,uid=uid), patch.object(privileged,'__file__',str(installed)), patch.object(Path,'lstat',autospec=True,side_effect=metadata), patch.object(Path,'is_symlink',return_value=False), patch.object(privileged.os,'walk',return_value=[]):
                if accepted:privileged.trusted_install()
                else:
                    with self.assertRaisesRegex(privileged.HelperError, '/usr/lib/lumen.*uid='):
                        privileged.trusted_install()

if __name__=='__main__':unittest.main()
