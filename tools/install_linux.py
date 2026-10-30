#!/usr/bin/env python3
"""Install only reviewed, root-owned helper modules and the polkit action."""
import argparse
import os
from pathlib import Path
import shutil
import stat

ROOT = Path(__file__).resolve().parent.parent


def install_directory(path):
    """Normalize app-owned/new directories, never chmod existing system parents."""
    path = Path(path)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise SystemExit('Refusing linked installation directory: ' + str(parent))
        if not parent.exists():
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise SystemExit('Invalid installation directory: ' + str(path))
    path.mkdir(mode=0o755, exist_ok=True)
    path.chmod(0o755)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--destdir', type=Path, help='Build a package staging tree without root')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    if args.destdir is None and os.geteuid() != 0:
        parser.error('Install with sudo python3 tools/install_linux.py, or use --destdir for packaging.')
    base = args.destdir or Path('/')
    package = base / 'usr/lib/lumen/linux_maker'
    wrapper = base / 'usr/libexec/lumen-helper'
    policy = base / 'usr/share/polkit-1/actions/org.lumen.helper.policy'
    if args.uninstall:
        shutil.rmtree(package.parent, ignore_errors=True)
        wrapper.unlink(missing_ok=True); policy.unlink(missing_ok=True)
        print('Removed the Lumen privileged helper and policy. User data was preserved.')
        return
    install_directory(package.parent)
    install_directory(package)
    # Do not place a GUI, downloader, arbitrary Python environment or executable request paths in this service.
    names = ['__init__.py', 'disks.py', 'privileged.py', 'hardware.py']
    for name in names:
        source = ROOT / 'linux_maker' / name
        if not source.is_file(): raise SystemExit('Missing helper component: ' + name)
        if (package / name).is_symlink():
            raise SystemExit('Refusing linked helper module: ' + str(package / name))
        shutil.copyfile(source, package / name)
        (package / name).chmod(0o644)
    # Only create missing system parents; their existing permissions are not ours to change.
    for target in (wrapper, policy):
        if target.is_symlink():
            raise SystemExit('Refusing linked installation file: ' + str(target))
        for parent in target.parents:
            if parent.is_symlink():
                raise SystemExit('Refusing linked installation directory: ' + str(parent))
        if not target.parent.exists():
            install_directory(target.parent)
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/lumen/linux_maker/privileged.py "$@"\n')
    wrapper.chmod(0o755)
    shutil.copyfile(ROOT / 'packaging/org.lumen.helper.policy', policy); policy.chmod(0o644)
    if args.destdir is None:
        for path in [package.parent, package, *package.iterdir(), wrapper, policy]: os.chown(path, 0, 0)
    print('Installed helper into ' + str(base))


if __name__ == '__main__': main()
