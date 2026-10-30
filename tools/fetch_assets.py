#!/usr/bin/env python3
"""Fetch unchanged companion assets directly from the upstream release, hash checked."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from linux_maker.updates import fetch
from linux_maker.writer import MAC_PACKAGE, sha256
from p1401.nullmoth import PACKAGE

def main():
    target = ROOT / 'assets'
    target.mkdir(exist_ok=True)
    companion = {'name': MAC_PACKAGE[0], 'sha256': MAC_PACKAGE[1],
                 'url': 'https://github.com/nullmoth/nvidia-macos-driver/releases/download/v2.6.4/' + MAC_PACKAGE[0]}
    for record in (companion, PACKAGE):
        path = target / record['name']
        if not path.is_file() or sha256(path) != record['sha256']:
            print('Downloading from upstream:', record['name'], flush=True)
            fetch(record['url'], path, record['sha256'])
        print('SHA256 verified:', record['name'])
if __name__ == '__main__':
    main()
