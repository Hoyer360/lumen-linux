#!/usr/bin/env python3
"""Wrap the verified portable archive in an executable, user-local installer."""
import hashlib
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from linux_maker import __version__

def main():
    archive = ROOT / 'dist' / f'lumen-{__version__}-linux-x86_64.tar.gz'
    data = archive.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    script = r'''#!/bin/sh
set -eu
if [ "$(id -u)" = 0 ]; then echo 'Run Lumen as your normal user, not root.' >&2; exit 1; fi
case "${1:-}" in
  --help) echo 'Usage: ./lumen-VERSION-linux-x86_64.run [--extract DIRECTORY]'; exit 0 ;;
  --extract) [ "$#" = 2 ] || { echo 'Specify one new extraction directory.' >&2; exit 1; }; lumen_target=$2; lumen_extract=1 ;;
  '') lumen_target=${XDG_DATA_HOME:-$HOME/.local/share}/lumen/app-VERSION; lumen_extract=0 ;;
  *) echo 'Unknown option; use --help.' >&2; exit 1 ;;
esac
lumen_self=$(readlink -f -- "$0")
lumen_tmp=$(mktemp -d)
trap 'rm -rf -- "$lumen_tmp"' EXIT HUP INT TERM
lumen_line=$(awk '/^__LUMEN_ARCHIVE_BELOW__$/ { print NR + 1; exit }' "$lumen_self")
tail -n +"$lumen_line" "$lumen_self" > "$lumen_tmp/package.tar.gz"
printf '%s  %s\n' 'DIGEST' "$lumen_tmp/package.tar.gz" | sha256sum -c -
if [ -e "$lumen_target" ] || [ -L "$lumen_target" ]; then
    echo "Destination exists: $lumen_target" >&2
    echo 'Launch its ./lumen or use --extract with a new directory.' >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$lumen_target")"
mkdir -- "$lumen_target"
tar -xzf "$lumen_tmp/package.tar.gz" -C "$lumen_target" --no-same-owner
printf 'Extracted Lumen to %s\n' "$lumen_target"
[ "$lumen_extract" = 1 ] && exit 0
cd "$lumen_target"
./tools/setup_linux.sh
printf '%s\n' 'Before creating media: .venv/bin/python tools/fetch_assets.py' 'For USB/ACPI access, follow README.md to install system dependencies and the helper.'
rm -rf -- "$lumen_tmp"
trap - EXIT HUP INT TERM
exec ./lumen
exit 0
__LUMEN_ARCHIVE_BELOW__
'''.replace('VERSION', __version__).replace('DIGEST', digest)
    target = archive.with_name(f'lumen-{__version__}-linux-x86_64.run')
    target.write_bytes(script.encode() + data)
    target.chmod(0o755)
    sums = ROOT / 'dist/SHA256SUMS.txt'
    sums.write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in (archive, target)))
    print(target)
if __name__ == '__main__':
    main()
