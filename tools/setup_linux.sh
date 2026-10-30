#!/bin/sh
set -eu
lumen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$lumen_root"
python3 - <<'PY'
import platform
import sys
if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
    raise SystemExit('Lumen requires Linux x86_64.')
if sys.version_info < (3, 12):
    raise SystemExit('Install Python 3.12 or newer before setting up Lumen.')
PY
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
printf '%s\n' 'Python environment ready. Run ./lumen.' 'For USB writing and ACPI reads, install system dependencies and run: sudo python3 tools/install_linux.py'
