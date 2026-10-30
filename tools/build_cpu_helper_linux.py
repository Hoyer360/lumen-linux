#!/usr/bin/env python3
"""Compile the fixed Linux CPUID helper and write its adjacent integrity pin."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    if platform.machine().lower() not in ('x86_64', 'amd64'):
        raise SystemExit('The CPUID helper requires x86_64')
    cc = shutil.which('cc') or shutil.which('gcc')
    if not cc:
        raise SystemExit('Install a C compiler (gcc/clang)')
    destination = ROOT / 'bin'
    destination.mkdir(exist_ok=True)
    temporary = destination / 'lumen-cpuinfo.part'
    binary = destination / 'lumen-cpuinfo'
    subprocess.run([cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-D_FORTIFY_SOURCE=2', '-fstack-protector-strong', '-fPIE', '-pie',
                    '-Wl,-z,relro,-z,now', str(ROOT / 'native/cpu/nm_cpuinfo_core.c'),
                    str(ROOT / 'native/cpu/nm_cpuinfo_linux.c'), '-o', str(temporary)],
                   check=True, timeout=60)
    temporary.replace(binary)
    pin = {'schema': 'lumen-cpu-helper/1', 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
           'platform': 'linux-x86_64', 'source': ['native/cpu/nm_cpuinfo_core.c', 'native/cpu/nm_cpuinfo_linux.c']}
    (destination / 'cpu-helper-linux.json').write_text(json.dumps(pin, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
