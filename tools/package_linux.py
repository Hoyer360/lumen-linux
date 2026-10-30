#!/usr/bin/env python3
"""Create an audited portable source/runtime-assets release, without user data."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from linux_maker import __version__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, default=ROOT / 'dist')
    ap.add_argument('--include-driver', action='store_true', help='Include the separately licensed 255 MiB driver assets')
    args = ap.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    folders = ['linux_maker','p1401','upstream','packaging','bin','native/cpu','tests_linux','docs/verification','tools/helper_qemu','licenses','tests/native']
    if args.include_driver: folders.append('assets')
    paths = [ROOT / n for n in ('lumen','README.md','README.zh-CN.md','LICENSE','NOTICE.md','LINUX-TOOLS.json','UPSTREAM-BASELINE.json','requirements.txt','requirements-dev.txt')]
    paths += [ROOT / 'tools' / n for n in ('install_linux.py','package_linux.py','setup_linux.sh','build_cpu_helper_linux.py','fetch_assets.py','package_run.py')]
    paths += [ROOT / 'docs/LINUX-FEATURES.md']
    for folder in folders:
        paths.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and not any(x in {'__pycache__','OCK_Files','Results','.git'} for x in p.parts))
    files = {}
    for path in sorted(set(paths)):
        if path.is_symlink(): raise ValueError('Refusing linked release input: ' + str(path))
        if path.is_file(): files[str(path.relative_to(ROOT))] = path.read_bytes()
    manifest = {'schema':'lumen-package/1','version':__version__,'platform':'linux-x86_64',
                'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['RELEASE-MANIFEST.json'] = (json.dumps(manifest,indent=2)+'\n').encode()
    target=args.output/f'lumen-{__version__}-linux-x86_64.tar.gz'
    with tarfile.open(target,'w:gz') as archive:
        for name,data in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(data);info.mtime=0;info.uid=info.gid=0
            info.mode=0o755 if name=='lumen' or name.endswith(('macserial.linux','/iasl','lumen-cpuinfo','.sh')) else 0o644
            archive.addfile(info,io.BytesIO(data))
    with target.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    (args.output/'SHA256SUMS.txt').write_text(f'{digest}  {target.name}\n')
    print(target);print(digest)


if __name__=='__main__':main()
