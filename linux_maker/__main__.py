"""Lumen desktop launcher and machine-readable worker entrypoint."""
import argparse
import json
import os
from pathlib import Path
import sys


def main(argv=None):
    ap = argparse.ArgumentParser(prog='lumen', description='Lumen Linux macOS installation media maker')
    ap.add_argument('--version', action='store_true')
    ap.add_argument('--worker', action='store_true', help='Read one JSON request on stdin and emit JSON events')
    ap.add_argument('--request', help='JSON request (CLI automation; disk erase still requires confirmed=true)')
    ap.add_argument('--lang', choices=['en','zh-CN'])
    sub = ap.add_subparsers(dest='command')
    for name in ('status', 'disks', 'scan', 'check-update', 'rollback'): sub.add_parser(name)
    for name in ('build','plan','guide','prepare'):
        p = sub.add_parser(name)
        p.add_argument('--scan'); p.add_argument('--build'); p.add_argument('--macos', choices=['24','25'], default='24')
        p.add_argument('--experimental', action='store_true'); p.add_argument('--persistent-nvram', action='store_true')
        p.add_argument('--new-identity', action='store_true'); p.add_argument('--boot-log', action='append', default=[])
        p.add_argument('--stopped-at', default=''); p.add_argument('--recovery-dir'); p.add_argument('--bios-only', action='store_true')
    p = sub.add_parser('import-scan'); p.add_argument('source')
    p = sub.add_parser('efi-check'); p.add_argument('path'); p.add_argument('--fix', action='store_true'); p.add_argument('--report')
    p = sub.add_parser('diagnose'); p.add_argument('--log', action='append', default=[]); p.add_argument('--stopped-at', default=''); p.add_argument('--report')
    p = sub.add_parser('export-logs'); p.add_argument('path')
    p = sub.add_parser('update-driver'); p.add_argument('--root', action='append', default=[])
    p = sub.add_parser('update-app'); p.add_argument('--source'); p.add_argument('--archive'); p.add_argument('--sha256')
    p.add_argument('--expected-version'); p.add_argument('--expected-sha256')
    args = ap.parse_args(argv)
    if args.version:
        from . import __version__
        print('Lumen ' + __version__); return 0
    if args.lang: os.environ['A1401_LANG'] = args.lang
    if args.worker or args.request or args.command:
        if args.worker:
            raw = sys.stdin.buffer.readline(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024: raise ValueError('Request exceeds 1 MiB')
            request = json.loads(raw)
        elif args.request: request = json.loads(args.request)
        else:
            request = vars(args); request['action'] = request.pop('command')
            request['boot_logs'] = request.pop('boot_log', [])
            request['logs'] = request.pop('log', [])
            request['roots'] = request.pop('root', [])
        if not isinstance(request, dict): raise ValueError('Request must be an object')
        from .service import run
        import signal
        def cancelled(signum, frame): raise KeyboardInterrupt('Task cancelled')
        signal.signal(signal.SIGTERM, cancelled)
        output = sys.stdout
        def emit(event):
            output.write(json.dumps(event, ensure_ascii=False, default=str) + '\n'); output.flush()
        return run(request, emit)
    from .gui import main as gui_main
    return gui_main(['--language', args.lang] if args.lang else [])


if __name__ == '__main__':
    raise SystemExit(main())
