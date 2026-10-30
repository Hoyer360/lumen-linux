import json,os,subprocess,time,traceback,hashlib
from pathlib import Path
os.chdir('/home/tester')
os.environ['PKEXEC_UID']='1000'
def helper(request):
 p=subprocess.run(['/usr/libexec/lumen-helper'],input=json.dumps(request),text=True,capture_output=True,timeout=240)
 print('HELPER',request['action'],'RC',p.returncode,p.stdout,p.stderr,flush=True)
 result=json.loads(p.stdout)
 if not result.get('ok'):raise RuntimeError(result)
 return result
try:
 print('GUEST_START',flush=True)
 disks=helper({'action':'disks'})['disks']
 print('INVENTORY',json.dumps(disks),flush=True)
 usb=[d for d in disks if d['tran']=='usb' and d['eligible']]
 assert len(usb)==1,usb
 disk=usb[0]
 s=helper({'action':'prepare','device':disk['path'],'fingerprint':disk['fingerprint'],'confirm':'ERASE'})
 root=Path(s['mountpoint'])
 # Exercise actual writable mount under the desktop user identity.
 child=os.fork()
 if child==0:
  os.setgid(1000);os.setuid(1000)
  path=root/'EFI/BOOT';path.mkdir(parents=True)
  with (path/'fixture.bin').open('wb') as f:
   f.write(b'LUMEN-READBACK-FIXTURE'*65536);f.flush();os.fsync(f.fileno())
  os._exit(0)
 assert os.waitpid(child,0)[1]==0
 expected=hashlib.sha256(b'LUMEN-READBACK-FIXTURE'*65536).hexdigest()
 checked=helper({'action':'readback','token':s['token']})
 assert checked['geometry_verified'] and checked['read_only']
 assert hashlib.sha256((root/'EFI/BOOT/fixture.bin').read_bytes()).hexdigest()==expected
 try:(root/'no-write').write_text('must fail')
 except OSError as e:print('READONLY_REFUSAL',e,flush=True)
 else:raise AssertionError('volume was not read-only')
 sessions=helper({'action':'sessions'})['sessions'];assert len(sessions)==1
 helper({'action':'close','token':s['token']})
 assert helper({'action':'sessions'})['sessions']==[]
 print('LUMEN_HELPER_INTEGRATION_PASS',flush=True)
except BaseException:
 traceback.print_exc()
 print('LUMEN_HELPER_INTEGRATION_FAIL',flush=True)
