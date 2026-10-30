from pathlib import Path
import shutil,subprocess,os,re,stat
import argparse
parser=argparse.ArgumentParser(description='Build a disposable file-backed helper integration guest; no host mounts')
parser.add_argument('--work', type=Path, required=True, help='Prepared scratch directory holding extracted kernel and busybox')
parser.add_argument('--mkfs-fat', type=Path, required=True, help='mkfs.fat executable to copy into the guest')
args=parser.parse_args()
base=args.work.resolve()
if not (base/'kernel/usr/lib/modules/7.2.11-arch1-1/vmlinuz').is_file():raise SystemExit('Extract pinned kernel package first; see README')
root=base/'root';root.mkdir(exist_ok=True)
for name in ('usr/bin','usr/lib','usr/lib64','etc','proc','sys','dev','run','tmp','root','home/tester','usr/lib/lumen/linux_maker','usr/libexec','lib/modules','mnt'):(root/name).mkdir(parents=True,exist_ok=True)
for name,target in [('bin','usr/bin'),('sbin','usr/bin'),('usr/sbin','bin')]:
 p=root/name
 if not p.exists():p.symlink_to(target)
# Keep /lib and /lib64 actual dirs to avoid source trust path surprises.
(root/'lib64').mkdir(exist_ok=True)
busy=base/'busybox/usr/bin/busybox';shutil.copy2(busy,root/'usr/bin/busybox')
for name in ('sh','poweroff','sleep','insmod','chown','chmod','mkdir','cat','echo','ls','mdev'):
 (root/'usr/bin'/name).unlink(missing_ok=True);(root/'usr/bin'/name).symlink_to('busybox')
seen=set()
def copy_binary(source):
 source=Path(source)
 if str(source) in seen:return
 seen.add(str(source));dest=root/str(source).lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest);dest.chmod(0o755)
 proc=subprocess.run(['ldd',str(source)],capture_output=True,text=True)
 for lib in re.findall(r'(?:=>\s+)?(/[^\s]+)',proc.stdout):
  path=Path(lib)
  if path.is_file():copy_binary(path)
for name in ('python3','blkid','lsblk','findmnt','sfdisk','wipefs','mount','umount','blockdev','sync'):
 copy_binary('/usr/bin/'+name)
shutil.copytree('/usr/lib/python3.14',root/'usr/lib/python3.14',dirs_exist_ok=True,ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','tkinter','idlelib','turtledemo','ensurepip'))
for extension in (root/'usr/lib/python3.14/lib-dynload').glob('*.so'):
 original=Path('/')/extension.relative_to(root)
 for lib in re.findall(r'(?:=>\s+)?(/[^\s]+)',subprocess.run(['ldd',str(original)],capture_output=True,text=True).stdout):
  if Path(lib).is_file():copy_binary(lib)
# dosfstools extracted locally, copy to standard guest pathname.
source=args.mkfs_fat.resolve();shutil.copy2(source,root/'usr/bin/mkfs.fat')
for lib in re.findall(r'(?:=>\s+)?(/[^\s]+)',subprocess.run(['ldd',str(source)],capture_output=True,text=True).stdout):
 if Path(lib).is_file():copy_binary(lib)
project=Path(__file__).resolve().parents[2]
for name in ('__init__.py','privileged.py','disks.py','hardware.py'):
 shutil.copy2(project/'linux_maker'/name,root/'usr/lib/lumen/linux_maker'/name)
(root/'usr/libexec/lumen-helper').write_text('#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/lumen/linux_maker/privileged.py "$@"\n');(root/'usr/libexec/lumen-helper').chmod(0o755)
(root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\ntester:x:1000:1000:tester:/home/tester:/bin/sh\n')
(root/'etc/group').write_text('root:x:0:\ntester:x:1000:\n')
(root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
(root/'etc/mtab').unlink(missing_ok=True);(root/'etc/mtab').symlink_to('/proc/self/mounts')
modules=base/'kernel/usr/lib/modules/7.2.11-arch1-1/kernel'
for name in ('drivers/usb/storage/usb-storage.ko.zst','fs/fat/fat.ko.zst','fs/fat/vfat.ko.zst','fs/nls/nls_iso8859-1.ko.zst'):
 dst=root/'lib/modules'/Path(name).name.removesuffix('.zst')
 with dst.open('wb') as f:subprocess.run(['zstd','-d','-c',str(modules/name)],stdout=f,check=True)
(root/'init').write_text('''#!/bin/sh
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs -o mode=755 tmpfs /run
chmod 1777 /tmp
chown -R 0:0 /usr /etc /lib /lib64 /init /guest_test.py
chmod 755 /usr /usr/lib /usr/lib/lumen /usr/lib/lumen/linux_maker /usr/libexec
for m in /lib/modules/*.ko; do insmod "$m"; done
sleep 3
/usr/bin/python3 -u /guest_test.py
sync
poweroff -f
''');(root/'init').chmod(0o755)
shutil.copy2(Path(__file__).with_name('guest_test.py'),root/'guest_test.py')
image=base/'root.img'
if image.exists():image.unlink()
with image.open('wb') as f:f.truncate(1<<30)
subprocess.run(['mkfs.ext4','-F','-q','-d',str(root),str(image)],check=True)
# mkfs -d preserves host uid on root; normalize root and parent directories for trust checks.
commands=base/'debugfs.commands'
commands.write_text('\n'.join('set_inode_field '+p+' uid 0\nset_inode_field '+p+' gid 0' for p in ['/','/usr','/usr/lib','/usr/lib/lumen','/usr/lib/lumen/linux_maker','/usr/libexec','/run'])+'\n')
subprocess.run(['debugfs','-w','-f',str(commands),str(image)],check=True,capture_output=True)
usb=base/'usb.img'
if not usb.exists():
 with usb.open('wb') as f:f.truncate(5<<30)
print('guest ready',image)
