# Disposable Linux helper integration

This development harness uses only ordinary files on the host. It boots a stock Linux kernel with an ext4 root image and an emulated USB disk, installs the actual root-owned helper inside the guest, and runs actual util-linux/dosfstools commands. It never passes a host block device to QEMU and requires no privileged host mounts or loop devices.

Verified on 2026-10-31 with Arch Linux userspace, Python 3.14.8 and QEMU/KVM. It covers 512-byte and 4096-byte logical sectors. Host tools: Python, ldd, tar/zstd, mkfs.ext4, debugfs, qemu-system-x86_64. The builder copies the host Python stdlib and its shared libraries; this harness targets the current Arch development environment rather than providing a portable VM distribution.

Extract these upstream packages into a private scratch directory (the corresponding `kernel/` and `busybox/` directories below). Do not run extracted binaries with host root privileges.

| Package | Upstream source | SHA256 observed |
|---|---|---|
| linux-7.2.11.arch1-1-x86_64.pkg.tar.zst | https://geo.mirror.pkgbuild.com/core/os/x86_64/linux-7.2.11.arch1-1-x86_64.pkg.tar.zst | `768377c62afada6cc04c48c9a281d8cb648cc7afc7b7c328c2c9072ba03085ff` |
| busybox-1.36.1-4-x86_64.pkg.tar.zst | https://geo.mirror.pkgbuild.com/extra/os/x86_64/busybox-1.36.1-4-x86_64.pkg.tar.zst | `14b14151bbc901c6e0c7cbb21fa73db2540df91cdea2a0ff1caf20be2cd8c333` |

These hashes record the files used in the integration; they do not replace Arch package signatures. Rolling mirror filenames may later disappear; Arch's archive can supply the same package.

Build, using a fresh scratch directory you own:

```sh
python3 tools/helper_qemu/build_guest.py --work /tmp/lumen-helper-guest --mkfs-fat /usr/bin/mkfs.fat
```

If `mkfs.fat` is not installed, an unprivileged extraction of dosfstools is sufficient. `build_guest.py` expects `kernel/usr/lib/modules/7.2.11-arch1-1/` and `busybox/usr/bin/busybox` below the work directory. It replaces only its own `root.img` and creates `usb.img` if absent.

Run the isolated guest (all `-drive file=` arguments below must remain regular scratch files):

```sh
qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -m 1024 -smp 2 \
  -kernel /tmp/lumen-helper-guest/kernel/usr/lib/modules/7.2.11-arch1-1/vmlinuz \
  -append 'root=/dev/vda rw init=/init console=ttyS0 panic=1' \
  -drive file=/tmp/lumen-helper-guest/root.img,format=raw,if=virtio \
  -device qemu-xhci,id=xhci \
  -drive if=none,id=usbdrive,file=/tmp/lumen-helper-guest/usb.img,format=raw \
  -device usb-storage,drive=usbdrive,bus=xhci.0,serial=LUMEN-TEST-USB \
  -nographic -no-reboot -nic none
```

For 4K sectors, use another new 5 GiB ordinary file as `usbdrive`, and add `logical_block_size=4096,physical_block_size=4096` to usb-storage. Never substitute `/dev/...` host devices.

`guest_test.py` sets `PKEXEC_UID=1000` inside the root guest to exercise the helper authorization boundary without installing a desktop polkit agent. It checks:

- actual guest root disk is protected, emulated USB selected;
- prepare creates one active MBR/FAT32 partition and writable user-owned mount;
- uid 1000 writes and fsyncs a nonempty fixture;
- readback unmounts, flushes, validates MBR/kernel/FAT32 geometry and remounts read-only;
- fixture SHA256 matches; new write is rejected with EROFS;
- session listing contains the operation, close unmounts and removes it, and the final list is empty.

Success ends with `LUMEN_HELPER_INTEGRATION_PASS`. This does not validate real USB bridge firmware, physical hotplug, desktop automount races, polkit UI, UEFI BootCurrent discovery, or installation of macOS.
