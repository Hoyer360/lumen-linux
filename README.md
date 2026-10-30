# Lumen for Linux

[简体中文](README.zh-CN.md) · [Downloads](https://github.com/Hoyer360/lumen-linux/releases) · [Validation records](docs/LINUX-FEATURES.md)

Lumen is an independent Linux adaptation of [1401 v2.6.4](https://github.com/nullmoth/1401). It builds macOS recovery installation media using the upstream EFI engine, with a native English/Chinese Qt interface.

**Experimental, noncommercial, and unofficial.** Physical USB devices, native ACPI capture, and macOS installation/GPU operation still need target-machine acceptance testing. Development includes AI-assisted code. Lumen is not endorsed by NullMoth.

## Download and run

Download `lumen-0.1.0-linux-x86_64.run` and `SHA256SUMS.txt` from [Releases](https://github.com/Hoyer360/lumen-linux/releases/tag/v0.1.0).

```bash
sha256sum --ignore-missing -c SHA256SUMS.txt
chmod +x lumen-0.1.0-linux-x86_64.run
./lumen-0.1.0-linux-x86_64.run
```

The executable is a **self-extracting installer**, not a standalone bundled Python/Qt binary. It installs under `~/.local/share/lumen/app-0.1.0` (or `$XDG_DATA_HOME/lumen`), creates a Python virtual environment, downloads the pinned Python dependencies from PyPI, and launches Lumen. The first run requires internet. Run it as your normal user.

For manual installation, extract `lumen-0.1.0-linux-x86_64.tar.gz` into an empty directory, or clone this repository:

```bash
git clone https://github.com/Hoyer360/lumen-linux.git
cd lumen-linux
./tools/setup_linux.sh
.venv/bin/python tools/fetch_assets.py
./lumen
```

Before creating media, run `tools/fetch_assets.py` with the installed `.venv/bin/python`. This downloads the unchanged Mac companion and NVIDIA packages directly from the author's release and verifies pinned SHA256 hashes. Neither those archives nor Apple recovery images are hosted in this repository or release.

## Requirements

- Native Linux x86_64; Python 3.12–3.15; glibc 2.34 or newer.
- X11 or Wayland desktop with a running polkit authentication agent.
- Internet for dependency downloads and Apple recovery; an erasable USB drive of at least 4 GiB.

Ubuntu 24.04/26.04 or Debian 13:

```bash
sudo apt install python3 python3-venv pciutils usbutils util-linux fdisk dosfstools mtools pkexec libegl1 libgl1 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxkbcommon-x11-0
```

Arch Linux:

```bash
sudo pacman -S --needed python python-pip pciutils usbutils util-linux dosfstools mtools polkit libxcb xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm libxkbcommon-x11 mesa
```

Ubuntu 24.04 CI and Arch/WSL2 development checks have passed. Other listed distributions are installation targets, not a claim of complete hardware validation. WSL can import target-machine reports, build EFI and export images; it cannot scan the physical target PC's firmware.

## USB access and ACPI

From the extracted or installed application directory:

```bash
sudo python3 tools/install_linux.py
./lumen status
```

This installs the restricted, root-owned helper into `/usr/lib/lumen`, `/usr/libexec/lumen-helper`, and its polkit policy. **Do not run `sudo ./lumen`.** GUI, downloads and file preparation run as your normal user. Reinstall the matching helper after an application update or rollback when prompted.

To remove the helper: `sudo python3 tools/install_linux.py --uninstall`. User data remains intact.

## Workflow and features

1. Scan the target PC from native Linux, or import its Hardware Sniffer `Report.json` and `ACPI` directory.
2. Choose macOS 15 Sequoia or macOS 26 Tahoe and build the EFI. Review experimental driver options deliberately.
3. Read the hardware-specific Linux firmware guide. Unknown settings remain unknown; firmware changes are manual.
4. Select the USB by model, capacity and device identity, then explicitly confirm erasure. Files are prepared and verified before erasing.
5. The writer formats, copies, flushes, remounts read-only, verifies the files and Apple chunklist, then unmounts. System disks and dependent devices are protected.
6. Boot the USB through UEFI and select macOS recovery. Recovery normally still needs internet. Use the original Mac companion on the USB after macOS starts.

Additional tools include EFI inspection/repair, boot-log diagnosis, rebuilds using boot logs, installer-image export, NVML/CUDA diagnostics, driver updates, verified local application updates/rollback, and redacted diagnostic exports.

## CLI

```bash
./lumen status
./lumen disks
./lumen import-scan /path/to/report-directory
./lumen build --macos 24
./lumen guide --macos 24
./lumen efi-check /path/to/efi-parent
./lumen diagnose --log /path/to/opencore-log.txt
./lumen export-logs /path/to/diagnostics.zip
```

Darwin `24` means macOS 15; `25` means macOS 26. `--request` and `--worker` expose structured operations. A bare device path is insufficient to authorize erasure.

## Data and updates

User data lives under `$XDG_DATA_HOME/lumen` (normally `~/.local/share/lumen`); caches use `$XDG_CACHE_HOME/lumen`. `LUMEN_HOME` overrides the data directory. Reports stay local unless you explicitly upload to a configured HTTPS endpoint. No hosted diagnostic receiver or automatic Linux update feed is configured. GitHub Releases provides manual downloads; verified archive installation and rollback are available in the app.

## Validation

- 92 Linux tests, including native ABI fixtures and actual FAT32 image round trips; GitHub CI passes on Ubuntu 24.04.
- Two real Intel/AMD hardware-report builds passed `ocvalidate` with zero issues.
- Apple recovery was downloaded and signature/chunk verified. A 4 GiB exported image booted to the OpenCore recovery picker in QEMU/OVMF.
- A Linux guest exercised actual block-device formatting, user writes, read-only verification and cleanup with 512/4096-byte sectors. Host physical disks were not used.
- The original development tree ran 767 upstream tests, with 11 conditional skips. This curated repository carries the Linux suite and its C fixtures.

See [detailed records](docs/LINUX-FEATURES.md) and [evidence](docs/verification). These checks do not establish physical USB, native firmware or macOS GPU compatibility.

```bash
.venv/bin/python -B -m unittest discover -s tests_linux -t . -v
QT_QPA_PLATFORM=offscreen .venv/bin/python -m linux_maker.gui --smoke-test
python3 tools/package_linux.py
python3 tools/package_run.py
```

## License and attribution

Derived from [nullmoth/1401](https://github.com/nullmoth/1401) and integrated with [nullmoth/nvidia-macos-driver](https://github.com/nullmoth/nvidia-macos-driver). The upstream code and Linux adaptation retain **PolyForm Noncommercial 1.0.0**; third-party components retain their own terms. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), and [licenses](licenses).

The required original copyright notice is preserved. Lumen uses independent branding and does not claim trademark rights or official affiliation. Driver and Mac companion assets are downloaded unchanged from upstream. Apple recovery comes directly from Apple; Apple's license terms apply.

## 中文说明

Lumen 是基于 1401 的非官方、非商业 Linux 移植版，提供中英文界面。请从 [Releases](https://github.com/Hoyer360/lumen-linux/releases) 下载 `.run` 可执行安装器或 `.tar.gz` 手动安装包。`.run` 首次运行会解压、创建 Python 环境并联网安装依赖，并非免依赖单文件程序。

制作介质前需安装系统依赖、运行 `tools/fetch_assets.py` 获取原作者组件，以及安装受限 helper。物理 USB、原生 ACPI 和 macOS 安装仍需实机验收。完整中文步骤见 [README.zh-CN.md](README.zh-CN.md)。
