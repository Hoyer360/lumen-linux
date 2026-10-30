# Lumen Linux macOS 制作器

[English](README.md) · [下载 Releases](https://github.com/Hoyer360/lumen-linux/releases)

可下载 `.run` 可执行安装器：校验 SHA256 后运行 `chmod +x lumen-0.1.0-linux-x86_64.run`，再执行它。安装器解压到 `~/.local/share/lumen/app-0.1.0`，创建虚拟环境、联网安装 Python 依赖并启动界面。它不是免依赖的独立二进制程序。制作前仍需运行安装目录内的 `.venv/bin/python tools/fetch_assets.py`，并按下文安装系统依赖与 helper。

Lumen 是基于 1401 v2.6.4 的独立 Linux 移植工程。它使用原版 Python EFI 引擎和规则，提供中英文 Qt 桌面向导、Linux 硬件检测、恢复介质制作、EFI 检查修复、启动诊断、驱动更新及本地日志。

这是非官方、非商业的派生项目，保留上游 PolyForm Noncommercial 1.0.0 许可及各组件声明。当前为实验版本，尚未完成物理 USB 与 macOS 安装实机验收。Linux 移植代码包含 AI 辅助开发成果。

## 获取与启动

```bash
git clone https://github.com/Hoyer360/lumen-linux.git
cd lumen-linux
./tools/setup_linux.sh
.venv/bin/python tools/fetch_assets.py
./lumen status
./lumen
```

驱动及 Mac 配套应用从原作者发行页直接下载并核验固定 SHA256，不由本仓库重新托管。系统依赖及受限 helper 的安装方法见下文。

支持目标为原生 Linux x86_64，Python 3.12–3.15、glibc 2.34 或更新版本，具有 X11 或 Wayland 桌面。推荐 Ubuntu 24.04/26.04、Debian 13 或当前 Arch；这些发行版属于安装目标，当前完成测试的是 Arch/WSL2。WSL 可以导入目标电脑的 `Report.json` 和 `ACPI` 目录来构建 EFI、运行诊断及导出镜像；WSL 的虚拟硬件不代表目标 PC，因此“检测本机”会明确拒绝它。

## 系统依赖与特权 helper

Arch Linux：

```bash
sudo pacman -S --needed python python-pip pciutils usbutils util-linux dosfstools mtools polkit libxcb xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm libxkbcommon-x11 mesa
```

Ubuntu 24.04/26.04 / Debian 13：

```bash
sudo apt install python3 python3-venv pciutils usbutils util-linux fdisk dosfstools mtools pkexec libegl1 libgl1 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxkbcommon-x11-0
```

桌面必须运行 polkit 认证代理。USB 格式化、挂载和受限 ACPI 读取需要一次性安装 root 所有的 helper：

```bash
sudo python3 tools/install_linux.py
```

安装位置为 `/usr/lib/lumen`、`/usr/libexec/lumen-helper` 和 `/usr/share/polkit-1/actions/org.lumen.helper.policy`。界面和下载仍以普通用户运行；不要使用 `sudo ./lumen`。helper 拒绝从用户可写的源码目录以 root 执行。

`bin/lumen-cpuinfo` 的 GLIBC 符号需求最高为 2.34。需要自行编译时，安装 gcc/clang 后运行 `python3 tools/build_cpu_helper_linux.py`，它同时生成新的完整性校验记录。

卸载 helper：

```bash
sudo python3 tools/install_linux.py --uninstall
```

## 完整制作流程

1. 在将要安装 macOS 的电脑上启动原生 Linux，运行“检测本机”；也可以导入那台电脑的 Hardware Sniffer 报告和 ACPI。
2. 选择 macOS 15 Sequoia 或 macOS 26 Tahoe，以及需要的实验驱动，构建 EFI。依赖从上游下载并校验，结果使用匹配版本的 `ocvalidate.linux` 检查。
3. 查看为报告生成的 BIOS 指南。缺失的固件数据会显示未知，不能视为设置已关闭。
4. 选择 USB，检查型号、容量和设备路径，确认擦除。程序先准备并校验恢复镜像和 payload，再授权清理所选 USB。系统盘、swap 和依赖设备受到保护。
5. 写入后卸载、刷新块设备缓冲并只读重新挂载，核验文件及 Apple 签名 chunklist；校验和最终卸载成功后才显示完成。
6. UEFI 启动 USB，进入 Apple Recovery 安装 macOS。恢复安装通常仍需要网络。进入 macOS 后，在 USB 的 `NullMoth` 目录运行原版 Mac 配套应用。

制作需要原版 `1401-Mac-2.6.4.zip` 和 `nullmoth-nvidia-2.6.4.tar.gz`，不修改其中的 macOS 软件。NVIDIA 支持范围和硬件验证情况以驱动上游说明为准。

工具菜单提供 EFI 医生、启动日志诊断、固件前置检查、驱动更新、应用更新、日志导出和组件许可。写盘和修复均需要用户在界面确认。

## CLI

```bash
./lumen status
./lumen disks
./lumen import-scan /path/to/target-report-directory
./lumen build --macos 24
./lumen guide --macos 24
./lumen efi-check /path/to/efi-parent
./lumen diagnose --log /path/to/opencore-log.txt
./lumen export-logs /path/to/lumen-diagnostics.zip
```

`--macos 24` 表示 macOS 15，`25` 表示 macOS 26，沿用上游 Darwin 版本编号。GUI 显示系统商品名。

`--request '{"action": ...}'` 和 `--worker` 提供结构化任务接口；worker 从 stdin 读取一个 JSON 请求并输出 JSON 事件。物理写盘请求需要当前磁盘指纹和明确确认，CLI 不接受一个裸 `/dev/sdX` 就擦除。

## 数据与更新

工作文件默认在 `$XDG_DATA_HOME/lumen`（通常为 `~/.local/share/lumen`），缓存在 `$XDG_CACHE_HOME/lumen`。可用 `LUMEN_HOME` 指定独立工作目录。原始报告仅本地保存；导出的诊断会脱敏。上传必须由用户触发并配置 HTTPS 接收端，本工程没有开通托管日志服务，也不会自动上传到原作者服务。

应用更新使用独立的 Linux 发布清单，拒绝 Windows 包。支持校验本地发布包、安装到用户 releases 目录、原子切换及回滚；尚未建立公共 Linux 更新频道。驱动更新仍查询原驱动项目的发行包，新下载的配对版本会用于后续制作。未知硬件 API 字段不会伪造为 Windows 检测结果。

应用更新或回滚后，如果系统 helper 与当前版本不一致，写盘会暂停并提示重新安装。进入更新结果显示的版本目录，运行 `sudo python3 tools/install_linux.py`；用户目录更新不会悄悄替换 root 程序。新机器解压发行包后先运行 `./tools/setup_linux.sh`，再按上文安装系统依赖和 helper。

## 验证与当前边界

详见 [功能与验证记录](docs/LINUX-FEATURES.md)。已完成两套真实报告的 EFI 构建并通过 ocvalidate，从 Apple 下载并校验恢复镜像，导出 4 GiB 安装镜像，并在 QEMU/OVMF 中启动到 OpenCore、识别到恢复安装项。

写盘 helper 也已在独立 Linux 虚拟机内通过真实块设备流程：512/4096 字节扇区的模拟 USB 格式化、普通用户写入、只读回验、卸载清理，以及系统盘拒绝。主机端只使用临时普通文件，未擦写真实 USB。

当前 WSL2 环境不能验证原生固件采集、真实 USB 擦写、UEFI 实机启动及 macOS GPU 驱动加载。原生 Linux 的 USB 操作代码已实现，但在这些实机项目完成之前，不应把本版称为所有电脑均可用或完全验证的稳定发行版。`out/` 下的示例 EFI/镜像只对应测试报告中的硬件，不应拿来直接安装当前电脑。

本仓库的验证与打包命令如下。767 项上游测试结果来自整理前完整开发工作区；公开仓库保留 Linux 测试及其 C ABI 夹具：

```bash
.venv/bin/python -m unittest discover -s tests_linux -t . -v

QT_QPA_PLATFORM=offscreen .venv/bin/python -m linux_maker.gui --smoke-test
python3 tools/package_linux.py
```

## 来源与许可

上游：[nullmoth/1401](https://github.com/nullmoth/1401)、[nullmoth/nvidia-macos-driver](https://github.com/nullmoth/nvidia-macos-driver)。源码基线文件记录在 `UPSTREAM-BASELINE.json`，本地 Linux 工具记录在 `LINUX-TOOLS.json`。

主要自有代码采用 PolyForm Noncommercial 1.0.0，第三方组件保持各自许可证。见 [LICENSE](LICENSE) 和 [NOTICE.md](NOTICE.md)。Lumen 使用独立名称与界面，不是 NullMoth 官方发行版；随盘附带的未修改驱动和 Mac 应用保留其原有名称与通知。
