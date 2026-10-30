# Linux 功能与验证记录

这是实现及验证状态表，不是实机兼容性保证。开发环境：Arch Linux、Python 3.14.8、Qt/PySide6 6.12.0、WSL2 x86_64。

| 功能 | 实现 | 当前证据 / 尚需验证 |
|---|---|---|
| 六步桌面向导、中英文、浅/深主题、缩放、进度、取消 | Qt 原生界面 | offscreen 和实际 WSLg/X11 启动、中文截图、子进程取消清理测试；需原生桌面完整交互验收 |
| 扫描/导入及 ACPI | Linux sysfs/udev/DRM + 现有 Sniffer；受限 ACPI helper | 固件解析、重复 SSDT、Secure Boot 二进制读取、报告绑定测试；WSL 正确拒绝虚拟硬件扫描 |
| CPU/PCI/GPU/网络/外设诊断 | Linux 数据源、CPUID、安装的 NVML/CUDA 及来源记录 | 本机实测 32 个逻辑 CPU、RTX 4090 Laptop 的 76 个 SM 与约 16 GiB 显存；未公开的 RT/Tensor 数量如实不可用 |
| EFI 构建、规则、kext、SSDT、SMBIOS | 共用原版引擎，Linux iasl/macserial/ocvalidate | OptiPlex 5050 + macOS 15、X570/5800X/RX6600XT + macOS 26 已完成构建和 ocvalidate 0 issues |
| BIOS 指南与独立固件检查 | 共用指南规则、独立品牌 | 两套 EFI 构建生成指南；未知值不冒充关闭 |
| EFI 医生、修复预览与备份 | 原版 efidoctor + GUI | 上游回归及 GUI 接口检查 |
| 启动日志及停止行诊断、据日志重建 | 原版 bootfix/diagnose + GUI | 上游规则回归；本地导出测试 |
| USB 枚举、保护、擦除、FAT32、复制与读回 | Linux 后端 + root 所有的 helper | QEMU Linux 客体内真实块设备流程通过：512/4096 扇区，系统盘拒绝、USB 格式化、uid 1000 写入、只读回验及会话清理；物理 USB 尚未运行 |
| Apple 恢复、签名 chunklist、续传 | 原版下载及 Linux payload 准备 | 真实下载 960,530,321 字节恢复镜像并通过 Apple 签名/分块校验；恢复安装通常需要网络 |
| 磁盘镜像导出 | MBR/FAT32 + mtools + 文件读回校验 | 导出 4 GiB 镜像、读回成功，在 QEMU/OVMF 启动到 OpenCore，识别 LUMEN 恢复项 |
| Mac 配套应用及 NVIDIA 驱动随盘 | 固定发行包与 SHA256 | 本地包哈希通过；macOS 安装/驱动加载尚需实机 |
| 驱动更新 | 上游 release + SHA256SUMS，缓存及已有 USB 更新 | 后续制作会采用选中的配对版本；损坏包/版本不匹配拒绝测试；新版与硬件兼容性仍由上游决定 |
| 应用更新及回滚 | Linux 清单、归档约束、哈希、用户目录原子指针 | 恶意归档/版本检查测试；公共更新频道尚未发布 |
| 日志保存、脱敏、导出、用户选择上传 | 本地报告模块与 HTTPS 上传接口 | 脱敏及拒绝无同意上传测试；托管接收服务未配置 |
| 打包和安装 | 独立 launcher、锁定 Python 依赖、helper/polkit 安装器、portable tar | staging 安装与发行归档验证；未在当前会话安装 root helper |

Windows 专属观测（例如 D3D12 特性、Windows 注册表记录、BitLocker 当前保护状态）在 Linux 无等价实测时显示不可用，可导入带来源的旧报告，不能声称字段完全一致。

开发期间没有擦写主机物理磁盘、修改 BIOS、修改系统 EFI 分区或上传本机诊断信息。虚拟机的格式化仅作用于新建的临时普通文件所模拟的 USB。

可复查证据保存在 `docs/verification/`：中文桌面截图、QEMU 启动截图、去掉终端控制序列的启动日志，以及两套 EFI / 恢复镜像校验摘要。测试报告的完整硬件信息、生成的 SMBIOS 身份和 Apple 恢复文件不放入发行包。

特权写盘集成测试的重现步骤与边界见 `tools/helper_qemu/README.md`。实际块设备测试修正了两个普通文件测试无法暴露的问题：sfdisk 与持有的独占 FD 冲突、mkfs.fat 自身的独占打开与外层独占 FD 冲突。修正后 512 与 4096 字节扇区的全流程均通过；桌面自动挂载、物理热拔插和 polkit 交互仍需原生实机验证。

最终回归：Linux 专属测试 92 项全部通过（包括真实 mkfs.fat/mtools 镜像往返）；上游测试共 767 项，11 项按平台/条件跳过，其余通过。命令与环境见 README，机器可读摘要见 `docs/verification/tests.json`。
