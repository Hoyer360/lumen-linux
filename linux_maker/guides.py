"""Linux-host installation instructions using the upstream firmware-setting rules.

This module changes instructions, never firmware or another operating system.
Saved/imported observations remain visibly distinct from a current Linux scan.
"""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path

from p1401 import guide as upstream, loc, scan_evidence

Step = upstream.Step

ZH = {
    "Lumen installation guide": "Lumen 安装指南",
    "Lumen firmware prerequisites": "Lumen 固件前置条件",
    "Independent Linux edition · based on 1401": "独立 Linux 版 · 基于 1401",
    "Target and report provenance": "目标机器与报告来源",
    "This guide describes the target in the selected hardware report and generated EFI. It does not establish macOS compatibility or prove that an attached USB belongs to that target.": "本指南描述所选硬件报告及生成 EFI 中的目标机器。它不能证明 macOS 兼容性，也不能证明接入的 U 盘属于该目标机器。",
    "This is an explicitly imported hardware report. Its saved bytes match the import receipt; its hardware and firmware settings were not measured on this Linux host for this guide.": "这是明确导入的硬件报告。保存的文件与导入记录匹配；本指南没有在当前 Linux 主机上重新测量报告中的硬件与固件设置。",
    "This report matches a completed local Linux scan from the current boot. It records observations at scan time; later firmware changes still require a new scan and build.": "此报告匹配当前启动期间已完成的本地 Linux 扫描。它记录扫描时的观察结果；之后若修改固件设置，仍需重新扫描并构建。",
    "This is a saved or unbound report. It is not verified as a fresh scan of this Linux host. Confirm that its hardware and firmware settings still describe the target PC.": "这是保存的报告或未绑定当前扫描的报告，不能确认是当前 Linux 主机的新扫描。请确认其中硬件与固件设置仍适用于目标电脑。",
    "Lumen does not change firmware, restart this PC, migrate storage, or suspend BitLocker automatically. You perform the reviewed changes yourself.": "Lumen 不会自动修改固件、重启电脑、迁移存储或暂停 BitLocker。请在核对后自行执行所需操作。",
    "Before you change firmware": "修改固件之前",
    "Back up important files. Use a separate disk for macOS when possible. The macOS installer erases the disk you deliberately select, so identify it by capacity and model before erasing.": "请备份重要文件，尽可能用独立磁盘安装 macOS。macOS 安装程序会清空你明确选择的磁盘，擦除前请根据容量和型号确认目标。",
    "Keep recovery media for every existing operating system. Changing storage mode, CSM or Secure Boot can affect Linux and other installed systems.": "为已有的每个操作系统保留恢复介质。更改存储模式、CSM 或安全启动可能影响 Linux 及其他已安装系统。",
    "Encrypted and dual-boot systems": "加密与多系统电脑",
    "If Windows is installed on this target, save and verify its BitLocker or device-encryption recovery key before changing Secure Boot, TPM-related settings or storage configuration. Linux cannot establish Windows' current BitLocker protection state.": "如果目标电脑安装了 Windows，请在更改安全启动、TPM 相关设置或存储配置前保存并核实 BitLocker 或设备加密恢复密钥。Linux 无法确认 Windows 当前的 BitLocker 保护状态。",
    "If protection must be suspended, do it yourself in Windows using the documented Windows or PC-vendor procedure, and resume protection after confirming normal startup. Lumen does not suspend or resume BitLocker.": "若需要暂停保护，请自行在 Windows 中按 Windows 或电脑厂商的文档操作，并在确认正常启动后恢复保护。Lumen 不会暂停或恢复 BitLocker。",
    "If Linux uses LUKS or TPM-based automatic unlocking, keep a working passphrase or recovery key. Check the distribution's documented recovery procedure before changing measured-boot or firmware settings. Do not disable TPM merely to install macOS.": "如果 Linux 使用 LUKS 或基于 TPM 的自动解锁，请准备可用的密码或恢复密钥。在更改启动度量或固件设置前，核对发行版的恢复流程。不要仅为安装 macOS 而禁用 TPM。",
    "Review the reported startup mode": "核对报告中的启动模式",
    "The selected report records legacy BIOS startup. That observation does not establish whether Windows is installed or how any other operating system starts.": "所选报告记录了传统 BIOS 启动。这不能证明安装了 Windows，也不能确定其他操作系统的启动方式。",
    "This OpenCore installer needs a working UEFI startup path. Before disabling CSM, confirm that each operating system you want to keep can boot in UEFI mode. Follow that system's and the motherboard vendor's documented conversion procedure if conversion is needed.": "此 OpenCore 安装介质需要可用的 UEFI 启动方式。关闭 CSM 前，请确认要保留的每个操作系统都能以 UEFI 模式启动。若需转换，请按照相应系统与主板厂商的文档操作。",
    "No automatic partition conversion is performed. If the firmware has no UEFI support, this installer cannot provide it.": "程序不会自动转换分区。如果固件不支持 UEFI，本安装介质无法补充该能力。",
    "The selected report does not establish the firmware startup mode. Check the target PC's firmware documentation and a fresh native scan before changing CSM.": "所选报告不能确认固件启动模式。更改 CSM 前请核对目标电脑的固件文档并进行新的原生扫描。",
    "Review storage mode before proceeding": "继续前核对存储模式",
    "The report names these storage controllers: {}. Their names do not prove which drive uses them or its current firmware mode.": "报告列出以下存储控制器：{}。名称本身不能证明哪块磁盘使用了它们，也不能确认当前固件模式。",
    "RAID, Intel RST, VMD and Optane arrangements may prevent the macOS installer from seeing its target disk. Do not switch modes blindly: existing RAID volumes or Linux/Windows boot drivers can lose access to data.": "RAID、Intel RST、VMD 与 Optane 配置可能使 macOS 安装程序看不到目标磁盘。不要盲目切换模式：已有 RAID 卷或 Linux/Windows 启动驱动可能失去对数据的访问。",
    "Use the exact PC or motherboard vendor's documented migration procedure, including preparation for every installed operating system. If no safe migration is documented, keep the setting and use a supported alternate storage path or stop.": "请使用对应电脑或主板厂商针对确切型号的迁移流程，包括对每个已安装操作系统的准备。若没有安全迁移文档，请保留原设置，改用受支持的其他存储方式或停止操作。",
    "After an intentional firmware or storage change, verify existing systems still start and their data remains accessible. Run a fresh target-PC scan and rebuild the EFI before relying on the previous report.": "主动修改固件或存储后，请确认已有系统仍能启动且数据可访问。依赖旧报告前，请重新扫描目标电脑并构建 EFI。",
    "Create the macOS recovery USB": "制作 macOS 恢复安装 U 盘",
    "In Lumen, use Create the macOS stick with an erasable USB drive of at least 4 GiB. Review its model, capacity and identity before confirming erasure.": "在 Lumen 的“制作安装 U 盘”中选择一只可清空、至少 4 GiB 的 USB 设备。确认擦除前请核对型号、容量与设备身份。",
    "The installer contains this target's OpenCore files and {} recovery downloaded from Apple with signed chunk verification. Recovery normally downloads the remaining macOS installation over the network.": "安装介质包含目标机器的 OpenCore 文件，以及从 Apple 下载并按签名分块验证的 {} 恢复镜像。恢复环境通常还需联网下载其余 macOS 安装内容。",
    "Have working Ethernet or another network connection supported by macOS Recovery. A bundled graphics driver does not make an unsupported Wi-Fi adapter work in Recovery.": "请准备可工作的以太网或 macOS 恢复环境支持的其他网络连接。随盘携带显卡驱动并不能让恢复环境支持原本不受支持的 Wi-Fi 适配器。",
    "Open firmware setup manually": "手动进入固件设置",
    "Save or photograph this guide before restarting. Close your applications and restart the target PC using your desktop's normal power menu, then press its firmware setup key at power-on.": "重启前请保存本指南或拍照。关闭应用，通过桌面的正常电源菜单重启目标电脑，然后在开机时按固件设置键。",
    "The reported vendor's usual setup key is [[{}]]. Confirm it in the exact model's manual; board revisions may differ.": "报告所示厂商常用的设置键是 [[{}]]。请以确切型号的手册为准，不同主板版本可能不同。",
    "Check the exact model's manual for its setup key (often Del, F2, F10 or F1). Lumen has no automatic restart-into-firmware button.": "请查阅确切型号手册中的设置键（常见为 Del、F2、F10 或 F1）。Lumen 没有自动重启进入固件的按钮。",
    "Apply only the settings below after completing any prerequisite migration. They follow the saved report and generated EFI; unavailable or unmeasured values must be checked in firmware.": "完成所需的前置迁移后，仅应用下列设置。它们依据保存的报告与生成的 EFI；不可获取或未经测量的值必须在固件中核对。",
    "Save and exit firmware (often [[F10]]). Confirm your existing Linux and any other installed systems still boot. This page performs no firmware changes.": "保存并退出固件（常见为 [[F10]]）。确认已有 Linux 及其他已安装系统仍能启动。本页面不会执行固件更改。",
    "Boot the USB manually": "手动从 U 盘启动",
    "Keep the completed USB plugged in. Restart using the desktop's power menu and open the target PC's one-time boot menu.": "保持已制作完成的 U 盘连接。通过桌面电源菜单重启，并打开目标电脑的一次性启动菜单。",
    "The reported vendor's usual boot-menu key is [[{}]]. Select the USB entry marked UEFI; use the exact model's manual if the key differs.": "报告所示厂商常用的启动菜单键是 [[{}]]。请选择标有 UEFI 的 USB 项；若按键不同，请查阅确切型号手册。",
    "Use the boot-menu key from your PC's manual (often F12, F11, F9 or Esc), then select the USB entry marked UEFI.": "使用电脑手册中的启动菜单键（常见为 F12、F11、F9 或 Esc），然后选择标有 UEFI 的 USB 项。",
    "In OpenCore, select the macOS recovery installer, commonly the entry ending in '(dmg)'. This guide does not invoke a Windows startup menu.": "在 OpenCore 中选择 macOS 恢复安装项，通常是以“(dmg)”结尾的项目。本指南不会调用 Windows 启动菜单。",
    "Install macOS on the intended target disk": "在预定目标磁盘安装 macOS",
    "In Disk Utility, choose View -> Show All Devices and identify the disk reserved for macOS. Do not erase a disk or partition containing Linux, Windows or data you want to keep. For a dedicated macOS disk, use APFS and GUID Partition Map.": "在磁盘工具中选择“显示 -> 显示所有设备”，确认预留给 macOS 的磁盘。不要清空包含 Linux、Windows 或需保留数据的磁盘或分区。独立 macOS 磁盘使用 APFS 与 GUID 分区图。",
    "Quit Disk Utility, choose Reinstall macOS, and select the intended macOS volume. Read the installer's target selection before continuing.": "退出磁盘工具，选择“重新安装 macOS”，并选择预定的 macOS 宗卷。继续前核对安装程序显示的目标。",
    "At each restart, boot through the same OpenCore USB and choose macOS Installer until the installed macOS volume appears. Keep the USB as the boot device until you deliberately configure another one.": "每次重启都从同一 OpenCore U 盘启动，选择“macOS Installer”，直到出现已安装的 macOS 宗卷。自行配置其他启动设备之前，请保留此 U 盘作为启动设备。",
    "If this EFI uses the NVIDIA driver, run the supplied Mac companion application after macOS starts. The driver runs in macOS; Linux media creation alone does not validate the GPU.": "如果此 EFI 使用 NVIDIA 驱动，请在 macOS 启动后运行随盘携带的 Mac 配套应用。驱动在 macOS 中运行，仅在 Linux 制作介质不能证明显卡已验证可用。",
    "No EFI has been generated by this prerequisite review. It does not read a boot configuration or change firmware, storage or security settings.": "本次前置条件检查没有生成 EFI，也不会读取启动配置或更改固件、存储与安全设置。",
    "Check the exact target PC and firmware revision before changing a setting. A completed EFI receives its own BIOS guide; this review does not authorize disk erasure.": "更改设置前，请核对确切的目标电脑与固件版本。EFI 构建完成后会生成对应 BIOS 指南；本次检查不授权擦除磁盘。",
    "Contents": "目录",
    "Review before firmware changes": "修改固件前先核对",
    "Print / save as PDF": "打印 / 保存为 PDF",
    "Saved observations, explicit manual steps": "保存的观察结果与明确的手动步骤",
    "This page is self-contained and makes no network requests.": "此页面内容完整，无需网络请求。",
    "Lumen is an independent Linux adaptation of 1401. Upstream code © 2026 NullMoth Systems; each component retains its own license. See LICENSE and NOTICE.md in the application.": "Lumen 是基于 1401 的独立 Linux 移植版。上游代码 © 2026 NullMoth Systems；各组件保留原有许可证。请参阅应用中的 LICENSE 与 NOTICE.md。",
}


def t(text, *args):
    translated = ZH.get(text, loc.t(text)) if loc.language() == "zh" else text
    return translated.format(*args) if args else translated


def provenance(report_path):
    """Read bounded receipts; never upgrade an import to live host observations."""
    path = Path(report_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise upstream.GuideError("A bounded regular hardware report is required")
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise upstream.GuideError("Hardware report exceeds the firmware review limit")
    value = json.loads(data)
    if not isinstance(value, dict): raise upstream.GuideError("Hardware report must be an object")
    digest = hashlib.sha256(data).hexdigest()
    imported = scan_evidence._read(path.parent / "import-source.json") or {}
    if imported.get("kind") == "imported_report" and imported.get("sha256") == digest:
        return "imported"
    receipt = scan_evidence._read(path.parent / scan_evidence.RECEIPT) or {}
    metadata = value.get("Linux Scan") or {}
    if not isinstance(metadata, dict):
        return "saved"
    if (receipt.get("schema") == scan_evidence.SCHEMA and receipt.get("report_sha256") == digest
            and receipt.get("phase") == "complete" and receipt.get("scan_status") == "complete"
            and scan_evidence.RUN_ID.fullmatch(str(receipt.get("run_id", "")))
            and metadata.get("schema") == "lumen-linux-scan/1" and metadata.get("boot_id")):
        from .hardware import boot_identity
        if metadata["boot_id"] == boot_identity().get("boot_id"):
            return "local"
    return "saved"


def context_step(source):
    messages = {
        "imported": "This is an explicitly imported hardware report. Its saved bytes match the import receipt; its hardware and firmware settings were not measured on this Linux host for this guide.",
        "local": "This report matches a completed local Linux scan from the current boot. It records observations at scan time; later firmware changes still require a new scan and build.",
        "saved": "This is a saved or unbound report. It is not verified as a fresh scan of this Linux host. Confirm that its hardware and firmware settings still describe the target PC.",
    }
    return Step(t("Target and report provenance"), [
        t(messages.get(source, messages["saved"])),
        t("This guide describes the target in the selected hardware report and generated EFI. It does not establish macOS compatibility or prove that an attached USB belongs to that target."),
        t("Lumen does not change firmware, restart this PC, migrate storage, or suspend BitLocker automatically. You perform the reviewed changes yourself."),
    ])


def precautions(report):
    steps = [Step(t("Before you change firmware"), [
        t("Back up important files. Use a separate disk for macOS when possible. The macOS installer erases the disk you deliberately select, so identify it by capacity and model before erasing."),
        t("Keep recovery media for every existing operating system. Changing storage mode, CSM or Secure Boot can affect Linux and other installed systems."),
    ]), Step(t("Encrypted and dual-boot systems"), [
        t("If Windows is installed on this target, save and verify its BitLocker or device-encryption recovery key before changing Secure Boot, TPM-related settings or storage configuration. Linux cannot establish Windows' current BitLocker protection state."),
        t("If protection must be suspended, do it yourself in Windows using the documented Windows or PC-vendor procedure, and resume protection after confirming normal startup. Lumen does not suspend or resume BitLocker."),
        t("If Linux uses LUKS or TPM-based automatic unlocking, keep a working passphrase or recovery key. Check the distribution's documented recovery procedure before changing measured-boot or firmware settings. Do not disable TPM merely to install macOS."),
    ], blocker=True)]
    bios = report.get("BIOS") or {}
    mode = str(bios.get("Firmware Type") or "").casefold()
    if mode in {"bios", "legacy"}:
        steps.append(Step(t("Review the reported startup mode"), [
            t("The selected report records legacy BIOS startup. That observation does not establish whether Windows is installed or how any other operating system starts."),
            t("This OpenCore installer needs a working UEFI startup path. Before disabling CSM, confirm that each operating system you want to keep can boot in UEFI mode. Follow that system's and the motherboard vendor's documented conversion procedure if conversion is needed."),
            t("No automatic partition conversion is performed. If the firmware has no UEFI support, this installer cannot provide it."),
        ], blocker=True))
    elif mode != "uefi":
        steps.append(Step(t("Review the reported startup mode"), [
            t("The selected report does not establish the firmware startup mode. Check the target PC's firmware documentation and a fresh native scan before changing CSM."),
        ], blocker=True))
    controllers = upstream._storage_trap(report)
    if controllers:
        steps.append(Step(t("Review storage mode before proceeding"), [
            t("The report names these storage controllers: {}. Their names do not prove which drive uses them or its current firmware mode.", ", ".join(controllers)),
            t("RAID, Intel RST, VMD and Optane arrangements may prevent the macOS installer from seeing its target disk. Do not switch modes blindly: existing RAID volumes or Linux/Windows boot drivers can lose access to data."),
            t("Use the exact PC or motherboard vendor's documented migration procedure, including preparation for every installed operating system. If no safe migration is documented, keep the setting and use a supported alternate storage path or stop."),
            t("After an intentional firmware or storage change, verify existing systems still start and their data remains accessible. Run a fresh target-PC scan and rebuild the EFI before relying on the previous report."),
        ], blocker=True))
    return steps


def build_guide(report, config, *, macos="", disabled_devices=None, source="saved"):
    if not (report.get("Motherboard") or {}).get("Name") or not report.get("CPU"):
        raise upstream.GuideError("The report has no motherboard or CPU; scan or import a complete target report")
    steps = [context_step(source), *precautions(report)]
    steps.append(Step(t("Create the macOS recovery USB"), [
        t("In Lumen, use Create the macOS stick with an erasable USB drive of at least 4 GiB. Review its model, capacity and identity before confirming erasure."),
        t("The installer contains this target's OpenCore files and {} recovery downloaded from Apple with signed chunk verification. Recovery normally downloads the remaining macOS installation over the network.", macos or "macOS"),
        t("Have working Ethernet or another network connection supported by macOS Recovery. A bundled graphics driver does not make an unsupported Wi-Fi adapter work in Recovery."),
    ]))
    keys = upstream.keys(report)
    steps.append(Step(t("Open firmware setup manually"), [
        t("Save or photograph this guide before restarting. Close your applications and restart the target PC using your desktop's normal power menu, then press its firmware setup key at power-on."),
        t("The reported vendor's usual setup key is [[{}]]. Confirm it in the exact model's manual; board revisions may differ.", keys[0]) if keys else
        t("Check the exact model's manual for its setup key (often Del, F2, F10 or F1). Lumen has no automatic restart-into-firmware button."),
        t("Apply only the settings below after completing any prerequisite migration. They follow the saved report and generated EFI; unavailable or unmeasured values must be checked in firmware."),
        t("Save and exit firmware (often [[F10]]). Confirm your existing Linux and any other installed systems still boot. This page performs no firmware changes."),
    ], settings=upstream.bios_settings(report, config, disabled_devices)))
    steps.append(Step(t("Boot the USB manually"), [
        t("Keep the completed USB plugged in. Restart using the desktop's power menu and open the target PC's one-time boot menu."),
        t("The reported vendor's usual boot-menu key is [[{}]]. Select the USB entry marked UEFI; use the exact model's manual if the key differs.", keys[1]) if keys else
        t("Use the boot-menu key from your PC's manual (often F12, F11, F9 or Esc), then select the USB entry marked UEFI."),
        t("In OpenCore, select the macOS recovery installer, commonly the entry ending in '(dmg)'. This guide does not invoke a Windows startup menu."),
    ]))
    steps.append(Step(t("Install macOS on the intended target disk"), [
        t("In Disk Utility, choose View -> Show All Devices and identify the disk reserved for macOS. Do not erase a disk or partition containing Linux, Windows or data you want to keep. For a dedicated macOS disk, use APFS and GUID Partition Map."),
        t("Quit Disk Utility, choose Reinstall macOS, and select the intended macOS volume. Read the installer's target selection before continuing."),
        t("At each restart, boot through the same OpenCore USB and choose macOS Installer until the installed macOS volume appears. Keep the USB as the boot device until you deliberately configure another one."),
        t("If this EFI uses the NVIDIA driver, run the supplied Mac companion application after macOS starts. The driver runs in macOS; Linux media creation alone does not validate the GPU."),
    ]))
    return steps


def build_prerequisite_guide(report, *, source="saved"):
    context = context_step(source)
    context.body[1] = t("No EFI has been generated by this prerequisite review. It does not read a boot configuration or change firmware, storage or security settings.")
    return [context, *precautions(report), Step(t("Lumen firmware prerequisites"), [
        t("Check the exact target PC and firmware revision before changing a setting. A completed EFI receives its own BIOS guide; this review does not authorize disk erasure."),
    ])]


CSS = """
:root { color-scheme: dark light; font-family: system-ui,sans-serif; line-height: 1.65; }
body { max-width: 1180px; margin: 0 auto; padding: 32px 24px; background: #10151f; color: #e7eef8; }
header { border-bottom: 1px solid #344257; margin-bottom: 24px; padding-bottom: 24px; }
.brand { color: #86bfff; letter-spacing: .18em; font-weight: 750; } h1 { margin: 12px 0; }
.subtitle, footer { color: #a6b6cb; } .layout { display: grid; grid-template-columns: 250px minmax(0,1fr); gap: 28px; }
nav { position: sticky; top: 20px; align-self: start; } nav ol { padding-left: 22px; } a { color: #a9d1ff; }
nav li { margin: 9px 0; } section { background: #17202d; border: 1px solid #2b3a50; border-radius: 10px; padding: 22px; margin-bottom: 22px; }
h2 { margin-top: 0; font-size: 1.3rem; } p { margin: 12px 0; } kbd, code { border: 1px solid #56708f; border-radius: 4px; padding: 1px 5px; }
.caution { color: #f5ce89; } .facts { display: grid; grid-template-columns: auto 1fr; gap: 2px 16px; margin: 16px 0; } dt { color: #a6b6cb; } dd { margin: 0; overflow-wrap: anywhere; }
table.bios { border-collapse: collapse; width: 100%; } table.bios td { border-top: 1px solid #405269; padding: 14px 8px; vertical-align: top; } td.set { width: 30%; } .want { color: #a9d1ff; }
.must { color: #f5ce89; } .opt, .miss, .saw { color: #b4c6da; } button { padding: 9px 16px; border: 1px solid #577395; border-radius: 6px; background: #284c77; color: white; cursor: pointer; }
footer { border-top: 1px solid #344257; padding-top: 20px; font-size: .9rem; }
@media(max-width:800px) { .layout { display: block; } nav { position: static; } body { padding: 18px 12px; } }
@media print { :root { color-scheme: light; } body, section { background: white; color: black; } body { max-width:none; padding:0; } nav, button { display:none; } .layout { display:block; } section { border: 1px solid #aaa; break-inside:avoid; padding:12px; } a, .subtitle, footer, .want, .caution, .must, .opt, .miss, .saw, dt { color:black; } }
"""


def render_html(report, steps, macos="", *, prerequisites=False):
    """Standalone Linux-branded guide with escaped report facts and no remote assets."""
    inline = upstream._inline
    title = t("Lumen firmware prerequisites" if prerequisites else "Lumen installation guide")
    links, sections = [], []
    for index, step in enumerate(steps, 1):
        anchor = f"step-{index}"
        links.append(f'<li><a href="#{anchor}">{inline(step.title)}</a></li>')
        body = "".join(f"<p>{inline(line)}</p>" for line in step.body)
        if step.settings: body += upstream._printout(step.settings)
        warning = f'<p class="caution">{inline(t("Review before firmware changes"))}</p>' if step.blocker else ""
        sections.append(f'<section id="{anchor}" aria-labelledby="heading-{index}"><h2 id="heading-{index}">{index}. {inline(step.title)}</h2>{warning}{body}</section>')
    facts = "".join(f"<dt>{inline(str(key))}</dt><dd>{inline(str(value))}</dd>" for key, value in upstream._pc(report, macos) if value)
    lang = "zh-CN" if loc.language() == "zh" else "en"
    return f'''<!doctype html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{html.escape(title)}</title><style>{CSS}</style></head>
<body><header><div class="brand">LUMEN</div><h1>{inline(title)}</h1>
<p class="subtitle">{inline(t("Independent Linux edition · based on 1401"))}<br>{inline(t("Saved observations, explicit manual steps"))}</p>
<dl class="facts">{facts}</dl><button type="button" id="print-guide">{inline(t("Print / save as PDF"))}</button></header>
<div class="layout"><nav aria-label="{html.escape(t('Contents'))}"><b>{inline(t('Contents'))}</b><ol>{''.join(links)}</ol></nav><main>{''.join(sections)}</main></div>
<footer><p>{inline(t("This page is self-contained and makes no network requests."))}</p>
<p>{inline(t("Lumen is an independent Linux adaptation of 1401. Upstream code © 2026 NullMoth Systems; each component retains its own license. See LICENSE and NOTICE.md in the application."))}</p></footer>
<script>document.getElementById('print-guide').addEventListener('click', function() {{ window.print(); }});</script>
</body></html>
'''
