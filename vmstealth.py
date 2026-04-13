#!/usr/bin/env python3
"""
vmstealth.py — VMware Stealth Patcher (elite edition)
Malware analysis lab tool.  Defeats every detection tier used by pafish,
al-khaser, VmwareHardenedLoader test suite, Emotet, TrickBot, and commodity
sandbox-aware samples.

Two-step workflow
─────────────────
Step 1 (HOST, VM must be shut down):
    python3 vmstealth.py "Windows 10.vmx" --guest-script clean_guest.ps1

Step 2 (inside Windows VM, Admin PowerShell):
    powershell -ExecutionPolicy Bypass -File .\\clean_guest.ps1

Optional flags:
    --scan        Audit a VMX without modifying it
    --aggressive  Also swap NIC to e1000e + disable 3D SVGA + remove xHCI
"""

import re
import sys
import random
import argparse
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  VMX STEALTH SETTINGS
#  Applied to the .vmx file on the HOST before booting the VM.
#  Format reminder: CPUID mask strings are 32 chars, leftmost = bit 0,
#  rightmost = bit 31.  "-------------------------------0" clears bit 31.
# ═══════════════════════════════════════════════════════════════════════════════

VMX_STEALTH: dict[str, str] = {

    # ── TIER 1 : CPUID ────────────────────────────────────────────────────────
    # Bit 31 of ECX at leaf 1 — the universal "hypervisor present" flag.
    # Almost every sandbox-aware sample checks this first.
    "CPUID.1.ECX": "-------------------------------0",

    # Explicitly zero the entire hypervisor vendor leaf (0x40000000).
    # With hypervisor.cpuid.v0=FALSE VMware already suppresses it, but
    # belt-and-suspenders zeroing defeats implementations that probe the
    # leaf directly regardless of bit 31.
    "cpuid.40000000.eax": "00000000000000000000000000000000",
    "cpuid.40000000.ebx": "00000000000000000000000000000000",
    "cpuid.40000000.ecx": "00000000000000000000000000000000",
    "cpuid.40000000.edx": "00000000000000000000000000000000",

    # Belt-and-suspenders: tell VMware's own CPUID filter not to advertise.
    "hypervisor.cpuid.v0": "FALSE",

    # ── TIER 2 : VMware backdoor I/O port (0x5658 / 'VMXh') ──────────────────
    # vmtoolsd uses IN dx,eax with magic 0x564D5868.  Malware probes it and
    # checks EBX for the VMware magic response.  Restricting it returns junk.
    "monitor_control.restrict_backdoor": "TRUE",

    # ── TIER 3 : RDTSC / timing ───────────────────────────────────────────────
    # Pass the real host TSC to the guest.  VM exits inflate the RDTSC-delta
    # measured around a CPUID call by hundreds of cycles — a strong VM tell.
    "monitor_control.virtual_rdtsc": "FALSE",

    # ── TIER 4 : SMBIOS / DMI ─────────────────────────────────────────────────
    # Inject the HOST machine's SMBIOS tables into the guest instead of
    # VMware's synthetic ones (Manufacturer="VMware, Inc.", etc.).
    "SMBIOS.reflectHost":       "TRUE",
    "board-id.reflectHost":     "TRUE",
    "hw.model.reflectHost":     "TRUE",
    "serialNumber.reflectHost": "TRUE",
    "SMBIOS.noOEMStrings":      "TRUE",

    # ── TIER 5 : ACPI tables ──────────────────────────────────────────────────
    # VMware's synthetic ACPI tables contain "VMWARE" in OEM ID / Table ID.
    # Pass host tables through to eliminate those strings.
    "acpi.passthru.bios": "TRUE",
    "acpi.passthru.cpu":  "TRUE",

    # ── TIER 6 : PCI device removal ───────────────────────────────────────────
    # VMCI (PCI VID 0x15AD DevID 0x0740) is enumerable via SetupDi and WMI.
    # Removing it at the VMX level prevents the device from appearing at all.
    "vmci0.present": "FALSE",

    # ── TIER 7 : Legacy hardware (dead giveaways) ─────────────────────────────
    # No 2020s bare-metal machine ships with floppy/serial/parallel.
    # Their presence in Device Manager instantly fingerprints a default VM.
    "floppy0.present":   "FALSE",
    "serial0.present":   "FALSE",
    "parallel0.present": "FALSE",

    # ── TIER 8 : SVGA VRAM ────────────────────────────────────────────────────
    # Default VMware VRAM = 16 MB.  Real GPUs ship with 256 MB – 8 GB.
    # Win32_VideoController.AdapterRAM is 0 or 16 MB in unpatched VMs.
    "svga.vramSize": "268435456",   # 256 MB

    # ── TIER 9 : Memory subsystem timing attacks ──────────────────────────────
    # Memory page-sharing (dedup) creates a measurable timing side-channel:
    # writing to a shared page is slower than writing to a private one.
    # Disabling it removes that oracle.
    "sched.mem.pshare.enable": "FALSE",

    # Named memory file: VMware creates a host-side file for guest RAM.
    # Its name (containing the VM name) is sometimes visible in filesystem
    # scans on the host — irrelevant inside the guest but eliminates one
    # possible information leak.
    "mainMem.useNamedFile": "FALSE",

    # Balloon driver at VMX level (belt-and-suspenders with service removal).
    "sched.mem.maxmemctl": "0",

    # Memory trim can produce observable latency spikes.
    "MemTrimRate": "0",

    # ── TIER 10 : Hyper-V enlightenments ──────────────────────────────────────
    # If vhv.enable=TRUE (sometimes set for Docker/WSL2 nested virt),
    # Windows receives Hyper-V CPUID leaves that trivially reveal the VM.
    "vhv.enable": "FALSE",

    # ── TIER 11 : Time synchronisation ───────────────────────────────────────
    # Clock-sync calls are observable; disabling all variants removes the
    # channel and avoids introducing clock-drift anomalies.
    "tools.syncTime":                 "FALSE",
    "time.synchronize.continue":      "FALSE",
    "time.synchronize.restore":       "FALSE",
    "time.synchronize.resume.disk":   "FALSE",
    "time.synchronize.shrink":        "FALSE",
    "time.synchronize.tools.startup": "FALSE",
    "time.synchronize.tools.enable":  "FALSE",

    # ── TIER 12 : Named-pipe channels (host↔guest) ────────────────────────────
    # Clipboard, DnD, and HGFS each open named pipes.  Malware enumerates
    # \\.\pipe\* and flags VMware-named pipes.
    "isolation.tools.copy.disable":         "TRUE",
    "isolation.tools.paste.disable":        "TRUE",
    "isolation.tools.dnd.disable":          "TRUE",
    "isolation.tools.setGUIOptions.enable": "FALSE",
    "isolation.tools.hgfs.disable":         "TRUE",
    "isolation.tools.autoInstall.disable":  "TRUE",

    # ── TIER 13 : VMware log files ────────────────────────────────────────────
    # VMware writes vmware.log / vmware-N.log next to the VMX.
    # Samples that scan %TEMP% and common directories find these.
    "logging": "FALSE",

    # ── Miscellaneous ─────────────────────────────────────────────────────────
    "mce.enable":            "TRUE",   # MCE should be present on bare metal
    "tools.upgrade.policy":  "manual",
}

# ── Aggressive-mode extras ────────────────────────────────────────────────────
VMX_AGGRESSIVE: dict[str, str] = {
    # Replace VMXNET3 (VID 0x15AD DevID 0x07B0, VMware-exclusive) with the
    # emulated Intel e1000e.  Windows 10/11 has the inbox driver; the adapter
    # will appear as new hardware on first boot.
    "ethernet0.virtualDev": "e1000e",

    # SVGA-3D PCI ID 0x15AD:0x0405 is detectable via SetupDi.
    # Disabling it presents a plain 2D SVGA adapter.
    "mks.enable3d": "FALSE",

    # Remove the VMware-branded USB 3.0 xHCI controller.
    "usb_xhci.present": "FALSE",
}

VMWARE_OUIS = {"00:0C:29", "00:50:56", "00:05:69", "00:1C:14"}

REAL_OUIS = [
    "00:1B:21", "8C:16:45", "FC:AA:14", "00:23:AE", "14:DD:A9",
    "A4:C3:F0", "AC:FD:CE", "A0:36:9F", "F4:4D:30",   # Intel
    "00:E0:4C", "BC:EE:7B", "E0:CB:4E", "D0:17:C2",   # Realtek
    "00:10:18", "00:1A:1E", "48:51:B7",                # Broadcom
    "38:EA:A7", "D4:3B:04", "8C:8D:28", "34:02:86",   # Intel Wi-Fi
]


def random_mac(oui: str) -> str:
    tail = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{tail}"


def is_vmware_mac(mac: str) -> bool:
    return mac.upper()[:8] in VMWARE_OUIS


# ═══════════════════════════════════════════════════════════════════════════════
#  PATCH MODE
# ═══════════════════════════════════════════════════════════════════════════════

def patch_vmx(vmx_path: Path, aggressive: bool = False) -> None:
    print(f"\n  vmstealth — patch mode\n  {'─'*50}")
    print(f"  Target : {vmx_path}")

    original = vmx_path.read_text(encoding="utf-8", errors="replace")
    lines = original.splitlines()

    backup = vmx_path.with_suffix(".vmx.bak")
    if not backup.exists():
        backup.write_text(original, encoding="utf-8")
        print(f"  Backup : {backup}")
    else:
        print(f"  Backup : already exists — skipping")

    # Case-insensitive key → line-index map
    key_idx: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"', line)
        if m:
            key_idx[m.group(1).lower()] = i

    updated  = list(lines)
    appended: list[str] = []

    settings = {**VMX_STEALTH, **(VMX_AGGRESSIVE if aggressive else {})}

    print(f"\n  {'─'*50}")
    print("  VMX stealth settings")
    print(f"  {'─'*50}")
    for key, value in settings.items():
        new_line = f'{key} = "{value}"'
        idx = key_idx.get(key.lower())
        if idx is not None:
            if updated[idx] != new_line:
                updated[idx] = new_line
                print(f"  [~] {key}")
        else:
            appended.append(new_line)
            print(f"  [+] {key}")

    # MAC randomisation
    print(f"\n  {'─'*50}")
    print("  MAC address randomisation")
    print(f"  {'─'*50}")
    found = False
    for i, line in enumerate(updated):
        m = re.match(r'^(ethernet\d+)\.address\s*=\s*"([^"]*)"', line, re.IGNORECASE)
        if not m:
            continue
        found = True
        adapter, old_mac = m.group(1), m.group(2)
        if is_vmware_mac(old_mac):
            new_mac = random_mac(random.choice(REAL_OUIS))
            updated[i] = f'{adapter}.address = "{new_mac}"'
            print(f"  [~] {adapter}: {old_mac}  →  {new_mac}")
            at_key  = f"{adapter}.addressType".lower()
            at_line = f'{adapter}.addressType = "static"'
            at_idx  = key_idx.get(at_key)
            if at_idx is not None:
                updated[at_idx] = at_line
            else:
                appended.append(at_line)
        else:
            print(f"  [ok] {adapter}: {old_mac}  (non-VMware OUI)")
    if not found:
        print("  [?]  No ethernet.address found — add a NIC in VM settings first")

    vmx_path.write_text("\n".join(updated + appended) + "\n", encoding="utf-8")

    print(f"\n  {'─'*50}")
    print(f"  Done → {vmx_path}")
    if aggressive:
        print("  Aggressive: NIC → e1000e  |  3D SVGA disabled  |  xHCI removed")
        print("  First boot will detect new NIC hardware — this is normal.")
    print("  ⚠  VM must be shut down before changes take effect.")
    print("  ⚠  After first boot run clean_guest.ps1 inside the VM as Admin.\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN / AUDIT MODE
# ═══════════════════════════════════════════════════════════════════════════════

def scan_vmx(vmx_path: Path) -> None:
    print(f"\n  vmstealth — scan / audit mode\n  {'─'*50}")
    print(f"  Target : {vmx_path}\n")

    text = vmx_path.read_text(encoding="utf-8", errors="replace")
    kv: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', line)
        if m:
            kv[m.group(1).lower()] = m.group(2)

    results: list[tuple[str, str, str]] = []   # (status, label, note)

    def chk(label: str, key: str, expected: str, note: str = "") -> None:
        val = kv.get(key.lower())
        suffix = f"  ({note})" if note else ""
        if val is None:
            results.append(("FAIL", label, f'missing — should be "{expected}"{suffix}'))
        elif val.lower() != expected.lower():
            results.append(("FAIL", label, f'"{val}" → should be "{expected}"{suffix}'))
        else:
            results.append(("PASS", label, f'"{val}"'))

    chk("CPUID hypervisor bit",        "CPUID.1.ECX",                    "-------------------------------0")
    chk("CPUID leaf 0x40000000 EAX",   "cpuid.40000000.eax",             "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 EBX",   "cpuid.40000000.ebx",             "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 ECX",   "cpuid.40000000.ecx",             "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 EDX",   "cpuid.40000000.edx",             "00000000000000000000000000000000")
    chk("Hypervisor CPUID leaf",       "hypervisor.cpuid.v0",            "FALSE")
    chk("Backdoor I/O port",           "monitor_control.restrict_backdoor", "TRUE")
    chk("RDTSC passthrough",           "monitor_control.virtual_rdtsc",  "FALSE",  "timing side-channel")
    chk("SMBIOS reflect host",         "SMBIOS.reflectHost",             "TRUE")
    chk("Board-ID reflect host",       "board-id.reflectHost",           "TRUE")
    chk("HW model reflect host",       "hw.model.reflectHost",           "TRUE")
    chk("Serial# reflect host",        "serialNumber.reflectHost",       "TRUE")
    chk("No OEM SMBIOS strings",       "SMBIOS.noOEMStrings",            "TRUE")
    chk("ACPI passthru BIOS",          "acpi.passthru.bios",             "TRUE")
    chk("ACPI passthru CPU",           "acpi.passthru.cpu",              "TRUE")
    chk("VMCI device removed",         "vmci0.present",                  "FALSE",  "PCI VID 0x15AD DevID 0x0740")
    chk("Floppy removed",              "floppy0.present",                "FALSE")
    chk("Serial port removed",         "serial0.present",                "FALSE")
    chk("Parallel port removed",       "parallel0.present",              "FALSE")
    chk("SVGA VRAM 256 MB",            "svga.vramSize",                  "268435456", "16 MB default is a tell")
    chk("Mem page-sharing off",        "sched.mem.pshare.enable",        "FALSE",  "dedup timing attack")
    chk("Named mem file off",          "mainMem.useNamedFile",           "FALSE")
    chk("Balloon driver off (VMX)",    "sched.mem.maxmemctl",            "0")
    chk("Mem trim off",                "MemTrimRate",                    "0")
    chk("Hyper-V compat off",          "vhv.enable",                     "FALSE")
    chk("Logging disabled",            "logging",                        "FALSE")
    chk("Time sync off",               "tools.syncTime",                 "FALSE")
    chk("DnD pipe disabled",           "isolation.tools.dnd.disable",    "TRUE")
    chk("Clipboard pipe disabled",     "isolation.tools.copy.disable",   "TRUE")
    chk("HGFS pipe disabled",          "isolation.tools.hgfs.disable",   "TRUE")

    # MAC check
    mac_clean = True
    for k, v in kv.items():
        if re.match(r'^ethernet\d+\.address$', k) and is_vmware_mac(v):
            results.append(("FAIL", "MAC address", f"VMware OUI in {k}: {v}"))
            mac_clean = False
    if mac_clean:
        results.append(("PASS", "MAC address", "no VMware OUI found"))

    # NIC virtual device
    nic = kv.get("ethernet0.virtualdev", "")
    if nic in ("vmxnet3", "vmxnet"):
        results.append(("WARN", "NIC virtual device", f'"{nic}" — VMware-only; use e1000e (--aggressive)'))
    elif nic == "e1000e":
        results.append(("PASS", "NIC virtual device", '"e1000e" (realistic Intel)'))
    else:
        results.append(("WARN", "NIC virtual device", f'"{nic or "(not set)"}" — confirm it is not vmxnet3'))

    # 3D SVGA
    s3d = kv.get("mks.enable3d", "TRUE")
    if s3d.upper() == "FALSE":
        results.append(("PASS", "3D SVGA",     "disabled"))
    else:
        results.append(("WARN", "3D SVGA",     "enabled — PCI ID 0x15AD:0x0405 detectable via SetupDi"))

    # RAM / vCPU
    try:
        mem = int(kv.get("memsize", "0"))
        if mem < 4096:
            results.append(("WARN", "RAM",  f"{mem} MB — < 4 GB triggers low-memory sandbox checks"))
        else:
            results.append(("PASS", "RAM",  f"{mem} MB"))
    except ValueError:
        pass

    cpus = kv.get("numvcpus", "1")
    if cpus == "1":
        results.append(("WARN", "vCPU count", "1 — single-core VMs are a common sandbox fingerprint"))
    else:
        results.append(("PASS", "vCPU count", cpus))

    # SCSI controller
    scsi = kv.get("scsi0.virtualdev", "")
    if scsi.lower() == "pvscsi":
        results.append(("WARN", "SCSI controller", "pvscsi — VMware-proprietary; consider lsisas1068"))
    elif scsi:
        results.append(("PASS", "SCSI controller", f'"{scsi}"'))

    # Print
    W = 36
    G, Y, R, NC = "\033[32m", "\033[33m", "\033[31m", "\033[0m"
    icons = {"PASS": f"{G}✔{NC}", "WARN": f"{Y}⚠{NC}", "FAIL": f"{R}✘{NC}"}

    print(f"  {'CHECK':<{W}}  STATUS / NOTE")
    print(f"  {'─'*W}  {'─'*36}")
    for status, label, note in results:
        print(f"  {icons[status]}  {label:<{W-3}} {note}")

    passed = sum(1 for s, _, _ in results if s == "PASS")
    warned = sum(1 for s, _, _ in results if s == "WARN")
    failed = sum(1 for s, _, _ in results if s == "FAIL")
    total  = len(results)
    print(f"\n  {passed}/{total} pass  |  {warned} warn  |  {failed} fail")
    if failed + warned:
        print("  Run without --scan to auto-apply all fixes.\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  GUEST-SIDE POWERSHELL SCRIPT  (embedded, written out with --guest-script)
# ═══════════════════════════════════════════════════════════════════════════════

GUEST_PS1 = r"""
# =============================================================================
#  VMware Guest Artifact Cleaner — elite edition
#  Run INSIDE Windows VM as Administrator.
#  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#
#  TAKE A SNAPSHOT BEFORE RUNNING.
#  Reboot after completion, then test with pafish.exe / al-khaser.exe
# =============================================================================

$ErrorActionPreference = "SilentlyContinue"

function Write-Step { param($m) Write-Host "`n  [$([char]9658)] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "    [+] $m" -ForegroundColor Green }
function Write-Skip { param($m) Write-Host "    [-] $m" -ForegroundColor DarkGray }
function Write-Warn { param($m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "    [X] $m" -ForegroundColor Red }

$banner = @"

  ██╗   ██╗███╗   ███╗    ███████╗████████╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗
  ██║   ██║████╗ ████║    ██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║
  ██║   ██║██╔████╔██║    ███████╗   ██║   █████╗  ███████║██║     ██║   ███████║
  ╚██╗ ██╔╝██║╚██╔╝██║    ╚════██║   ██║   ██╔══╝  ██╔══██║██║     ██║   ██╔══██║
   ╚████╔╝ ██║ ╚═╝ ██║    ███████║   ██║   ███████╗██║  ██║███████╗██║   ██║  ██║
    ╚═══╝  ╚═╝     ╚═╝    ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝
                          VMware Guest Cleaner — Elite Edition
"@
Write-Host $banner -ForegroundColor DarkCyan
Write-Host "  Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)`n"


# ─────────────────────────────────────────────────────────────────────────────
#  1. REGISTRY — VMware software + service + driver keys
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Registry — removing VMware keys"

$regKeys = @(
    # Software hive
    "HKLM:\SOFTWARE\VMware, Inc.",
    "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.",
    "HKCU:\Software\VMware, Inc.",
    # Service keys — CurrentControlSet
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMware Physical Disk Helper Service",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmx86",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmci",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmmemctl",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmusb",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vsock",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VGAuthService",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dmp",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dmp-debug",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dmp-stats",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMUSBArbService",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmvss",
    "HKLM:\SYSTEM\CurrentControlSet\Services\pvscsi",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6",
    # ControlSet001 mirror
    "HKLM:\SYSTEM\ControlSet001\Services\VMTools",
    "HKLM:\SYSTEM\ControlSet001\Services\vmci",
    "HKLM:\SYSTEM\ControlSet001\Services\vmhgfs",
    "HKLM:\SYSTEM\ControlSet001\Services\vmmemctl",
    "HKLM:\SYSTEM\ControlSet001\Services\VGAuthService",
    "HKLM:\SYSTEM\ControlSet001\Services\pvscsi",
    # Uninstall entries
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VMware Tools",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VMware Tools",
    # MUI / event message files
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{VMWARE_TOOLS_GUID}"
)
foreach ($key in $regKeys) {
    if (Test-Path $key) { Remove-Item $key -Recurse -Force; Write-Ok $key }
    else                { Write-Skip $key }
}


# ─────────────────────────────────────────────────────────────────────────────
#  2. SERVICES — stop and disable
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Services — stopping and disabling VMware services"

foreach ($svc in @("VMTools","VGAuthService","VMware Physical Disk Helper Service",
                   "VMUSBArbService","vmvss","vm3dmp","vmci","pvscsi")) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service  $svc -Force -ErrorAction SilentlyContinue
        Set-Service   $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Ok "Stopped + disabled: $svc"
    } else { Write-Skip $svc }
}


# ─────────────────────────────────────────────────────────────────────────────
#  3. PROCESSES — kill running VMware processes
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Processes — terminating VMware processes"

foreach ($proc in @("vmtoolsd","vmwaretray","vmwareuser","vmacthlp",
                    "VGAuthService","VMwareService","vmnat","vmnetdhcp")) {
    $p = Get-Process $proc -ErrorAction SilentlyContinue
    if ($p) { $p | Stop-Process -Force; Write-Ok "Killed: $proc" }
    else    { Write-Skip $proc }
}


# ─────────────────────────────────────────────────────────────────────────────
#  4. BINARIES — rename VMware executables to generic system names
#     NtQuerySystemInformation(SystemModuleInformation) returns loaded image
#     names; filesystem enumeration of Program Files is also common.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Binaries — renaming VMware executables"

$binaryMap = @{
    "vmtoolsd.exe"      = "RuntimeBroker2.exe"
    "vmwaretray.exe"    = "taskhostw2.exe"
    "vmwareuser.exe"    = "sihost2.exe"
    "vmacthlp.exe"      = "ctfmon2.exe"
    "VGAuthService.exe" = "LsaIso2.exe"
}
$vmDir = "$env:ProgramFiles\VMware\VMware Tools"
foreach ($orig in $binaryMap.Keys) {
    $full = Join-Path $vmDir $orig
    if (Test-Path $full) {
        Rename-Item $full -NewName $binaryMap[$orig] -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$orig  →  $($binaryMap[$orig])" }
        else    { Write-Warn "Locked (in use?): $orig — reboot and retry" }
    } else { Write-Skip $full }
}


# ─────────────────────────────────────────────────────────────────────────────
#  5. KERNEL DRIVERS (.sys) — rename VMware driver files
#     Detected via NtQuerySystemInformation(SystemModuleInformation),
#     NtQueryDirectoryFile on drivers\, and direct path checks.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Kernel drivers — renaming VMware .sys files"

$driverMap = @{
    "vmhgfs.sys"       = "hgfsport.sys"
    "vmci.sys"         = "msgpioclx2.sys"
    "vm3dmp.sys"       = "dxgkrnl2.sys"
    "vm3dmp-debug.sys" = "dxgkrnl2d.sys"
    "vm3dmp-stats.sys" = "dxgkrnl2s.sys"
    "vmmouse.sys"      = "mouclass2.sys"
    "vmrawdsk.sys"     = "partmgr2.sys"
    "vmusbmouse.sys"   = "mouhid2.sys"
    "vmmemctl.sys"     = "dxgmms2.sys"
    "vsock.sys"        = "rfcomm2.sys"
    "vmxnet3ndis6.sys" = "e1g6032e.sys"
    "pvscsi.sys"       = "lsi_sas2.sys"
}
$driversDir = "$env:SystemRoot\System32\drivers"
foreach ($orig in $driverMap.Keys) {
    $full = Join-Path $driversDir $orig
    if (Test-Path $full) {
        & takeown /f $full /a       2>&1 | Out-Null
        & icacls  $full /grant "Administrators:F" 2>&1 | Out-Null
        Rename-Item $full -NewName $driverMap[$orig] -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$orig  →  $($driverMap[$orig])" }
        else    { Write-Warn "Could not rename (file in use): $orig — reboot first" }
    } else { Write-Skip $orig }
}


# ─────────────────────────────────────────────────────────────────────────────
#  6. VMware DLLs — rename guest library DLLs
#     LoadLibrary("vmGuestLib.dll") succeeds on VMware → instant detection.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "DLLs — renaming VMware guest library DLLs"

$dllPaths = @(
    "$env:SystemRoot\System32\vmGuestLib.dll",
    "$env:SystemRoot\SysWOW64\vmGuestLib.dll",
    "$env:SystemRoot\System32\vmGuestLibJava.jar",
    "$env:SystemRoot\System32\vm3dgl.dll",
    "$env:SystemRoot\System32\vm3dgl64.dll",
    "$env:SystemRoot\System32\vmhgfs.dll"
)
foreach ($dll in $dllPaths) {
    if (Test-Path $dll) {
        & takeown /f $dll /a 2>&1 | Out-Null
        & icacls  $dll /grant "Administrators:F" 2>&1 | Out-Null
        $newName = (Split-Path $dll -Leaf) -replace "vmGuestLib","msvcm140_app" `
                                           -replace "vmhgfs",    "ntdll_ext" `
                                           -replace "vm3dgl",    "d3d11_2"
        Rename-Item $dll -NewName $newName -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$(Split-Path $dll -Leaf)  →  $newName" }
        else    { Write-Warn "Could not rename: $dll" }
    } else { Write-Skip $dll }
}


# ─────────────────────────────────────────────────────────────────────────────
#  7. PCI DEVICE REGISTRY — patch all VMware VID (0x15AD) entries
#     Win32_PNPEntity.Name, Device Manager, and SetupDi all read from
#     FriendlyName / DeviceDesc in HKLM\...\Enum\PCI\VEN_15AD*
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "PCI devices — patching VMware VID 0x15AD hardware entries"

$pciReplace = @{
    "DEV_0405" = "Intel(R) UHD Graphics 630"                   # SVGA II
    "DEV_0740" = "Intel(R) Serial I/O GPIO Host Controller"    # VMCI
    "DEV_07B0" = "Intel(R) 82579LM Gigabit Network Connection" # VMXNET3
    "DEV_07C0" = "LSI Adapter, SAS 3000 series, 4-port"        # PVSCSI
    "DEV_0770" = "Intel(R) USB 3.0 eXtensible Host Controller" # EHCI
    "DEV_0774" = "Intel(R) USB 2.0 Enhanced Host Controller"   # UHCI
    "DEV_07A0" = "Intel(R) PCI Express Root Port #1"           # PCIe Root
    "DEV_1977" = "Realtek High Definition Audio"               # HD Audio
    "DEV_0790" = "Intel(R) PCI-to-PCI Bridge"                  # PCI Bridge
    "DEV_0801" = "Intel(R) Management Engine Interface"        # VMCI v2
}

$pciRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
if (Test-Path $pciRoot) {
    Get-ChildItem $pciRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $hwid = $_.PSChildName.ToUpper()
        if ($hwid -notmatch "VEN_15AD") { return }

        $replacement = $null
        foreach ($devID in $pciReplace.Keys) {
            if ($hwid -match $devID) { $replacement = $pciReplace[$devID]; break }
        }
        if (-not $replacement) { $replacement = "Intel(R) System Device" }

        Get-ChildItem $_.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p) {
                if ($p.FriendlyName) {
                    Set-ItemProperty $_.PSPath "FriendlyName" $replacement -Force -ErrorAction SilentlyContinue
                }
                if ($p.DeviceDesc) {
                    Set-ItemProperty $_.PSPath "DeviceDesc"   $replacement -Force -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Ok "VEN_15AD $($hwid -replace 'VEN_15AD&','')  →  $replacement"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  8. DISK DEVICE STRINGS — SCSI + IDE enum FriendlyName
#     Win32_DiskDrive.Model and Device Manager read from here.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Disk devices — patching SCSI/IDE friendly names"

foreach ($bus in @("HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI",
                   "HKLM:\SYSTEM\CurrentControlSet\Enum\IDE")) {
    if (-not (Test-Path $bus)) { continue }
    Get-ChildItem $bus -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.FriendlyName -imatch "VMware|VMWARE") {
            $new = $p.FriendlyName `
                -replace "VMware Virtual NVMe Disk",  "Samsung SSD 970 EVO 500GB" `
                -replace "VMware Virtual SCSI Disk",  "ST1000DM010-2EP102" `
                -replace "VMware Virtual S",          "WDC WD10EZEX-08WN4A0" `
                -replace "VMware Virtual disk",       "ST1000DM010-2EP102" `
                -replace "VMware",                    "ATA"
            Set-ItemProperty $_.PSPath "FriendlyName" $new -Force
            Write-Ok "Disk: '$($p.FriendlyName)'  →  '$new'"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  9. HARDWARE\DEVICEMAP\Scsi — Identifier field
#     Some malware queries this path directly for "VMWARE VIRTUAL IDE".
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "DEVICEMAP\\Scsi — patching Identifier field"

$deviceMap = "HKLM:\HARDWARE\DEVICEMAP\Scsi"
if (Test-Path $deviceMap) {
    Get-ChildItem $deviceMap -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.Identifier -imatch "VMWARE|VMware") {
            Set-ItemProperty $_.PSPath "Identifier" "WDC WD10EZEX-08WN4A0     " -Force
            Write-Ok "DEVICEMAP Scsi Identifier patched: '$($p.Identifier)'"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  10. NIC CLASS REGISTRY — Win32_NetworkAdapter.Name + Device Manager
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Network adapter — patching class registry DriverDesc"

$nicClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $nicClass) {
    Get-ChildItem $nicClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware|VMXNET") {
            Set-ItemProperty $_.PSPath "DriverDesc"   "Intel(R) 82579LM Gigabit Network Connection" -Force
            Set-ItemProperty $_.PSPath "ProviderName" "Intel" -Force
            Write-Ok "NIC: '$($p.DriverDesc)'  →  Intel 82579LM"
        }
    }
}
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -imatch "VMware|VMXNET" } |
    ForEach-Object {
        Rename-NetAdapter -Name $_.Name -NewName "Ethernet" -ErrorAction SilentlyContinue
        Write-Ok "Renamed adapter: '$($_.Name)'  →  Ethernet"
    }


# ─────────────────────────────────────────────────────────────────────────────
#  11. DISPLAY ADAPTER CLASS — Win32_VideoController + Device Manager
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Display adapter — patching GPU class registry"

$gpuClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $gpuClass) {
    Get-ChildItem $gpuClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware|SVGA") {
            Set-ItemProperty $_.PSPath "DriverDesc"                        "Intel(R) UHD Graphics 630" -Force
            Set-ItemProperty $_.PSPath "ProviderName"                      "Intel Corporation" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.AdapterString" "Intel(R) UHD Graphics 630" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.ChipType"      "Intel UHD Graphics Family" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.DacType"       "Internal" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.MemorySize"    ([uint32]268435456) -Force
            Write-Ok "GPU: '$($p.DriverDesc)'  →  Intel UHD Graphics 630 (256 MB VRAM)"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  12. AUDIO DEVICE CLASS — Win32_SoundDevice + Device Manager
#      VMware HD Audio (VID 0x15AD DevID 0x1977) is a strong VM indicator.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Audio device — patching class registry"

$audioClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96C-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $audioClass) {
    Get-ChildItem $audioClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware") {
            Set-ItemProperty $_.PSPath "DriverDesc"   "Realtek High Definition Audio" -Force
            Set-ItemProperty $_.PSPath "ProviderName" "Realtek Semiconductor Corp." -Force
            Write-Ok "Audio: '$($p.DriverDesc)'  →  Realtek HD Audio"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  13. SYSTEM INFORMATION REGISTRY
#      malware reads HKLM\...\Control\SystemInformation for OEM product name.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "SystemInformation registry — spoofing OEM strings"

$sysInfo = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"
if (Test-Path $sysInfo) {
    $replacements = @{
        "SystemProductName"  = "20B7S2UX00"        # Lenovo ThinkPad T490
        "SystemManufacturer" = "LENOVO"
        "SystemFamily"       = "ThinkPad T490"
        "SystemVersion"      = "ThinkPad"
        "BIOSVersion"        = "N2IET95W (1.60 )"
        "BIOSReleaseDate"    = "08/14/2022"
        "BIOSVendor"         = "LENOVO"
    }
    $p = Get-ItemProperty $sysInfo -ErrorAction SilentlyContinue
    foreach ($field in $replacements.Keys) {
        $val = $p.$field
        if ($val -imatch "VMware|Virtual|BOCHS|QEMU|Hyper-V|innotek") {
            Set-ItemProperty $sysInfo $field $replacements[$field] -Force
            Write-Ok "SystemInfo.$field: '$val'  →  '$($replacements[$field])'"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  14. BIOS / FIRMWARE strings
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "BIOS strings — patching HARDWARE\\DESCRIPTION hive"

$hwDesc = "HKLM:\HARDWARE\DESCRIPTION\System"
if (Test-Path $hwDesc) {
    $p = Get-ItemProperty $hwDesc
    $badPattern = "VBOX|VMWARE|VIRTUAL|BOCHS|QEMU|SEABIOS"
    if ($p.SystemBiosVersion -imatch $badPattern) {
        Set-ItemProperty $hwDesc "SystemBiosVersion" "LENOVO BIOS Version N2IET95W (1.60 )" -Force
        Write-Ok "Patched SystemBiosVersion"
    }
    if ($p.SystemBiosDate -and ($p.SystemBiosDate -lt "01/01/2019")) {
        Set-ItemProperty $hwDesc "SystemBiosDate"    "08/14/2022" -Force
        Write-Ok "Patched SystemBiosDate"
    }
    if ($p.VideoBiosVersion -imatch $badPattern) {
        Set-ItemProperty $hwDesc "VideoBiosVersion"  "Version 3.0 Rev. A" -Force
        Write-Ok "Patched VideoBiosVersion"
    }
    if ($p.Identifier -imatch "VRTUAL|Virtual") {
        Set-ItemProperty $hwDesc "Identifier"        "AT/AT COMPATIBLE" -Force
        Write-Ok "Patched Identifier"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  15. ACPI TABLE KEYS — report VMware OEM ID strings
#      These are only fully fixable via VMX acpi.passthru.bios=TRUE on the host.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "ACPI tables — checking for VMware OEM strings"

foreach ($tbl in @("DSDT","FADT","RSDT","SSDT","APIC","BOOT")) {
    $path = "HKLM:\HARDWARE\ACPI\$tbl"
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.PSChildName -imatch "VMWARE|VBOX|BOCHS|QEMU") {
            Write-Warn "ACPI $tbl\$($_.PSChildName) still has VM OEM string."
            Write-Warn "  Fix: VMX acpi.passthru.bios=TRUE (applied by vmstealth.py)"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  16. INSTALLED PROGRAMS — Add/Remove Programs list
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Installed programs — cleaning Uninstall registry"

$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DisplayName -imatch "VMware") {
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "Removed: $($p.DisplayName)"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  17. PREFETCH FILES
#      C:\Windows\Prefetch\VMWARE*.pf  is a common sandbox filesystem scan.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Prefetch — deleting VMware prefetch files"

$prefetch = "$env:SystemRoot\Prefetch"
foreach ($pat in @("VMWARE*","VMTOOL*","VMACTHLP*","VGAUTH*","VM3DMP*","PVSCSI*")) {
    Get-ChildItem $prefetch -Filter $pat -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force
        Write-Ok "Deleted: $($_.Name)"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  18. SCHEDULED TASKS
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Scheduled tasks — removing VMware tasks"

Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -imatch "VMware" -or $_.TaskPath -imatch "VMware" } |
    ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath `
            -Confirm:$false -ErrorAction SilentlyContinue
        Write-Ok "Removed task: $($_.TaskPath)$($_.TaskName)"
    }


# ─────────────────────────────────────────────────────────────────────────────
#  19. EVENT LOGS — clear VMware-provider entries
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Event logs — clearing VMware-tagged entries"

foreach ($logName in @("System","Application","Setup")) {
    $vmEvts = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
              Where-Object { $_.ProviderName -imatch "VMware" -or $_.Message -imatch "VMware Tools" }
    if ($vmEvts) {
        wevtutil cl $logName 2>&1 | Out-Null
        Write-Ok "Cleared $logName log ($($vmEvts.Count) VMware events)"
    } else { Write-Skip "$logName (no VMware events)" }
}

# Remove VMware event-provider DLL registrations
$evtProvRoot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"
if (Test-Path $evtProvRoot) {
    Get-ChildItem $evtProvRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.'(default)' -imatch "VMware" -or $p.MessageFileName -imatch "VMware") {
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "Removed event provider: $($p.'(default)')"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  20. FIREWALL RULES — remove VMware-added rules
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Firewall — removing VMware firewall rules"

Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -imatch "VMware" -or $_.Description -imatch "VMware" } |
    ForEach-Object {
        Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
        Write-Ok "Removed rule: $($_.DisplayName)"
    }


# ─────────────────────────────────────────────────────────────────────────────
#  21. ENVIRONMENT VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Environment variables — removing VM/sandbox vars"

foreach ($var in @("VBOX_MSI_INSTALL_PATH","VBOX_INSTALL_PATH",
                   "VMWARE_USE_SHIPPED_GTKMM","SANDBOX","SANDBOXIE")) {
    foreach ($scope in @("Machine","User")) {
        if ([Environment]::GetEnvironmentVariable($var, $scope)) {
            [Environment]::SetEnvironmentVariable($var, $null, $scope)
            Write-Ok "Removed [$scope] env var: $var"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  22. WMI — informational dump (verify SMBIOS host-reflect worked)
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "WMI — hardware string verification"

$cs   = Get-WmiObject Win32_ComputerSystem   -ErrorAction SilentlyContinue
$bios = Get-WmiObject Win32_BIOS             -ErrorAction SilentlyContinue
$disk = Get-WmiObject Win32_DiskDrive        -ErrorAction SilentlyContinue
$vid  = Get-WmiObject Win32_VideoController  -ErrorAction SilentlyContinue
$snd  = Get-WmiObject Win32_SoundDevice      -ErrorAction SilentlyContinue
$net  = Get-WmiObject Win32_NetworkAdapter -Filter "PhysicalAdapter=TRUE" -ErrorAction SilentlyContinue

if ($cs)   { Write-Host "    Manufacturer  : $($cs.Manufacturer)  |  Model: $($cs.Model)"
             if ($cs.Manufacturer -imatch "VMware") { Write-Warn "Still VMware — SMBIOS.reflectHost=TRUE needed in VMX" } }
if ($bios) { Write-Host "    BIOS Vendor   : $($bios.Manufacturer)  |  Ver: $($bios.SMBIOSBIOSVersion)"
             if ($bios.Manufacturer -imatch "VMware|Phoenix") { Write-Warn "BIOS vendor looks like VM" } }
if ($disk) { $disk | ForEach-Object { Write-Host "    Disk          : $($_.Model)" }
             if (($disk | Where-Object Model -imatch "VMware")) { Write-Warn "Disk model still VMware — check SCSI enum" } }
if ($vid)  { $vid  | ForEach-Object { Write-Host "    GPU           : $($_.Name)  VRAM: $([math]::Round($_.AdapterRAM/1MB)) MB" }
             if (($vid | Where-Object Name -imatch "VMware|SVGA")) { Write-Warn "GPU still VMware" } }
if ($snd)  { $snd  | ForEach-Object { Write-Host "    Audio         : $($_.Name)" }
             if (($snd | Where-Object Name -imatch "VMware")) { Write-Warn "Audio device still VMware" } }
if ($net)  { $net  | ForEach-Object { Write-Host "    NIC           : $($_.Name)  MAC: $($_.MACAddress)" } }


# ─────────────────────────────────────────────────────────────────────────────
#  23. NETWORK TELLS — gateway fingerprint + DNS suffix
#      VMware NAT default gateway is always 192.168.x.2.
#      Some malware detects this subnet pattern.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Network — checking for VMware NAT gateway fingerprint"

$defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
foreach ($r in $defaultRoutes) {
    if ($r.NextHop -match "^192\.168\.(1|2|131|254)\.2$") {
        Write-Warn "Default gateway $($r.NextHop) is a VMware NAT tell."
        Write-Warn "  Switch to Bridged networking, or change the VMnet subnet."
    } elseif ($r.NextHop -and $r.NextHop -ne "0.0.0.0") {
        Write-Ok "Gateway: $($r.NextHop)"
    }
}

$dnsSuffix = (Get-DnsClient -ErrorAction SilentlyContinue).ConnectionSpecificSuffix |
             Where-Object { $_ -match "localdomain|vmware" }
if ($dnsSuffix) {
    Write-Warn "DNS suffix '$dnsSuffix' may indicate VM — change to 'home.lan' or similar"
}


# ─────────────────────────────────────────────────────────────────────────────
#  24. COMPUTER NAME — flag sandbox-pattern names
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Computer name — checking for VM/sandbox patterns"

$vmNamePat = "^(WIN-[A-Z0-9]{11}|sandbox|malware|virus|cuckoo|any\.run|triage|DESKTOP-[A-Z0-9]{7})$"
if ($env:COMPUTERNAME -imatch $vmNamePat) {
    $pick = @("JOHNS-PC","LAPTOP-HOME","WORKSTATION","DESKTOP-K7M2P4","USER-LAPTOP") | Get-Random
    Write-Warn "Computer name '$($env:COMPUTERNAME)' matches VM naming pattern."
    Write-Warn "Rename: Rename-Computer -NewName '$pick' -Force -Restart"
} else {
    Write-Ok "Computer name: $($env:COMPUTERNAME)"
}


# ─────────────────────────────────────────────────────────────────────────────
#  25. USERNAME — flag analyst/sandbox usernames
#      Many samples abort if the username matches known analyst account names.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Username — checking for sandbox account names"

$badUsers = @("sandbox","malware","virus","john","user","analyst","test","sample",
              "admin","guest","cuckoo","vmware","triage","any","runner","lab")
if ($env:USERNAME -iin $badUsers) {
    Write-Warn "Username '$($env:USERNAME)' is a known sandbox account name."
    Write-Warn "Create a new local account with a realistic name (e.g., 'jsmith', 'mike.johnson')."
} else {
    Write-Ok "Username: $($env:USERNAME)"
}


# ─────────────────────────────────────────────────────────────────────────────
#  26. SCREEN RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Screen resolution — checking for VM defaults"

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
try {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    Write-Host "    Resolution: $($b.Width) x $($b.Height)"
    if ($b.Width -le 1024) {
        Write-Warn "Resolution $($b.Width)x$($b.Height) is a common VM default — set to 1920x1080"
    } else {
        Write-Ok "Resolution looks realistic: $($b.Width)x$($b.Height)"
    }
} catch { Write-Skip "Could not read resolution" }


# ─────────────────────────────────────────────────────────────────────────────
#  27. RAM + vCPU
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Hardware specs — RAM and CPU sanity check"

$cs2 = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs2) {
    $ramGB = [math]::Round($cs2.TotalPhysicalMemory / 1GB, 1)
    $cpus  = $cs2.NumberOfLogicalProcessors
    Write-Host "    RAM: $ramGB GB   |   Logical CPUs: $cpus"
    if ($ramGB -lt 4)  { Write-Warn "< 4 GB RAM — increase VM memory to 4-8 GB" }
    else               { Write-Ok "RAM: $ramGB GB" }
    if ($cpus -lt 2)   { Write-Warn "Only 1 vCPU — increase to 2+ in VM settings" }
    else               { Write-Ok "CPUs: $cpus" }
}


# ─────────────────────────────────────────────────────────────────────────────
#  28. DISK SIZE
#      Malware checks if the primary disk is suspiciously small (< 60 GB).
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Disk size — checking for sandbox-small disks"

Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
    $gb = if ($_.Size) { [math]::Round($_.Size / 1GB) } else { 0 }
    Write-Host "    $($_.Model): $gb GB"
    if ($gb -lt 60) {
        Write-Warn "Disk only $gb GB — many sandbox detectors flag < 60 GB; expand VM disk to 80+ GB"
    } else {
        Write-Ok "Disk size OK: $gb GB"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  29. VOLUME SERIAL NUMBER
#      Some samples compare the C: serial against a hardcoded list of known
#      sandbox serials (e.g. Cuckoo = 0xCD1A40B).
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Volume serial — checking against known sandbox fingerprints"

$vol = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
if ($vol -and $vol.VolumeSerialNumber) {
    $serial = $vol.VolumeSerialNumber.ToUpper()
    $knownBad = @("0CD1A40B","70144A7E","E8F6A80D","A8A0B820","E84BA848")
    Write-Host "    C: serial: $serial"
    if ($serial -iin $knownBad) {
        Write-Fail "Volume serial $serial is a known sandbox fingerprint!"
        Write-Warn "Reformat C: or use diskpart 'assign letter= id=<random>'"
    } else {
        Write-Ok "Volume serial not in known-bad list"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  30. VM UPTIME
#      Fresh sandbox boots often have < 5 min uptime.  Some samples sleep and
#      check again, or simply refuse to run if uptime is too low.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Uptime — checking for fresh-sandbox boot pattern"

$os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
    $uptime = (Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    Write-Host "    Uptime: $([int]$uptime.TotalHours)h $($uptime.Minutes)m"
    if ($uptime.TotalMinutes -lt 30) {
        Write-Warn "Uptime < 30 min — let the VM run idle for 30+ min before detonating"
    } else {
        Write-Ok "Uptime OK: $([int]$uptime.TotalHours)h $($uptime.Minutes)m"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  31. LOCALE AND TIMEZONE
#      Plain UTC timezone with no regional locale is a strong sandbox tell.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Locale / timezone — checking for sandbox defaults"

$tz = (Get-TimeZone).Id
Write-Host "    Timezone : $tz    Locale: $((Get-Culture).Name)"
if ($tz -eq "UTC" -or $tz -match "^UTC$") {
    Write-Warn "Plain UTC timezone — set a realistic regional timezone (e.g., Eastern Standard Time)"
} else {
    Write-Ok "Timezone: $tz"
}


# ─────────────────────────────────────────────────────────────────────────────
#  32. NAMED PIPE CHECK
#      Malware enumerates \\.\pipe\* for VMware / sandbox indicators.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Named pipes — checking for VM/sandbox pipe names"

try {
    $pipes = [System.IO.Directory]::GetFiles("\\.\\pipe\\")
    $badPipes = $pipes | Where-Object { $_ -imatch "vmware|cuckoo|sandbox|vbox|anubis|cape" }
    if ($badPipes) {
        $badPipes | ForEach-Object { Write-Warn "Suspicious pipe: $_" }
    } else {
        Write-Ok "No VM/sandbox pipes found ($($pipes.Count) total pipes enumerated)"
    }
} catch { Write-Skip "Could not enumerate pipes (normal on some Windows builds)" }


# ─────────────────────────────────────────────────────────────────────────────
#  33. ANTI-ANALYSIS TOOL DETECTION
#      Close these before detonating — samples check for them.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Analysis tools — check for running tools that malware detects"

$tools = @{
    "wireshark"  ="Wireshark";   "Procmon"   ="Process Monitor";
    "Procmon64"  ="Procmon x64"; "procexp"   ="Process Explorer";
    "procexp64"  ="ProcExp x64"; "tcpview"   ="TCPView";
    "autoruns"   ="Autoruns";    "autorunsc" ="Autoruns CLI";
    "ollydbg"    ="OllyDbg";     "x32dbg"    ="x32dbg";
    "x64dbg"     ="x64dbg";      "windbg"    ="WinDbg";
    "idaq"       ="IDA Pro";     "idaq64"    ="IDA Pro x64";
    "Fiddler"    ="Fiddler";     "pestudio"  ="PE Studio";
    "die"        ="DIE";         "cuckoo"    ="Cuckoo agent";
    "regshot"    ="Regshot";     "fakenet"   ="FakeNet-NG";
}
$found = @()
foreach ($proc in $tools.Keys) {
    if (Get-Process $proc -ErrorAction SilentlyContinue) { $found += $tools[$proc] }
}
if ($found) {
    Write-Fail "$($found.Count) analysis tool(s) running: $($found -join ', ')"
    Write-Warn "Close them BEFORE detonating the sample."
} else {
    Write-Ok "No known analysis tools detected"
}


# ─────────────────────────────────────────────────────────────────────────────
#  34. USER ARTIFACTS — create plausible user activity
#      Empty profiles with no documents, no recent files, and no browser
#      history are a strong sandbox indicator.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "User artifacts — generating realistic user activity"

$docs    = [Environment]::GetFolderPath("MyDocuments")
$desktop = [Environment]::GetFolderPath("Desktop")
$pics    = [Environment]::GetFolderPath("MyPictures")
$music   = [Environment]::GetFolderPath("MyMusic")
$rng     = New-Object System.Random

$fakeFiles = @(
    @{ Path = "$docs\budget_2024.xlsx";          Age = 14 }
    @{ Path = "$docs\notes.txt";                 Age = 3  }
    @{ Path = "$docs\work_report_Q1.docx";       Age = 30 }
    @{ Path = "$docs\tax_return_2023.pdf.lnk";   Age = 90 }
    @{ Path = "$desktop\TODO.txt";               Age = 1  }
    @{ Path = "$desktop\Shortcut to Chrome.lnk"; Age = 45 }
    @{ Path = "$pics\IMG_20231005_$($rng.Next(1000,9999)).jpg"; Age = 120 }
    @{ Path = "$music\playlist.wpl";             Age = 200 }
)
foreach ($f in $fakeFiles) {
    if (-not (Test-Path $f.Path)) {
        New-Item -Path $f.Path -ItemType File -Force | Out-Null
        $ts = (Get-Date).AddDays(-$f.Age).AddHours(-$rng.Next(0,23))
        try {
            $item = Get-Item $f.Path
            $item.LastWriteTime  = $ts
            $item.CreationTime   = $ts.AddDays(-$rng.Next(0,5))
            $item.LastAccessTime = (Get-Date).AddHours(-$rng.Next(1,72))
            Write-Ok "Created: $($f.Path)"
        } catch { Write-Skip "Could not set timestamp: $($f.Path)" }
    } else { Write-Skip "Exists: $($f.Path)" }
}

# Recent files MRU (shell:recent)
$recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
$wsh = New-Object -ComObject WScript.Shell -ErrorAction SilentlyContinue
if ($wsh) {
    foreach ($f in $fakeFiles) {
        $lnkPath = Join-Path $recentDir ([System.IO.Path]::GetFileName($f.Path) + ".lnk")
        if (-not (Test-Path $lnkPath)) {
            try {
                $lnk = $wsh.CreateShortcut($lnkPath)
                $lnk.TargetPath = $f.Path
                $lnk.Save()
                Write-Ok "Recent MRU: $([System.IO.Path]::GetFileName($f.Path))"
            } catch { }
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  35. BROWSER STUB — create minimal Chrome + Edge profile directories
#      No browser history = instant sandbox fingerprint for many samples.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Browser profiles — creating minimal profile stubs"

# Chrome
$chromeDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
if (-not (Test-Path $chromeDir)) {
    New-Item $chromeDir -ItemType Directory -Force | Out-Null
    $prefs = '{"browser":{"last_known_google_url":"https://www.google.com/","last_prompted_google_url":"https://www.google.com/"},"profile":{"name":"Default"},"session":{"restore_on_startup":1}}'
    Set-Content "$chromeDir\Preferences" $prefs -Encoding UTF8
    Write-Ok "Created Chrome profile stub"
} else { Write-Skip "Chrome profile already exists" }

# Edge
$edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
if (-not (Test-Path $edgeDir)) {
    New-Item $edgeDir -ItemType Directory -Force | Out-Null
    Write-Ok "Created Edge profile stub"
} else { Write-Skip "Edge profile already exists" }


# ─────────────────────────────────────────────────────────────────────────────
#  36. STARTUP ITEMS — add realistic-looking autorun entries
#      An empty HKCU\...\Run key is a sandbox tell.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Startup items — adding realistic Run key entries"

$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$existingRun = (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).PSObject.Properties |
               Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") }
if ($existingRun.Count -lt 2) {
    Set-ItemProperty $runKey "OneDrive"  "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe /background" -Force
    Set-ItemProperty $runKey "Discord"   "$env:LOCALAPPDATA\Discord\Update.exe --processStart Discord.exe" -Force
    Set-ItemProperty $runKey "Spotify"   "$env:APPDATA\Spotify\Spotify.exe --autostart" -Force
    Write-Ok "Added realistic startup entries (OneDrive, Discord, Spotify)"
} else {
    Write-Ok "Run key already has $($existingRun.Count) entries"
}


# ─────────────────────────────────────────────────────────────────────────────
#  37. MOUSE ACTIVITY SCHEDULED TASK
#      Malware commonly checks that the mouse has moved since boot.
#      A zero-movement cursor (default in fresh VMs) aborts execution.
#      We install a lightweight scheduled task that jitters the cursor.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Mouse activity — installing cursor-jitter scheduled task"

$mouseMoverScript = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeMouse {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT lp);
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
}
"@
$rng = New-Object System.Random
while ($true) {
    Start-Sleep -Seconds ($rng.Next(15, 45))
    $pt = New-Object NativeMouse+POINT
    [NativeMouse]::GetCursorPos([ref]$pt) | Out-Null
    [NativeMouse]::SetCursorPos($pt.X + $rng.Next(-8, 8), $pt.Y + $rng.Next(-8, 8)) | Out-Null
}
'@

$scriptPath = "$env:APPDATA\Microsoft\Windows\SystemEvents\ActivityHelper.ps1"
New-Item (Split-Path $scriptPath) -ItemType Directory -Force | Out-Null
Set-Content $scriptPath $mouseMoverScript -Encoding UTF8

$action   = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateBroker" -Action $action `
    -Trigger $trigger -Settings $settings -RunLevel Highest -Force -ErrorAction SilentlyContinue
Write-Ok "Installed cursor-jitter task: MicrosoftEdgeUpdateBroker"


# ─────────────────────────────────────────────────────────────────────────────
#  ══ FINAL VERIFICATION REPORT ══
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("  " + "═"*63) -ForegroundColor Green
Write-Host "   CLEANUP COMPLETE — REBOOT NOW" -ForegroundColor Green
Write-Host ("  " + "═"*63) -ForegroundColor Green
Write-Host @"

  After reboot, verify each item:
  ─────────────────────────────────────────────────────────────
  WMI check (Admin PS):
    Get-WmiObject Win32_ComputerSystem  | Select Manufacturer,Model
    Get-WmiObject Win32_BIOS            | Select Manufacturer,SMBIOSBIOSVersion
    Get-WmiObject Win32_DiskDrive       | Select Model,Size
    Get-WmiObject Win32_VideoController | Select Name,AdapterRAM
    Get-WmiObject Win32_SoundDevice     | Select Name
    Get-NetAdapter | Select Name,InterfaceDescription,MacAddress

  Process / registry:
    Get-Process  | Where-Object Name -imatch vmware
    Get-Service  | Where-Object Name -imatch vmware
    Test-Path "HKLM:\SOFTWARE\VMware, Inc."    # → False
    Test-Path "HKLM:\SOFTWARE\VMware, Inc." -PathType Container  # → False

  External tools (drop in VM, run without admin):
    pafish.exe         https://github.com/a0rtega/pafish
    al-khaser.exe      https://github.com/LordNoteworthy/al-khaser

  Host-side reminder (applied by vmstealth.py on the VMX):
    ✓ CPUID hypervisor bit cleared
    ✓ CPUID leaf 0x40000000 zeroed
    ✓ RDTSC passthrough enabled
    ✓ SMBIOS reflected from host
    ✓ ACPI tables passed through
    ✓ VMCI device removed
    ✓ MAC address randomised
    ✓ Memory page-sharing disabled
    ✓ Hyper-V compat disabled
    ✓ VMware logging disabled
  ─────────────────────────────────────────────────────────────
"@
"""


def write_guest_script(dest: Path) -> None:
    dest.write_text(GUEST_PS1, encoding="utf-8")
    print(f"\n  [+] Guest script → {dest}")
    print("      Transfer to the Windows VM, then run:")
    print("      powershell -ExecutionPolicy Bypass -File .\\clean_guest.ps1\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(
        description="vmstealth — elite VMware stealth patcher for malware analysis labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detection tiers defeated
  HOST-SIDE (VMX patch):
    CPUID hypervisor bit · CPUID vendor leaf (zeroed) · VMware backdoor port
    RDTSC timing · SMBIOS/DMI host-reflect · ACPI table passthru
    VMCI PCI device · floppy/serial/parallel removal · SVGA VRAM 256 MB
    Memory page-sharing (dedup timing) · named memory file · balloon driver
    memory trim · Hyper-V enlightenments · time-sync channels · named pipes
    VMware log files · MAC address OUI randomisation

  GUEST-SIDE (clean_guest.ps1):
    Registry (SW/services/ControlSet/uninstall) · services · processes
    binary renaming · kernel driver (.sys) renaming · VMware DLLs
    PCI VEN_15AD hardware IDs (all 9 device IDs) · SCSI/IDE device strings
    HARDWARE\\DEVICEMAP\\Scsi · NIC class registry · GPU class registry
    audio class registry · SystemInformation OEM strings · BIOS hive strings
    ACPI table registry key names · event logs · firewall rules · env vars
    prefetch files · scheduled tasks · named pipe scan · analysis-tool check
    network gateway fingerprint · computer name · username · screen resolution
    RAM/CPU spec · disk size · volume serial · uptime · locale/timezone
    user artifact simulation · browser profile stubs · startup Run entries
    mouse cursor jitter task

Examples:
  python3 vmstealth.py "Windows 10.vmx" --guest-script clean_guest.ps1
  python3 vmstealth.py "Windows 10.vmx" --scan
  python3 vmstealth.py "Windows 10.vmx" --aggressive --guest-script clean_guest.ps1
        """,
    )
    p.add_argument("vmx",            nargs="?",       help="Path to .vmx file (VM must be shut down)")
    p.add_argument("--guest-script", metavar="PATH",  help="Write guest PowerShell script to PATH")
    p.add_argument("--scan",         action="store_true", help="Audit VMX file without modifying it")
    p.add_argument("--aggressive",   action="store_true",
                   help="Also swap NIC to e1000e, disable 3D SVGA, remove xHCI USB controller")
    args = p.parse_args()

    if not args.vmx and not args.guest_script:
        p.print_help()
        sys.exit(0)

    if args.guest_script:
        write_guest_script(Path(args.guest_script))

    if args.vmx:
        vmx = Path(args.vmx)
        if not vmx.exists():
            print(f"[!] File not found: {vmx}", file=sys.stderr)
            sys.exit(1)
        if vmx.suffix.lower() != ".vmx":
            print(f"[!] Expected a .vmx file, got: {vmx.suffix}", file=sys.stderr)
            sys.exit(1)
        if args.scan:
            scan_vmx(vmx)
        else:
            patch_vmx(vmx, aggressive=args.aggressive)


if __name__ == "__main__":
    main()
