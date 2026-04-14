#!/usr/bin/env python3
"""
vmstealth_fusion_arm.py — VMware Fusion Stealth Patcher (Apple Silicon Edition)
Malware-analysis lab tool for VMware Fusion 13+ on Apple Silicon (M1/M2/M3/M4).

Two-step workflow
─────────────────
Step 1  (HOST — VM must be shut down):
    python3 vmstealth_fusion_arm.py "Windows 11.vmwarevm" --guest-script clean_guest_arm.ps1

Step 2  (inside Windows ARM VM, Admin PowerShell):
    powershell -ExecutionPolicy Bypass -File .\\clean_guest_arm.ps1

Flags:
    --scan        Audit the VMX without modifying it
    --aggressive  Also swap NIC to e1000e + disable 3D SVGA + remove xHCI

Requirements:
    Python 3.9+ (uses built-in type hints)

Apple Silicon / Fusion-specific notes
──────────────────────────────────────
• VMware Fusion stores VMs as .vmwarevm bundles (macOS packages).  This script
  accepts either the bundle directory path OR the raw .vmx path inside it.

• SMBIOS.reflectHost on an Apple Silicon Mac passes APPLE hardware strings
  (Manufacturer="Apple Inc.", Product="Mac Studio", etc.) into the guest —
  NOT VMware strings.  The companion script clean_guest_arm.ps1 (Section 0)
  patches those Apple strings to a Dell identity before anything else runs.

• monitor_control.virtual_rdtsc has no effect for native ARM64 guest code
  (which uses CNTPCT_EL0 instead of RDTSC).  It is still applied because x86
  malware running under the WoW64/Prism emulation layer does execute RDTSC and
  is subject to timing side-channels through the emulation path.

• monitor_control.restrict_backdoor is still relevant: VMware Tools probes the
  backdoor I/O port (0x5658 / 'VMXh') even in ARM guests for host ↔ guest
  communication.

• Windows 11 ARM64 architecture (Win32_Processor.Architecture=12) is an
  unavoidable fingerprint for ARM64-native samples.  x86/x64 malware running
  under WoW64 sees Architecture=9 and is unaffected.
"""

import re
import sys
import random
import argparse
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
#  VMX STEALTH SETTINGS — Fusion / Apple Silicon edition
#
#  Format reminder: CPUID mask strings are 32 chars, leftmost = bit 0,
#  rightmost = bit 31.  "-------------------------------0" clears bit 31.
# ═══════════════════════════════════════════════════════════════════════════════

VMX_STEALTH: dict[str, str] = {

    # ── TIER 1 : CPUID hypervisor bit ─────────────────────────────────────────
    # Bit 31 of ECX at leaf 1.  On ARM Windows, x86 binaries execute under the
    # Prism WoW64 emulation layer, which still exposes an emulated CPUID; the
    # hypervisor bit in ECX is visible there.
    "CPUID.1.ECX": "-------------------------------0",

    # Zero the hypervisor vendor leaf (0x40000000) entirely.
    # belt-and-suspenders on top of hypervisor.cpuid.v0=FALSE.
    "cpuid.40000000.eax": "00000000000000000000000000000000",
    "cpuid.40000000.ebx": "00000000000000000000000000000000",
    "cpuid.40000000.ecx": "00000000000000000000000000000000",
    "cpuid.40000000.edx": "00000000000000000000000000000000",
    "hypervisor.cpuid.v0": "FALSE",

    # ── TIER 2 : VMware backdoor I/O port (0x5658 / 'VMXh') ──────────────────
    # Probed by VMware Tools for host ↔ guest RPC even in ARM guests.
    # Restricting it returns junk instead of the VMware magic EBX value.
    "monitor_control.restrict_backdoor": "TRUE",

    # ── TIER 3 : RDTSC / timing ───────────────────────────────────────────────
    # No-op for native ARM64 guest code (ARM uses CNTPCT_EL0, not RDTSC).
    # Still applied for x86/x64 binaries running under Prism emulation, which
    # do execute RDTSC and can detect VM-exit timing inflation.
    "monitor_control.virtual_rdtsc": "FALSE",

    # ── TIER 4 : SMBIOS / DMI ─────────────────────────────────────────────────
    # On Apple Silicon, reflectHost passes APPLE hardware data into the guest
    # (Manufacturer="Apple Inc.", Product="Mac Studio", etc.).
    # clean_guest_arm.ps1 Section 0 patches these to Dell OptiPlex 7090.
    "SMBIOS.reflectHost":       "TRUE",
    "board-id.reflectHost":     "TRUE",   # passes Apple board-id, e.g. "Mac14,13"
    "hw.model.reflectHost":     "TRUE",
    "serialNumber.reflectHost": "TRUE",
    "SMBIOS.noOEMStrings":      "TRUE",

    # ── TIER 5 : ACPI tables ──────────────────────────────────────────────────
    # Apple's ACPI OEM strings ("APPLE ", "Apple Inc") contain no "VMWARE".
    # Passthrough removes any residual VMware ACPI identifiers and replaces
    # them with Apple's real tables — an improvement over synthetic VMware ones.
    "acpi.passthru.bios": "TRUE",
    "acpi.passthru.cpu":  "TRUE",

    # ── TIER 6 : VMCI PCI device ──────────────────────────────────────────────
    # PCI VID 0x15AD DevID 0x0740 — still present in Fusion ARM guests.
    # Enumerable via SetupDi and WMI; removing it at VMX level is cleaner
    # than registry patching alone.
    "vmci0.present": "FALSE",

    # ── TIER 7 : Legacy hardware (dead giveaways) ─────────────────────────────
    # No 2020s bare-metal machine ships with floppy/serial/parallel ports.
    "floppy0.present":   "FALSE",
    "serial0.present":   "FALSE",
    "parallel0.present": "FALSE",

    # ── TIER 8 : SVGA VRAM ────────────────────────────────────────────────────
    # Default VMware VRAM = 16 MB.  Win32_VideoController.AdapterRAM = 16 MB
    # is a strong VM tell.  256 MB is realistic for integrated graphics.
    "svga.vramSize": "268435456",   # 256 MB

    # ── TIER 9 : Memory subsystem timing attacks ──────────────────────────────
    # Page-sharing (dedup) creates a write-latency side-channel.
    # Named memory file and balloon driver are additional VM tells.
    "sched.mem.pshare.enable": "FALSE",
    "mainMem.useNamedFile":    "FALSE",
    "sched.mem.maxmemctl":     "0",
    "MemTrimRate":             "0",

    # ── TIER 10 : Hyper-V enlightenments ──────────────────────────────────────
    # Windows 11 ARM uses Hyper-V enlightenments internally.  Exposing them
    # via vhv.enable reveals nested Hyper-V CPUID leaves to the guest.
    "vhv.enable": "FALSE",

    # ── TIER 11 : Time synchronisation ───────────────────────────────────────
    "tools.syncTime":                 "FALSE",
    "time.synchronize.continue":      "FALSE",
    "time.synchronize.restore":       "FALSE",
    "time.synchronize.resume.disk":   "FALSE",
    "time.synchronize.shrink":        "FALSE",
    "time.synchronize.tools.startup": "FALSE",
    "time.synchronize.tools.enable":  "FALSE",

    # ── TIER 12 : Named-pipe channels (host ↔ guest) ──────────────────────────
    # Clipboard, DnD, and HGFS each open named pipes.  Malware enumerates
    # \\.\pipe\* and flags VMware-named pipes.
    "isolation.tools.copy.disable":         "TRUE",
    "isolation.tools.paste.disable":        "TRUE",
    "isolation.tools.dnd.disable":          "TRUE",
    "isolation.tools.setGUIOptions.enable": "FALSE",
    "isolation.tools.hgfs.disable":         "TRUE",
    "isolation.tools.autoInstall.disable":  "TRUE",

    # ── TIER 13 : VMware log files ────────────────────────────────────────────
    "logging": "FALSE",

    # ── Miscellaneous ─────────────────────────────────────────────────────────
    "mce.enable":           "TRUE",   # MCE present on real bare-metal
    "tools.upgrade.policy": "manual",
}

# ── Aggressive-mode extras (--aggressive) ─────────────────────────────────────
VMX_AGGRESSIVE: dict[str, str] = {
    # Replace VMXNET3 (VID 0x15AD DevID 0x07B0) with emulated Intel e1000e.
    # Windows 11 ARM has the inbox e1000e driver; expect a new-hardware prompt.
    "ethernet0.virtualDev": "e1000e",

    # Disable 3D SVGA (PCI ID 0x15AD:0x0405 is detectable via SetupDi).
    "mks.enable3d": "FALSE",

    # Remove VMware-branded xHCI USB controller.
    "usb_xhci.present": "FALSE",
}

# ── MAC address OUI tables ────────────────────────────────────────────────────
VMWARE_OUIS = {"00:0C:29", "00:50:56", "00:05:69", "00:1C:14"}

REAL_OUIS = [
    "00:1B:21", "8C:16:45", "FC:AA:14", "00:23:AE", "14:DD:A9",
    "A4:C3:F0", "AC:FD:CE", "A0:36:9F", "F4:4D:30",   # Intel
    "00:E0:4C", "BC:EE:7B", "E0:CB:4E", "D0:17:C2",   # Realtek
    "00:10:18", "00:1A:1E", "48:51:B7",                # Broadcom
    "38:EA:A7", "D4:3B:04", "8C:8D:28", "34:02:86",   # Intel Wi-Fi
]


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def random_mac(oui: str) -> str:
    tail = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{tail}"


def is_vmware_mac(mac: str) -> bool:
    return mac.upper()[:8] in VMWARE_OUIS


def resolve_vmx(path: Path) -> Path:
    """Accept a .vmwarevm bundle or a bare .vmx; return the .vmx path."""
    if path.suffix.lower() == ".vmwarevm":
        if not path.is_dir():
            print(f"[!] Bundle path is not a directory: {path}", file=sys.stderr)
            sys.exit(1)
        candidates = sorted(path.glob("*.vmx"))
        if not candidates:
            print(f"[!] No .vmx found inside bundle: {path}", file=sys.stderr)
            sys.exit(1)
        if len(candidates) > 1:
            print(f"  [?] Multiple .vmx files found inside bundle — using: {candidates[0].name}")
        return candidates[0]
    return path


# ═══════════════════════════════════════════════════════════════════════════════
#  PATCH MODE
# ═══════════════════════════════════════════════════════════════════════════════

def patch_vmx(vmx_path: Path, aggressive: bool = False) -> None:
    print(f"\n  vmstealth-fusion-arm — patch mode\n  {'─'*54}")
    print(f"  Target : {vmx_path}")

    original = vmx_path.read_text(encoding="utf-8", errors="replace")
    lines    = original.splitlines()

    backup = vmx_path.with_suffix(".vmx.bak")
    if not backup.exists():
        backup.write_text(original, encoding="utf-8")
        print(f"  Backup : {backup}")
    else:
        print(f"  Backup : already exists — skipping")

    # Build case-insensitive key → line-index map
    key_idx: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"', line)
        if m:
            key_idx[m.group(1).lower()] = i

    updated:  list[str] = list(lines)
    appended: list[str] = []

    settings = {**VMX_STEALTH, **(VMX_AGGRESSIVE if aggressive else {})}

    print(f"\n  {'─'*54}\n  VMX stealth settings\n  {'─'*54}")
    for key, value in settings.items():
        new_line = f'{key} = "{value}"'
        idx = key_idx.get(key.lower())
        if idx is not None:
            if updated[idx] != new_line:
                updated[idx] = new_line
                print(f"  [~] {key}")
            # else: already correct — silent
        else:
            appended.append(new_line)
            print(f"  [+] {key}")

    # ── MAC address randomisation ──────────────────────────────────────────────
    print(f"\n  {'─'*54}\n  MAC address randomisation\n  {'─'*54}")
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
            # Force addressType to static so the new MAC sticks
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

    print(f"\n  {'─'*54}")
    print(f"  Done → {vmx_path}")
    if aggressive:
        print("  Aggressive: NIC → e1000e  |  3D SVGA disabled  |  xHCI removed")
        print("  First boot will prompt for new NIC hardware — this is normal.")
    print()
    print("  ⚠  VM must be shut down before changes take effect.")
    print("  ⚠  SMBIOS reflects Apple Silicon host data (Apple Inc. manufacturer).")
    print("  ⚠  Run clean_guest_arm.ps1 inside the VM as Admin to patch Apple strings.")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN / AUDIT MODE
# ═══════════════════════════════════════════════════════════════════════════════

def scan_vmx(vmx_path: Path) -> None:
    print(f"\n  vmstealth-fusion-arm — scan / audit mode\n  {'─'*54}")
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

    chk("CPUID hypervisor bit",      "CPUID.1.ECX",                       "-------------------------------0")
    chk("CPUID leaf 0x40000000 EAX", "cpuid.40000000.eax",                "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 EBX", "cpuid.40000000.ebx",                "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 ECX", "cpuid.40000000.ecx",                "00000000000000000000000000000000")
    chk("CPUID leaf 0x40000000 EDX", "cpuid.40000000.edx",                "00000000000000000000000000000000")
    chk("Hypervisor CPUID leaf",     "hypervisor.cpuid.v0",               "FALSE")
    chk("Backdoor I/O port",         "monitor_control.restrict_backdoor", "TRUE")
    chk("RDTSC (WoW64 emulation)",   "monitor_control.virtual_rdtsc",     "FALSE",
        "no-op for native ARM64; covers x86 apps under Prism WoW64")
    chk("SMBIOS reflect host",       "SMBIOS.reflectHost",                "TRUE",
        "reflects Apple SMBIOS — guest script patches to Dell")
    chk("Board-ID reflect host",     "board-id.reflectHost",              "TRUE")
    chk("HW model reflect host",     "hw.model.reflectHost",              "TRUE")
    chk("Serial# reflect host",      "serialNumber.reflectHost",          "TRUE")
    chk("No OEM SMBIOS strings",     "SMBIOS.noOEMStrings",               "TRUE")
    chk("ACPI passthru BIOS",        "acpi.passthru.bios",                "TRUE",
        "Apple ACPI has no VMWARE strings — safe to pass through")
    chk("ACPI passthru CPU",         "acpi.passthru.cpu",                 "TRUE")
    chk("VMCI device removed",       "vmci0.present",                     "FALSE",
        "PCI VID 0x15AD DevID 0x0740")
    chk("Floppy removed",            "floppy0.present",                   "FALSE")
    chk("Serial port removed",       "serial0.present",                   "FALSE")
    chk("Parallel port removed",     "parallel0.present",                 "FALSE")
    chk("SVGA VRAM 256 MB",          "svga.vramSize",                     "268435456",
        "16 MB default is a tell")
    chk("Mem page-sharing off",      "sched.mem.pshare.enable",           "FALSE",
        "dedup timing side-channel")
    chk("Named mem file off",        "mainMem.useNamedFile",              "FALSE")
    chk("Balloon driver off",        "sched.mem.maxmemctl",               "0")
    chk("Mem trim off",              "MemTrimRate",                       "0")
    chk("Hyper-V compat off",        "vhv.enable",                        "FALSE")
    chk("Logging disabled",          "logging",                           "FALSE")
    chk("Time sync off",             "tools.syncTime",                    "FALSE")
    chk("DnD pipe disabled",         "isolation.tools.dnd.disable",       "TRUE")
    chk("Clipboard pipe disabled",   "isolation.tools.copy.disable",      "TRUE")
    chk("HGFS pipe disabled",        "isolation.tools.hgfs.disable",      "TRUE")

    # MAC address check
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
        results.append(("WARN", "NIC virtual device",
                        f'"{nic}" — VMware-only; use e1000e (--aggressive)'))
    elif nic == "e1000e":
        results.append(("PASS", "NIC virtual device", '"e1000e" (realistic Intel)'))
    else:
        results.append(("WARN", "NIC virtual device",
                        f'"{nic or "(not set)"}" — confirm it is not vmxnet3'))

    # 3D SVGA
    s3d = kv.get("mks.enable3d", "TRUE")
    if s3d.upper() == "FALSE":
        results.append(("PASS", "3D SVGA", "disabled"))
    else:
        results.append(("WARN", "3D SVGA",
                        "enabled — PCI ID 0x15AD:0x0405 detectable via SetupDi"))

    # RAM
    try:
        mem = int(kv.get("memsize", "0"))
        if mem < 4096:
            results.append(("WARN", "RAM", f"{mem} MB — < 4 GB triggers sandbox checks"))
        else:
            results.append(("PASS", "RAM", f"{mem} MB"))
    except ValueError:
        pass

    # vCPU
    cpus = kv.get("numvcpus", "1")
    if cpus == "1":
        results.append(("WARN", "vCPU count", "1 — single-core is a sandbox fingerprint"))
    else:
        results.append(("PASS", "vCPU count", cpus))

    # SCSI
    scsi = kv.get("scsi0.virtualdev", "")
    if scsi.lower() == "pvscsi":
        results.append(("WARN", "SCSI controller",
                        "pvscsi — VMware-proprietary; consider lsisas1068"))
    elif scsi:
        results.append(("PASS", "SCSI controller", f'"{scsi}"'))

    # Print results table
    W = 40
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
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED GUEST SCRIPT
#  Written to disk with --guest-script <path>.
#  This is the ARM edition of clean_guest.ps1 with:
#    - Section 0: Apple SMBIOS patching (patches Apple Inc. → Dell OptiPlex 7090)
#    - Section 38: ARM64 architecture fingerprint note
#    - All WMI calls updated to Get-CimInstance
#    - Pattern matching extended to include "Apple" strings
# ═══════════════════════════════════════════════════════════════════════════════

GUEST_PS1 = r"""
# =============================================================================
#  VMware Guest Artifact Cleaner — Apple Silicon / ARM Edition
#  Run INSIDE Windows 11 ARM VM as Administrator.
#  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#
#  TARGET: VMware Fusion 13+ on Apple Silicon (M1/M2/M3/M4)
#          Guest: Windows 11 ARM64
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

Write-Host "`n  VMware Guest Cleaner — Apple Silicon ARM Edition" -ForegroundColor DarkCyan
Write-Host "  Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)`n"

$vmPattern = "Apple|VMware|Virtual|BOCHS|QEMU|Hyper-V|innotek|Parallels"

# ─────────────────────────────────────────────────────────────────────────────
#  0. APPLE SMBIOS — patch host-reflected Apple hardware identity  [ARM SPECIFIC]
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Apple SMBIOS — patching host-reflected Apple hardware identity"

$dellIdentity = @{
    "SystemProductName"  = "OptiPlex 7090"
    "SystemManufacturer" = "Dell Inc."
    "SystemFamily"       = "OptiPlex"
    "SystemVersion"      = "OptiPlex 7090"
    "BIOSVersion"        = "1.12.0"
    "BIOSReleaseDate"    = "09/15/2023"
    "BIOSVendor"         = "Dell Inc."
}
$sysInfoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"
if (Test-Path $sysInfoPath) {
    $p = Get-ItemProperty $sysInfoPath -ErrorAction SilentlyContinue
    foreach ($field in $dellIdentity.Keys) {
        $val = $p.$field
        if ($val -imatch $vmPattern) {
            Set-ItemProperty $sysInfoPath $field $dellIdentity[$field] -Force
            Write-Ok "$field: '$val'  ->  '$($dellIdentity[$field])'"
        } elseif ($val) { Write-Skip "$field already clean: '$val'" }
    }
}
$hwDesc = "HKLM:\HARDWARE\DESCRIPTION\System"
if (Test-Path $hwDesc) {
    $p = Get-ItemProperty $hwDesc -ErrorAction SilentlyContinue
    if ($p.SystemBiosVersion -imatch "Apple|VMWARE|VIRTUAL|BOCHS|QEMU|SEABIOS") {
        Set-ItemProperty $hwDesc "SystemBiosVersion" "Dell Inc. 1.12.0, 09/15/2023" -Force
        Write-Ok "Patched HARDWARE SystemBiosVersion"
    }
    if ($p.SystemBiosDate -and ($p.SystemBiosDate -lt "01/01/2020")) {
        Set-ItemProperty $hwDesc "SystemBiosDate" "09/15/2023" -Force
        Write-Ok "Patched HARDWARE SystemBiosDate"
    }
    if ($p.VideoBiosVersion -imatch "Apple|VMWARE|VIRTUAL|BOCHS|QEMU|SEABIOS") {
        Set-ItemProperty $hwDesc "VideoBiosVersion" "Version 3.0 Rev. A" -Force
        Write-Ok "Patched HARDWARE VideoBiosVersion"
    }
    if ($p.Identifier -imatch "VRTUAL|Virtual|Apple") {
        Set-ItemProperty $hwDesc "Identifier" "AT/AT COMPATIBLE" -Force
        Write-Ok "Patched HARDWARE Identifier"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  EMBEDDED FALLBACK — condensed sections
#  Covers: registry, services, processes, binaries, drivers, DLLs, PCI devices,
#  disk strings, NICs, GPU, audio, sysinfo, programs, prefetch, scheduled tasks,
#  event logs, firewall rules, WMI verification, network, computer name,
#  username, RAM/CPU, disk size, uptime, timezone, user artifacts, startup items.
#
#  Missing vs. standalone clean_guest_arm.ps1: DEVICEMAP\Scsi (9), ACPI keys
#  (15), environment variables (21), screen resolution (26), volume serial (29),
#  named pipes (32), anti-analysis tools (33), browser stubs (35), mouse jitter
#  (37).  Copy clean_guest_arm.ps1 next to this script to get all 38 sections.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Registry — removing VMware keys"
$regKeys = @(
    "HKLM:\SOFTWARE\VMware, Inc.","HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.",
    "HKCU:\Software\VMware, Inc.",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmci",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmmemctl",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vsock",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VGAuthService",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dmp",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMUSBArbService",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmvss",
    "HKLM:\SYSTEM\CurrentControlSet\Services\pvscsi",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6",
    "HKLM:\SYSTEM\ControlSet001\Services\VMTools",
    "HKLM:\SYSTEM\ControlSet001\Services\vmci",
    "HKLM:\SYSTEM\ControlSet001\Services\VGAuthService",
    "HKLM:\SYSTEM\ControlSet001\Services\pvscsi",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VMware Tools",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VMware Tools"
)
foreach ($key in $regKeys) {
    if (Test-Path $key) { Remove-Item $key -Recurse -Force; Write-Ok $key }
    else                { Write-Skip $key }
}

Write-Step "Services — stopping and disabling VMware services"
foreach ($svc in @("VMTools","VGAuthService","VMware Physical Disk Helper Service",
                   "VMUSBArbService","vmvss","vm3dmp","vmci","pvscsi")) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        Set-Service  $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Ok "Stopped + disabled: $svc"
    } else { Write-Skip $svc }
}

Write-Step "Processes — terminating VMware processes"
foreach ($proc in @("vmtoolsd","vmwaretray","vmwareuser","vmacthlp",
                    "VGAuthService","VMwareService","vmnat","vmnetdhcp")) {
    $p = Get-Process $proc -ErrorAction SilentlyContinue
    if ($p) { $p | Stop-Process -Force; Write-Ok "Killed: $proc" }
    else    { Write-Skip $proc }
}

Write-Step "Binaries — renaming VMware executables"
$binaryMap = @{
    "vmtoolsd.exe"="RuntimeBroker2.exe"; "vmwaretray.exe"="taskhostw2.exe"
    "vmwareuser.exe"="sihost2.exe"; "vmacthlp.exe"="ctfmon2.exe"
    "VGAuthService.exe"="LsaIso2.exe"
}
$vmDir = "$env:ProgramFiles\VMware\VMware Tools"
foreach ($orig in $binaryMap.Keys) {
    $full = Join-Path $vmDir $orig
    if (Test-Path $full) {
        Rename-Item $full -NewName $binaryMap[$orig] -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$orig  ->  $($binaryMap[$orig])" }
        else    { Write-Warn "Locked: $orig — reboot and retry" }
    } else { Write-Skip $orig }
}

Write-Step "Kernel drivers — renaming VMware .sys files (ARM64)"
$driverMap = @{
    "vmhgfs.sys"="hgfsport.sys"; "vmci.sys"="msgpioclx2.sys"
    "vm3dmp.sys"="dxgkrnl2.sys"; "vmmemctl.sys"="dxgmms2.sys"
    "vsock.sys"="rfcomm2.sys"; "pvscsi.sys"="lsi_sas2.sys"
    "vmxnet3ndis6.sys"="e1g6032e.sys"; "vmmouse.sys"="mouclass2.sys"
}
$driversDir = "$env:SystemRoot\System32\drivers"
foreach ($orig in $driverMap.Keys) {
    $full = Join-Path $driversDir $orig
    if (Test-Path $full) {
        & takeown /f $full /a 2>&1 | Out-Null
        & icacls  $full /grant "Administrators:F" 2>&1 | Out-Null
        Rename-Item $full -NewName $driverMap[$orig] -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$orig  ->  $($driverMap[$orig])" }
        else    { Write-Warn "Could not rename (HVCI/in-use): $orig — reboot first" }
    } else { Write-Skip $orig }
}

Write-Step "DLLs — renaming VMware guest library DLLs"
$dllPaths = @(
    "$env:SystemRoot\System32\vmGuestLib.dll",
    "$env:SystemRoot\SysWOW64\vmGuestLib.dll",
    "$env:SystemRoot\System32\vm3dgl.dll",
    "$env:SystemRoot\System32\vmhgfs.dll"
)
foreach ($dll in $dllPaths) {
    if (Test-Path $dll) {
        & takeown /f $dll /a 2>&1 | Out-Null
        & icacls  $dll /grant "Administrators:F" 2>&1 | Out-Null
        $newName = (Split-Path $dll -Leaf) `
            -replace "vmGuestLib","msvcm140_app" `
            -replace "vmhgfs","ntdll_ext" `
            -replace "vm3dgl","d3d11_2"
        Rename-Item $dll -NewName $newName -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Ok "$(Split-Path $dll -Leaf)  ->  $newName" }
        else    { Write-Warn "Could not rename: $dll" }
    } else { Write-Skip $dll }
}

Write-Step "PCI devices — patching VMware VID 0x15AD hardware entries"
$pciReplace = @{
    "DEV_0405"="Intel(R) UHD Graphics 630"; "DEV_0740"="Intel(R) Serial I/O GPIO Host Controller"
    "DEV_07B0"="Intel(R) 82579LM Gigabit Network Connection"; "DEV_07C0"="LSI Adapter, SAS 3000 series, 4-port"
    "DEV_0770"="Intel(R) USB 3.0 eXtensible Host Controller"; "DEV_1977"="Realtek High Definition Audio"
    "DEV_07A0"="Intel(R) PCI Express Root Port #1"; "DEV_0801"="Intel(R) Management Engine Interface"
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
            if ($p.FriendlyName) { Set-ItemProperty $_.PSPath "FriendlyName" $replacement -Force -ErrorAction SilentlyContinue }
            if ($p.DeviceDesc)   { Set-ItemProperty $_.PSPath "DeviceDesc"   $replacement -Force -ErrorAction SilentlyContinue }
        }
        Write-Ok "VEN_15AD $($hwid -replace 'VEN_15AD&','')  ->  $replacement"
    }
}

Write-Step "Disk devices — patching SCSI/IDE friendly names"
foreach ($bus in @("HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI","HKLM:\SYSTEM\CurrentControlSet\Enum\IDE")) {
    if (-not (Test-Path $bus)) { continue }
    Get-ChildItem $bus -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.FriendlyName -imatch "VMware|VMWARE") {
            $new = $p.FriendlyName `
                -replace "VMware Virtual NVMe Disk","Samsung SSD 970 EVO 500GB" `
                -replace "VMware Virtual SCSI Disk","ST1000DM010-2EP102" `
                -replace "VMware Virtual S","WDC WD10EZEX-08WN4A0" `
                -replace "VMware Virtual disk","ST1000DM010-2EP102" `
                -replace "VMware","ATA"
            Set-ItemProperty $_.PSPath "FriendlyName" $new -Force
            Write-Ok "Disk: '$($p.FriendlyName)'  ->  '$new'"
        }
    }
}

Write-Step "NIC class registry — patching DriverDesc"
$nicClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $nicClass) {
    Get-ChildItem $nicClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware|VMXNET") {
            Set-ItemProperty $_.PSPath "DriverDesc"   "Intel(R) 82579LM Gigabit Network Connection" -Force
            Set-ItemProperty $_.PSPath "ProviderName" "Intel" -Force
            Write-Ok "NIC: '$($p.DriverDesc)'  ->  Intel 82579LM"
        }
    }
}
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -imatch "VMware|VMXNET" } |
    ForEach-Object {
        Rename-NetAdapter -Name $_.Name -NewName "Ethernet" -ErrorAction SilentlyContinue
        Write-Ok "Renamed adapter: '$($_.Name)'  ->  Ethernet"
    }

Write-Step "GPU class registry — patching DriverDesc"
$gpuClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $gpuClass) {
    Get-ChildItem $gpuClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware|SVGA") {
            Set-ItemProperty $_.PSPath "DriverDesc"                        "Intel(R) UHD Graphics 630" -Force
            Set-ItemProperty $_.PSPath "ProviderName"                      "Intel Corporation" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.AdapterString" "Intel(R) UHD Graphics 630" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.ChipType"      "Intel UHD Graphics Family" -Force
            Set-ItemProperty $_.PSPath "HardwareInformation.MemorySize"    ([uint32]268435456) -Force
            Write-Ok "GPU: '$($p.DriverDesc)'  ->  Intel UHD Graphics 630"
        }
    }
}

Write-Step "Audio device class — patching DriverDesc"
$audioClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96C-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $audioClass) {
    Get-ChildItem $audioClass -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc -imatch "VMware") {
            Set-ItemProperty $_.PSPath "DriverDesc"   "Realtek High Definition Audio" -Force
            Set-ItemProperty $_.PSPath "ProviderName" "Realtek Semiconductor Corp." -Force
            Write-Ok "Audio: '$($p.DriverDesc)'  ->  Realtek HD Audio"
        }
    }
}

Write-Step "SystemInformation registry — verifying Dell identity"
$sysInfo = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"
if (Test-Path $sysInfo) {
    $replacements = @{
        "SystemProductName"="OptiPlex 7090"; "SystemManufacturer"="Dell Inc."
        "SystemFamily"="OptiPlex"; "SystemVersion"="OptiPlex 7090"
        "BIOSVersion"="1.12.0"; "BIOSReleaseDate"="09/15/2023"; "BIOSVendor"="Dell Inc."
    }
    $p = Get-ItemProperty $sysInfo -ErrorAction SilentlyContinue
    foreach ($field in $replacements.Keys) {
        $val = $p.$field
        if ($val -imatch $vmPattern) {
            Set-ItemProperty $sysInfo $field $replacements[$field] -Force
            Write-Ok "SystemInfo.$field: '$val'  ->  '$($replacements[$field])'"
        }
    }
}

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

Write-Step "Prefetch — deleting VMware prefetch files"
$prefetch = "$env:SystemRoot\Prefetch"
foreach ($pat in @("VMWARE*","VMTOOL*","VMACTHLP*","VGAUTH*","VM3DMP*","PVSCSI*")) {
    Get-ChildItem $prefetch -Filter $pat -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force; Write-Ok "Deleted: $($_.Name)"
    }
}

Write-Step "Scheduled tasks — removing VMware tasks"
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -imatch "VMware" -or $_.TaskPath -imatch "VMware" } |
    ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath `
            -Confirm:$false -ErrorAction SilentlyContinue
        Write-Ok "Removed task: $($_.TaskPath)$($_.TaskName)"
    }

Write-Step "Event logs — clearing VMware entries"
foreach ($logName in @("System","Application","Setup")) {
    $vmEvts = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
              Where-Object { $_.ProviderName -imatch "VMware" -or $_.Message -imatch "VMware Tools" }
    if ($vmEvts) {
        wevtutil cl $logName 2>&1 | Out-Null
        Write-Ok "Cleared $logName log ($($vmEvts.Count) VMware events)"
    } else { Write-Skip "$logName (no VMware events)" }
}

Write-Step "Firewall — removing VMware rules"
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -imatch "VMware" } |
    ForEach-Object { Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue; Write-Ok "Removed: $($_.DisplayName)" }

# ─────────────────────────────────────────────────────────────────────────────
#  WMI hardware verification — checks VMware AND Apple strings
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "WMI — hardware string verification (VMware + Apple)"

$cs   = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS            -ErrorAction SilentlyContinue
$disk = Get-CimInstance Win32_DiskDrive       -ErrorAction SilentlyContinue
$vid  = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
$net  = Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=TRUE" -ErrorAction SilentlyContinue

$badStrings = "VMware|Apple Inc\.|Apple Computer"

if ($cs) {
    Write-Host "    Manufacturer : $($cs.Manufacturer)  |  Model: $($cs.Model)"
    if ($cs.Manufacturer -imatch $badStrings) {
        Write-Fail "Still shows VM/Apple: '$($cs.Manufacturer)' — Section 0 may have failed, re-run as Admin"
    } else { Write-Ok "Manufacturer clean: $($cs.Manufacturer)" }
}
if ($bios) {
    Write-Host "    BIOS Vendor  : $($bios.Manufacturer)  |  Ver: $($bios.SMBIOSBIOSVersion)"
    if ($bios.Manufacturer -imatch $badStrings) { Write-Warn "BIOS vendor shows VM/Apple" }
    else { Write-Ok "BIOS vendor: $($bios.Manufacturer)" }
}
if ($disk) { $disk | ForEach-Object { Write-Host "    Disk         : $($_.Model)" } }
if ($vid)  { $vid  | ForEach-Object { Write-Host "    GPU          : $($_.Name)  VRAM: $([math]::Round($_.AdapterRAM/1MB)) MB" } }
if ($net)  { $net  | ForEach-Object { Write-Host "    NIC          : $($_.Name)  MAC: $($_.MACAddress)" } }

# ─────────────────────────────────────────────────────────────────────────────
#  Sandbox checks — same as x86 edition
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Network — checking for VMware NAT gateway fingerprint"
$defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
foreach ($r in $defaultRoutes) {
    if ($r.NextHop -match "^192\.168\.(1|2|131|254)\.2$") {
        Write-Warn "Default gateway $($r.NextHop) is a VMware NAT tell — switch to Bridged"
    } elseif ($r.NextHop -and $r.NextHop -ne "0.0.0.0") { Write-Ok "Gateway: $($r.NextHop)" }
}

Write-Step "Computer name — checking for VM/sandbox patterns"
$vmNamePat = "^(WIN-[A-Z0-9]{11}|sandbox|malware|virus|cuckoo|any\.run|triage|DESKTOP-[A-Z0-9]{7})$"
if ($env:COMPUTERNAME -imatch $vmNamePat) {
    $pick = @("JOHNS-PC","LAPTOP-HOME","WORKSTATION","DESKTOP-K7M2P4","USER-LAPTOP") | Get-Random
    Write-Warn "Computer name '$($env:COMPUTERNAME)' matches VM pattern."
    Write-Warn "Rename: Rename-Computer -NewName '$pick' -Force -Restart"
} else { Write-Ok "Computer name: $($env:COMPUTERNAME)" }

Write-Step "Username — checking for sandbox account names"
$badUsers = @("sandbox","malware","virus","john","user","analyst","test","sample",
              "admin","guest","cuckoo","vmware","triage","any","runner","lab")
if ($env:USERNAME -iin $badUsers) {
    Write-Warn "Username '$($env:USERNAME)' is a known sandbox name — create a realistic account"
} else { Write-Ok "Username: $($env:USERNAME)" }

Write-Step "Hardware specs — RAM and CPU"
$cs2 = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs2) {
    $ramGB = [math]::Round($cs2.TotalPhysicalMemory / 1GB, 1)
    $cpus  = $cs2.NumberOfLogicalProcessors
    Write-Host "    RAM: $ramGB GB   |   Logical CPUs: $cpus"
    if ($ramGB -lt 4) { Write-Warn "< 4 GB RAM — increase VM memory" } else { Write-Ok "RAM: $ramGB GB" }
    if ($cpus  -lt 2) { Write-Warn "Only 1 vCPU — increase to 2+" }   else { Write-Ok "CPUs: $cpus" }
}

Write-Step "Disk size — checking for sandbox-small disks"
Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
    $gb = if ($_.Size) { [math]::Round($_.Size / 1GB) } else { 0 }
    Write-Host "    $($_.Model): $gb GB"
    if ($gb -lt 60) { Write-Warn "Disk $gb GB — expand to 80+ GB" } else { Write-Ok "Disk size OK: $gb GB" }
}

Write-Step "Uptime — checking for fresh-sandbox boot pattern"
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Host "    Uptime: $([int]$uptime.TotalHours)h $($uptime.Minutes)m"
    if ($uptime.TotalMinutes -lt 30) {
        Write-Warn "Uptime < 30 min — let the VM run idle 30+ min before detonating"
    } else { Write-Ok "Uptime OK" }
}

Write-Step "Locale / timezone"
$tz = (Get-TimeZone).Id
Write-Host "    Timezone: $tz   Locale: $((Get-Culture).Name)"
if ($tz -match "^UTC$") { Write-Warn "Plain UTC — set a realistic timezone" } else { Write-Ok "Timezone: $tz" }

Write-Step "User artifacts — generating realistic user activity"
$docs = [Environment]::GetFolderPath("MyDocuments")
$desktop = [Environment]::GetFolderPath("Desktop")
$rng = New-Object System.Random
$fakeFiles = @(
    @{ Path="$docs\budget_2024.xlsx"; Age=14 }
    @{ Path="$docs\notes.txt"; Age=3 }
    @{ Path="$docs\work_report_Q1.docx"; Age=30 }
    @{ Path="$desktop\TODO.txt"; Age=1 }
)
foreach ($f in $fakeFiles) {
    if (-not (Test-Path $f.Path)) {
        New-Item -Path $f.Path -ItemType File -Force | Out-Null
        $ts = (Get-Date).AddDays(-$f.Age)
        try {
            $item = Get-Item $f.Path
            $item.LastWriteTime = $ts; $item.CreationTime = $ts
            Write-Ok "Created: $($f.Path)"
        } catch { }
    } else { Write-Skip "Exists: $($f.Path)" }
}

Write-Step "Startup items — adding realistic Run key entries"
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$existingRun = (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).PSObject.Properties |
               Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") }
if ($existingRun.Count -lt 2) {
    Set-ItemProperty $runKey "OneDrive" "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe /background" -Force
    Set-ItemProperty $runKey "Discord"  "$env:LOCALAPPDATA\Discord\Update.exe --processStart Discord.exe" -Force
    Write-Ok "Added realistic startup entries"
} else { Write-Ok "Run key already has $($existingRun.Count) entries" }

# ─────────────────────────────────────────────────────────────────────────────
#  38. ARM64 ARCHITECTURE — unavoidable fingerprint note  [ARM SPECIFIC]
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "ARM64 architecture — noting fingerprint (Apple Silicon specific)"

$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cpu) {
    Write-Host "    Processor    : $($cpu.Name)"
    Write-Host "    Architecture : $($cpu.Architecture)  (9=x64, 12=ARM64)"
    if ($cpu.Architecture -eq 12) {
        Write-Warn "Architecture=12 (ARM64) visible to native ARM64 processes."
        Write-Warn "  x86/x64 malware under WoW64 emulation sees Architecture=9 — unaffected."
        Write-Warn "  ARM64-native samples may detect this. Cannot be hidden from inside the guest."
        Write-Ok   "  Use x86/x64 samples for analysis; avoid ARM64-targeted malware."
    }
    if ($cpu.Name -imatch "VMware|QEMU|Virtual") {
        Write-Warn "Processor name '$($cpu.Name)' contains VM string"
    } else { Write-Ok "Processor name clean: $($cpu.Name)" }
}

Write-Host ""
Write-Host ("  " + "="*63) -ForegroundColor Green
Write-Host "   CLEANUP COMPLETE — REBOOT NOW" -ForegroundColor Green
Write-Host ("  " + "="*63) -ForegroundColor Green
Write-Host @"

  Verify after reboot:
    (Get-CimInstance Win32_ComputerSystem).Manufacturer   # -> Dell Inc.
    (Get-CimInstance Win32_BIOS).Manufacturer             # -> Dell Inc.
    Get-CimInstance Win32_VideoController | Select Name,AdapterRAM

  Apple Silicon specific:
    Section 0 patched Apple SMBIOS -> Dell OptiPlex 7090
    ARM64 architecture is an unavoidable fingerprint for ARM64-native malware
    x86/x64 malware under WoW64 is NOT affected by ARM architecture
"@
"""


def write_guest_script(dest: Path) -> None:
    """Write the guest PowerShell script to dest.

    Preference order:
      1. clean_guest_arm.ps1 in the same directory as this script — the full,
         comprehensive standalone version (38 sections).  Always prefer this.
      2. Embedded GUEST_PS1 fallback — a functional subset used when the
         standalone file is not present (e.g., this script was copied alone).
    """
    companion = Path(__file__).resolve().parent / "clean_guest_arm.ps1"
    if companion.exists() and companion.resolve() != dest.resolve():
        dest.write_bytes(companion.read_bytes())
        print(f"  Guest script copied from companion → {dest}")
        print(f"  (Using full 38-section standalone version)")
    else:
        dest.write_text(GUEST_PS1.lstrip("\n"), encoding="utf-8")
        print(f"  Guest script written (embedded fallback) → {dest}")
        print(f"  Tip: place clean_guest_arm.ps1 next to this script for the full version.")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(
        description="vmstealth-fusion-arm — VMware Fusion stealth patcher for Apple Silicon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detection tiers defeated
  HOST-SIDE (VMX patch):
    CPUID hypervisor bit · CPUID vendor leaf (zeroed) · VMware backdoor port
    RDTSC timing (WoW64 emulation layer) · SMBIOS/DMI host-reflect (Apple data)
    ACPI table passthru (Apple tables, no VMWARE strings) · VMCI PCI device
    floppy/serial/parallel removal · SVGA VRAM 256 MB · memory dedup timing
    balloon driver · Hyper-V enlightenments · time sync · named pipes
    VMware logging · MAC address OUI randomisation

  GUEST-SIDE (clean_guest_arm.ps1):
    Apple SMBIOS -> Dell identity (NEW) · registry / services / processes
    binary + driver (.sys) renaming · VMware DLLs · PCI VEN_15AD entries
    disk/NIC/GPU/audio class registry · BIOS hive (Apple + VMware patterns)
    installed programs · prefetch · scheduled tasks · event logs
    firewall rules · WMI verification (VMware + Apple) · network gateway
    computer name · username · RAM/CPU/disk checks · user artifact simulation
    startup entries · ARM64 architecture note (NEW)

Examples:
  python3 vmstealth_fusion_arm.py "Windows 11.vmwarevm" --guest-script clean_guest_arm.ps1
  python3 vmstealth_fusion_arm.py "Windows 11.vmwarevm" --scan
  python3 vmstealth_fusion_arm.py "Windows 11.vmwarevm" --aggressive --guest-script clean_guest_arm.ps1
  python3 vmstealth_fusion_arm.py "Windows 11.vmwarevm/Windows 11 ARM.vmx" --scan
        """,
    )
    p.add_argument("vmx",
                   nargs="?",
                   help="Path to .vmwarevm bundle or .vmx file (VM must be shut down)")
    p.add_argument("--guest-script",
                   metavar="PATH",
                   help="Write ARM guest PowerShell script to PATH")
    p.add_argument("--scan",
                   action="store_true",
                   help="Audit VMX without modifying it")
    p.add_argument("--aggressive",
                   action="store_true",
                   help="Also swap NIC to e1000e, disable 3D SVGA, remove xHCI USB controller")
    args = p.parse_args()

    if not args.vmx and not args.guest_script:
        p.print_help()
        sys.exit(0)

    if args.guest_script:
        write_guest_script(Path(args.guest_script))

    if args.vmx:
        raw = Path(args.vmx)
        if not raw.exists():
            print(f"[!] Path not found: {raw}", file=sys.stderr)
            sys.exit(1)
        vmx = resolve_vmx(raw)
        if vmx.suffix.lower() != ".vmx":
            print(f"[!] Expected a .vmx file, got: {vmx.suffix}", file=sys.stderr)
            sys.exit(1)
        if args.scan:
            scan_vmx(vmx)
        else:
            patch_vmx(vmx, aggressive=args.aggressive)


if __name__ == "__main__":
    main()
