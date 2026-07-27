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

__version__ = "1.0.0"

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
#  GUEST-SIDE POWERSHELL SCRIPT
#  The companion clean_guest.ps1 alongside this script is the single source of
#  truth.  --guest-script copies it to the requested destination, preserving
#  the UTF-8 BOM that PowerShell 5.1 needs for non-ASCII content.
# ═══════════════════════════════════════════════════════════════════════════════

COMPANION_PS1 = "clean_guest.ps1"


def write_guest_script(dest: Path) -> None:
    companion = Path(__file__).resolve().parent / COMPANION_PS1
    if not companion.exists():
        print(f"[!] Companion script not found: {companion}", file=sys.stderr)
        print(f"    {COMPANION_PS1} must live next to this script.", file=sys.stderr)
        sys.exit(1)
    if companion.resolve() == dest.resolve():
        print(f"  Guest script already in place: {dest}")
    else:
        dest.write_bytes(companion.read_bytes())
        print(f"  Guest script copied → {dest}")
    print(f"    Transfer to the Windows VM, then run:")
    print(f"    powershell -ExecutionPolicy Bypass -File .\\{COMPANION_PS1}\n")


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
    p.add_argument("--version",      action="version", version=f"vmstealth {__version__}")
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
