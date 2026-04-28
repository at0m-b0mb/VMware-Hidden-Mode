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
#  GUEST-SIDE POWERSHELL SCRIPT
#  The companion clean_guest_arm.ps1 alongside this script is the single source
#  of truth.  --guest-script copies it to the requested destination, preserving
#  the UTF-8 BOM that PowerShell 5.1 needs for non-ASCII content.
# ═══════════════════════════════════════════════════════════════════════════════

COMPANION_PS1 = "clean_guest_arm.ps1"


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
    print(f"    powershell -ExecutionPolicy Bypass -File .\\{COMPANION_PS1}")


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
