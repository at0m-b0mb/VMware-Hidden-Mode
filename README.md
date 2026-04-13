# VMware-Hidden-Mode

A malware-analysis lab toolkit that makes a VMware Workstation / Fusion guest VM virtually undetectable by sandbox-aware samples.  It defeats every major detection tier used by tools such as **pafish**, **al-khaser**, **VmwareHardenedLoader**, Emotet, TrickBot, and commodity sandbox-evasion code.

> ⚠️ **For defensive/research use only.**  Use this tool solely in isolated malware-analysis environments.  Do not use it to bypass security controls on production systems.

---

## Overview

Two scripts work together in a two-step workflow:

| Script | Where it runs | What it does |
|---|---|---|
| `vmstealth.py` | **Host** (VM must be shut down) | Patches the `.vmx` configuration file to remove hypervisor fingerprints at the hardware-emulation layer |
| `clean_guest.ps1` | **Guest** (inside Windows VM, as Administrator) | Scrubs all VMware artifacts from the running Windows guest OS |

---

## Detection Tiers Defeated

### Host-side (`vmstealth.py`) — VMX patching

| Tier | Technique | What is changed |
|---|---|---|
| 1 | CPUID hypervisor bit | Clears bit 31 of ECX at leaf 1; zeroes hypervisor vendor leaf 0x40000000 |
| 2 | VMware backdoor I/O port (0x5658 / `VMXh`) | Restricts the backdoor port so magic-value probes return junk |
| 3 | RDTSC / timing | Passes real host TSC to eliminate VM-exit timing inflation |
| 4 | SMBIOS / DMI | Reflects host SMBIOS tables instead of synthetic VMware tables |
| 5 | ACPI tables | Passes host ACPI tables through to remove VMware OEM strings |
| 6 | PCI device removal | Removes VMCI (VID 0x15AD DevID 0x0740) from the virtual PCI bus |
| 7 | Legacy hardware | Removes floppy, serial, and parallel port devices |
| 8 | SVGA VRAM | Expands VRAM from 16 MB to 256 MB to match real GPUs |
| 9 | Memory timing side-channel | Disables page-sharing (dedup) to eliminate timing oracle |
| 10 | Hyper-V enlightenments | Disables `vhv.enable` so nested Hyper-V CPUID leaves are absent |
| 11 | Time synchronisation | Disables all VMware clock-sync channels |
| 12 | Named-pipe channels | Disables clipboard, drag-and-drop, and HGFS pipes |
| 13 | VMware log files | Disables `vmware.log` to prevent filesystem-scan detection |

**Aggressive mode** (`--aggressive`) additionally:
- Replaces the VMware-exclusive VMXNET3 NIC with an emulated Intel e1000e
- Disables 3D SVGA (removes PCI ID 0x15AD:0x0405)
- Removes the VMware-branded USB 3.0 xHCI controller

### Guest-side (`clean_guest.ps1`) — Windows OS scrubbing

The PowerShell script covers 33 remediation and verification steps:

1. Registry — removes VMware software, service, and driver keys  
2. Services — stops and disables all VMware services  
3. Processes — terminates running VMware processes  
4. Binaries — renames VMware executables to generic Windows names  
5. Kernel drivers — renames VMware `.sys` files  
6. DLLs — renames VMware guest-library DLLs  
7. PCI device registry — patches VID 0x15AD hardware entries (FriendlyName / DeviceDesc)  
8. Disk device strings — replaces VMware model strings in SCSI/IDE enum  
9. DEVICEMAP\Scsi — patches the `Identifier` field  
10. NIC class registry — patches DriverDesc for VMXNET adapters  
11. Display adapter class — patches GPU DriverDesc, VRAM, and chip strings  
12. Audio device class — patches VMware HD Audio device strings  
13. SystemInformation registry — spoofs OEM product/manufacturer strings  
14. BIOS / firmware strings — patches HARDWARE\DESCRIPTION hive  
15. ACPI table keys — flags any remaining VMware OEM strings  
16. Installed programs — removes VMware entries from Add/Remove Programs  
17. Prefetch files — deletes `VMWARE*` / `VMTOOL*` prefetch entries  
18. Scheduled tasks — unregisters VMware scheduled tasks  
19. Event logs — clears VMware-tagged entries and event-provider registrations  
20. Firewall rules — removes VMware-added firewall rules  
21. Environment variables — removes VM/sandbox environment variables  
22. WMI verification — dumps hardware strings to confirm SMBIOS host-reflect worked  
23. Network tells — checks for VMware NAT gateway fingerprint and DNS suffix  
24. Computer name — flags sandbox-pattern machine names  
25. Username — flags known analyst/sandbox account names  
26. Screen resolution — checks for VM-default resolutions  
27. RAM + vCPU — checks for sandbox-low memory and single-core configurations  
28. Disk size — checks for suspiciously small disks (< 60 GB)  
29. Volume serial number — checks against known sandbox serial fingerprints  
30. VM uptime — flags fresh-sandbox boot patterns (< 30 min uptime)  
31. Locale / timezone — checks for plain UTC timezone and no regional locale  
32. Named pipes — enumerates `\\.\pipe\*` for VM/sandbox pipe names  
33. Anti-analysis tools — checks for running debuggers and analysis tools  

---

## Requirements

- **Host:** Python 3.9+ (no third-party packages required)
- **Guest:** Windows 10 / 11 with Windows PowerShell 5.1 or PowerShell 7+, run as Administrator
- **VMware:** Workstation Pro / Fusion — the VM must be **shut down** before running the host-side script

---

## Usage

### Step 1 — Patch the VMX file (on the host, VM shut down)

```bash
# Standard mode
python3 vmstealth.py "path/to/Windows 10.vmx"

# Standard mode + copy guest script to a specific output path
python3 vmstealth.py "Windows 10.vmx" --guest-script clean_guest.ps1

# Aggressive mode (also swaps NIC to e1000e, disables 3D SVGA, removes xHCI)
python3 vmstealth.py "Windows 10.vmx" --aggressive

# Audit/scan only — report issues without modifying the VMX
python3 vmstealth.py "Windows 10.vmx" --scan
```

A backup of the original `.vmx` is automatically saved as `.vmx.bak` before any changes are made.

### Step 2 — Scrub the guest OS (inside the Windows VM, Admin PowerShell)

> ⚠️ **Take a snapshot before running this script.**

```powershell
powershell -ExecutionPolicy Bypass -File .\clean_guest.ps1
```

Reboot the VM after the script completes, then verify with **pafish.exe** or **al-khaser.exe**.

---

## Scan Mode Output

`--scan` audits a VMX file and prints a colour-coded report without making any changes:

```
  CHECK                                STATUS / NOTE
  ────────────────────────────────────  ────────────────────────────────────
  ✔  CPUID hypervisor bit              "-------------------------------0"
  ✔  Backdoor I/O port                 "TRUE"
  ✘  SMBIOS reflect host               missing — should be "TRUE"
  ⚠  NIC virtual device               "vmxnet3" — VMware-only; use e1000e (--aggressive)

  18/23 pass  |  2 warn  |  1 fail
  Run without --scan to auto-apply all fixes.
```

---

## Files

| File | Description |
|---|---|
| `vmstealth.py` | Host-side VMX patcher and auditor |
| `clean_guest.ps1` | Guest-side Windows artifact cleaner |
| `LICENSE` | MIT License |

---

## License

MIT — see [LICENSE](LICENSE) for details.