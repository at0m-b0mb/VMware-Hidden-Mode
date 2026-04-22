# VMware Hidden Mode

A collection of PowerShell scripts that remove or mask VMware guest artifacts inside a Windows VM, making it harder for malware or anti-analysis tools to detect the virtualized environment.

> **Warning – For research and educational use only.**  
> Run these scripts only in VMs you own. Always take a snapshot before running. The authors accept no liability for any damage caused.

---

## Table of Contents

1. [Overview](#overview)
2. [Scripts](#scripts)
3. [Quick Start — ARM Edition (VMware Fusion on Apple Silicon)](#quick-start--arm-edition-vmware-fusion-on-apple-silicon)
4. [Quick Start — x86/x64 Edition](#quick-start--x86x64-edition)
5. [What the ARM Script Does](#what-the-arm-script-does)
6. [Troubleshooting the Parse Errors](#troubleshooting-the-parse-errors)
7. [Known Limitations (Apple Silicon)](#known-limitations-apple-silicon)
8. [Verification After Running](#verification-after-running)
9. [File Reference](#file-reference)

---

## Overview

When malware or anti-analysis tools run inside a VM, they often check for signs of virtualization (registry keys, driver names, BIOS strings, WMI data, etc.).  
These scripts clean, rename, or patch those indicators so the guest looks like a real physical machine to the software under test.

---

## Scripts

| File | Target | Host |
|------|--------|------|
| `clean_guest_arm.ps1` | Windows 11 ARM64 guest | VMware Fusion 13+ on Apple Silicon (M1/M2/M3/M4) |
| `clean_guest.ps1` | Windows 10/11 x86-64 guest | VMware Workstation / Fusion on Intel |
| `vmstealth_fusion_arm.py` | macOS host-side tweaks | macOS (Apple Silicon) |
| `vmstealth.py` | macOS/Linux host-side tweaks | Intel host |

---

## Quick Start — ARM Edition (VMware Fusion on Apple Silicon)

### Prerequisites

| Requirement | Details |
|-------------|---------|
| Host | macOS with VMware Fusion 13 or later on an Apple Silicon Mac (M1 / M2 / M3 / M4) |
| Guest | Windows 11 ARM64 (the VM must be an ARM64 guest) |
| Privileges | The script **must** run as **Administrator** inside the guest |
| PowerShell | Windows PowerShell 5.1 **or** PowerShell 7+ inside the guest |
| Snapshot | Take a VM snapshot **before** running — changes to the registry and drivers can be difficult to reverse manually |

### Steps

1. **Take a snapshot** in VMware Fusion before doing anything else.

2. Copy `clean_guest_arm.ps1` into the Windows ARM guest (e.g. drag-and-drop via Fusion's shared clipboard, or put it in a shared folder).

3. Open **PowerShell as Administrator** inside the guest:
   - Press **Win + X** → *Windows PowerShell (Admin)* or *Terminal (Admin)*

4. Allow the script to run (execution policy bypass):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\clean_guest_arm.ps1
   ```

   Or, if you are already in an elevated PowerShell session:

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\clean_guest_arm.ps1
   ```

5. Read the coloured output:
   - `[+]` green — action completed successfully
   - `[-]` grey — item not present / skipped
   - `[!]` yellow — warning, review manually
   - `[X]` red — action failed

6. **Reboot the guest** when the script finishes.

7. After reboot, run the [verification commands](#verification-after-running).

---

## Quick Start — x86/x64 Edition

The steps are identical to the ARM edition above, but use `clean_guest.ps1` instead.  
This script targets Windows 10/11 x86-64 guests running in VMware Workstation or VMware Fusion on Intel Macs.

```powershell
powershell -ExecutionPolicy Bypass -File .\clean_guest.ps1
```

---

## What the ARM Script Does

The script works through the following sections in order:

| # | Section | What it does |
|---|---------|--------------|
| 0 | **Apple SMBIOS** *(ARM-specific)* | Patches `HKLM:\SYSTEM\...\SystemInformation` and `HKLM:\HARDWARE\DESCRIPTION\System` to replace Apple/VMware BIOS strings with Dell OptiPlex 7090 identity |
| 1 | **Registry keys** | Deletes `HKLM:\SOFTWARE\VMware, Inc.` and all VMware service/driver registry keys |
| 2 | **Services** | Stops and disables VMware services (VMTools, VGAuthService, vmci, pvscsi, …) |
| 3 | **Processes** | Terminates running VMware processes (vmtoolsd, vmwaretray, …) |
| 4 | **Binaries** | Renames VMware executables in `%ProgramFiles%\VMware\VMware Tools` to generic Windows names |
| 5 | **Kernel drivers** | Renames VMware `.sys` files in `System32\drivers` (ARM64-specific driver names) |
| 6 | **DLLs** | Renames `vmGuestLib.dll`, `vm3dgl.dll`, `vmhgfs.dll` to innocuous names |
| 7 | **PCI devices** | Patches FriendlyName / DeviceDesc for VMware VID 0x15AD devices to Intel equivalents |
| 8 | **Disk devices** | Patches SCSI/IDE FriendlyName strings (replaces "VMware Virtual …" with Samsung/WD/Seagate names) |
| 9 | **NIC** | Patches DriverDesc in the NIC class key; renames the adapter to "Ethernet" |
| 10 | **GPU** | Patches DriverDesc to "Intel UHD Graphics 630" |
| 11 | **Audio** | Patches DriverDesc to "Realtek High Definition Audio" |
| 12 | **SystemInformation** | Verifies Dell identity was applied in section 0 |
| 13 | **Uninstall registry** | Removes "VMware Tools" from Programs & Features |
| 14 | **Prefetch** | Deletes VMware prefetch files |
| 15 | **Scheduled tasks** | Removes VMware scheduled tasks |
| 16 | **Event logs** | Clears System / Application / Setup logs of VMware entries |
| 17 | **Firewall rules** | Removes VMware firewall rules |
| 18 | **WMI verification** | Reads WMI (Win32_ComputerSystem, Win32_BIOS, etc.) and warns if VM strings remain |
| 19 | **Network** | Checks the default gateway for VMware NAT fingerprints |
| 20 | **Computer name** | Warns if the computer name matches known sandbox patterns |
| 21 | **Username** | Warns if the username matches known sandbox account names |
| 22 | **RAM / CPU** | Warns if RAM < 4 GB or logical CPUs < 2 |
| 23 | **Disk size** | Warns if any disk is < 60 GB |
| 24 | **Uptime** | Warns if uptime is < 30 minutes |
| 25 | **Timezone** | Warns if timezone is plain UTC |
| 26 | **User artifacts** | Creates realistic decoy files (budget spreadsheet, notes, work report) with backdated timestamps |
| 27 | **Startup items** | Adds realistic OneDrive / Discord Run key entries if fewer than 2 entries exist |
| 38¹ | **ARM64 fingerprint** *(ARM-specific)* | Reports CPU architecture; warns that ARM64 = 12 is visible to native ARM64 processes |

> ¹ Section 38 is the ARM-specific closing section. Its number aligns with the full x86 edition's section index so both scripts share a consistent numbering scheme.

---

## Troubleshooting the Parse Errors

If you see errors like the ones below when running the script, follow the steps in this section.

```
Variable reference is not valid. ':' was not followed by a valid variable name character.
Unexpected token 'VMware' in expression or statement.
Missing closing '}' in statement block or type definition.
```

### Root Cause

There are two causes:

**1. UTF-8 encoding without BOM (affects Windows PowerShell 5.1)**

Windows PowerShell 5.1 reads `.ps1` files using the system ANSI code page (typically Windows-1252 on English Windows) when the file has **no UTF-8 Byte Order Mark (BOM)**. The script contains Unicode characters (em dashes `—` and box-drawing lines `─`). Their UTF-8 byte sequences include `0x94`, which Windows-1252 maps to the RIGHT DOUBLE QUOTATION MARK (`"`). PowerShell's parser treats this as a closing string delimiter, breaking string literals and causing cascading parse failures.

**Fix:** The file in this repository now includes a UTF-8 BOM (bytes `EF BB BF` at the start of the file). Make sure you are using the latest version of the file. If you downloaded an older copy, re-download it.

You can verify the BOM is present in PowerShell:
```powershell
$bytes = [System.IO.File]::ReadAllBytes('.\clean_guest_arm.ps1')
'{0:X2} {1:X2} {2:X2}' -f $bytes[0], $bytes[1], $bytes[2]
# Should print: EF BB BF
```

If the BOM is missing, add it:
```powershell
$content = Get-Content '.\clean_guest_arm.ps1' -Raw -Encoding UTF8
[System.IO.File]::WriteAllText(
    (Resolve-Path '.\clean_guest_arm.ps1'),
    $content,
    [System.Text.UTF8Encoding]::new($true)   # $true = emit BOM
)
```

**2. `$field:` variable reference in string interpolation (PowerShell 5.1 and 7+)**

PowerShell interprets `"$name: value"` as a PSDrive-qualified variable (like `$env:PATH`). Because `field` is not a valid drive name, the parser raises `Variable reference is not valid`.

**Fix:** Use `${field}` to delimit the variable name: `"${field}: value"`. This has already been applied in the current version of the file.

---

## Known Limitations (Apple Silicon)

| Limitation | Explanation |
|------------|-------------|
| **ARM64 architecture code (12)** | `Win32_Processor.Architecture` returns `12` for ARM64. Native ARM64 processes can read this and detect the non-x86 environment. x86/x64 malware running under WoW64 emulation sees `Architecture=9` and is unaffected. This value cannot be changed from inside the guest. |
| **SMBIOS patch requires reboot** | The registry patches to `SystemInformation` are read at boot. A reboot is required before WMI / `GetSystemFirmwareTable` queries return the new values. |
| **HVCI / Secure Boot may block driver renames** | If Hypervisor-Protected Code Integrity is enabled, kernel driver files in use cannot be renamed. The script will warn and ask you to reboot first. |
| **VMware Tools re-installation resets changes** | Installing or updating VMware Tools will restore many of the patched values. Re-run the script after any Tools update. |
| **Network bridged mode recommended** | NAT mode uses gateway addresses in the `192.168.x.2` range that are recognised as VMware fingerprints. Switch the VM's network adapter to Bridged mode for cleaner network identity. |

---

## Verification After Running

Run these commands inside the guest **after rebooting**:

```powershell
# Manufacturer and model (should show Dell Inc. / OptiPlex 7090)
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model

# BIOS vendor (should show Dell Inc.)
Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion

# GPU name (should show Intel UHD Graphics 630)
Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM

# NIC description (should not contain VMware/VMXNET)
Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=TRUE" | Select-Object Name, MACAddress

# Check no VMware registry keys remain
Test-Path "HKLM:\SOFTWARE\VMware, Inc."          # should be False
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools"  # should be False
```

Run `pafish.exe` or `al-khaser.exe` inside the guest to confirm the VM is no longer detected.

---

## File Reference

```
VMware-Hidden-Mode/
├── clean_guest_arm.ps1       # Guest cleaner — Windows 11 ARM64 in VMware Fusion on Apple Silicon
├── clean_guest.ps1           # Guest cleaner — Windows 10/11 x64 in VMware Workstation / Fusion Intel
├── vmstealth_fusion_arm.py   # Host-side stealth tweaks for VMware Fusion on Apple Silicon
├── vmstealth.py              # Host-side stealth tweaks for VMware Workstation / Fusion Intel
└── README.md                 # This file
```