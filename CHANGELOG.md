# Changelog

All notable changes to **VMware Hidden Mode** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-26

First tagged release. The four-tool suite (x86-64 + Apple-Silicon ARM64, host +
guest) is feature-complete and verified against a synthetic default VMware
profile (0/36 → 33/36 stealth checks passing after patch).

### Added
- `vmstealth.py` — host-side VMX stealth patcher for VMware Workstation /
  Fusion on Intel. 13 detection tiers, `--scan` audit mode, `--aggressive`
  hardware-swap mode, automatic `.vmx.bak` backup, MAC-OUI randomisation.
- `vmstealth_fusion_arm.py` — host-side VMX patcher for VMware Fusion 13+ on
  Apple Silicon (M1–M4). Accepts `.vmwarevm` bundles or raw `.vmx` paths;
  documents the Apple-SMBIOS reflect-host behaviour.
- `clean_guest.ps1` — 37-section in-guest cleaner for Windows 10/11 x64
  (registry, services, drivers, DLLs, PCI/disk/NIC/GPU/audio strings, SMBIOS,
  event logs, artifact simulation, final verification report).
- `clean_guest_arm.ps1` — in-guest cleaner for Windows 11 ARM64, including the
  Apple-SMBIOS → Dell identity patch (Section 0) and the ARM64 fingerprint note.
- `--version` flag on both Python tools.
- Project branding: logomark, hero banner, pipeline diagram, detection-tier
  infographic, and a real before/after scan capture.
- `.gitignore`, `CHANGELOG.md`, `SECURITY.md`.

### Notes
- Both PowerShell scripts ship with a UTF-8 BOM so Windows PowerShell 5.1 parses
  their non-ASCII output correctly.
- ARM64 architecture code (`Win32_Processor.Architecture = 12`) remains visible
  to native ARM64 processes and cannot be masked from inside the guest.

[1.0.0]: https://github.com/at0m-b0mb/VMware-Hidden-Mode/releases/tag/v1.0.0
