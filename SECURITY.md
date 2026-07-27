# Security & Responsible Use

**VMware Hidden Mode** is a defensive malware-analysis tool. It hardens a
*virtual machine you own* so that sandbox-aware malware behaves naturally during
analysis instead of detecting the VM and hiding its payload. This is the same
technique used by professional reverse-engineers and sandbox vendors.

## Intended use

- Malware analysis and reverse engineering in an isolated lab
- Security research and detection-engineering
- Testing the robustness of anti-analysis / anti-VM logic
- Education and CTF exercises

## Out of scope / not intended

- Evading legitimate anti-cheat, DRM, or licensing enforcement
- Bypassing corporate endpoint controls on machines you do not own
- Any use on a VM or host you are not authorised to modify

You are responsible for complying with all applicable laws and with the terms of
any software you run inside the guest.

## Safe-operation checklist

1. **Only run against VMs you own.** Never point the patcher at a shared or
   production VM.
2. **Snapshot first.** Take a VMware snapshot before running the guest cleaner —
   it renames drivers and edits the registry, and manual reversal is tedious.
   The host patcher writes a `*.vmx.bak` backup automatically.
3. **Keep the lab isolated.** Run detonation VMs on a host-only / isolated
   network, with no path back to anything you care about.
4. **Expect to re-run after a Tools update.** Reinstalling VMware Tools restores
   many patched values.

## Reporting an issue

Found a bug, a false "clean" result, or a detection vector the suite misses?
Open an issue on the [tracker](https://github.com/at0m-b0mb/VMware-Hidden-Mode/issues)
with the VMware product + version, guest OS + architecture, and the check that
behaved unexpectedly.
