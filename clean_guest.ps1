
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
