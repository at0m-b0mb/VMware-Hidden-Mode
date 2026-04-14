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
