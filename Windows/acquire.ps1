# ============================================================
# Windows Interactive Live Forensic Acquisition Script
# RAM -> Disk -> Network -> System
# ============================================================

# ---------- CONSTANTS ----------
$SectorSize = 512   # kept for reference, not used in updated dc3dd commands

# ---------- ADMIN CHECK ----------
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] Run PowerShell as Administrator."
    exit 1
}

# ---------- BASE PATH ----------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$WinPmem = "$ScriptRoot\Windows-Tools\RAM\winpmem.exe"
$Dc3dd   = "$ScriptRoot\Windows-Tools\DISK\dc3dd-dcfl-win7-64-7-2-641\dc3dd.exe"

if (!(Test-Path $WinPmem)) { Write-Error "winpmem.exe not found"; exit 1 }
if (!(Test-Path $Dc3dd))   { Write-Error "dc3dd.exe not found"; exit 1 }

Write-Host "`n=== Windows Live Forensic Acquisition ===`n"

# ============================================================
# ---------- INPUT PROMPTS FIRST ----------
# ============================================================

# 1️⃣ Evidence storage drive
Write-Host "[?] Available drives:"
Get-PSDrive -PSProvider FileSystem |
    Select Name, Root, Free |
    Format-Table -AutoSize

$EvidenceRoot = Read-Host "`nEnter drive letter for evidence storage (example: E:)"

if (!(Test-Path "$EvidenceRoot\")) {
    Write-Error "Invalid storage location."
    exit 1
}

# Timestamped case folder
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CaseDir   = "$EvidenceRoot\Forensic_Case_$Timestamp"

$MemDir  = "$CaseDir\memory"
$DiskDir = "$CaseDir\disks"
$NetDir  = "$CaseDir\network"
$LogDir  = "$CaseDir\logs"

New-Item -ItemType Directory -Force -Path `
    $MemDir, $DiskDir, $NetDir, $LogDir | Out-Null

Write-Host "[+] Evidence will be stored at: $CaseDir"

# 2️⃣ Disk acquisition mode
Write-Host "`n[?] Disk acquisition mode:"
Write-Host "  1 - Logical (Drive Letters: C:, D:, etc.)"
Write-Host "  2 - Physical (Entire Disk: PhysicalDrive0, 1, etc.)"

$DiskMode = Read-Host "Select option (1 or 2)"

# 3️⃣ Disk selection based on mode
$SelectedDrives = @()
$SelectedDisks  = @()

if ($DiskMode -eq "1") {
    Write-Host "`n[+] Available logical drives:`n"
    Get-CimInstance Win32_LogicalDisk |
        Where-Object { $_.DriveType -eq 3 } |
        Select DeviceID, VolumeName, FileSystem, Size |
        Format-Table -AutoSize

    $DriveSelection = Read-Host "Enter drive letters to image (comma-separated, example: C,D)"
    $SelectedDrives = $DriveSelection -split "," | ForEach-Object {
        $_.Trim().TrimEnd(":").ToUpper()
    }
}
elseif ($DiskMode -eq "2") {
    $Disks = Get-CimInstance Win32_DiskDrive |
        Select Index, Model, InterfaceType, Size

    $Disks | Format-Table -AutoSize

    $Selection = Read-Host "Enter disk indexes to image (comma-separated, example: 0,1)"
    $SelectedDisks = $Selection -split "," | ForEach-Object { $_.Trim() }
}
else {
    Write-Error "Invalid disk acquisition mode selected."
    exit 1
}

# ============================================================
# ---------- BEGIN ACQUISITION ----------
# ============================================================

# 1️⃣ MEMORY ACQUISITION
Write-Host "`n[+] Acquiring RAM..."
& $WinPmem "acquire" "--nosparse" "$MemDir\memory.raw" `
    2> "$LogDir\winpmem_error.log" `
    | Tee-Object "$LogDir\winpmem.log"

# 2️⃣ LOGICAL DRIVE IMAGING
if ($DiskMode -eq "1") {
    foreach ($DriveLetter in $SelectedDrives) {
        $ImageFile = "$DiskDir\drive_${DriveLetter}.img"
        $LogFile   = "$LogDir\drive_${DriveLetter}.log"

        Write-Host "[+] Imaging drive $DriveLetter"

        & $Dc3dd `
            "if=\\.\${DriveLetter}:" `
            "of=$ImageFile" `
            "hash=sha256" `
            "log=$LogFile"
    }
}

# 3️⃣ PHYSICAL DISK IMAGING
if ($DiskMode -eq "2") {
    $Disks = Get-CimInstance Win32_DiskDrive
    foreach ($Index in $SelectedDisks) {
        $Disk = $Disks | Where-Object Index -eq [int]$Index
        if (!$Disk) {
            Write-Warning "Disk $Index not found."
            continue
        }

        $Model = ($Disk.Model -replace '[^a-zA-Z0-9]', '_')
        $ImageFile = "$DiskDir\disk${Index}_${Model}.img"
        $LogFile   = "$LogDir\disk${Index}.log"

        Write-Host "[+] Imaging PhysicalDrive$Index"

        & $Dc3dd `
            "if=\\.\PhysicalDrive$Index" `
            "of=$ImageFile" `
            "hash=sha256" `
            "log=$LogFile"
    }
}

# 4️⃣ NETWORK + SYSTEM METADATA
Write-Host "`n[+] Collecting network and system metadata..."
ipconfig /all  > "$NetDir\ipconfig.txt"
arp -a         > "$NetDir\arp.txt"
netstat -ano   > "$NetDir\netstat.txt"
route print    > "$NetDir\routes.txt"

systeminfo     > "$LogDir\systeminfo.txt"
tasklist /v    > "$LogDir\tasks.txt"

# ============================================================
# DONE
# ============================================================
Write-Host "`n[+] Acquisition complete"
Write-Host "[+] Evidence stored at: $CaseDir"
