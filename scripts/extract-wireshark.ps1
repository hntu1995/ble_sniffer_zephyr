#requires -Version 5.1
<#
.SYNOPSIS
    Extract a Wireshark MSI into a portable folder without administrator rights.

.DESCRIPTION
    The Wireshark MSI requires elevation to *install*, but its payload can be
    laid out per-user. This script reads the MSI File/Directory tables through
    the Windows Installer COM API (read-only, no install), extracts the
    cabinets with 7-Zip, and renames every file to its real target path.

    Npcap is NOT included; that only matters for native interface capture.
    Extcap interfaces (like our BLE sniffer) work with no extra driver.

.EXAMPLE
    .\scripts\extract-wireshark.ps1 -Msi "$env:TEMP\Wireshark-4.6.9-x64.msi"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "Wireshark")
)

$ErrorActionPreference = "Stop"

foreach ($tool in @("7z")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH (install 7-Zip or use the official installer as admin)."
    }
}
if (-not (Test-Path $Msi)) { throw "MSI not found: $Msi" }

$work = Join-Path $env:TEMP ("wsx-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$cabDir = Join-Path $work "cabs"
New-Item -ItemType Directory -Force -Path $cabDir, $Destination | Out-Null

Write-Host "Reading MSI tables (read-only) ..."
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember(
    "OpenDatabase", "InvokeMethod", $null, $installer, @($Msi, 0))

function Read-MsiTable {
    param($Database, [string]$Query)
    $view = $Database.GetType().InvokeMember(
        "OpenView", "InvokeMethod", $null, $Database, @($Query))
    $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
    $rows = @()
    while ($true) {
        $record = $view.GetType().InvokeMember(
            "Fetch", "InvokeMethod", $null, $view, $null)
        if ($null -eq $record) { break }
        $count = $record.GetType().InvokeMember(
            "FieldCount", "GetProperty", $null, $record, $null)
        $values = @()
        for ($i = 1; $i -le $count; $i++) {
            $values += [string]$record.GetType().InvokeMember(
                "StringData", "GetProperty", $null, $record, @($i))
        }
        $rows += , $values
    }
    $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
    return $rows
}

# Directory table: every key path from the TARGETDIR root.
$dirPaths = @{}
$rootDir = $null
foreach ($d in (Read-MsiTable $db 'SELECT `Directory`.`Directory`, `Directory`.`Directory_Parent`, `Directory`.`DefaultDir` FROM `Directory`')) {
    $key, $parent, $default = $d
    $name = if ($default -like "*|*") { $default.Split("|")[1] } else { $default }
    if ([string]::IsNullOrEmpty($parent)) {
        $dirPaths[$key] = $name
        if ($null -eq $rootDir) { $rootDir = $key }
    } else {
        $parentPath = if ($dirPaths.ContainsKey($parent)) { $dirPaths[$parent] } else { "" }
        $dirPaths[$key] = if ($parentPath) { Join-Path $parentPath $name } else { $name }
    }
}
Write-Host "  directories: $($dirPaths.Count)"

# File table: Sequence -> real path. Cabinet entries use the File key.
$files = @{}
foreach ($f in (Read-MsiTable $db 'SELECT `File`.`File`, `File`.`Component_`, `File`.`FileName`, `File`.`Sequence` FROM `File`')) {
    $key, $component, $fileName, $sequence = $f
    $name = if ($fileName -like "*|*") { $fileName.Split("|")[1] } else { $fileName }
    $files[$key] = @{ Name = $name; Component = $component }
}
Write-Host "  files: $($files.Count)"

# Component -> Directory, so each file lands in the right folder.
$componentDir = @{}
foreach ($c in (Read-MsiTable $db 'SELECT `Component`.`Component`, `Component`.`Directory_` FROM `Component`')) {
    $componentDir[$c[0]] = $c[1]
}

Write-Host "Extracting cabinets ..."
7z x $Msi "-o$work\raw" -y | Out-Null
foreach ($cab in (Get-ChildItem $work\raw -Filter *.cab)) {
    7z x $cab.FullName "-o$cabDir" -y | Out-Null
}

$byName = @{}
foreach ($entry in (Get-ChildItem $cabDir -File)) {
    $byName[$entry.Name] = $entry.FullName
}

$copied = 0
$missing = 0
foreach ($key in $files.Keys) {
    $source = $null
    foreach ($candidate in @($key, ($files[$key].Name), ($files[$key].Name.ToUpper()))) {
        if ($byName.ContainsKey($candidate)) { $source = $byName[$candidate]; break }
    }
    if (-not $source) { $missing++; continue }

    $dirKey = $componentDir[$files[$key].Component]
    $relative = if ($dirKey -and $dirPaths.ContainsKey($dirKey)) { $dirPaths[$dirKey] } else { "" }
    $targetDir = if ($relative) { Join-Path $Destination $relative } else { $Destination }
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    Copy-Item $source (Join-Path $targetDir $files[$key].Name) -Force
    $copied++
}

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Copied $copied files, $missing unmatched -> $Destination"
$exe = Join-Path $Destination "Wireshark.exe"
if (Test-Path $exe) {
    Write-Host "OK: $exe"
} else {
    Write-Warning "Wireshark.exe not found in $Destination"
}
