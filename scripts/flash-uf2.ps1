#requires -Version 5.1
<#
.SYNOPSIS
    Copy the built UF2 image to an nRF52840 UF2 bootloader drive.

.DESCRIPTION
    Double-tap the reset pad on the SuperMini so the bootloader drive appears,
    then run this script. It looks for a drive containing INFO_UF2.TXT.

.EXAMPLE
    .\scripts\flash-uf2.ps1
    .\scripts\flash-uf2.ps1 -Uf2 .\build\zephyr.uf2
#>
[CmdletBinding()]
param(
    [string]$Uf2 = (Join-Path (Split-Path $PSScriptRoot -Parent) "build\zephyr.uf2")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Uf2)) {
    throw "UF2 not found: $Uf2. Build first with .\scripts\build.ps1"
}

$boot = Get-PSDrive -PSProvider FileSystem | Where-Object {
    $root = $_.Root
    (Test-Path (Join-Path $root "INFO_UF2.TXT")) -or
    (Test-Path (Join-Path $root "INDEX.HTM"))
} | Select-Object -First 1

if (-not $boot) {
    throw "No UF2 bootloader drive found. Double-tap RST and try again."
}

Write-Host "Copying $Uf2 to $($boot.Root) ..."
Copy-Item $Uf2 $boot.Root -Force
Write-Host "Done. The board reboots automatically."
