#requires -Version 5.1
<#
.SYNOPSIS
    Build the sniffer firmware from a space-free staging directory.

.DESCRIPTION
    Zephyr 4.x's CMake glue splits some generated file lists on spaces, so an
    application path containing a space (like "bluetooh sniffer") fails during
    configure. This script copies firmware/ to a space-free staging directory,
    builds there, and copies the artifacts back to <repo>\build\.

.EXAMPLE
    .\scripts\build.ps1
    .\scripts\build.ps1 -Board promicro_nrf52840/nrf52840 -Pristine
#>
[CmdletBinding()]
param(
    [string]$Board = "promicro_nrf52840/nrf52840/uf2",
    [string]$ZephyrBase = $env:ZEPHYR_BASE,
    [string]$BuildRoot = (Join-Path $env:LOCALAPPDATA "ble-sniffer-build"),
    [switch]$Pristine
)

$ErrorActionPreference = "Stop"

if (-not $ZephyrBase) {
    $ZephyrBase = "C:\Users\Tu\zephyrproject\zephyr"
}
if (-not (Test-Path (Join-Path $ZephyrBase "VERSION"))) {
    throw "Zephyr base not found: $ZephyrBase (set ZEPHYR_BASE)"
}
if ($BuildRoot -match ' ') {
    throw "BuildRoot must not contain spaces: $BuildRoot"
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$source = Join-Path $projectRoot "firmware"
$staging = Join-Path $BuildRoot "firmware"
$buildDir = Join-Path $BuildRoot ("build\" + ($Board -replace '[\\/]', '_'))

if (-not (Test-Path (Join-Path $source "CMakeLists.txt"))) {
    throw "firmware/CMakeLists.txt not found under $projectRoot"
}

if (Test-Path $staging) {
    Remove-Item -Recurse -Force $staging
}
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item (Join-Path $source "*") $staging -Recurse -Force

if ($Pristine -and (Test-Path $buildDir)) {
    Remove-Item -Recurse -Force $buildDir
}

$env:ZEPHYR_BASE = $ZephyrBase

Write-Host "Configuring $Board ..."
& cmake -S $staging -B $buildDir -G Ninja "-DBOARD=$Board"
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)" }

Write-Host "Building ..."
& cmake --build $buildDir
if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)" }

$outDir = Join-Path $projectRoot "build"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Get-ChildItem $buildDir -Recurse -Include *.uf2, *.hex, *.bin -File |
    ForEach-Object { Copy-Item $_.FullName $outDir -Force }

Write-Host ""
Write-Host "Artifacts copied to: $outDir"
Get-ChildItem $outDir | Select-Object Name, Length | Format-Table -AutoSize
