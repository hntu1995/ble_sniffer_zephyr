#requires -Version 5.1
<#
.SYNOPSIS
    Install the sniffer extcap into Wireshark's personal extcap folder.

.EXAMPLE
    .\scripts\install-extcap.ps1
    .\scripts\install-extcap.ps1 -ExtcapDir "C:\ProgramData\Wireshark\extcap"
#>
[CmdletBinding()]
param(
    [string]$ExtcapDir = (Join-Path $env:APPDATA "Wireshark\extcap")
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

New-Item -ItemType Directory -Force -Path $ExtcapDir | Out-Null
Copy-Item (Join-Path $root "host\nrf_ble_sniffer.py") $ExtcapDir -Force
Copy-Item (Join-Path $root "host\nrf_ble_sniffer.bat") $ExtcapDir -Force

Write-Host "Installed extcap to $ExtcapDir"
Write-Host ""

try {
    python -m pip install --user -r (Join-Path $root "host\requirements.txt")
} catch {
    Write-Warning "Could not install pyserial automatically. Run: pip install pyserial"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Restart Wireshark (or press F5 in the interface list)."
Write-Host "  2. Select 'nRF52840 BLE Sniffer (Zephyr)' and start a capture."
Write-Host "  3. Filter with: btle"
