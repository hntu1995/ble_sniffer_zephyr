@echo off
rem Wireshark extcap launcher for the nRF52840 BLE sniffer.
rem Requires Python 3 with pyserial on PATH.
setlocal
where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python "%~dp0nrf_ble_sniffer.py" %*
) else (
    py -3 "%~dp0nrf_ble_sniffer.py" %*
)
