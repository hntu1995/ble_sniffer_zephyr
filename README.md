# nRF52840 SuperMini BLE Sniffer

A fully open **Zephyr** firmware + **Wireshark extcap** that turns an nRF52840
SuperMini (XC168-class, Nice!Nano-compatible) into a Bluetooth LE Link-Layer
sniffer. No proprietary Nordic sniffer binary is used.

Phase 1 captures **advertising channels 37/38/39**: ADV_IND, ADV_NONCONN_IND,
SCAN_REQ/SCAN_RSP, CONNECT_IND and BLE 5 primary ADV_EXT_IND PDUs. Packets are
streamed over native USB (CDC-ACM) and shown in Wireshark with channel, RSSI and
CRC status.

## Status

- Firmware builds for `promicro_nrf52840/nrf52840/uf2` with Zephyr 4.3.99.
- Host protocol and pcap writer are unit-tested (14 tests).
- Connection following (data channels) is **not** implemented yet; the capture
  of CONNECT_IND is the input for that next step.

### Verified on hardware

Tested against a SuperMini nRF52840 running the **nice!nano UF2 bootloader
0.6.0** (SoftDevice S140 6.1.1):

- Partition layout: SoftDevice `0x0-0x26000`, application `0x26000-0xEC000`,
  UF2 bootloader at `0xF4000`. The UF2 image is written at `0x26000`, which
  matches this bootloader exactly.
- Enumerates as USB serial `VID 0x2FE3 / PID 0x0008`.
- Live capture confirmed advertisements on channels 37, 38 and 39, with both
  CRC-good and CRC-error frames and RSSI in the -96..-53 dBm range.
- Recorded pcap validates as link type 256 with correct AA and CRC flags.
- Wireshark 4.6.9 decodes the stream directly (`tshark -i <extcap>`), showing
  channel, RSSI, PDU type and advertiser address. Capture included `ADV_IND`,
  `ADV_NONCONN_IND`, `SCAN_REQ` and `ADV_EXT_IND` (PDU type 0x07).

## Requirements

Hardware:
- nRF52840 SuperMini / XC168 board with native USB and the 2.4 GHz antenna
- USB-C data cable
- Optional: SWD probe (J-Link, DAPLink, ST-Link) if the UF2 bootloader is absent

Software:
- Zephyr 4.1+ workspace with the Zephyr SDK (`west` + `cmake` + `ninja`)
- Python 3.9+ with `pyserial`
- Wireshark 4.x (with the BTLE dissector, included by default)

## Quick start

### 1. Build

```powershell
.\scripts\build.ps1
```

Artifacts land in `build\` (`zephyr.uf2`, `zephyr.hex`, `zephyr.bin`).

> **Why a script?** Zephyr's CMake glue splits some generated file lists on
> spaces, so this repository's original folder name (`bluetooh sniffer`) breaks
> configure. `build.ps1` copies `firmware/` to a space-free staging directory
> (`%LOCALAPPDATA%\ble-sniffer-build`), builds there, and copies the artifacts
> back. If you move the repo to a path without spaces **on the same drive as
> the Zephyr workspace**, plain
> `west build -b promicro_nrf52840/nrf52840/uf2 firmware` works too.

### 2. Flash

UF2 bootloader (factory default on most SuperMini boards):

1. Double-tap the reset pad. A USB drive appears.
2. Run:

```powershell
.\scripts\flash-uf2.ps1
```

Or copy `build\zephyr.uf2` to the drive manually.

SWD (no bootloader):

```powershell
# Build without the UF2 partition layout, then flash with your probe
.\scripts\build.ps1 -Board promicro_nrf52840/nrf52840
west flash -d "$env:LOCALAPPDATA\ble-sniffer-build\build\promicro_nrf52840_nrf52840" --runner jlink
```

(`--runner pyocd` / `openocd` also work if configured.)

### 3. Install the Wireshark extcap

```powershell
.\scripts\install-extcap.ps1
```

This copies the extcap into `%APPDATA%\Wireshark\extcap` and installs `pyserial`.

#### No administrator rights?

The official Wireshark MSI requires elevation (`msiexec` returns 1603 without
it). Extcap capture does **not** need Npcap, so Wireshark can be laid out
per-user instead:

```powershell
.\scripts\extract-wireshark.ps1 -Msi "$env:TEMP\Wireshark-4.6.9-x64.msi"
```

The script reads the MSI tables read-only, unpacks the cabinets, and writes a
run-from-anywhere copy to `%LOCALAPPDATA%\Wireshark\Wireshark`. Launch
`Wireshark.exe` from there.

Limitation: without Npcap you cannot capture native Ethernet/Wi-Fi interfaces,
but extcap sources (this sniffer) work normally.

### 4. Capture

1. Open Wireshark. Press **F5** (refresh interfaces).
2. Select **nRF52840 BLE Sniffer (Zephyr)** and start.
3. Filter with `btle` (or `btle.advertising_address`).

If the port is not auto-detected, set it in the interface options
(**Serial port**, e.g. `COM7`).

### Without Wireshark

```powershell
python host\nrf_ble_sniffer.py --list-ports
python host\nrf_ble_sniffer.py --port COM7 --cli
python host\nrf_ble_sniffer.py --port COM7 --pcap capture.pcap
```

## How it works

```
nRF52840 RADIO (1M, dewhitened RX)          USB CDC-ACM          Wireshark
  ch37/38/39, 10 ms dwell        ──►  framed binary  ──►  extcap → pcap DLT 256
  END ISR: RSSI + 1 µs stamp
```

- The radio is configured exactly like Zephyr's own BLE controller:
  S0 = LL header, 8-bit length, 4-byte AA (base + prefix), BLE CRC with the
  address skipped, whitening enabled.
- RX buffers contain `[LL header][length][payload]`. The firmware prepends the
  advertising AA and appends three placeholder CRC bytes; the real CRC result is
  carried in the frame flags.
- `FREQUENCY` uses MHz offsets: ch37 → 2, ch38 → 26, ch39 → 80.
- A 1 MHz, 32-bit TIMER1 timestamp is captured at END. The host maps it to
  wall-clock time and tracks the ~71 minute wrap, preserving inter-packet timing.
- The host emits pcap with DLT 256 (`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`), so
  Wireshark shows RF channel, RSSI, AA validity and CRC validity.

Details: [`docs/protocol.md`](docs/protocol.md) and
[`docs/superpowers/specs/2026-11-18-nrf52840-ble-sniffer-design.md`](docs/superpowers/specs/2026-11-18-nrf52840-ble-sniffer-design.md).

## Limitations

- **Advertising channels only.** A single radio cannot follow a connection; data
  channel PDUs are not captured yet.
- One radio, three advertising channels: the firmware dwells 10 ms per channel,
  so very fast advertisers can occasionally be missed. This is inherent to
  single-radio advertising sniffing.
- CRC bytes are not available from the nRF RX hardware; Wireshark is told the CRC
  status instead, and the three CRC bytes in the packet are zero placeholders.
- Logs go to UART0 (P0.09 TX / P0.10 RX, 115200) so the USB port stays binary
  clean. Do not attach a serial terminal to the CDC port during capture.

## Troubleshooting

**No interface in Wireshark**
- Confirm the files are in `%APPDATA%\Wireshark\extcap`.
- Run `python host\nrf_ble_sniffer.py --extcap-interfaces`; it must print an
  `extcap {…}` line and an `interface {…}` line.
- Restart Wireshark completely, then refresh interfaces.

**No COM port**
- Use a data cable (not charge-only).
- Check Device Manager for a USB serial device (Windows 10+ uses `usbser.sys`).
- Re-flash; if the board is in UF2 mode it will not run the sniffer.

**Interface exists but no packets**
- Verify data without Wireshark: `--cli` should print frames when nearby BLE
  devices advertise.
- Advertising intervals are commonly 100 ms+, so give it a few seconds.
- Increase the dwell (edit `dwell_ms` in `radio_sniffer.c`, default 10 ms).
- Check the antenna and keep the board away from USB 3.0 / 2.4 GHz noise.

**Frames show crc=bad / Wireshark marks CRC invalid**
- Normal for weak or colliding packets; bad-CRC frames are intentionally kept.
- Move closer to the transmitter.

**Build fails during CMake configure**
- Ensure the staging directory has no spaces (the script enforces this).
- Ensure `ZEPHYR_BASE` and `ZEPHYR_SDK_INSTALL_DIR` are set, and `cmake`/`ninja`
  are on `PATH`.
- `west build` cannot relativize paths across Windows drive letters; build from
  the same drive as the Zephyr workspace or use `scripts/build.ps1`.

## Legal

Passive reception only. Only sniff devices you own or have explicit permission
to test. Radio regulations vary by country.

## Roadmap

1. Connection following (CSA#1/CSA#2), using the captured CONNECT_IND parameters.
2. BLE 5 extended advertising (2M PHY, AUX chains).
3. 802.15.4 / Thread / Zigbee mode on the same radio engine.
4. On-device pcap logging (flash/SD) and multi-board aggregation.
