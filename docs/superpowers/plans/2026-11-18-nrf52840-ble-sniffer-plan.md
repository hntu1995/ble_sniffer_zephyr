# Implementation Plan — nRF52840 SuperMini BLE Sniffer

Spec: `docs/superpowers/specs/2026-11-18-nrf52840-ble-sniffer-design.md`

## Steps

1. **Scaffold**
   - `firmware/` Zephyr app (`CMakeLists.txt`, `prj.conf`, `app.overlay`)
   - `host/` Python extcap and tests
   - `.gitignore`, `README.md`

2. **Firmware: protocol header**
   - `src/sniffer_proto.h`: header layout, type/flag constants, max sizes.

3. **Firmware: radio engine**
   - `src/radio_sniffer.c/h`:
     - `sniffer_init()` — RADIO registers, IRQ, TIMER1, HFCLK.
     - `sniffer_start()/sniffer_poll()` — channel schedule + ring drain.
     - END/DISABLED ISR — timestamp, RSSI, CRC status, copy to lock-free ring.
   - Verify compile.

4. **Firmware: USB stream**
   - `src/stream.c/h` — DTR-aware, non-blocking CDC writes, hello frame.

5. **Firmware: main**
   - `src/main.c` — init order, DTR wait, 1 ms loop.

6. **Build**
   - `west build -b promicro_nrf52840/nrf52840/uf2` using the local Zephyr workspace.
   - Also build the non-UF2 variant.
   - Fix all warnings.

7. **Host: extcap**
   - `host/nrf_ble_sniffer.py`:
     - extcap discovery (`--extcap-interfaces`, `--extcap-dlts`, `--extcap-config`)
     - capture mode (`--capture --fifo`), pcap writer with DLT 256
     - frame parser with magic resync and timestamp-wrap handling
     - port auto-detect, `--cli`, `--pcap` debug modes
   - `host/nrf_ble_sniffer.bat`, `host/install_extcap.ps1`, `requirements.txt`.

8. **Host tests**
   - `host/tests/test_protocol.py`: framing, resync, pcap header/record, timestamp wrap,
     pseudo-header flags.

9. **Docs**
   - README: prerequisites, build, flash (UF2 + SWD), install extcap, Wireshark usage,
     troubleshooting, limitations, roadmap.
   - `docs/protocol.md` (wire + pcap mapping).

10. **Verify & commit**
    - Run host tests; run firmware build; `git add`/`commit`.
