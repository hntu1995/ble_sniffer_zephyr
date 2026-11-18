# nRF52840 SuperMini BLE Sniffer — Design

Date: 2026-11-18
Status: Approved for implementation (user unavailable; autonomous decisions recorded below)

## Goal

Turn an nRF52840 SuperMini (XC168-class, Nice!Nano-compatible) into a Bluetooth LE
Link-Layer sniffer that works with Zephyr and Wireshark, with a codebase that can grow
into connection following, extended advertising, and other protocols.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Firmware | Fully open Zephyr app using the nRF `RADIO` peripheral directly | No proprietary Nordic sniffer binary, fully extensible |
| Phase 1 scope | BLE advertising channels 37/38/39 (legacy + extended primary PDUs) | Highest value/complexity ratio; CONNECT_IND is captured, enabling Phase 2 |
| Board | Upstream Zephyr `promicro_nrf52840/nrf52840/uf2` (UF2) and non-UF2 variant | Zephyr documents this board as covering "SuperMini nRF52840" boards; includes USB CDC |
| Host transport | Native USB CDC-ACM (single port) → Wireshark extcap | No extra USB-UART adapter; 12 Mbit/s is ample |
| Logs | Console moved to UART0 (P0.09 TX / P0.10 RX, 115200) | Keeps the CDC port byte-clean for packet data |
| Host format | pcap, DLT 256 `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` | Wireshark shows channel, RSSI, CRC status and decodes PDU |
| Extcap | Python + pyserial, with `.bat` launcher | Easy to modify; works on Windows |

Rejected alternatives:
- Nordic nRF Sniffer firmware: instant results but closed, not Zephyr, not extensible.
- HCI/observer mode: no raw PHY control, no per-packet RSSI/CRC, not a true sniffer.
- UART-only output: needs an external adapter; USB is built into the board.

## Architecture

```
 nRF52840                                        Windows host
┌──────────────────────────┐   USB CDC-ACM   ┌─────────────────────────────┐
│ RADIO (1 Mbit, ch 37-39) │ ──────────────► │ nrf_ble_sniffer.py (extcap) │
│  └ END ISR: copy + RSSI  │   framed binary │  ├ frame parser / resync    │
│     + 1 µs timestamp     │                 │  ├ pcap writer (DLT 256)    │
│  └ channel hopper (10 ms)│                 │  └ Wireshark named pipe     │
│  └ lock-free ring buffer │                 └─────────────────────────────┘
└──────────────────────────┘
```

Firmware modules:
- `radio_sniffer.c` — radio configuration, ISR, ring buffer, channel scheduler.
- `stream.c` — framing and CDC-ACM writes.
- `main.c` — init, DTR wait, main loop.

Host modules:
- `nrf_ble_sniffer.py` — extcap interface, serial reader, pcap writer, CLI mode.
- `nrf_ble_sniffer.bat` — Wireshark extcap launcher.

## Radio configuration (nRF52840)

Verified against Zephyr's own BLE controller (`ll_sw/nordic/.../radio.c`, `lll.c`):

- `MODE = Ble_1Mbit`.
- `PCNF0`: `S0LEN=1` (LL header byte), `LFLEN=8` (length byte), `S1LEN=0`, `PLEN=8bit`.
- `PCNF1`: `MAXLEN=255`, `BALEN=3` (base) with 1-byte prefix → 4-byte AA, little endian, whitening on.
- Address: `BASE0=0x89BED600`, `PREFIX0=0x8E`, `RXADDRESSES=ADDR0` → advertising AA `0x8E89BED6`.
- CRC: 3 bytes, skip address (BLE CRC covers PDU only), poly `0x00065B`, init `0x555555`.
  Bad-CRC frames are kept and reported; they still end with `END`.
- `FREQUENCY` is the MHz offset from 2400: ch37→2, ch38→26, ch39→80.
  Data channels use `4 + 2k` for `k < 11` and `28 + 2(k - 11)` for `k ≥ 11`
  (the numbering skips the advertising channel frequencies).
- `DATAWHITEIV` = BLE channel index (37/38/39); hardware dewhitens RX.
- `SHORTS = READY_START | TRX_END_DISABLE | ADDRESS_RSSISTART | DISABLED_RSSISTOP`.
- RX buffer layout: `[LL header][length][payload]` (no AA, no CRC written by hardware).
  Firmware prepends the AA and appends three placeholder CRC bytes for Wireshark.

Timing: TIMER1, prescaler 4 → 1 MHz, 32-bit, captured with `TASKS_CAPTURE[0]`
at END. HFCLK is requested through the nRF clock-control driver so the timer and
radio share a stable clock.

Channel policy: round-robin 37→38→39 with a configurable dwell (default 10 ms).
A single radio cannot listen to all three channels simultaneously; this captures a
representative subset of advertisers and all CONNECT_INDs seen during a dwell.

## Wire protocol (device → host), v1

14-byte header, little endian:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `0x5A 0xC3` |
| 2 | 1 | version = 1 |
| 3 | 1 | type: 1 = packet, 2 = hello |
| 4 | 2 | payload length |
| 6 | 4 | timestamp, µs (wraps every ~71.6 min) |
| 10 | 1 | RF channel (37/38/39 in Phase 1) |
| 11 | 1 | RSSI, dBm (signed) |
| 12 | 1 | flags: bit0 CRC ok, bit1 CRC checked, bit2 dewhitened, bit3 direction, bit4 AA valid, bit5 aux adv, bit6 truncated |
| 13 | 1 | reserved |

Packet payload: `AA(4)` + `PDU header(1)` + `length(1)` + `payload` + `CRC(3, zeroed)`.
Hello payload: ASCII version string.

## Host behavior

- Resynchronizes on the magic bytes; validates version and length (≤ 600).
- DLT 256 pseudo-header (10 bytes): channel, RSSI, noise invalid, AA offenses valid (0),
  reference AA `0x8E89BED6`, flags = dewhitened | signal valid | ref-AA valid |
  offenses valid | CRC checked | (CRC valid when set), PDU type 0, PHY 0.
- Timestamps: host epoch offset established on the first frame; 32-bit device wrap
  is tracked, so packet spacing (not just host arrival time) is preserved.
- Port auto-detection prefers USB VID `0x2FE3` (Zephyr), then "Zephyr"/"nRF"/"CDC"
  descriptions, then the first port. `--port COMx` overrides.
- Standalone modes (`--cli`, `--pcap FILE`) allow testing without Wireshark.

## Error handling and limits

- Ring buffer drops (with counter) if USB or the host cannot keep up.
- The main loop never blocks on USB: CDC ACM `poll_out` discards when its TX ring is full.
- DTR is awaited for up to 5 s, then streaming starts anyway (host may just be slow).
- Phase 1 cannot follow connections: data-channel traffic is not captured. CONNECT_IND
  advertising PDUs are captured, which is the input needed for Phase 2.
- Capture is inherently lossy on the advertising channels because one radio cannot
  listen to three frequencies at once.

## Extensibility roadmap

1. **Connection following**: on `CONNECT_IND`, parse `InitA/AdvA`, `CRCInit`, `WinSize`,
   `WinOffset`, `Interval`, `Latency`, `Timeout`, and `ChM`; switch to the data-channel
   AA/CRC, then hop using CSA#1 (and CSA#2 for BLE 5). Requires a dedicated scheduler
   with anchor-point timing.
2. **BLE 5 extended advertising / 2M PHY**: change `PCNF0.PLEN`, `MODE`, and PDU-type
   flags; follow `AUX_PTR` chains.
3. **802.15.4 / Thread / Zigbee**: reuse the radio engine with the
   `IEEE802154` packet config (Zephyr's `ieee802154_nrf5.c` is a reference).
4. **On-device logging**: add a flash ring buffer or SD card and a PCAP export command.
5. **Multiple concurrent channels**: not possible with one radio; use multiple boards
   (future multi-device merge in the host).

## Verification

- Firmware compiles for `promicro_nrf52840/nrf52840/uf2` with no warnings.
- Host unit tests feed synthetic frames (including noise/resync and timestamp wrap)
  and assert pcap structure and numbering.
- Manual: flash, open COM port, confirm hello; open Wireshark, select the interface,
  observe advertising reports with correct channel/RSSI; verify a known beacon's
  address appears.
