# Sniffer wire protocol and Wireshark mapping

Firmware: `firmware/src/sniffer_proto.h`
Host: `host/nrf_ble_sniffer.py`

## Device → host framing

14-byte header, little endian:

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 2 | magic | `0x5A 0xC3` |
| 2 | 1 | version | `1` |
| 3 | 1 | type | `1` = LL packet, `2` = hello |
| 4 | 2 | payload length | bytes after the header |
| 6 | 4 | timestamp | µs, free-running, wraps every 2³² µs (~71.6 min) |
| 10 | 1 | channel | RF channel index: 37/38/39 (0–36 reserved for data) |
| 11 | 1 | RSSI | signed dBm |
| 12 | 1 | flags | see below |
| 13 | 1 | reserved | 0 |

Flags:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | CRC_OK | hardware CRC check passed |
| 1 | CRC_CHECKED | CRC was checked (always set) |
| 2 | DEWHITENED | payload is dewhitened (always set) |
| 3 | DIRECTION | reserved for connection following |
| 4 | AA_VALID | access address is known/valid |
| 5 | AUX_ADV | auxiliary advertising PDU (future) |
| 6 | TRUNCATED | payload was cut short |
| 7 | — | reserved |

### Packet payload

```
AA (4 bytes, on-air order, e.g. D6 BE 89 8E)
LL header (1 byte)
length (1 byte)
payload (length bytes)
CRC (3 bytes, zero placeholders)
```

The nRF52 radio does not copy the received CRC to RAM. The pseudo-header's
CRC-valid flag carries the hardware result instead.

### Hello payload

ASCII, e.g. `nrf52840-ble-sniffer 1.0.0`. The host ignores it for capture but
prints it in CLI mode.

## Host → Wireshark

The host writes a pcap stream (`<IHHIIII>` global header, magic `0xa1b2c3d4`,
snaplen 65535, linktype **256**) to the extcap FIFO.

Each record is `10-byte BTLE RF pseudo-header + payload`:

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 1 | RF channel | 37/38/39 |
| 1 | 1 | signal power (dBm) | from RSSI |
| 2 | 1 | noise power | unused (valid flag not set) |
| 3 | 1 | AA offenses | 0 (valid flag set) |
| 4 | 4 | reference AA | `0x8E89BED6`, little endian |
| 8 | 2 | flags | see below |

Pseudo-header flags used:

- `0x0001` dewhitened
- `0x0002` signal power valid
- `0x0010` reference AA valid
- `0x0020` AA offenses valid
- `0x0400` CRC checked
- `0x0800` CRC valid (when the firmware CRC_OK flag is set)
- bits 7–9 PDU type: 0 = unspecified/legacy advertising, 1 = auxiliary advertising
- bits 14–15 PHY: 0 = LE 1M

Wireshark then hands `payload` (AA + PDU + CRC) to the BTLE dissector.

## Timestamp mapping

The host establishes `offset = host_time - device_time` on the first packet.
Subsequent timestamps are `offset + device_time`, with 32-bit wrap tracking. This
preserves packet spacing better than using host arrival time, while staying close
to wall-clock time.

## Adding connection following (future)

Extend the packet flags with a direction bit and emit data-channel PDUs with the
connection's access address. The host already sends `channel` (0–36) and a
reference AA; only the AA value in the pseudo-header and the packet's AA bytes
need to become connection-specific. Keep the 14-byte header stable so old hosts
can still parse it (version bump only if the layout changes).
