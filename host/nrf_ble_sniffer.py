#!/usr/bin/env python3
"""Wireshark extcap + CLI for the nRF52840 Zephyr BLE advertising sniffer.

The firmware streams framed, dewhitened Link-Layer PDUs over USB CDC-ACM.
This tool converts them into pcap records with DLT 256
(LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR), which Wireshark's BTLE dissector
understands natively.

Modes:
  extcap:   --extcap-interfaces | --extcap-dlts | --extcap-config | --capture
  CLI:      --port COM7 --list-ports | --cli | --pcap out.pcap
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from dataclasses import dataclass

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # tests and --extcap-interfaces still work
    serial = None
    list_ports = None

# --------------------------------------------------------------------------
# Wire protocol (keep in sync with firmware/src/sniffer_proto.h)
# --------------------------------------------------------------------------

MAGIC = b"\x5a\xc3"
PROTO_VERSION = 1
TYPE_PACKET = 1
TYPE_HELLO = 2

HDR = struct.Struct("<2sBBHIBBBB")
HDR_SIZE = HDR.size  # 14
MAX_PAYLOAD = 600
PAYLOAD_OVERHEAD = 4 + 2 + 3  # AA, header+length already in PDU, CRC placeholder

FLAG_CRC_OK = 1 << 0
FLAG_CRC_CHECKED = 1 << 1
FLAG_DEWHITENED = 1 << 2
FLAG_DIRECTION = 1 << 3
FLAG_AA_VALID = 1 << 4
FLAG_AUX_ADV = 1 << 5
FLAG_TRUNCATED = 1 << 6

# --------------------------------------------------------------------------
# Wireshark / libpcap constants
# --------------------------------------------------------------------------

PCAP_MAGIC = 0xA1B2C3D4
DLT_BTLE_LL_WITH_PHDR = 256
SNAPLEN = 65535

LE_DEWHITENED = 0x0001
LE_SIGPOWER_VALID = 0x0002
LE_NOISEPOWER_VALID = 0x0004
LE_PACKET_DECRYPTED = 0x0008
LE_REF_AA_VALID = 0x0010
LE_AA_OFFENSES_VALID = 0x0020
LE_CHANNEL_ALIASED = 0x0040
LE_PDU_TYPE = 0x0380
LE_PDU_TYPE_SHIFT = 7
LE_CRC_CHECKED = 0x0400
LE_CRC_VALID = 0x0800
LE_MIC_CHECKED = 0x1000
LE_MIC_VALID = 0x2000
LE_PHY = 0xC000

ADV_AA = 0x8E89BED6


@dataclass
class Frame:
    type: int
    payload: bytes
    timestamp_us: int
    channel: int
    rssi: int
    flags: int


class FrameParser:
    """Incremental parser that resynchronizes on the magic bytes."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        frames: list[Frame] = []

        while True:
            idx = self._buf.find(MAGIC)
            if idx < 0:
                # Keep a trailing magic[0] in case the magic is split.
                if self._buf and self._buf[-1] == MAGIC[0]:
                    del self._buf[:-1]
                else:
                    self._buf.clear()
                break

            if idx:
                del self._buf[:idx]

            if len(self._buf) < HDR_SIZE:
                break

            (magic, version, ftype, plen, ts, channel, rssi,
             flags, _reserved) = HDR.unpack_from(self._buf)

            if magic != MAGIC or version != PROTO_VERSION or plen > MAX_PAYLOAD:
                # Not a real header; drop one byte and search again.
                del self._buf[0]
                continue

            total = HDR_SIZE + plen
            if len(self._buf) < total:
                break

            payload = bytes(self._buf[HDR_SIZE:total])
            del self._buf[:total]

            if ftype == TYPE_PACKET and plen < PAYLOAD_OVERHEAD:
                continue

            frames.append(
                Frame(
                    type=ftype,
                    payload=payload,
                    timestamp_us=ts,
                    channel=channel,
                    rssi=struct.unpack("b", struct.pack("B", rssi))[0],
                    flags=flags,
                )
            )

        return frames


class TimestampMapper:
    """Maps the device's 32-bit microsecond clock to host wall-clock time."""

    WRAP = 1 << 32
    HALF = 1 << 31

    def __init__(self) -> None:
        self._offset: float | None = None
        self._last_raw: int | None = None
        self._wraps = 0

    def map(self, raw: int, host_time: float | None = None) -> tuple[int, int]:
        host_time = time.time() if host_time is None else host_time

        if self._last_raw is not None and raw + self.HALF < self._last_raw:
            self._wraps += 1
        self._last_raw = raw

        raw64 = raw + self._wraps * self.WRAP
        if self._offset is None:
            self._offset = host_time - raw64 / 1_000_000.0

        seconds = self._offset + raw64 / 1_000_000.0
        sec = int(seconds)
        usec = int(round((seconds - sec) * 1_000_000.0))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        return sec, usec


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, DLT_BTLE_LL_WITH_PHDR
    )


def build_record(frame: Frame, ts_sec: int, ts_usec: int) -> bytes:
    """Build one pcap record: 10-byte BTLE RF pseudo-header + LL packet."""
    flags = (
        LE_DEWHITENED
        | LE_SIGPOWER_VALID
        | LE_REF_AA_VALID
        | LE_AA_OFFENSES_VALID
        | LE_CRC_CHECKED
    )
    if frame.flags & FLAG_CRC_OK:
        flags |= LE_CRC_VALID
    if frame.flags & FLAG_AUX_ADV:
        flags |= 1 << LE_PDU_TYPE_SHIFT  # auxiliary advertising PDU type

    pseudo = (
        bytes((frame.channel & 0xFF, frame.rssi & 0xFF, 0x00, 0x00))
        + struct.pack("<I", ADV_AA)
        + struct.pack("<H", flags)
    )
    data = pseudo + frame.payload
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


# --------------------------------------------------------------------------
# Port selection and extcap plumbing
# --------------------------------------------------------------------------

IFACE_VALUE = "nrf52840-ble"
IFACE_DISPLAY = "nRF52840 BLE Sniffer (Zephyr)"
EXTCAP_VERSION = "1.0.0"


def list_serial_ports():
    if list_ports is None:
        return []
    return list(list_ports.comports())


def find_port(explicit: str | None, quiet: bool = False) -> str | None:
    if explicit:
        return explicit

    ports = list_serial_ports()
    if not ports:
        return None

    # Zephyr's default USB VID; ours uses 0x2FE3:0x0008.
    for port in ports:
        if getattr(port, "vid", None) == 0x2FE3:
            return port.device

    for port in ports:
        text = " ".join(
            str(x) for x in (port.description, port.manufacturer, port.product) if x
        ).lower()
        if any(k in text for k in ("zephyr", "nrf", "sniffer", "cdc")):
            return port.device

    if not quiet:
        print(
            "Multiple serial ports found; using the first. "
            "Pass --port COMx to choose.",
            file=sys.stderr,
        )
    return ports[0].device


def cmd_extcap_interfaces() -> int:
    print(f"extcap {{version={EXTCAP_VERSION}}}"
          f"{{display={IFACE_DISPLAY}}}"
          "{help=Bluetooth LE advertising sniffer for nRF52840 + Zephyr}")
    print(f"interface {{value={IFACE_VALUE}}}{{display={IFACE_DISPLAY}}}")
    return 0


def cmd_extcap_dlts(iface: str) -> int:
    if iface != IFACE_VALUE:
        print(f"Unknown interface {iface}", file=sys.stderr)
        return 1
    print("dlt {number=256}{name=BLUETOOTH_LE_LL_WITH_PHDR}"
          "{display=Bluetooth LE Link Layer with pseudo-header}")
    return 0


def cmd_extcap_config(iface: str) -> int:
    if iface != IFACE_VALUE:
        print(f"Unknown interface {iface}", file=sys.stderr)
        return 1
    print("arg {number=0}{call=--port}{display=Serial port}"
          "{type=string}{tooltip=COM port (leave empty to auto-detect)}"
          "{group=Capture}")
    return 0


def open_fifo(path: str):
    # Wireshark creates the named pipe before launching us, but give it a moment.
    last_error = None
    for _ in range(50):
        try:
            return open(path, "wb", buffering=0)
        except FileNotFoundError as exc:  # pragma: no cover - host dependent
            last_error = exc
            time.sleep(0.05)
    raise last_error  # type: ignore[misc]


def open_serial(port: str):
    if serial is None:
        raise RuntimeError("pyserial is not installed (pip install pyserial)")
    ser = serial.Serial(port, 115200, timeout=0.05, write_timeout=0)
    try:
        ser.dtr = True
        ser.rts = True
    except Exception:
        pass
    return ser


def cmd_capture(fifo_path: str, port_arg: str | None) -> int:
    port = find_port(port_arg)
    if not port:
        print(
            "No serial port found. Flash the firmware and pass --port COMx.",
            file=sys.stderr,
        )
        return 1

    try:
        fifo = open_fifo(fifo_path)
    except OSError as exc:
        print(f"Failed to open extcap FIFO: {exc}", file=sys.stderr)
        return 1

    fifo.write(pcap_global_header())

    try:
        ser = open_serial(port)
    except Exception as exc:
        print(f"Failed to open {port}: {exc}", file=sys.stderr)
        return 1

    parser = FrameParser()
    mapper = TimestampMapper()

    try:
        while True:
            chunk = ser.read(4096)
            now = time.time()
            if not chunk:
                continue
            for frame in parser.feed(chunk):
                if frame.type != TYPE_PACKET:
                    continue
                ts_sec, ts_usec = mapper.map(frame.timestamp_us, now)
                try:
                    fifo.write(build_record(frame, ts_sec, ts_usec))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # serial unplugged, etc.
        print(f"Capture stopped: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            ser.close()
        except Exception:
            pass
        try:
            fifo.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Standalone CLI (useful without Wireshark)
# --------------------------------------------------------------------------

def _addr_reversed(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(raw))


def describe(frame: Frame) -> str:
    p = frame.payload
    if len(p) < 7:
        return f"ch={frame.channel} rssi={frame.rssi} short frame"
    pdu_type = p[4] & 0x0F
    plen = p[5]
    extra = ""
    if pdu_type in (0, 1, 2, 3, 4, 6) and len(p) >= 12:
        extra = f" adva={_addr_reversed(p[6:12])}"
    elif pdu_type == 5 and len(p) >= 18:
        extra = (f" inita={_addr_reversed(p[6:12])}"
                 f" adva={_addr_reversed(p[12:18])}")
    crc = "ok" if frame.flags & FLAG_CRC_OK else "bad"
    return (f"ch={frame.channel:2d} rssi={frame.rssi:4d}dBm "
            f"pdu=0x{pdu_type:02x} len={plen:3d} crc={crc}{extra}")


def cmd_cli(port_arg: str | None, pcap_path: str | None) -> int:
    port = find_port(port_arg)
    if not port:
        print("No serial port found.", file=sys.stderr)
        return 1

    ser = open_serial(port)
    parser = FrameParser()
    mapper = TimestampMapper()
    pcap = open(pcap_path, "wb") if pcap_path else None

    if pcap:
        pcap.write(pcap_global_header())

    print(f"Listening on {port} (Ctrl-C to stop)", file=sys.stderr)

    try:
        while True:
            chunk = ser.read(4096)
            now = time.time()
            if not chunk:
                continue
            for frame in parser.feed(chunk):
                if frame.type == TYPE_HELLO:
                    print(f"firmware: {frame.payload.decode(errors='replace')}",
                          file=sys.stderr)
                    continue
                if frame.type != TYPE_PACKET:
                    continue
                ts_sec, ts_usec = mapper.map(frame.timestamp_us, now)
                if pcap:
                    pcap.write(build_record(frame, ts_sec, ts_usec))
                else:
                    print(f"{ts_sec}.{ts_usec:06d} {describe(frame)}")
    except KeyboardInterrupt:
        return 0
    finally:
        ser.close()
        if pcap:
            pcap.close()


def main(argv: list[str]) -> int:
    args, _unknown = build_arg_parser().parse_known_args(argv)

    if args.extcap_version:
        print(EXTCAP_VERSION)
        return 0
    if args.extcap_interfaces:
        return cmd_extcap_interfaces()
    if args.extcap_dlts:
        return cmd_extcap_dlts(args.extcap_interface or IFACE_VALUE)
    if args.extcap_config:
        return cmd_extcap_config(args.extcap_interface or IFACE_VALUE)
    if args.capture:
        if not args.fifo:
            print("--capture requires --fifo", file=sys.stderr)
            return 1
        return cmd_capture(args.fifo, args.port)
    if args.list_ports:
        for port in list_serial_ports():
            print(f"{port.device}\t{port.description}")
        return 0
    if args.cli or args.pcap:
        return cmd_cli(args.port, args.pcap)

    build_arg_parser().print_help()
    return 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nrf_ble_sniffer",
        description="nRF52840 BLE sniffer extcap / CLI",
    )
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-version", action="store_true")
    parser.add_argument("--extcap-interface", default=None)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo", default=None)
    parser.add_argument("--port", default=None,
                        help="serial port, e.g. COM7 (default: auto)")
    parser.add_argument("--list-ports", action="store_true")
    parser.add_argument("--cli", action="store_true",
                        help="print packets to the console")
    parser.add_argument("--pcap", default=None,
                        help="write packets to a pcap file and exit on Ctrl-C")
    return parser


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
