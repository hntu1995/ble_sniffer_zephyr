import os
import struct
import sys
import unittest

HOST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, HOST_DIR)

import nrf_ble_sniffer as sniffer  # noqa: E402


def make_frame(payload: bytes, ts: int = 1234, channel: int = 37,
               rssi: int = -50, flags: int = 0, ftype: int = 1) -> bytes:
    header = sniffer.HDR.pack(
        sniffer.MAGIC, sniffer.PROTO_VERSION, ftype, len(payload),
        ts, channel, rssi & 0xFF, flags, 0
    )
    return header + payload


def pdu(payload: bytes = b"\x01\x02\x03", pdu_type: int = 0) -> bytes:
    ll = bytes([pdu_type, len(payload)]) + payload
    return b"\xd6\xbe\x89\x8e" + ll + b"\x00\x00\x00"


class FrameParserTests(unittest.TestCase):
    def test_header_is_14_bytes(self):
        self.assertEqual(sniffer.HDR_SIZE, 14)

    def test_roundtrip(self):
        frame = make_frame(pdu())
        out = sniffer.FrameParser().feed(frame)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].channel, 37)
        self.assertEqual(out[0].rssi, -50)
        self.assertEqual(out[0].timestamp_us, 1234)

    def test_split_across_reads(self):
        frame = make_frame(pdu())
        parser = sniffer.FrameParser()
        out = []
        for i in range(0, len(frame), 3):
            out += parser.feed(frame[i:i + 3])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].payload, pdu())

    def test_resync_on_garbage(self):
        parser = sniffer.FrameParser()
        out = parser.feed(b"\x00garbage\x5a\x00\x5a" + make_frame(pdu()))
        self.assertEqual(len(out), 1)

    def test_bad_version_dropped(self):
        bad = bytearray(make_frame(pdu()))
        bad[2] = 99
        parser = sniffer.FrameParser()
        self.assertEqual(parser.feed(bytes(bad) + make_frame(pdu())), [
            sniffer.FrameParser().feed(make_frame(pdu()))[0]
        ])

    def test_truncated_waits(self):
        frame = make_frame(pdu())
        parser = sniffer.FrameParser()
        self.assertEqual(parser.feed(frame[:-1]), [])
        out = parser.feed(frame[-1:])
        self.assertEqual(len(out), 1)

    def test_hello_is_returned_but_not_a_packet(self):
        frame = make_frame(b"hello", ftype=sniffer.TYPE_HELLO)
        out = sniffer.FrameParser().feed(frame)
        self.assertEqual(out[0].type, sniffer.TYPE_HELLO)


class PcapTests(unittest.TestCase):
    def test_global_header(self):
        magic, major, minor, _, _, snaplen, network = struct.unpack(
            "<IHHIIII", sniffer.pcap_global_header()
        )
        self.assertEqual(magic, sniffer.PCAP_MAGIC)
        self.assertEqual((major, minor), (2, 4))
        self.assertEqual(snaplen, 65535)
        self.assertEqual(network, 256)

    def test_record_layout_and_flags(self):
        frame = sniffer.Frame(
            type=sniffer.TYPE_PACKET, payload=pdu(), timestamp_us=0,
            channel=38, rssi=-42,
            flags=sniffer.FLAG_CRC_OK | sniffer.FLAG_CRC_CHECKED,
        )
        rec = sniffer.build_record(frame, 100, 200)
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", rec[:16])
        self.assertEqual((ts_sec, ts_usec), (100, 200))
        self.assertEqual(incl, len(rec) - 16)
        self.assertEqual(orig, incl)

        data = rec[16:]
        self.assertEqual(data[0], 38)
        self.assertEqual(struct.unpack("b", data[1:2])[0], -42)
        self.assertEqual(data[2:4], b"\x00\x00")
        self.assertEqual(struct.unpack("<I", data[4:8])[0], 0x8E89BED6)
        flags = struct.unpack("<H", data[8:10])[0]
        self.assertTrue(flags & sniffer.LE_CRC_VALID)
        self.assertTrue(flags & sniffer.LE_CRC_CHECKED)
        self.assertTrue(flags & sniffer.LE_DEWHITENED)
        self.assertEqual(data[10:], pdu())

    def test_crc_error_clears_valid_bit(self):
        frame = sniffer.Frame(
            type=sniffer.TYPE_PACKET, payload=pdu(), timestamp_us=0,
            channel=37, rssi=-80, flags=sniffer.FLAG_CRC_CHECKED,
        )
        flags = struct.unpack("<H", sniffer.build_record(frame, 0, 0)[24:26])[0]
        self.assertEqual(flags & sniffer.LE_CRC_VALID, 0)

    def test_aux_adv_pdu_type(self):
        frame = sniffer.Frame(
            type=sniffer.TYPE_PACKET, payload=pdu(), timestamp_us=0,
            channel=39, rssi=-60, flags=sniffer.FLAG_AUX_ADV,
        )
        flags = struct.unpack("<H", sniffer.build_record(frame, 0, 0)[24:26])[0]
        self.assertEqual((flags & sniffer.LE_PDU_TYPE) >> sniffer.LE_PDU_TYPE_SHIFT, 1)


class TimestampTests(unittest.TestCase):
    def test_monotonic_with_wrap(self):
        mapper = sniffer.TimestampMapper()
        s1, u1 = mapper.map(0xFFFFFF00, host_time=1000.0)
        s2, u2 = mapper.map(0x00000100, host_time=1000.1)
        self.assertAlmostEqual((s2 + u2 / 1e6) - (s1 + u1 / 1e6), 0.000512, places=6)

    def test_offset_uses_first_host_time(self):
        mapper = sniffer.TimestampMapper()
        sec, usec = mapper.map(1_000_000, host_time=500.0)
        self.assertEqual(sec, 500)
        self.assertEqual(usec, 0)


class CapturePathTests(unittest.TestCase):
    """End-to-end: fake serial -> parser -> pcap, without Wireshark."""

    def test_capture_writes_valid_pcap(self):
        class FakeSerial:
            def __init__(self, *args, **kwargs):
                self._chunks = [make_frame(pdu())]

            def read(self, _n):
                if self._chunks:
                    return self._chunks.pop(0)
                raise KeyboardInterrupt

            def close(self):
                pass

        original_serial = sniffer.serial
        original_find = sniffer.find_port
        tmp = os.path.join(os.path.dirname(__file__), "_capture_test.pcap")

        class FakeSerialModule:
            Serial = FakeSerial

        sniffer.serial = FakeSerialModule
        sniffer.find_port = lambda port, quiet=False: "COM_TEST"
        try:
            self.assertEqual(sniffer.cmd_capture(tmp, None), 0)
        finally:
            sniffer.serial = original_serial
            sniffer.find_port = original_find

        with open(tmp, "rb") as fh:
            data = fh.read()
        os.unlink(tmp)

        magic, _maj, _min, _tz, _sig, _snap, network = struct.unpack(
            "<IHHIIII", data[:24]
        )
        self.assertEqual(magic, sniffer.PCAP_MAGIC)
        self.assertEqual(network, sniffer.DLT_BTLE_LL_WITH_PHDR)
        self.assertEqual(len(data), 24 + 16 + 10 + len(pdu()))
        self.assertEqual(data[24 + 16], 37)
        self.assertEqual(data[24 + 16 + 10:], pdu())


if __name__ == "__main__":
    unittest.main()
