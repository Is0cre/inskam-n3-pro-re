import struct
import unittest

from cam_tui import CamClient, EventLog, Sniffer


class DummyCamClient(CamClient):
    def reopen_socket(self):
        self.sock = None


class CamTests(unittest.TestCase):
    def setUp(self):
        self.log = EventLog('/tmp/cam_tui_test.log', quiet=True)
        self.c = DummyCamClient('192.168.1.1', 10005, '0.0.0.0', self.log)

    def test_build_empty_packet(self):
        p = self.c.build_packet(0x01, 0, b'', seq=1)
        self.assertEqual(p.hex(), 'eeffeeff0100010000000000')

    def test_build_led_on_packet_exact(self):
        body = bytes.fromhex('0101ff000000')
        p = self.c.build_packet(0x0C, 1, body, seq=1)
        self.assertEqual(p.hex(), 'eeffeeff01000c00010006000101ff000000')

    def test_sequence_increments(self):
        self.c.seq = 1
        self.c.build_packet(1, 0, b'')
        self.c.build_packet(1, 0, b'')
        self.assertEqual(self.c.seq, 3)

    def test_decode_get_device_info_ascii(self):
        body = b'\x00YPC\x00ota ok\x00UseeEar-37f1e\x00'
        pkt = struct.pack('<IHHHH', 0xFFEEFFEE, 1, 1, 0, len(body)) + body
        rep = self.c.decode(pkt)
        text = self.c.extract_ascii(rep.body)
        self.assertIn('YPC', text)
        self.assertIn('ota ok', text)

    def test_decode_led_on_ack(self):
        body = bytes.fromhex('0101ff000000')
        pkt = struct.pack('<IHHHH', 0xFFEEFFEE, 2, 0x0C, 0x0301, len(body)) + body
        rep = self.c.decode(pkt)
        self.assertEqual(rep.op, 0x0301)
        self.assertEqual(rep.body, body)

    def test_decode_led_off_ack(self):
        body = bytes.fromhex('000100000000')
        pkt = struct.pack('<IHHHH', 0xFFEEFFEE, 3, 0x0C, 0x0301, len(body)) + body
        rep = self.c.decode(pkt)
        self.assertEqual(rep.body, body)

    def test_decode_status_port(self):
        body = bytes.fromhex('01204e') + b'\x00' * 53
        d = self.c.decode_status(body)
        self.assertEqual(d['possible_port_le16'], 20000)

    def test_decode_unsupported_op(self):
        self.assertEqual(self.c.decode_op(0x0200), 'UNSUPPORTED')

    def test_invalid_short_packet(self):
        with self.assertRaises(ValueError):
            self.c.decode(b'\x00' * 11)

    def test_ascii_extraction(self):
        out = self.c.extract_ascii(b'\x00abc\x00de\x00fghij\x00')
        self.assertEqual(out, ['abc', 'fghij'])

    def test_decode_op_mapping(self):
        self.assertEqual(self.c.decode_op(0x0000), 'OK')
        self.assertEqual(self.c.decode_op(0x0301), 'ACK')

    def test_registration_bodies(self):
        bodies = Sniffer.registration_bodies(20000)
        self.assertEqual(bodies[0], struct.pack('<I', 20000))
        self.assertEqual(bodies[2], struct.pack('<H', 20000))
        self.assertEqual(bodies[4], b'\x01' + struct.pack('<I', 20000))


if __name__ == '__main__':
    unittest.main()
