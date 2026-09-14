"""
tests/test_pro_tools.py — verify pro_tools.py enhancements.
Tests value formatting, type detection, copy formats, AOB search logic.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pro_tools import (
    format_value,
    auto_detect_type,
    WatchEntryPro,
    MemoryWatchProWindow,
    HexViewerProWindow,
)


class TestValueFormatting(unittest.TestCase):

    def test_hex_int32(self):
        raw = (0x12345678).to_bytes(4, 'little')
        result = format_value(raw, "int32", "Hex")
        self.assertEqual(result, "0x12345678")

    def test_decimal_uint32(self):
        raw = (42).to_bytes(4, 'little')
        result = format_value(raw, "uint32", "Decimal")
        self.assertEqual(result, "42")

    def test_float_format(self):
        import struct
        raw = struct.pack('<f', 3.14)
        result = format_value(raw, "float", "Float")
        self.assertIn("3.14", result)

    def test_binary_int8(self):
        raw = (0b10110101).to_bytes(1, 'little')
        result = format_value(raw, "int8", "Binary")
        self.assertIn("0b1", result)

    def test_string_type(self):
        raw = b"Hello\x00world"
        result = format_value(raw, "string", "Hex")
        self.assertEqual(result, "Hello")

    def test_empty_raw(self):
        result = format_value(None, "int32", "Hex")
        self.assertEqual(result, "?")

    def test_scientific_double(self):
        import struct
        raw = struct.pack('<d', 1234567.89)
        result = format_value(raw, "double", "Scientific")
        self.assertIn("e+", result.lower())

    def test_auto_type_then_format(self):
        import struct
        raw = struct.pack('<f', 2.5)
        result = format_value(raw, "float", "Float")
        self.assertIn("2.5", result)


class TestAutoDetectType(unittest.TestCase):

    def test_detect_float(self):
        import struct
        raw = struct.pack('<f', 3.14159)
        detected = auto_detect_type(raw)
        self.assertEqual(detected, "float")

    def test_detect_int32(self):
        raw = (100).to_bytes(4, 'little')
        detected = auto_detect_type(raw)
        self.assertEqual(detected, "int32")

    def test_detect_string(self):
        raw = b"Hello World\x00\x00\x00\x00"
        detected = auto_detect_type(raw)
        self.assertEqual(detected, "string")

    def test_detect_short_raw(self):
        raw = b'\x01\x02'
        detected = auto_detect_type(raw)
        self.assertEqual(detected, "int32")  # default for short


class TestWatchEntryPro(unittest.TestCase):

    def test_basic_creation(self):
        entry = WatchEntryPro(address=0x140001000, vtype="int32")
        self.assertEqual(entry.address, 0x140001000)
        self.assertEqual(entry.vtype, "int32")
        self.assertFalse(entry.frozen)

    def test_update_tracks_changes(self):
        entry = WatchEntryPro(address=0x1000)
        entry.update_value(b'\x01\x00\x00\x00')
        entry.update_value(b'\x02\x00\x00\x00')
        self.assertTrue(entry.has_changed)
        self.assertEqual(entry.change_count, 1)

    def test_no_change_when_same(self):
        entry = WatchEntryPro(address=0x1000)
        entry.update_value(b'\x01\x00\x00\x00')
        entry.update_value(b'\x01\x00\x00\x00')
        self.assertFalse(entry.has_changed)

    def test_history_capped(self):
        entry = WatchEntryPro(address=0x1000)
        entry.max_history = 5
        for i in range(10):
            entry.update_value(bytes([i]))
        self.assertEqual(len(entry.change_history), 5)

    def test_freeze_state(self):
        entry = WatchEntryPro(address=0x1000)
        entry.frozen = True
        self.assertTrue(entry.frozen)


class TestCopyFormats(unittest.TestCase):

    def test_c_array(self):
        data = b'\x48\x8B\x05\x00\x00\x00\x00'
        result = HexViewerProWindow._format_c_array(data)
        self.assertIn("unsigned char bytes[]", result)
        self.assertIn("0x48", result)

    def test_python_bytes(self):
        data = b'\x48\x8B\x05'
        result = HexViewerProWindow._format_python(data)
        self.assertIn("data = (", result)
        self.assertIn("b'\\x48\\x8B\\x05'", result)

    def test_go_bytes(self):
        data = b'\x01\x02\x03'
        result = HexViewerProWindow._format_go(data)
        self.assertIn("[]byte{", result)
        self.assertIn("0x01", result)

    def test_rust_bytes(self):
        data = b'\xFF\xFE'
        result = HexViewerProWindow._format_rust(data)
        self.assertIn("[u8;", result)
        self.assertIn("0xFF", result)

    def test_lua_table(self):
        data = b'\x0A\x0B'
        result = HexViewerProWindow._format_lua(data)
        self.assertIn("local data = {", result)
        self.assertIn("0x0A", result)


class TestAOBSearch(unittest.TestCase):
    """Test AOB pattern matching logic."""

    def test_parse_pattern(self):
        """Parse AOB string into pattern + mask."""
        pattern_str = "48 8B ?? ?? 05"
        parts = pattern_str.split()
        pattern = []
        mask = []
        for p in parts:
            if p in ('?', '??'):
                pattern.append(0)
                mask.append(0)
            else:
                pattern.append(int(p, 16))
                mask.append(0xFF)
        self.assertEqual(pattern, [0x48, 0x8B, 0, 0, 0x05])
        self.assertEqual(mask, [0xFF, 0xFF, 0, 0, 0xFF])

    def test_match_with_wildcard(self):
        data = bytes([0x48, 0x8B, 0x99, 0x88, 0x05])
        pattern_str = "48 8B ?? ?? 05"
        parts = pattern_str.split()
        pattern = [0x48, 0x8B, 0, 0, 0x05]
        mask = [0xFF, 0xFF, 0, 0, 0xFF]

        match = True
        for j in range(len(pattern)):
            if mask[j] and (data[j] & mask[j]) != (pattern[j] & mask[j]):
                match = False
                break
        self.assertTrue(match)

    def test_no_match_without_wildcard(self):
        data = bytes([0x48, 0x8B, 0x99, 0x88, 0x06])  # last byte differs
        pattern = [0x48, 0x8B, 0, 0, 0x05]
        mask = [0xFF, 0xFF, 0, 0, 0xFF]

        match = True
        for j in range(len(pattern)):
            if mask[j] and (data[j] & mask[j]) != (pattern[j] & mask[j]):
                match = False
                break
        self.assertFalse(match)


if __name__ == "__main__":
    unittest.main(verbosity=2)
