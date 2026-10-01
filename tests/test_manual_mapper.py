"""
tests/test_manual_mapper.py — unit tests for manual_mapper.py
Tests PE parsing and shellcode generation (no live injection).
"""

import struct
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from manual_mapper import (
    PEImage,
    _generate_dllmain_caller_x64,
    _generate_dllmain_caller_x86,
    IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW,
)


def _make_minimal_dll_x64() -> bytes:
    """Create a minimal valid x64 PE DLL for testing."""
    data = bytearray(0x1000)

    # DOS Header
    struct.pack_into('<H', data, 0, IMAGE_DOS_SIGNATURE)  # e_magic = "MZ"
    struct.pack_into('<I', data, 0x3C, 0x80)  # e_lfanew

    # PE Signature
    struct.pack_into('<I', data, 0x80, IMAGE_NT_SIGNATURE)

    # COFF File Header (at 0x84)
    struct.pack_into('<HH', data, 0x84, 0x8664, 0)  # machine = AMD64, num_sections = 0

    # Optional Header (at 0x98) — 64-bit
    oh_offset = 0x98
    struct.pack_into('<H', data, oh_offset, 0x20b)  # magic = PE32+ (64-bit)
    struct.pack_into('<Q', data, oh_offset + 24, 0x140000000)  # image_base
    struct.pack_into('<I', data, oh_offset + 56, 0x1000)  # section_alignment
    struct.pack_into('<I', data, oh_offset + 60, 0x200)  # file_alignment
    struct.pack_into('<I', data, oh_offset + 88, 0x1000)  # size_of_image
    struct.pack_into('<I', data, oh_offset + 92, 0x400)  # size_of_headers
    struct.pack_into('<H', data, oh_offset + 112, 0x22)  # subsystem = GUI
    struct.pack_into('<I', data, oh_offset + 216, 16)  # num_rva_and_sizes = 16

    return bytes(data)


class TestPEImage(unittest.TestCase):
    """Test PE parsing."""

    def test_parse_minimal_dll(self):
        data = _make_minimal_dll_x64()
        pe = PEImage(data)
        self.assertEqual(pe.e_magic, IMAGE_DOS_SIGNATURE)
        self.assertEqual(pe.signature, IMAGE_NT_SIGNATURE)
        self.assertTrue(pe.is_64bit)

    def test_invalid_magic(self):
        data = b'\x00' * 0x100
        with self.assertRaises(ValueError):
            PEImage(data)

    def test_image_base(self):
        data = _make_minimal_dll_x64()
        pe = PEImage(data)
        self.assertEqual(pe.image_base, 0x140000000)

    def test_entry_point(self):
        data = _make_minimal_dll_x64()
        pe = PEImage(data)
        self.assertEqual(pe.entry_point_rva, 0)  # Minimal DLL has no entry point


class TestShellcodeGeneration(unittest.TestCase):
    """Test shellcode generation."""

    def test_x64_shellcode_aligns_stack_before_call(self):
        # x64 ABI: the CALL must land on a 16-byte aligned stack with 32
        # bytes of shadow space reserved, so the prologue is
        # `sub rsp, 0x28` = 48 83 EC 28. An earlier version emitted
        # `mov rcx` first and had no prologue at all, which corrupts the
        # callee's shadow space — assert the alignment, not the old layout.
        sc = _generate_dllmain_caller_x64(0x140000000, 0x1000)
        self.assertEqual(sc[0:4], b'\x48\x83\xEC\x28')
        # and it is torn down symmetrically before the ret:
        # add rsp, 0x28 = 48 83 C4 28, then C3
        self.assertEqual(sc[-5:], b'\x48\x83\xC4\x28\xC3')

    def test_x64_shellcode_has_mov_rcx(self):
        sc = _generate_dllmain_caller_x64(0x140000000, 0x1000)
        # mov rcx, imm64 = 48 B9 <8 bytes> — follows the stack prologue
        self.assertIn(b'\x48\xB9' + struct.pack('<Q', 0x140000000), sc)

    def test_x64_shellcode_has_ret(self):
        sc = _generate_dllmain_caller_x64(0x140000000, 0x1000)
        self.assertEqual(sc[-1:], b'\xC3')

    def test_x64_shellcode_contains_base(self):
        base = 0x140000000
        sc = _generate_dllmain_caller_x64(base, 0x1000)
        base_bytes = struct.pack('<Q', base)
        self.assertIn(base_bytes, sc)

    def test_x86_shellcode_has_push(self):
        sc = _generate_dllmain_caller_x86(0x14000000, 0x1000)
        # push instructions start with 6A or 68
        self.assertIn(sc[0:1], [b'\x6A', b'\x68'])

    def test_x86_shellcode_has_ret(self):
        sc = _generate_dllmain_caller_x86(0x14000000, 0x1000)
        self.assertEqual(sc[-1:], b'\xC3')


if __name__ == "__main__":
    unittest.main(verbosity=2)
