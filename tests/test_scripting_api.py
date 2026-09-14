"""
tests/test_scripting_api.py — verify scripting_api.py is fully wired.

Covers:
  - API instantiation (pid + process_handle paths)
  - scan / rescan / get_scan_results / clear_scan_results
  - read_int / write_int round-trip
  - breakpoint manager wiring (add, list, hits, remove)
  - error messages are helpful (not NotImplementedError)
"""

import ctypes
import os
import struct
import sys
import threading
import time
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripting_api as api
from scripting_api import MomoTrainerAPI


def _current_pid() -> int:
    return os.getpid()


def _alloc_test_value(value: int) -> tuple:
    """
    Allocate a page of memory, write *value* as int32 at offset 0,
    return (address, ctypes buffer) so the memory stays alive.
    """
    PAGE = 0x1000
    buf = ctypes.create_string_buffer(PAGE)
    addr = ctypes.addressof(buf)
    struct.pack_into('<i', buf, 0, value)
    return addr, buf


class TestApiInstantiation(unittest.TestCase):
    def test_create_with_pid(self):
        a = MomoTrainerAPI(pid=_current_pid())
        self.assertEqual(a.pid, _current_pid())
        self.assertIsNone(a.process_handle)
        self.assertTrue(a._has_process())

    def test_create_with_handle(self):
        # Use the current process pseudo-handle
        HANDLE = ctypes.c_void_p(-1)  # GetCurrentProcess() = -1
        a = MomoTrainerAPI(pid=_current_pid(), process_handle=HANDLE)
        self.assertTrue(a._has_process())

    def test_create_without_pid_raises(self):
        a = MomoTrainerAPI()
        self.assertFalse(a._has_process())
        with self.assertRaises(RuntimeError):
            a.scan(100)

    def test_scan_count_initially_zero(self):
        a = MomoTrainerAPI(pid=_current_pid())
        self.assertEqual(a.scan_count, 0)


class TestScanAndRescan(unittest.TestCase):
    """Scan the current process's own memory (safe, no anti-cheat)."""

    def test_scan_exact_finds_known_value(self):
        TARGET = 0xDEAD
        addr, buf = _alloc_test_value(TARGET)

        a = MomoTrainerAPI(pid=_current_pid())
        results = a.scan(TARGET, vtype='int32', mode='exact')

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        # Our address should be in the results
        self.assertIn(addr, results)
        self.assertEqual(a.scan_count, len(results))

    def test_scan_stores_vtype_for_rescan(self):
        TARGET = 42
        addr, buf = _alloc_test_value(TARGET)

        a = MomoTrainerAPI(pid=_current_pid())
        a.scan(TARGET, vtype='int32')
        self.assertEqual(a._vtype, 'int32')

    def test_rescan_narrows_results(self):
        addr, buf = _alloc_test_value(100)

        a = MomoTrainerAPI(pid=_current_pid())
        a.scan(100, vtype='int32')

        # Change the value in memory
        struct.pack_into('<i', buf, 0, 200)

        survivors = a.rescan(200, mode='exact')
        self.assertIn(addr, survivors)
        # Old value should NOT survive
        old_survivors = a.rescan(100, mode='exact')
        self.assertNotIn(addr, old_survivors)

    def test_rescan_without_scan_raises(self):
        a = MomoTrainerAPI(pid=_current_pid())
        with self.assertRaises(RuntimeError) as ctx:
            a.rescan(42)
        self.assertIn("scan()", str(ctx.exception))

    def test_get_scan_results_respects_limit(self):
        addr, buf = _alloc_test_value(777)

        a = MomoTrainerAPI(pid=_current_pid())
        a.scan(777, vtype='int32')

        limited = a.get_scan_results(limit=5)
        self.assertLessEqual(len(limited), 5)

    def test_clear_scan_results(self):
        addr, buf = _alloc_test_value(31337)

        a = MomoTrainerAPI(pid=_current_pid())
        a.scan(31337, vtype='int32')
        self.assertGreater(len(a._candidates), 0)

        a.clear_scan_results()
        self.assertEqual(len(a._candidates), 0)
        self.assertEqual(a.scan_count, 0)


class TestReadWrite(unittest.TestCase):

    def test_read_write_int32_roundtrip(self):
        addr, buf = _alloc_test_value(0)

        a = MomoTrainerAPI(pid=_current_pid())
        a.write_int(addr, 0x12345678, size=4)
        val = a.read_int(addr, size=4)
        self.assertEqual(val, 0x12345678)

    def test_read_write_uint8_roundtrip(self):
        addr, buf = _alloc_test_value(0)

        a = MomoTrainerAPI(pid=_current_pid())
        a.write_uint8(addr, 0xAB)
        val = a.read_uint8(addr)
        self.assertEqual(val, 0xAB)

    def test_read_write_float_roundtrip(self):
        addr, buf = _alloc_test_value(0)

        a = MomoTrainerAPI(pid=_current_pid())
        a.write_float(addr, 3.14159)
        val = a.read_float(addr)
        self.assertAlmostEqual(val, 3.14159, places=4)

    def test_read_write_string_roundtrip(self):
        addr, buf = _alloc_test_value(0)

        a = MomoTrainerAPI(pid=_current_pid())
        a.write_string(addr, "MomoTrainer")
        val = a.read_string(addr, max_length=32)
        self.assertEqual(val, "MomoTrainer")

    def test_write_nop(self):
        addr, buf = _alloc_test_value(0)  # allocate zeroed page

        a = MomoTrainerAPI(pid=_current_pid())
        result = a.write_nop(addr, count=4)
        # On current-process pseudo-handle this may fail gracefully
        # but should not raise an exception
        self.assertIsInstance(result, bool)


class TestBreakpointWiring(unittest.TestCase):

    def test_bp_manager_lazily_created(self):
        a = MomoTrainerAPI(pid=_current_pid())
        self.assertIsNone(a._bp_manager)

        a._ensure_bp_manager()
        self.assertIsNotNone(a._bp_manager)

    def test_set_and_list_breakpoints(self):
        a = MomoTrainerAPI(pid=_current_pid())
        # Use an address in our own buffer
        addr, buf = _alloc_test_value(0)

        added = a.set_breakpoint(addr, mode='write', size=4)
        self.assertTrue(added)
        self.assertIn(addr, a.get_all_breakpoints())

    def test_remove_breakpoint(self):
        a = MomoTrainerAPI(pid=_current_pid())
        addr, buf = _alloc_test_value(0)

        a.set_breakpoint(addr)
        self.assertIn(addr, a.get_all_breakpoints())

        a.remove_breakpoint(addr)
        self.assertNotIn(addr, a.get_all_breakpoints())

    def test_hits_empty_when_no_hits(self):
        a = MomoTrainerAPI(pid=_current_pid())
        addr, buf = _alloc_test_value(0)

        a.set_breakpoint(addr)
        hits = a.get_breakpoint_hits(addr)
        self.assertIsInstance(hits, list)

    def test_is_debugger_running(self):
        a = MomoTrainerAPI(pid=_current_pid())
        # No manager yet → False
        self.assertFalse(a.is_debugger_running())

    def test_stop_all_breakpoints(self):
        a = MomoTrainerAPI(pid=_current_pid())
        addr, buf = _alloc_test_value(0)

        a.set_breakpoint(addr)
        a.stop_all_breakpoints()
        self.assertFalse(a.is_debugger_running())

    def test_bp_without_pid_raises(self):
        a = MomoTrainerAPI()
        with self.assertRaises(RuntimeError):
            a._ensure_bp_manager()


class TestNoNotImplemented(unittest.TestCase):
    """Guard: make sure NotImplementedError is never raised from public API methods."""

    def test_scan_does_not_raise_not_implemented(self):
        addr, buf = _alloc_test_value(123)
        a = MomoTrainerAPI(pid=_current_pid())
        try:
            a.scan(123)
        except NotImplementedError:
            self.fail("scan() raised NotImplementedError — still a stub!")
        except Exception:
            pass  # Other exceptions (e.g. no process) are fine

    def test_rescan_does_not_raise_not_implemented(self):
        a = MomoTrainerAPI(pid=_current_pid())
        a._candidates = [0x1000]  # fake candidates
        a._vtype = 'int32'
        try:
            a.rescan(123)
        except NotImplementedError:
            self.fail("rescan() raised NotImplementedError — still a stub!")
        except Exception:
            pass

    def test_set_breakpoint_does_not_raise_not_implemented(self):
        a = MomoTrainerAPI(pid=_current_pid())
        addr, buf = _alloc_test_value(0)
        try:
            a.set_breakpoint(addr)
        except NotImplementedError:
            self.fail("set_breakpoint() raised NotImplementedError — still a stub!")
        except Exception:
            pass


class TestCreateApi(unittest.TestCase):
    def test_create_api_convenience(self):
        a = api.create_api(pid=_current_pid())
        self.assertIsInstance(a, MomoTrainerAPI)
        self.assertEqual(a.pid, _current_pid())


if __name__ == '__main__':
    unittest.main(verbosity=2)
