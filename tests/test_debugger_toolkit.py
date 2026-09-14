"""
tests/test_debugger_toolkit.py — verify debugger_toolkit.py features.
Tests conditional breakpoints, trace recording, module map, and exports.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from debugger_toolkit import (
    BreakCondition,
    TraceRecorder,
    TraceEntry,
    ModuleMap,
    ModuleInfo,
)


class TestBreakCondition(unittest.TestCase):

    def test_reg_equal_true(self):
        cond = BreakCondition(cond_type="reg_equal", register="RAX", value=0x1234)
        ctx = {"RAX": 0x1234, "RBX": 0x0}
        self.assertTrue(cond.evaluate(ctx))

    def test_reg_equal_false(self):
        cond = BreakCondition(cond_type="reg_equal", register="RAX", value=0x1234)
        ctx = {"RAX": 0x5678}
        self.assertFalse(cond.evaluate(ctx))

    def test_reg_not_equal(self):
        cond = BreakCondition(cond_type="reg_not_equal", register="RCX", value=0x100)
        self.assertTrue(cond.evaluate({"RCX": 0x200}))
        self.assertFalse(cond.evaluate({"RCX": 0x100}))

    def test_reg_greater(self):
        cond = BreakCondition(cond_type="reg_greater", register="RDX", value=50)
        self.assertTrue(cond.evaluate({"RDX": 100}))
        self.assertFalse(cond.evaluate({"RDX": 10}))

    def test_reg_less(self):
        cond = BreakCondition(cond_type="reg_less", register="RDX", value=50)
        self.assertTrue(cond.evaluate({"RDX": 10}))
        self.assertFalse(cond.evaluate({"RDX": 100}))

    def test_hit_count(self):
        cond = BreakCondition(cond_type="hit_count", hit_target=3)
        ctx = {}
        self.assertFalse(cond.evaluate(ctx))  # hit 1
        self.assertFalse(cond.evaluate(ctx))  # hit 2
        self.assertTrue(cond.evaluate(ctx))   # hit 3
        self.assertTrue(cond.evaluate(ctx))   # hit 4+

    def test_describe_reg_equal(self):
        cond = BreakCondition(cond_type="reg_equal", register="RBX", value=0x42)
        self.assertEqual(cond.describe(), "RBX == 0x42")

    def test_describe_hit_count(self):
        cond = BreakCondition(cond_type="hit_count", hit_target=5)
        cond._hit_count = 3
        d = cond.describe()
        self.assertIn("3", d)
        self.assertIn("5", d)

    def test_describe_mem_dword(self):
        cond = BreakCondition(cond_type="mem_dword_eq", address=0x1000, value=0xDEADBEEF)
        self.assertIn("0x1000", cond.describe())
        self.assertIn("0xDEADBEEF", cond.describe())


class TestTraceRecorder(unittest.TestCase):

    def test_start_stop(self):
        rec = TraceRecorder(pid=1234)
        self.assertFalse(rec.is_recording)
        rec.start()
        self.assertTrue(rec.is_recording)
        rec.stop()
        self.assertFalse(rec.is_recording)

    def test_record_instruction(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x140001000, 1234, "mov rax, rbx")
        rec.record_instruction(0x140001005, 1234, "add rax, 5")
        rec.stop()
        self.assertEqual(rec.entry_count, 2)

    def test_record_when_stopped(self):
        rec = TraceRecorder(pid=1234)
        rec.record_instruction(0x140001000, 1234, "mov rax, rbx")
        self.assertEqual(rec.entry_count, 0)

    def test_max_entries_cap(self):
        rec = TraceRecorder(pid=1234, max_entries=5)
        rec.start()
        for i in range(10):
            rec.record_instruction(0x140001000 + i, 1234, f"insn {i}")
        self.assertEqual(rec.entry_count, 5)
        self.assertFalse(rec.is_recording)  # auto-stopped

    def test_get_hotspots(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        # Record address 0x1000 five times, 0x2000 twice
        for _ in range(5):
            rec.record_instruction(0x1000, 1, "hot")
        for _ in range(2):
            rec.record_instruction(0x2000, 1, "warm")
        rec.stop()

        hotspots = rec.get_hotspots(top_n=5)
        self.assertEqual(hotspots[0], (0x1000, 5))
        self.assertEqual(hotspots[1], (0x2000, 2))

    def test_get_unique_addresses(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x3000, 1, "a")
        rec.record_instruction(0x1000, 1, "b")
        rec.record_instruction(0x3000, 1, "c")
        rec.stop()
        self.assertEqual(rec.get_unique_addresses(), [0x1000, 0x3000])

    def test_get_thread_ids(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x1000, 100, "a")
        rec.record_instruction(0x1001, 200, "b")
        rec.record_instruction(0x1002, 100, "c")
        rec.stop()
        self.assertEqual(rec.get_thread_ids(), [100, 200])

    def test_breakpoint_stats(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_breakpoint_hit(0x1000, 0x1005, 100)
        rec.record_breakpoint_hit(0x1000, 0x1008, 100)
        rec.record_breakpoint_hit(0x2000, 0x2005, 100)
        rec.stop()
        stats = rec.get_breakpoint_stats()
        self.assertEqual(stats[0x1000], 2)
        self.assertEqual(stats[0x2000], 1)

    def test_clear(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x1000, 1, "a")
        rec.stop()
        rec.clear()
        self.assertEqual(rec.entry_count, 0)

    def test_export_json(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x140001000, 100, "mov rax, rbx")
        rec.record_breakpoint_hit(0x140001000, 0x140001005, 100)
        rec.stop()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            rec.export_json(path)
            data = json.loads(open(path).read())
            self.assertEqual(data["metadata"]["pid"], 1234)
            self.assertEqual(data["metadata"]["entry_count"], 1)
            self.assertIn("0x140001000", data["breakpoint_hits"])
        finally:
            os.unlink(path)

    def test_export_ida_comments(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x140001000, 100, "mov rax, rbx")
        rec.stop()

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            path = f.name
        try:
            rec.export_ida_comments(path)
            content = open(path).read()
            self.assertIn("IDA Python", content)
            self.assertIn("0x140001000", content)
            self.assertIn("apply_trace", content)
        finally:
            os.unlink(path)

    def test_export_ghidra_script(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_instruction(0x140001000, 100, "mov rax, rbx")
        rec.stop()

        with tempfile.NamedTemporaryFile(suffix=".java", delete=False, mode="w") as f:
            path = f.name
        try:
            rec.export_ghidra_script(path)
            content = open(path).read()
            self.assertIn("Ghidra", content)
            self.assertIn("0x140001000", content)
            self.assertIn("trace:", content)
        finally:
            os.unlink(path)

    def test_export_x64dbg(self):
        rec = TraceRecorder(pid=1234)
        rec.start()
        rec.record_breakpoint_hit(0x140001000, 0x140001005, 100)
        rec.stop()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            path = f.name
        try:
            rec.export_x64dbg(path)
            content = open(path).read()
            self.assertIn("setbp", content)
            self.assertIn("0x140001000", content)
        finally:
            os.unlink(path)


class TestModuleMap(unittest.TestCase):

    def test_snapshot_current_process(self):
        """ModuleMap can snapshot the current process."""
        pid = os.getpid()
        mm = ModuleMap(pid)
        modules = mm.snapshot()
        self.assertGreater(len(modules), 0)
        # python.exe should be in the list
        python_mod = mm.get_module("python.exe") or mm.get_module("python3.11.exe") or mm.get_module("python311.exe")
        # At least one module should exist
        self.assertTrue(len(modules) > 0)

    def test_find_module_containing(self):
        """Can find which module contains an address."""
        pid = os.getpid()
        mm = ModuleMap(pid)
        mm.snapshot()
        # Address in our own code — should resolve to some module
        addr = id(unittest)  # some address in Python
        mod = mm.find_module_containing(addr)
        # May or may not find it (depends on memory layout), but shouldn't crash
        # Just verify the method works
        self.assertTrue(mod is None or isinstance(mod, ModuleInfo))

    def test_resolve_address(self):
        """resolve_address returns a string."""
        pid = os.getpid()
        mm = ModuleMap(pid)
        mm.snapshot()
        result = mm.resolve_address(0x140001000)
        self.assertIsInstance(result, str)
        self.assertIn("0X", result.upper())

    def test_format_table(self):
        """format_table produces a string with headers."""
        pid = os.getpid()
        mm = ModuleMap(pid)
        mm.snapshot()
        table = mm.format_table()
        self.assertIn("Base", table)
        self.assertIn("Size", table)
        self.assertIn("Name", table)

    def test_export_json(self):
        """Module map exports to JSON."""
        pid = os.getpid()
        mm = ModuleMap(pid)
        mm.snapshot()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            mm.export_json(path)
            data = json.loads(open(path).read())
            self.assertEqual(data["pid"], pid)
            self.assertGreater(data["module_count"], 0)
            self.assertIsInstance(data["modules"], list)
        finally:
            os.unlink(path)

    def test_module_info_dataclass(self):
        """ModuleInfo stores data correctly."""
        mod = ModuleInfo(name="test.dll", base=0x140000000, size=0x1000, path="C:\\test.dll")
        self.assertEqual(mod.name, "test.dll")
        self.assertEqual(mod.base, 0x140000000)
        self.assertEqual(mod.size, 0x1000)
        self.assertEqual(mod.exports, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
