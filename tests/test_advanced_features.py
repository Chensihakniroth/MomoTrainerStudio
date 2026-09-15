"""
tests/test_advanced_features.py — unit tests for advanced_features.py
Tests Lua engine, script recorder, speedhack, structure dissect logic, pointer map.
"""

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from advanced_features import (
    LuaScriptEngine,
    ScriptRecorder,
    Speedhack,
    PointerMap,
    StructureDissect,
    AutoAssembler,
    ScanSession,
    PluginManager,
)
from debugger_toolkit import BreakCondition
from pro_tools import format_value


class TestBreakCondition(unittest.TestCase):
    """Test conditional breakpoint logic."""

    def test_reg_equal(self):
        cond = BreakCondition("reg_equal", register="RAX", value=0x1234)
        self.assertTrue(cond.evaluate({"RAX": 0x1234}))
        self.assertFalse(cond.evaluate({"RAX": 0x5678}))

    def test_reg_greater(self):
        cond = BreakCondition("reg_greater", register="RDX", value=100)
        self.assertTrue(cond.evaluate({"RDX": 200}))
        self.assertFalse(cond.evaluate({"RDX": 50}))

    def test_hit_count(self):
        cond = BreakCondition("hit_count", hit_target=3)
        self.assertFalse(cond.evaluate({}))
        self.assertFalse(cond.evaluate({}))
        self.assertTrue(cond.evaluate({}))
        self.assertTrue(cond.evaluate({}))

    def test_describe(self):
        cond = BreakCondition("reg_equal", register="RBX", value=42)
        self.assertIn("RBX", cond.describe())
        self.assertIn("2A", cond.describe())  # 42 in hex


class TestLuaScriptEngine(unittest.TestCase):
    """Test the scripting engine."""

    def test_load_script(self):
        class MockAPI:
            pass

        engine = LuaScriptEngine(MockAPI())
        engine.register_script("test", "x = 1 + 2")
        self.assertGreater(len(engine.get_log()), 0)

    def test_event_handlers(self):
        class MockAPI:
            pass

        engine = LuaScriptEngine(MockAPI())
        called = []

        def on_scan(results):
            called.append(results)

        engine._handlers["onScanComplete"].append(on_scan)
        engine.fire_event("onScanComplete", [1, 2, 3])
        self.assertEqual(called, [[1, 2, 3]])

    def test_log(self):
        engine = LuaScriptEngine(None)
        engine._log_msg("test message")
        self.assertIn("test message", engine.get_log()[-1])

    def test_clear_log(self):
        engine = LuaScriptEngine(None)
        engine._log_msg("msg1")
        engine._log_msg("msg2")
        engine.clear_log()
        self.assertEqual(len(engine.get_log()), 0)


class TestScriptRecorder(unittest.TestCase):
    """Test script recording."""

    def test_record_actions(self):
        rec = ScriptRecorder()
        rec.start()
        rec.record_scan(100, "int32", "exact")
        rec.record_add_address(0x140001000, "int32", "HP")
        rec.record_freeze(0x140001000, True)
        rec.record_write(0x140001000, 9999, "int32")
        rec.stop()

        script = rec.get_script()
        self.assertIn("api.scan", script)
        self.assertIn("0x140001000", script)
        self.assertIn("api.toggle_freeze", script)

    def test_not_recording(self):
        rec = ScriptRecorder()
        rec.record_scan(100, "int32", "exact")
        self.assertEqual(len(rec.get_script()), 0)

    def test_export(self):
        rec = ScriptRecorder()
        rec.start()
        rec.record_scan(42, "int32", "exact")
        rec.stop()

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            path = f.name
        try:
            rec.export(path)
            content = open(path).read()
            self.assertIn("Recorded", content)
            self.assertIn("42", content)
        finally:
            os.unlink(path)


class TestSpeedhack(unittest.TestCase):
    """Test speedhack state management."""

    def test_set_speed(self):
        sh = Speedhack(1234)
        sh.set_speed(2.5)
        self.assertEqual(sh.speed, 2.5)

    def test_speed_clamps(self):
        sh = Speedhack(1234)
        sh.set_speed(0.01)
        self.assertEqual(sh.speed, 0.1)  # min clamp
        sh.set_speed(100)
        self.assertEqual(sh.speed, 10.0)  # max clamp

    def test_enable_disable(self):
        sh = Speedhack(1234)
        sh.enable()
        self.assertTrue(sh.active)
        sh.disable()
        self.assertFalse(sh.active)

    def test_toggle(self):
        sh = Speedhack(1234)
        result = sh.toggle()
        self.assertTrue(result)
        result = sh.toggle()
        self.assertFalse(result)

    def test_status(self):
        sh = Speedhack(1234)
        self.assertIn("OFF", sh.get_status())
        sh.enable()
        self.assertIn("ON", sh.get_status())


class TestPointerMap(unittest.TestCase):
    """Test pointer map graph operations."""

    def test_empty_graph(self):
        pm = PointerMap(1234)
        self.assertEqual(len(pm.get_graph()), 0)
        stats = pm.get_stats()
        self.assertEqual(stats["total_pointers"], 0)

    def test_add_pointers(self):
        pm = PointerMap(1234)
        # Manually add some pointers
        pm._graph[0x1000] = [0x2000, 0x3000]
        pm._graph[0x2000] = [0x4000]

        self.assertEqual(len(pm.get_sources(0x1000)), 2)
        self.assertEqual(len(pm.get_sources(0x2000)), 1)
        self.assertEqual(len(pm.get_targets()), 2)

    def test_get_stats(self):
        pm = PointerMap(1234)
        pm._graph[0x1000] = [0x2000, 0x3000, 0x4000]
        pm._graph[0x2000] = [0x5000]

        stats = pm.get_stats()
        self.assertEqual(stats["total_pointers"], 4)
        self.assertEqual(stats["unique_targets"], 2)
        self.assertEqual(stats["most_pointed"]["sources"], 3)

    def test_export_json(self):
        pm = PointerMap(1234)
        pm._graph[0x1000] = [0x2000]
        pm._scanned = True

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            pm.export_json(path)
            data = json.loads(open(path).read())
            self.assertIn("stats", data)
            self.assertIn("pointers", data)
        finally:
            os.unlink(path)

    def test_export_dot(self):
        pm = PointerMap(1234)
        pm._graph[0x1000] = [0x2000]
        pm._scanned = True

        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False, mode="w") as f:
            path = f.name
        try:
            pm.export_dot(path)
            content = open(path).read()
            self.assertIn("digraph", content)
            self.assertIn("->", content)
        finally:
            os.unlink(path)


class TestScanSession(unittest.TestCase):
    """Test scan session persistence."""

    def test_save(self):
        class MockApp:
            def __init__(self):
                self.pid = 1234
                self.exe_name = "test.exe"
                self.candidates = []
                self.addresses = [{"addr": 0x140001000, "vtype": "int32", "description": "HP", "frozen": False}]

        session = ScanSession(MockApp())

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            session.save(path)
            data = json.loads(open(path).read())
            self.assertEqual(data["pid"], 1234)
            self.assertEqual(len(data["addresses"]), 1)
            self.assertEqual(data["addresses"][0]["description"], "HP")
        finally:
            os.unlink(path)


class TestPluginManager(unittest.TestCase):
    """Test plugin discovery and loading."""

    def test_discover_empty(self):
        pm = PluginManager("/nonexistent_dir")
        self.assertEqual(len(pm.discover()), 0)

    def test_discover_with_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a dummy plugin
            Path(tmpdir, "test_plugin.py").write_text("# test plugin\ndef register(api): pass\n")
            pm = PluginManager(tmpdir)
            plugins = pm.discover()
            self.assertIn("test_plugin", plugins)

    def test_load_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "my_plugin.py").write_text(
                "def register(api):\n    api._test_loaded = True\n"
            )
            pm = PluginManager(tmpdir)

            class MockAPI:
                pass

            api = MockAPI()
            result = pm.load("my_plugin", api)
            self.assertTrue(result)
            self.assertTrue(getattr(api, "_test_loaded", False))

    def test_unload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "temp_plugin.py").write_text("def register(api): pass\n")
            pm = PluginManager(tmpdir)
            pm.load("temp_plugin")
            self.assertIn("temp_plugin", pm.get_loaded())
            pm.unload("temp_plugin")
            self.assertNotIn("temp_plugin", pm.get_loaded())


class TestFormatValue(unittest.TestCase):
    """Test value formatting."""

    def test_hex_format(self):
        raw = struct.pack('<I', 0xDEADBEEF)
        result = format_value(raw, "uint32", "Hex")
        self.assertIn("DEADBEEF", result)

    def test_decimal_format(self):
        raw = struct.pack('<i', -42)
        result = format_value(raw, "int32", "Decimal")
        self.assertEqual(result, "-42")


if __name__ == "__main__":
    unittest.main(verbosity=2)
