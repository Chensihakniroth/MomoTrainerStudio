"""
tests/test_dll_compiler.py — unit tests for dll_compiler.py
Tests DLL source generation, feature conversion, and compilation.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dll_compiler import (
    DLLCompiler,
    DLLInjector,
    cheat_table_to_features,
    _get_type_info,
    TYPE_MAP,
    DLL_TEMPLATE,
)


class TestGetTypeInfo(unittest.TestCase):
    """Test type mapping."""

    def test_int32(self):
        code, field = _get_type_info("int32")
        self.assertEqual(code, 0)
        self.assertEqual(field, "int32_val")

    def test_float(self):
        code, field = _get_type_info("float")
        self.assertEqual(code, 2)
        self.assertEqual(field, "float_val")

    def test_double(self):
        code, field = _get_type_info("double")
        self.assertEqual(code, 4)
        self.assertEqual(field, "double_val")

    def test_unknown_defaults(self):
        code, field = _get_type_info("unknown_type")
        self.assertEqual(code, 0)
        self.assertEqual(field, "int32_val")


class TestDLLCompiler(unittest.TestCase):
    """Test DLL source generation."""

    def test_generate_basic(self):
        comp = DLLCompiler()
        features = [
            {'name': 'HP', 'address': 0x140001000, 'vtype': 'float', 'value': 9999.0, 'mode': 'freeze'},
        ]
        source = comp.generate_source(features, "TestDLL")
        self.assertIn("TestDLL", source)
        self.assertIn("DllMain", source)
        self.assertIn("HP", source)
        self.assertIn("9999", source)

    def test_generate_multiple_features(self):
        comp = DLLCompiler()
        features = [
            {'name': 'HP', 'address': 0x140001000, 'vtype': 'float', 'value': 100.0, 'mode': 'freeze'},
            {'name': 'Ammo', 'address': 0x140001004, 'vtype': 'int32', 'value': 999, 'mode': 'freeze'},
            {'name': 'Speed', 'address': 0x140001008, 'vtype': 'float', 'value': 2.0, 'mode': 'freeze', 'hotkey': 0x70},
        ]
        source = comp.generate_source(features, "MultiDLL")
        self.assertIn("HP", source)
        self.assertIn("Ammo", source)
        self.assertIn("Speed", source)

    def test_generate_empty_features(self):
        comp = DLLCompiler()
        source = comp.generate_source([], "EmptyDLL")
        self.assertIn("DllMain", source)

    def test_set_source(self):
        comp = DLLCompiler()
        features = [{'name': 'Test', 'address': 0x1000, 'vtype': 'int32', 'value': 42, 'mode': 'freeze'}]
        source = comp.generate_source(features)

        with tempfile.NamedTemporaryFile(suffix=".cpp", delete=False, mode="w") as f:
            path = f.name
        try:
            comp.save_source(source, path)
            content = open(path).read()
            self.assertIn("DllMain", content)
        finally:
            os.unlink(path)

    def test_get_source(self):
        comp = DLLCompiler()
        features = [{'name': 'Test', 'address': 0x1000, 'vtype': 'int32', 'value': 42, 'mode': 'freeze'}]
        comp.generate_source(features)
        self.assertIn("DllMain", comp.get_source())

    def test_template_has_required_elements(self):
        self.assertIn("DllMain", DLL_TEMPLATE)
        self.assertIn("WriteProcessMemory", DLL_TEMPLATE)
        self.assertIn("g_features", DLL_TEMPLATE)


class TestCheatTableToFeatures(unittest.TestCase):
    """Test conversion from cheat table to DLL features."""

    def test_basic_conversion(self):
        entries = [
            {'addr': 0x140001000, 'vtype': 'float', 'description': 'HP', 'frozen': True},
            {'addr': 0x140001004, 'vtype': 'int32', 'description': 'Ammo', 'frozen': False, 'value': 100},
        ]
        features = cheat_table_to_features(entries)
        self.assertEqual(len(features), 2)
        self.assertEqual(features[0]['mode'], 'freeze')
        self.assertEqual(features[1]['mode'], 'set')

    def test_empty(self):
        features = cheat_table_to_features([])
        self.assertEqual(len(features), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
