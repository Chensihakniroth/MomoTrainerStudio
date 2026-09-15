"""
tests/test_pro_gui.py — unit tests for pro_gui.py
Tests CT importer, signature database, session dialogs.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pro_gui import (
    CTFileImporter,
    SignatureDatabase,
)


class TestCTFileImporter(unittest.TestCase):
    """Test Cheat Engine CT file parsing."""

    def test_parse_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".ct", delete=False, mode="w") as f:
            f.write("")
            path = f.name
        try:
            entries = CTFileImporter.parse_ct_file(path)
            self.assertEqual(len(entries), 0)
        finally:
            os.unlink(path)

    def test_parse_simple_ct(self):
        ct_content = """<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>1</ID>
      <Description>"HP"</Description>
      <Type>2</Type>
      <Address>0x140001000</Address>
    </CheatEntry>
    <CheatEntry>
      <ID>2</ID>
      <Description>"Mana"</Description>
      <Type>2</Type>
      <Address>0x140001004</Address>
    </CheatEntry>
  </CheatEntries>
</CheatTable>"""
        with tempfile.NamedTemporaryFile(suffix=".ct", delete=False, mode="w") as f:
            f.write(ct_content)
            path = f.name
        try:
            entries = CTFileImporter.parse_ct_file(path)
            self.assertGreater(len(entries), 0)
        finally:
            os.unlink(path)

    def test_parse_invalid_path(self):
        entries = CTFileImporter.parse_ct_file("/nonexistent/file.ct")
        self.assertEqual(len(entries), 0)


class TestSignatureDatabase(unittest.TestCase):
    """Test signature database operations."""

    def test_add_and_get(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            db = SignatureDatabase(path)
            db.add_signature("Game.exe", "HP", "48 8B 05 ?? ?? ?? ??", 0, "Health pointer")
            sigs = db.get_signatures("Game.exe")
            self.assertEqual(len(sigs), 1)
            self.assertEqual(sigs[0]["name"], "HP")
        finally:
            os.unlink(path)

    def test_get_games(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            db = SignatureDatabase(path)
            db.add_signature("Game1.exe", "test", "90 90")
            db.add_signature("Game2.exe", "test", "CC CC")
            games = db.get_games()
            self.assertIn("Game1.exe", games)
            self.assertIn("Game2.exe", games)
        finally:
            os.unlink(path)

    def test_search(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            db = SignatureDatabase(path)
            db.add_signature("Game.exe", "Health", "48 8B", 0, "HP pointer")
            db.add_signature("Game.exe", "Mana", "48 89", 0, "MP pointer")
            results = db.search("health")
            self.assertIn("Game.exe", results)
        finally:
            os.unlink(path)

    def test_delete(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            db = SignatureDatabase(path)
            db.add_signature("Game.exe", "test", "90")
            self.assertEqual(len(db.get_signatures("Game.exe")), 1)
            db.delete_signature("Game.exe", 0)
            self.assertEqual(len(db.get_signatures("Game.exe")), 0)
        finally:
            os.unlink(path)

    def test_persistence(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            db1 = SignatureDatabase(path)
            db1.add_signature("Game.exe", "test", "90 90", 0, "test sig")

            # Reopen and verify
            db2 = SignatureDatabase(path)
            sigs = db2.get_signatures("Game.exe")
            self.assertEqual(len(sigs), 1)
            self.assertEqual(sigs[0]["pattern"], "90 90")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
