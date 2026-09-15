"""
tests/test_velocity_connector.py — unit tests for velocity_connector.py
Tests pipe name generation and Lua encoding.
"""

import base64
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from velocity_connector import (
    PipeConnection,
    PipeManager,
)


class TestPipeConnection(unittest.TestCase):
    """Test pipe connection basics."""

    def test_pipe_name_format(self):
        """Pipe name should follow Velocity format."""
        conn = PipeConnection(1234)
        self.assertIn("uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_1234", conn.pipe_name)

    def test_custom_pipe_suffix(self):
        """Custom pipe suffix should work."""
        conn = PipeConnection(1234, pipe_suffix="my_custom_pipe")
        self.assertIn("my_custom_pipe", conn.pipe_name)

    def test_lua_encoding(self):
        """Lua script should be Base64 encoded."""
        script = "print('hello')"
        encoded = base64.b64encode(script.encode('utf-8'))
        decoded = base64.b64decode(encoded).decode('utf-8')
        self.assertEqual(decoded, script)

    def test_pipe_name_with_pid(self):
        """Pipe name should include PID."""
        pid = 5678
        conn = PipeConnection(pid)
        self.assertIn(str(pid), conn.pipe_name)

    def test_pipe_manager(self):
        """Pipe manager should manage multiple connections."""
        manager = PipeManager()
        self.assertIsNotNone(manager.get_connection(1234))
        self.assertIsNotNone(manager.get_connection(5678))
        # Should be separate connections
        c1 = manager.get_connection(1234)
        c2 = manager.get_connection(5678)
        self.assertNotEqual(c1.pid, c2.pid)


if __name__ == '__main__':
    unittest.main(verbosity=2)
