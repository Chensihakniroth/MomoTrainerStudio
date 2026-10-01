"""
tests/test_uwp_inject.py — unit tests for uwp_inject.py
Tests UWP detection and package info extraction.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uwp_inject


class TestUWPInject(unittest.TestCase):

    def test_is_uwp_current_process(self):
        """Current process (Python) should NOT be UWP."""
        pid = os.getpid()
        result = uwp_inject.is_uwp_process(pid)
        self.assertFalse(result)

    def test_get_package_full_name_current(self):
        """Current process should have no package identity."""
        pid = os.getpid()
        result = uwp_inject.get_package_full_name(pid)
        self.assertIsNone(result)

    def test_is_appcontainer_current(self):
        """Current process should NOT be AppContainer."""
        pid = os.getpid()
        result = uwp_inject.is_appcontainer_process(pid)
        self.assertFalse(result)

    def test_get_uwp_apps(self):
        """Should return a list of installed UWP apps."""
        apps = uwp_inject.get_uwp_apps()
        self.assertIsInstance(apps, list)
        if apps:
            self.assertIn('package_full_name', apps[0])

    def test_launch_uwp(self):
        """UWP launcher should be instantiable."""
        launcher = uwp_inject.UWPLauncher()
        self.assertIsNotNone(launcher)
        self.assertIsNotNone(launcher)


if __name__ == '__main__':
    unittest.main(verbosity=2)