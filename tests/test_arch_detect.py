"""
tests/test_arch_detect.py — unit tests for arch_detect.py
Tests process architecture detection.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arch_detect


class TestArchDetect(unittest.TestCase):

    def test_is_64bit_os(self):
        result = arch_detect.is_64bit_os()
        self.assertIsInstance(result, bool)

    def test_get_injector_arch(self):
        arch = arch_detect.get_injector_arch()
        self.assertIn(arch, ('x64', 'x86'))

    def test_is_wow64_current_process(self):
        """Current process WOW64 status should be detectable."""
        import os
        pid = os.getpid()
        result = arch_detect.is_wow64_process(pid)
        # On 64-bit Python, this should be False
        # On 32-bit Python on 64-bit OS, this would be True
        self.assertIsInstance(result, bool)

    def test_get_process_arch_current(self):
        """Current process architecture should be detectable."""
        import os
        pid = os.getpid()
        arch = arch_detect.get_process_arch(pid)
        self.assertIn(arch, ('x64', 'x86'))

    def test_can_inject_same_arch(self):
        """Same architecture should always work."""
        injector = arch_detect.get_injector_arch()
        can, method, note = arch_detect.can_inject(injector)
        self.assertTrue(can)
        self.assertEqual(method, "native")

    def test_can_inject_64_to_32(self):
        """64-bit injector to 32-bit target should be possible."""
        can, method, note = arch_detect.can_inject('x86')
        # Result depends on injector arch
        injector = arch_detect.get_injector_arch()
        if injector == 'x64':
            self.assertTrue(can)
        else:
            self.assertTrue(can)  # 32→32 is native

    def test_can_inject_32_to_64(self):
        """32-bit injector to 64-bit target should fail."""
        can, method, note = arch_detect.can_inject('x64')
        injector = arch_detect.get_injector_arch()
        if injector == 'x86':
            self.assertFalse(can)


if __name__ == '__main__':
    unittest.main(verbosity=2)
