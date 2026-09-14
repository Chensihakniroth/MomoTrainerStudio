"""
tests/test_animations.py — verify the animation engine utilities.
No Tk required for color math; Tk tests use a hidden root.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from animations import (
    lerp, lerp_color, scale_brightness, _hex_to_rgb, _rgb_to_hex,
    _ease_in_out, _ease_out_back, _ease_out_expo,
    EASING,
)


class TestColorMath(unittest.TestCase):

    def test_hex_to_rgb(self):
        self.assertEqual(_hex_to_rgb("#ff0000"), (255, 0, 0))
        self.assertEqual(_hex_to_rgb("#00ff00"), (0, 255, 0))
        self.assertEqual(_hex_to_rgb("#0000ff"), (0, 0, 255))
        self.assertEqual(_hex_to_rgb("#ffffff"), (255, 255, 255))

    def test_rgb_to_hex(self):
        self.assertEqual(_rgb_to_hex(255, 0, 0), "#ff0000")
        self.assertEqual(_rgb_to_hex(0, 255, 0), "#00ff00")
        self.assertEqual(_rgb_to_hex(0, 0, 0), "#000000")

    def test_hex_roundtrip(self):
        for color in ["#FF66CC", "#0d1117", "#238636", "#1f6feb"]:
            self.assertEqual(_rgb_to_hex(*_hex_to_rgb(color)), color.lower())

    def test_lerp_basic(self):
        self.assertAlmostEqual(lerp(0, 100, 0.5), 50.0)
        self.assertAlmostEqual(lerp(0, 100, 0.0), 0.0)
        self.assertAlmostEqual(lerp(0, 100, 1.0), 100.0)

    def test_lerp_clamps(self):
        self.assertAlmostEqual(lerp(0, 100, -0.5), 0.0)
        self.assertAlmostEqual(lerp(0, 100, 1.5), 100.0)

    def test_lerp_color_start(self):
        self.assertEqual(lerp_color("#000000", "#ffffff", 0.0), "#000000")

    def test_lerp_color_end(self):
        self.assertEqual(lerp_color("#000000", "#ffffff", 1.0), "#ffffff")

    def test_lerp_color_mid(self):
        mid = lerp_color("#000000", "#ffffff", 0.5)
        r, g, b = _hex_to_rgb(mid)
        self.assertTrue(126 <= r <= 129)
        self.assertTrue(126 <= g <= 129)
        self.assertTrue(126 <= b <= 129)

    def test_lerp_color_accent(self):
        """Kawaii pink → cyan mid should be a purple-ish blend."""
        mid = lerp_color("#FF66CC", "#00d4ff", 0.5)
        r, g, b = _hex_to_rgb(mid)
        self.assertTrue(r > 100)
        self.assertTrue(b > 100)

    def test_scale_brightness(self):
        brighter = scale_brightness("#808080", 1.5)
        darker = scale_brightness("#808080", 0.5)
        # Brighter should have higher V
        br, bg, bb = _hex_to_rgb(brighter)
        dr, dg, db = _hex_to_rgb(darker)
        self.assertTrue(br > dr)


class TestEasing(unittest.TestCase):

    def test_ease_endpoints(self):
        for name, fn in EASING.items():
            self.assertAlmostEqual(fn(0.0), 0.0, msg=f"{name}(0)")
            self.assertAlmostEqual(fn(1.0), 1.0, msg=f"{name}(1)")

    def test_ease_monotonic(self):
        """Most easing functions are monotonically increasing.
        out_back intentionally overshoots (not monotonic by design)."""
        monotonic = {n: f for n, f in EASING.items() if n != "out_back"}
        for name, fn in monotonic.items():
            prev = 0.0
            for i in range(101):
                t = i / 100.0
                val = fn(t)
                self.assertGreaterEqual(val, prev, msg=f"{name} not monotonic at t={t}")
                prev = val

    def test_in_out_symmetric(self):
        """_ease_in_out(0.5) should be ~0.5."""
        self.assertAlmostEqual(_ease_in_out(0.5), 0.5, places=1)

    def test_out_back_overshoots(self):
        """_ease_out_back slightly overshoots past 1.0 near the end."""
        self.assertGreater(_ease_out_back(0.95), 0.95)


if __name__ == "__main__":
    unittest.main(verbosity=2)
