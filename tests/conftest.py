"""
tests/conftest.py — make the repo root importable for every test.

The suites import project modules (`memory_core`, `memory_core_panel`,
`trainer_compiler`, ...) that live at the repo root, and several spawn
`DummyGame.py` as a child process. Both only worked when pytest was
invoked from the repo root; running it from inside `tests/` failed with
ModuleNotFoundError. Putting the root on sys.path here makes the suite
runnable from any directory.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
