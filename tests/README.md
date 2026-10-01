# Tests

MomoTrainer Studio test suites.

## Layout

```
tests/
├── conftest.py            puts the repo root on sys.path
├── test_*.py              real suites (21)
└── probes/                one-off diagnostics from the injection work (19)
```

Two kinds of test live here, and they run differently:

- **pytest suites** — `test_*.py` with `test_*` functions. Run them all with
  `python -m pytest tests/ -q` (185 tests, ~4s). Works from any directory.
- **standalone scripts** — `test_memory_core.py`, `test_memory_core_gui.py`,
  `test_shared_handle.py`, `test_instance_picker.py`,
  `test_studio_integration.py`. These have a `main()` and a `__main__`
  guard, spawn a real `DummyGame.py` target, and print per-check
  `[PASS]`/`[FAIL]` lines. Run one directly:
  `python tests/test_memory_core.py`.

Do **not** run a standalone script through pytest — it has no test
functions, so pytest collects nothing and reports a vacuous pass.

## Cross-process suites need a real target

The five standalone suites each copy the interpreter to a uniquely-named
exe and run `DummyGame.py` under it, so attach-by-exe-name is
unambiguous. Two consequences:

- **Run them one at a time.** They bind fixed exe names; two concurrent
  runs attach to each other's targets and fail confusingly.
- A crashed run leaves the copied exe locked. Clear it with
  `python <skills>/scripts/find_exe_holders.py "tests/MomoPickTarget.exe" --kill`
  or just delete `tests/Momo*Target.exe`.

The copied interpreter is a **launcher shim**: it keeps the exe name and
spawns the real interpreter as a child. Name-based lookups resolve to the
shim, but the test allocations live in the child PID the target prints.
Reading a Player address through the shim fails with error 299 — that is
correct Win32 behaviour, not a bug. The suites keep both PIDs: assertions
about name resolution use the shim PID, reads/writes use the printed one.

## Probes

`probes/` is not a test suite. These are single-purpose diagnostic scripts
kept for reference — one-off pipe enumeration attempts, IAT checks,
injection traces. Several spawn processes or `sys.exit()` at import time,
so `pytest.ini` sets `norecursedirs = probes`; collecting them crashes
pytest with an INTERNALERROR. Run one by hand if you need to:

```bash
python tests/probes/test_diagnose.py
```

If a probe has outlived its purpose, delete it — they are throwaway by
nature and nothing imports them.
