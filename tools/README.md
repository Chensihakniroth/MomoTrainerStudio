# tools/

Development and build helpers. Nothing in the shipped app imports these —
they are run by hand.

## Build / verification

| Script | What it does |
|---|---|
| `verify_build.py` | Confirms the built exe really contains a working `memory_core` — extracts `PYZ.pyz` from `dist/MoStudio - beta.exe` and execs the engine's self-test out of it. Run after **every** build; `Build complete!` does not mean the module shipped. Override the target with `MOMOSTUDIO_EXE=/path/to.exe`. |
| `make_momotrainer_icon.py` | Regenerates `assets/momotrainer_icon.ico` / `.png` (1024px source). |
| `make_gui_icons.py` | Regenerates the toolbar icons in `assets/icons/`. |

Both icon generators resolve `assets/` from the repo root, so they work
from any directory.

## Profilers (`memory_scanner`)

Kept from the v4 scanner performance work. They measure where scan time
actually goes, which is why `memory_scanner.py` is shaped the way it is.

| Script | What it measures |
|---|---|
| `bench.py` | `first_scan` vs the CE-style ceiling: pages read, bytes scanned, MB/s, per-thread timing. |
| `bench_c_vs_python.py` | The C `scan_engine.dll` path vs the Python path. |
| `bench_realistic.py` | Throughput against realistic page distributions. |
| `bench_where_time_goes.py` | Where the time is spent inside a scan. |
| `breakdown.py` / `breakdown2.py` | Per-stage timing breakdowns. |
| `instrument.py` | Fine-grained instrumentation. |

## Reverse engineering

| Script | What it does |
|---|---|
| `check_jx2.py` | Probe a running JX2 process. |
| `find_callers.py` | Locate callers of a function by signature. |
| `find_hp_function.py` | Locate the HP update routine. |
| `universal_scanner.py` | IAT-hook pointer/value scanner for any process. Superseded by `memory_scanner.py`; kept for reference. |

## One-shot

| Script | Note |
|---|---|
| `patch_studio_gui.py` | A one-time in-place patcher that has **already been applied** to `studio_gui.py`. Do not re-run it — it rewrites the file by regex and will corrupt it. Kept only to show what the narrow-button change was. |
| `verify_numpy_path.py` | Confirms numpy resolves correctly. |

## Running them

These import project modules from the repo root by bare name, so each one
carries a `sys.path` bootstrap — run them from anywhere:

```bash
python tools/bench.py
python tools/verify_build.py
```

`python_backend.py` is **not** here — it is an app module with a real test
(`tests/test_backend_qol.py`), so it lives in the repo root.
