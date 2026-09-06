# CE-Inspired Improvements — Implementation Plan

> Source: cheat-engine/cheat-engine (memscan.pas 8964 lines, pointerscanworker.pas 927 lines,
> pointerscancontroller.pas 5537 lines, simpleaobscanner.pas 149 lines)
> Target: MomoTrainerStudio `memory_scanner.py` (732 lines) + `trainer_compiler.py` (316 lines)

---

## Phase 1 — Quick Wins (1–2 hours each, no architecture change)

### 1.1 `fsmLastDigits` fast-scan alignment
- **CE**: `fastscanmethod=fsmLastDigits` + `fastscandigitcount` — scans only addresses ending in N hex digits (e.g. `F00`)
- **Add to**: `memory_scanner.py` `first_scan()` / `rescan()` param `fast_scan_digits=None`
- **Logic**: `stepsize = 16**digits`, `p += fastscanalignsize` then `inc(p, stepsize)` per CE line 3890
- **Impact**: ~10–40× fewer addresses for wildcard-heavy scans

### 1.2 Dispatch-table comparator (replace if/elif chain)
- **CE**: `CheckRoutine: TCheckRoutine` function pointer set once in `configurescanroutine` (line 4564), called in hot loop (line 3970)
- **Add to**: `memory_scanner.py` — `COMPARATORS[(vtype, mode)]` dict mapping to typed functions
- **Impact**: cleaner code, ~5–10% faster inner loop (no branch mispredict)

### 1.3 `noLoop` pointer-scan loop prevention
- **CE**: `noLoop` flag in `TPointerscanWorker` — checks visited set per path to avoid circular references
- **Add to**: `memory_scanner.py` `pointer_scan()` — track `seen_addresses` per path
- **Impact**: eliminates infinite loops on recursive pointers

### 1.4 `useHeapData` heap-only pointer filtering
- **CE**: `useHeapData` / `useOnlyHeapData` — uses `HeapBaseLevel` from `frmMemoryAllocHandler` to restrict pointer results to heap regions
- **Add to**: `memory_scanner.py` `pointer_scan()` — call `VirtualQueryEx` once to build heap region list, filter results
- **Impact**: removes false positives from code/data sections

### 1.5 Percentage scan modes
- **CE**: `ByteIncreasedValueByPercentage`, `ByteDecreasedValueByPercentage`, `FloatIncreasedValueByPercentage`, etc.
- **Add to**: `memory_scanner.py` — new modes `increased_pct`, `decreased_pct` with `svalue`/`svalue2` params
- **Impact**: CE's killer feature for float scanning — find values that grew/shrank by a percentage

---

## Phase 2 — Architecture (1–2 days)

### 2.1 `Scanner` class (wrap `memory_scanner.py`)
- **CE**: `TScanner` class — all scan state in one object, `CheckRoutine` set at config time
- **Structure**:
  ```python
  class Scanner:
      def __init__(self, handle, nthreads=None):
          self.handle = handle
          self.nthreads = nthreads or os.cpu_count()
          self.checkroutine = None
          self.variable_type = None
          self.scan_type = None  # stFirstScan / stNextScan
          self.fastscan_method = None
          self.value = 0
          self.value2 = 0
  ```
- **Methods**: `configure(vtype, mode, scan_options)`, `first_scan(start, stop, progress_cb, stop_cb)`, `rescan(candidates, ...)`
- **Migration**: `first_scan()` and `rescan()` become instance methods; module-level functions become thin wrappers

### 2.2 `FoundList` class (replace raw SQLite)
- **CE**: `TFoundList` — `Initialize(vartype)`, `GetAddress(i)`, `GetValue(i)`, `Deinitialize()`
- **Structure**: wraps SQLite but provides `add(address, value)`, `get(index)`, `count`, `filter(predicate)`
- **Benefit**: decouples result storage from scan logic; enables disk-backed mode later

### 2.3 Disk-backed results (temp files per thread)
- **CE**: `AddressFile` + `MemoryFile` per thread (`ADDRESSES-<tid>.TMP`, `Memory-<tid>.TMP`)
- **Add to**: `FoundList` — when `count > threshold` (e.g. 100K), spill to temp file instead of SQLite
- **Benefit**: avoids GIL contention on DB writes (current known PITFALL: `Queue.put` → GIL contention)

### 2.4 `TScanType` enum (replace string modes)
- **CE**: `TScanType = (stNewScan=0, stFirstScan=1, stNextScan=2)`
- **Add to**: `memory_scanner.py` — `ScanType.FIRST / ScanType.NEXT / ScanType.NEW` enum constants
- **Benefit**: type safety, no string typos

---

## Phase 3 — Full Pointer Scan Rewrite (3–5 days)

### 3.1 `PointerScanWorker` thread
- **CE**: `TPointerscanWorker = class(TThread)` — `rscan(valuetofind, level)`, path queue with semaphore
- **Structure**:
  ```python
  class PointerScanWorker(threading.Thread):
      def __init__(self, handle, path_queue, result_queue, max_depth, ...):
          self.path_queue = path_queue  # queue.Queue with semaphore
          self.result_queue = result_queue
          self.max_depth = max_depth
          self.no_loop = True
          self.use_heap = False
          self.heap_regions = []  # built once from VirtualQueryEx
  ```
- **Core**: `rscan(target_addr, level)` — read memory at `target_addr`, find all pointers pointing to it, recurse

### 3.2 `PointerScanController`
- **CE**: `TPointerscanController` — 5537 lines managing queue, workers, result merging, resume, network distribute
- **Subset to implement**:
  - `start(target, max_depth, max_offset)` — spawn workers, feed path queue
  - `wait()` — block until done
  - `get_results()` — merged, deduplicated pointer paths
  - `save(path)` / `load(path)` — resume support
  - `merge(other_results)` — combine partial scans

### 3.3 Path queue with semaphore coordination
- **CE**: `pathqueuesemaphore: THandle`, `pathqueueCS: TCriticalSection`, `MAXQUEUESIZE=64`
- **Python**: `queue.Queue(maxsize=64)` + `threading.Semaphore` for backpressure

---

## Phase 4 — Advanced Features (2–3 days, optional)

### 4.1 Lua formula scan
- **CE**: `ByteLuaFormula` — pushes value + old_value to Lua stack, calls user Lua function
- **Approach**: embed Lua interpreter (lupa/lua) or accept Python lambda as formula
- **Risk**: security — only evaluate trusted formulas

### 4.2 `vtAll` (scan all types at once)
- **CE**: `variableType=vtAll` sets `typematch[]` bitmask per address, checks all types in one pass
- **Add to**: `first_scan()` — single pass that records which types match at each address

### 4.3 Case-sensitive string scan
- **CE**: `CaseSensitiveAnsiStringExact` / `CaseSensitiveUnicodeStringExact`
- **Add to**: `memory_scanner.py` string scan with `case_sensitive=True` param

### 4.4 Custom type support
- **CE**: `customType: TCustomType` — user-defined byte size + conversion + comparison
- **Add to**: `Scanner.configure()` — accept custom struct format string (like `struct.pack`)

---

## Verification Plan

| Step | Command | Expected |
|------|---------|----------|
| 1. Syntax check | `python -m py_compile memory_scanner.py` | No errors |
| 2. Unit test Phase 1 | `python -m pytest tests/test_scanner.py -k phase1` | All pass |
| 3. Build test | `python trainer_compiler.py trainers/test_trainer.yaml --build` | `.exe` produced |
| 4. Pointer scan smoke test | `python -c "from memory_scanner import pointer_scan; ..."` | No crash, returns dict |
| 5. End-to-end | Full scan → compile → run `.exe` against target | Values correct |

---

## Dependencies

| Feature | New Dependency |
|---------|---------------|
| Lua formula (4.1) | `lupa` or `aiolua` |
| Disk-backed results (2.3) | None (tempfile + mmap) |
| Pointer scan (3.x) | None (pure ctypes + threading) |

---

## Estimated Effort

| Phase | Time | Risk |
|-------|------|------|
| 1. Quick Wins | 5–8 hours | Low |
| 2. Architecture | 1–2 days | Medium (refactor risk) |
| 3. Pointer Scan | 3–5 days | High (complex recursion + threading) |
| 4. Advanced | 2–3 days | Medium |
| **Total** | **1–2 weeks** | |

---

*Plan created 2026-09-06. CE source verified via GitHub API (raw content fetched and analyzed).*
