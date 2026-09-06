# CE Lite Implementation Plan (with MinHook)

> **For Anakot:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build a Cheat Engine-inspired toolkit (scanner + disassembly + debugger + Lua scripting) in Python, with MinHook for function hooking, memory access breakpoints, and API monitoring.

**Architecture:** Python + Tkinter GUI, MinHook x64 DLL for inline hooking, Capstone for disassembly, lupa for Lua, ctypes for Win32 API.

**Tech Stack:** Python 3.11+, Capstone, lupa, MinHook (v1.3.4), ctypes, tkinter, sqlite3

---

## Phase 1: Scanner Hardening (Week 1-2)

**Objective:** Fix the 12 bugs in MomoTrainerStudio and make the scanner CE-comparable.

### Task 1: Fix signed comparison bug (Bug #1)
**Files:** `memory_scanner.py:387-470` (_compare_one, _COMPARATORS)
**Steps:**
1. Read `_compare_one` — confirm `signed=False` in `int.from_bytes`
2. Change to `signed=True` for signed types (int8, int16, int32, int64)
3. Add test: `int8 -50` between `-100` and `0` → True (was False)
4. Verify all signed types: int16, int32, int64 increased/decreased modes
5. Run `python -m py_compile memory_scanner.py`
6. Smoke test: `python -c "from memory_scanner import Scanner; s=Scanner(); assert s._compare_one(-50, -100, 0, 'int8', 'increased')"`

### Task 2: Fix template path bug (Bug #3)
**Files:** `studio_gui.py` (template path)
**Steps:**
1. Find `os.path.abspath('templates/trainer_template.cpp')`
2. Replace with `os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'trainer_template.cpp')`
3. Verify from non-project CWD: `cd /tmp && python D:/game/MomoTrainerStudio/studio_gui.py`
4. Confirm template loads correctly

### Task 3: Fix duplicate addresses bug (Bug #2)
**Files:** `memory_scanner.py` (_add_candidates_to_table, _reset_scan)
**Steps:**
1. Add address dedup check before append in `_add_candidates_to_table`
2. Fix `_reset_scan` to also clear addresses list
3. Test: scan → rescan → verify no duplicate addresses

### Task 4: Add missing scan modes
**Files:** `memory_scanner.py` (SCAN_MODES, _COMPARATORS)
**Steps:**
1. Add `changed`, `unchanged` modes
2. Add `increasedBy`/`decreasedBy` with value parameter
3. Add `percentage` mode for all numeric types
4. Update validation in `first_scan()`
5. Test each mode with known values

### Task 5: Add vtAll scan type
**Files:** `memory_scanner.py` (VTYPES)
**Steps:**
1. Add `VTYPES_ALL` tuple with all 10 numeric types
2. Implement multi-type scan in `_first_scan_worker`
3. Test: scan for value across all types simultaneously

### Task 6: Add float rounding modes
**Files:** `memory_scanner.py` (_COMPARATORS)
**Steps:**
1. Add round-to-nearest, round-to-zero, round-up, round-down
2. Implement in float/double comparators
3. Test each rounding mode with known float values

### Task 7: Add case-sensitive string scan
**Files:** `memory_scanner.py` (string scan worker)
**Steps:**
1. Add `case_sensitive=False` param to `first_scan()`/`rescan()`
2. Worker uses `buf.find(needle)` (sensitive) or `.lower()` compare (insensitive)
3. Test both modes with mixed-case strings

### Task 8: Add saved scan comparison
**Files:** `memory_scanner.py` (result storage)
**Steps:**
1. Implement `compareToSavedScan` — store previous scan results
2. Compare current scan against saved scan
3. Test: scan → save → modify memory → rescan → compare

### Task 9: Add OnlyOne flag
**Files:** `memory_scanner.py` (scan workers)
**Steps:**
1. Add `only_one=False` param to `first_scan()`/`rescan()`
2. Exit early after first match when enabled
3. Test: scan with only_one=True → verify exactly 1 result

### Task 10: Add disk-backed results for >1M candidates
**Files:** `memory_scanner.py` (FoundList)
**Steps:**
1. Implement `_spill_to_disk()` — spill to temp SQLite when count > 100K
2. Per-thread temp files (CE pattern: ADDRESSES-<tid>.TMP)
3. Merge at end of scan
4. Test: simulate >100K hits → verify no OOM

### Task 11: Fix pointer_scan missing function (Bug #2 API mismatch)
**Files:** `memory_scanner.py`
**Steps:**
1. Add standalone `pointer_scan()` function (not just PointerScanController class)
2. Maintain backward compatibility with class-based API
3. Test both APIs

### Task 12: Fix signature parsing token validation (Bug #9)
**Files:** `memory_scanner.py` (parse_signature)
**Steps:**
1. Add `len(tok) > 2` validation before `int(tok, 16) & 0xFF`
2. Raise ValueError with helpful message: "Did you forget spaces?"
3. Test: `parse_signature("DEADBEEFCAFEBABE")` → raises ValueError
4. Test: `parse_signature("DE AD BE EF CA FE BA BE")` → works

### Task 13: Verify all fixes
**Steps:**
1. `python -m py_compile memory_scanner.py` ✓
2. Run full test suite
3. Build pipeline: `python trainer_compiler.py trainers/test_trainer.yaml --build`
4. Verify Test Trainer.exe still builds

---

## Phase 2: Disassembly Engine (Week 3-4)

**Objective:** Add Capstone disassembly + memory browser + assembly scanner.

### Task 14: Install Capstone
**Steps:**
1. `pip install capstone` (Python bindings)
2. Verify: `python -c "from capstone import Cs; print(Cs(64, 0).detail)"`
3. Test disassembly: `python -c "from capstone import Cs; md=Cs(64,0); print(list(md.disasm(b'\x55\x48\x8b\x05\xb8\x13\x00\x00', 0x1000)))"`

### Task 15: Memory browser (hex view)
**Files:** `studio_gui.py` (add MemoryBrowser tab)
**Steps:**
1. Create `MemoryBrowser` class with hex view + ASCII dump
2. Navigate by address, follow pointers
3. Integrate into studio_gui.py as new tab
4. Test: open memory browser → navigate to module base → verify hex display

### Task 16: Disassembly view
**Files:** `studio_gui.py` (add Disassembly tab)
**Steps:**
1. Create `DisassemblyView` class using Capstone
2. Show instructions at address, with context (before/after)
3. Click-to-follow, address navigation
4. Test: disassemble at known function address → verify instructions match

### Task 17: Assembly scanner
**Files:** `memory_scanner.py` (add assembly_scan function)
**Steps:**
1. Add `assembly_scan(h, pattern)` — scan for instruction patterns
2. Use Capstone to disassemble modules, match instruction patterns
3. Test: scan for `mov rax, [rip+?]` pattern → verify hits

---

## Phase 3: Debugger + MinHook (Week 5-6) ⭐

**Objective:** Add debugger with breakpoints, API monitoring, and memory access breakpoints using MinHook.

### Task 18: MinHook ctypes bindings
**Files:** Create `minhook.py`
**Steps:**
1. Download MinHook v1.3.4 source from GitHub
2. Build MinHook.x64.dll (CMake + MSVC or MinGW)
3. Create `minhook.py` with ctypes bindings for all 8 MH_* functions
4. Test: load DLL → MH_Initialize → MH_Uninitialize → no errors

### Task 19: Memory access breakpoints (hook VirtualProtect)
**Files:** `minhook.py`, `debugger.py` (new)
**Steps:**
1. Hook `VirtualProtect` in target process via MinHook
2. When protection changes on a watched page, trigger breakpoint
3. Log: address, old protection, new protection, call stack
4. Test: watch an address → game modifies it → breakpoint fires

### Task 20: Function breakpoint hooks
**Files:** `debugger.py`
**Steps:**
1. Hook game functions via MinHook (MH_CreateHook on function address)
2. In detour: log params, optionally modify, call original
3. Conditional breakpoints: break only when args match condition
4. Test: hook known game function → verify detour fires with correct args

### Task 21: API monitoring
**Files:** `debugger.py`
**Steps:**
1. Hook key APIs: `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `ReadProcessMemory`, `WriteProcessMemory`, `CreateFile`, `WriteFile`
2. Log all calls with parameters to scrollable window
3. Filter by API name, address range
4. Test: monitor API calls while game runs → verify logging works

### Task 22: Debug event handling
**Files:** `debugger.py`
**Steps:**
1. Use `DebugActiveProcess` + `WaitForDebugEvent` + `ContinueDebugEvent`
2. Handle EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, EXCEPTION_GUARD_PAGE
3. Map debug events to UI notifications
4. Test: set breakpoint → verify debug event received → continue execution

### Task 23: Call stack view
**Files:** `debugger.py`, `studio_gui.py`
**Steps:**
1. Capture call stack at breakpoint (StackWalk64 or background thread)
2. Display in GUI with function names (from symbols)
3. Click to navigate to address in disassembly view
4. Test: trigger breakpoint → verify call stack displayed

---

## Phase 4: Lua Scripting + Auto-Assembler (Week 7-8)

**Objective:** Add Lua scripting engine with memory API + auto-assembler for cheat scripts.

### Task 24: lupa integration
**Steps:**
1. `pip install lupa`
2. Verify: `python -c "from lupa import LuaRuntime; lua=LuaRuntime(); print(lua.eval('1+1'))"`
3. Create `lua_engine.py` with LuaRuntime + custom globals

### Task 25: Lua memory API
**Files:** `lua_engine.py`
**Steps:**
1. Expose to Lua: `readByte(addr)`, `readInt(addr)`, `readFloat(addr)`, `readDouble(addr)`, `readString(addr)`
2. Expose: `writeByte(addr, val)`, `writeInt(addr, val)`, `writeFloat(addr, val)`
3. Expose: `scan(value, vtype, mode)` — memory scan from Lua
4. Expose: `getModuleBase(name)` — get module base address
5. Test: Lua script reads/writes memory → verify values change in target process

### Task 26: Lua script editor in GUI
**Files:** `studio_gui.py` (add Lua tab)
**Steps:**
1. Add Lua script editor tab with syntax highlighting
2. Run/Stop buttons for Lua scripts
3. Output console for Lua print() and errors
4. Test: write Lua script → run → verify output in console

### Task 27: Auto-assembler script engine
**Files:** `autoassembler.py` (new)
**Steps:**
1. Parse auto-assembler scripts (CE syntax: `alloc`, `label`, `registersymbol`, `HookFunction`, etc.)
2. Compile to machine code (using Capstone for validation)
3. Use MinHook for function hooks
4. Allocate executable memory for injected code
5. Test: run simple auto-assembler script → verify hook fires

### Task 28: Trainer feature hooks via MinHook
**Files:** `trainer_compiler.py`, `templates/trainer_template.cpp`
**Steps:**
1. Add `hook` feature type to YAML trainer definitions
2. Compiler generates C++ code with MinHook hook on specified function
3. Detour modifies game behavior (freeze value, set value, etc.)
4. Test: YAML with hook feature → compile → run trainer → verify hook works

---

## Phase 5: Polish (Week 9-12)

**Objective:** Settings, plugins, network, pointer scan improvements.

### Task 29: Settings/configuration system
**Files:** `settings.py` (new), `studio_gui.py`
**Steps:**
1. JSON-based settings (scan defaults, hotkeys, window positions)
2. Settings dialog in GUI
3. Test: change settings → restart → verify persisted

### Task 30: Pointer scan improvements
**Files:** `memory_scanner.py`
**Steps:**
1. Pointer scan resume (save/load state)
2. Pointer scan merge (combine multiple scans)
3. Pointer sort/filter (by depth, by module)
4. Test: large pointer scan → resume → verify continuation

### Task 31: Network features
**Files:** `network.py` (new)
**Steps:**
1. Distributed scanning (scan across multiple machines)
2. Remote memory view (view target process memory from another PC)
3. Test: scan from remote → verify results match local

### Task 32: Plugin system
**Files:** `plugins/` (new directory)
**Steps:**
1. Plugin API: `on_scan_start()`, `on_scan_complete()`, `on_breakpoint()`
2. Example plugins: speed hack, teleport, item finder
3. Test: install plugin → verify callbacks fire

---

## MinHook Integration Summary

| Use Case | Phase | MinHook Function | Target |
|---|---|---|---|
| Memory access breakpoints | 3 | MH_CreateHook on VirtualProtect | Detect page protection changes |
| Function breakpoints | 3 | MH_CreateHook on game functions | Log/modify function behavior |
| API monitoring | 3 | MH_CreateHookApi on kernel32 APIs | Track all API calls |
| Trainer features | 4 | MH_CreateHook on game functions | Freeze/modify values at runtime |
| Auto-assembler hooks | 4 | MH_CreateHook + alloc exec memory | Inject custom code |

**MinHook build:**
```bash
# Build MinHook DLL from source
cd /tmp/minhook-master
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
# Output: MinHook.x64.dll (or .lib for linking)
```

**MinHook ctypes bindings (minhook.py):**
```python
import ctypes
from ctypes import wintypes

class MinHook:
    def __init__(self, dll_path="MinHook.x64.dll"):
        self._mh = ctypes.WinDLL(dll_path)
        self._mh.MH_Initialize.restype = wintypes.BOOL
        self._mh.MH_Initialize.argtypes = []
        # ... similar for all MH_* functions
    
    def initialize(self):
        return self._mh.MH_Initialize()
    
    def create_hook(self, target, detour, original=None):
        return self._mh.MH_CreateHook(target, detour, original)
    
    def enable_hook(self, target):
        return self._mh.MH_EnableHook(target)
    
    def disable_hook(self, target):
        return self._mh.MH_DisableHook(target)
    
    def remove_hook(self, target):
        return self._mh.MH_RemoveHook(target)
    
    def uninitialize(self):
        return self._mh.MH_Uninitialize()
```

---

## Verification Commands

```bash
# Phase 1 verification
python -m py_compile memory_scanner.py
python -m pytest tests/test_scanner.py -v
python trainer_compiler.py trainers/test_trainer.yaml --build --g++ "C:/mingw64/bin/g++.exe"

# Phase 2 verification
python -c "from capstone import Cs; md=Cs(64,0); print(len(list(md.disasm(b'\x55\x48\x8b\x05', 0x1000))))"
python -m pytest tests/test_disasm.py -v

# Phase 3 verification
python -c "from minhook import MinHook; mh=MinHook(); assert mh.initialize() == 0"
python -m pytest tests/test_debugger.py -v

# Phase 4 verification
python -c "from lupa import LuaRuntime; lua=LuaRuntime(); assert lua.eval('1+1') == 2"
python -m pytest tests/test_lua.py -v

# Full integration
python -m pytest tests/ -v
```

---

## Risks & Tradeoffs

| Risk | Mitigation |
|---|---|
| MinHook build fails on MSYS | Use vcpkg or prebuilt binary from GitHub releases |
| Capstone disassembly inaccurate for obfuscated code | Validate against known binaries, fall back to manual analysis |
| lupa Lua 5.3 compatibility | Pin lupa version, test with target Lua scripts |
| Debugger crashes target process | Use DebugActiveProcess with careful exception handling |
| GIL contention in debugger | Run debug event loop in separate process, not thread |
| MinHook hooks cause game crashes | Always call original in detour; test on harmless functions first |

## Open Questions

1. Should the debugger use `DebugActiveProcess` or manual MinHook-only approach? (CE uses both)
2. Lua script sandboxing — restrict file/network access?
3. Auto-assembler — support full CE syntax or subset?
4. Network features — TCP only, or also UDP for speed?
