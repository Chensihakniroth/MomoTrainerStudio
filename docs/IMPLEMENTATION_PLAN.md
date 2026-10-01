# MomoTrainer Studio - Debugging QoL Implementation Plan

**Created:** 2026-09-08
**Status:** IN PROGRESS

---

## Execution Plan (Concise)

### Phase 1: Core Infrastructure (3 files)
1. `debugger_unified.py` - Unified debugger interface
2. `breakpoint_manager.py` - Breakpoint management panel
3. `hotkey_manager.py` - Global hotkey system

### Phase 2: UI Components (3 files)
4. `disassembly_view.py` - Live disassembly panel
5. `memory_watch.py` - Memory watch window
6. `call_stack_tracer.py` - Call stack capture

### Phase 3: Scripting API (1 file)
7. `scripting_api.py` - Python scripting API

### Phase 4: Integration
8. Patch `studio_gui.py` to integrate all components

---

## File Dependencies

```
debugger_unified.py
    ├── imports: debugger.py, stealth_debugger.py
    └── used by: breakpoint_manager.py, hotkey_manager.py

breakpoint_manager.py
    ├── imports: debugger_unified.py
    └── used by: studio_gui.py

disassembly_view.py
    ├── imports: capstone
    └── used by: studio_gui.py

memory_watch.py
    └── used by: studio_gui.py

call_stack_tracer.py
    ├── imports: debugger_unified.py
    └── used by: studio_gui.py

hotkey_manager.py
    ├── imports: debugger_unified.py, memory_scanner.py
    └── used by: studio_gui.py

scripting_api.py
    ├── imports: all above
    └── used by: user scripts
```

---

## Implementation Order

1. ✅ `debugger_unified.py` (foundation)
2. ✅ `breakpoint_manager.py` (uses unified debugger)
3. ✅ `hotkey_manager.py` (uses unified debugger)
4. ✅ `disassembly_view.py` (standalone UI component)
5. ✅ `memory_watch.py` (standalone UI component)
6. ✅ `call_stack_tracer.py` (uses unified debugger)
7. ✅ `scripting_api.py` (exposes all functionality)
8. ✅ Patch `studio_gui.py` (integrate all panels)

---

## Success Criteria

- Unified debugger auto-detects anti-cheat
- Breakpoint manager shows all breakpoints with hit counts
- F2/F5/F9/Ctrl+N hotkeys work
- Disassembly view shows live context
- Memory watch auto-refreshes with change highlighting
- Scripting API can read/write/set breakpoints
- All integrated into existing UI

---

## Auto-Proceeding...
