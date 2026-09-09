# MomoTrainer Studio - Debugging QoL Improvements

**Created:** 2026-09-08
**Author:** Momo / Hikari Pixel
**Status:** Planning Phase

---

## Executive Summary

Improve runtime debugging and disassembly workflows by:
1. Unifying the two debugger backends (hardware + stealth)
2. Adding visual debugging tools (disassembly, breakpoints, call stack)
3. Streamlining common workflows with hotkeys and automation
4. Enhancing memory inspection with live updates and diff views

---

## Current State (v4)

### Debugger Backends
- **debugger.py**: Hardware breakpoints via Win32 Debug API (detectable by anti-cheat)
- **stealth_debugger.py**: PAGE_GUARD + VEH (undetectable, no Debug API)

### Memory Scanner
- **memory_scanner.py**: CE-style multi-threaded scanner with disk-backed results
- **scan_engine.c**: C-based scan engine for hot-path optimization

### UI
- **studio_gui.py**: Tkinter-based UI with Hick's Law design
- **momotrainer_modern.py**: CustomTkinter theming wrapper

---

## Phase 1: Unified Debugger Interface

**Goal:** Single debugger class that auto-selects the appropriate backend

### Implementation: `debugger_unified.py`

```python
class UnifiedDebugger:
    """
    Auto-routing debugger:
    - Detects anti-cheat presence
    - Routes to stealth_debugger for protected games
    - Routes to hardware debugger for unprotected games
    """
    
    def __init__(self, pid, force_stealth=False):
        self.pid = pid
        self.force_stealth = force_stealth
        self._backend = None
        self._protection_detected = []
        
    def scan_for_protection(self):
        """Detect anti-cheat drivers/processes"""
        known_protections = [
            'EasyAntiCheat', 'BattlEye', 'Vanguard', 
            'FaceItClient', 'EQU8', 'Hyperion'
        ]
        # Scan modules and processes
        return detected_list
        
    def attach(self, address, access_type='write'):
        """Attach with auto-selected backend"""
        if self.force_stealth or self._protection_detected:
            from stealth_debugger import StealthDebugger
            self._backend = StealthDebugger(self.pid)
        else:
            from debugger import HardwareDebugger
            self._backend = HardwareDebugger(self.pid)
        return self._backend.attach(address, access_type)
```

### Benefits
- One-click debugging without manual backend selection
- Automatic anti-cheat detection
- Seamless fallback to stealth mode

---

## Phase 2: Live Disassembly View

**Goal:** Real-time disassembly panel showing current instruction context

### Features
- **RIP Context View**: Show 20 instructions before/after current RIP
- **Module Resolution**: Convert relative addresses to module + offset
- **String Reference Detection**: Inline display of referenced strings
- **Jump Target Highlighting**: Color-coded branches (taken/not taken)
- **Cross-reference Count**: Show how many times each address is referenced

### Implementation: `disassembly_view.py`

```python
class DisassemblyView(ttk.Frame):
    """
    Live disassembly panel with:
    - Syntax highlighting (Capstone)
    - Module name resolution
    - String reference detection
    - Jump/call target visualization
    """
    
    def __init__(self, parent, pid):
        super().__init__(parent)
        self.pid = pid
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        
        # UI components
        self.text = tk.Text(self, bg='#0a0e27', fg='#00d4ff',
                           font=('Consolas', 10))
        self.yscroll = ttk.Scrollbar(self, orient='vertical',
                                     command=self.text.yview)
        
    def render_context(self, rip, num_instructions=20):
        """Render disassembly around RIP"""
        # Read memory around RIP
        base = rip - (num_instructions * 8)
        size = num_instructions * 16
        
        data = self._read_memory(base, size)
        
        # Disassemble
        for insn in self.md.disasm(data, base):
            self._render_instruction(insn, is_rip=(insn.address == rip))
            
    def _render_instruction(self, insn, is_rip=False):
        """Render single instruction with highlighting"""
        addr = f'{insn.address:016X}'
        bytes_str = ' '.join(f'{b:02X}' for b in insn.bytes)
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        # Color scheme
        if is_rip:
            self.text.insert('end', f'→ ', 'rip-marker')
            self.text.insert('end', f'{addr}  ', 'address-rip')
        else:
            self.text.insert('end', f'  {addr}  ', 'address')
            
        self.text.insert('end', f'{bytes_str:<24}  ', 'bytes')
        self.text.insert('end', f'{mnemonic} ', 'mnemonic')
        self.text.insert('end', f'{op_str}\n', 'operands')
```

### Integration Points
- Hook into `debugger.py` and `stealth_debugger.py` breakpoint callbacks
- Display in split pane alongside found results table
- Add "View Disassembly" context menu to address table

---

## Phase 3: Breakpoint Manager Panel

**Goal:** Visual management of all breakpoints across both backends

### Features
- **Unified List**: All hardware + PAGE_GUARD breakpoints in one view
- **Enable/Disable Toggle**: Click to toggle without removing
- **Hit Counter**: Show number of times each breakpoint triggered
- **Conditional Breakpoints**: Break only when value matches condition
- **Quick Actions**: Replace with NOPs, Edit bytes, Copy address

### Implementation: `breakpoint_manager.py`

```python
class BreakpointManager(ttk.Frame):
    """
    Visual breakpoint manager:
    - List all active breakpoints
    - Enable/disable individual breakpoints
    - Show hit count and last value
    - Conditional breakpoint support
    """
    
    def __init__(self, parent, unified_debugger):
        super().__init__(parent)
        self.udb = unified_debugger
        
        # Treeview for breakpoints
        columns = ('address', 'type', 'hits', 'condition', 'enabled')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        
        # Column headers
        self.tree.heading('address', text='Address')
        self.tree.heading('type', text='Type')
        self.tree.heading('hits', text='Hits')
        self.tree.heading('condition', text='Condition')
        self.tree.heading('enabled', text='Enabled')
        
        # Context menu
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Toggle", command=self._toggle_bp)
        self.menu.add_command(label="Set Condition", command=self._set_condition)
        self.menu.add_command(label="Replace with NOPs", command=self._nop_current)
        self.menu.add_command(label="Remove", command=self._remove_bp)
        
    def refresh_list(self):
        """Update breakpoint list from debugger backends"""
        self.tree.delete(*self.tree.get_children())
        
        for bp in self.udb.list_breakpoints():
            self.tree.insert('', 'end', values=(
                f'{bp.address:016X}',
                bp.access_type,
                bp.hit_count,
                bp.condition or '-',
                '✓' if bp.enabled else '✗'
            ))
```

---

## Phase 4: Call Stack Tracer

**Goal:** Capture and display call stack at breakpoint

### Features
- **Stack Walk**: Walk stack using RBP/RSP chain
- **Symbol Resolution**: Resolve addresses to module + function name
- **Argument Capture**: Display function arguments (if readable)
- **Export to IDA**: Generate IDA script to mark all addresses

### Implementation: `call_stack_tracer.py`

```python
class CallStackTracer:
    """
    Capture call stack at breakpoint:
    - Walk x64 stack chain
    - Resolve module names
    - Show return addresses
    """
    
    def __init__(self, pid, process_handle):
        self.pid = pid
        self.h = process_handle
        
    def capture_stack(self, context):
        """Capture current call stack from context"""
        stack = []
        rbp = context['RBP']
        rip = context['RIP']
        
        # Current frame
        stack.append({
            'address': rip,
            'return_addr': None,
            'module': self._resolve_module(rip),
            'offset': None
        })
        
        # Walk stack frames (max 20)
        for _ in range(20):
            # Read saved RBP and return address
            saved_rbp = self._read_ptr(rbp)
            return_addr = self._read_ptr(rbp + 8)
            
            if not saved_rbp or not return_addr:
                break
                
            stack.append({
                'address': return_addr,
                'return_addr': return_addr,
                'module': self._resolve_module(return_addr),
                'offset': self._get_module_offset(return_addr)
            })
            
            rbp = saved_rbp
            
        return stack
        
    def _resolve_module(self, addr):
        """Find which module contains this address"""
        # Query memory region to get allocation base
        # Look up in module list
        return module_name
```

---

## Phase 5: Memory Watch Window

**Goal:** Live memory inspection with auto-refresh and change highlighting

### Features
- **Multi-Value Display**: Show same bytes as hex, int, float, string simultaneously
- **Change Highlighting**: Green for increased, red for decreased, yellow for changed
- **Auto-Refresh**: Configurable refresh rate (10ms - 1000ms)
- **Freeze Column**: Quick freeze/unfreeze toggle
- **Byte Diff View**: Show which bytes changed since last read

### Implementation: `memory_watch.py`

```python
class MemoryWatchWindow(ttk.Toplevel):
    """
    Live memory watch window:
    - Auto-refreshing values
    - Change highlighting
    - Multiple format display
    - Freeze/unfreeze toggle
    """
    
    def __init__(self, parent, pid, initial_addresses=[]):
        super().__init__(parent)
        self.title("Memory Watch")
        self.pid = pid
        
        # Watch list
        columns = ('address', 'hex', 'int', 'float', 'string', 'changed', 'freeze')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        
        # Previous values for diff detection
        self._prev_values = {}
        
        # Auto-refresh timer
        self._refresh_job = None
        self.refresh_interval = 100  # ms
        
        self._start_auto_refresh()
        
    def _start_auto_refresh(self):
        """Start auto-refresh cycle"""
        self._refresh_values()
        self._refresh_job = self.after(self.refresh_interval, 
                                        self._start_auto_refresh)
        
    def _refresh_values(self):
        """Read and update all watched addresses"""
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            addr = int(values[0], 16)
            
            # Read current value
            data = self._read_memory(addr, 16)
            
            # Detect changes
            prev = self._prev_values.get(addr)
            if prev and prev != data:
                changed = '✓'
            else:
                changed = ''
                
            # Update display
            self.tree.item(item, values=(
                f'{addr:016X}',
                data.hex(),
                struct.unpack('<i', data[:4])[0],
                struct.unpack('<f', data[:4])[0],
                data.decode('utf-8', errors='replace')[:16],
                changed,
                values[6]  # Keep freeze state
            ))
            
            self._prev_values[addr] = data
```

---

## Phase 6: Hotkey System

**Goal:** Configurable hotkeys for common debugging operations

### Default Hotkeys
- **F2**: Toggle breakpoint at current address
- **F5**: Run/Continue
- **F9**: Toggle freeze on selected address
- **F10**: Step over (if supported)
- **F11**: Step into (if supported)
- **Ctrl+B**: Add to cheat table
- **Ctrl+N**: Replace current instruction with NOPs
- **Ctrl+C**: Copy address to clipboard
- **Ctrl+G**: Go to address (dialog)

### Implementation: `hotkey_manager.py`

```python
class HotkeyManager:
    """
    Global hotkey manager for debugging operations
    """
    
    def __init__(self, root, debugger, scanner, gui):
        self.root = root
        self.debugger = debugger
        self.scanner = scanner
        self.gui = gui
        
        self._hotkeys = {}
        self._register_defaults()
        
    def _register_defaults(self):
        """Register default hotkeys"""
        self.register('<F2>', self._toggle_breakpoint)
        self.register('<F5>', self._continue_execution)
        self.register('<F9>', self._toggle_freeze)
        self.register('<Control-n>', self._nop_instruction)
        self.register('<Control-g>', self._goto_address)
        
    def register(self, key_sequence, callback):
        """Register a hotkey"""
        self._hotkeys[key_sequence] = callback
        self.root.bind(key_sequence, lambda e: callback())
        
    def _toggle_breakpoint(self):
        """Toggle breakpoint at selected address"""
        addr = self.gui.get_selected_address()
        if addr:
            self.debugger.toggle_breakpoint(addr)
```

---

## Phase 7: Scripting/Plugin System

**Goal:** Python-based scripting for custom workflows

### Features
- **Custom Scan Patterns**: Define complex scan patterns as Python functions
- **Automated Analysis**: Scripts that run on breakpoint hits
- **Trainer Generation**: Auto-generate trainer from cheat table
- **Export Tools**: Generate IDA/Ghidra scripts, sig files, etc.

### Implementation: `scripting_api.py`

```python
class MomoTrainerAPI:
    """
    Public API for MomoTrainer scripting
    """
    
    def __init__(self, studio):
        self.studio = studio
        self.scanner = studio.scanner
        self.debugger = studio.debugger
        
    # Memory operations
    def read_int(self, address):
        """Read 4-byte integer from address"""
        
    def write_int(self, address, value):
        """Write 4-byte integer to address"""
        
    def read_bytes(self, address, size):
        """Read raw bytes from address"""
        
    # Scanner operations
    def scan(self, value, vtype='int32', mode='exact'):
        """Run a scan and return results"""
        
    def rescan(self, value, mode='exact'):
        """Rescan previous results"""
        
    # Debugger operations
    def set_breakpoint(self, address, access_type='write'):
        """Set a breakpoint"""
        
    def get_breakpoint_hits(self, address):
        """Get hit count and captured data for breakpoint"""
        
    # Trainer operations
    def add_to_cheat_table(self, address, description, vtype='int32'):
        """Add address to cheat table"""
        
    def generate_trainer(self, output_path):
        """Generate standalone trainer exe"""
        
    # Export operations
    def export_to_ida_script(self, output_path):
        """Generate IDA Python script to mark all addresses"""
        
    def export_signatures(self, output_path):
        """Export all AOB signatures as sig file"""
```

### Example Script: Auto-NOP All Writers

```python
# auto_nop_writers.py
"""
Find all addresses writing to target address and NOP them automatically
"""

from momotrainer_api import MomoTrainerAPI

api = MomoTrainerAPI(studio)

# Target address
target = 0x140001000

# Set breakpoint to find writers
api.set_breakpoint(target, access_type='write')

# Wait for hits
print("Waiting for writers...")
time.sleep(5)

# Get all captured writers
hits = api.get_breakpoint_hits(target)

# NOP each unique instruction
seen = set()
for hit in hits:
    if hit.rip not in seen:
        print(f"NOPing instruction at {hit.rip:016X}")
        api.write_bytes(hit.rip, b'\x90\x90\x90\x90\x90')  # 5 NOPs
        seen.add(hit.rip)
        
print(f"NOPed {len(seen)} unique writers")
```

---

## Implementation Priority

### P0 (Immediate)
1. Unified Debugger Interface
2. Hotkey System (basic)
3. Breakpoint Manager Panel

### P1 (Next Sprint)
4. Live Disassembly View
5. Memory Watch Window
6. Scripting API (basic)

### P2 (Future)
7. Call Stack Tracer
8. Advanced Scripting (plugins, custom UI)
9. Export to IDA/Ghidra

---

## Technical Considerations

### Threading Model
- All debugger callbacks run in separate thread
- UI updates must use `root.after()` or queue system
- Memory reads must be synchronized

### Anti-Cheat Safety
- Stealth debugger should be default for unknown games
- Hardware debugger only for confirmed unprotected games
- Never mix both backends simultaneously

### Performance
- Disassembly view should cache recent results
- Memory watch refresh rate should be configurable
- Limit max breakpoints to avoid slowdown

---

## Success Metrics

- **Time to find writer**: < 30 seconds for unprotected, < 2 min for protected
- **Breakpoint management**: < 5 clicks to set/toggle/remove
- **Disassembly context**: Always visible without switching tools
- **Scripting efficiency**: 10-minute automation saves 1 hour of manual work

---

## Next Steps

1. Create `debugger_unified.py` with auto-detection
2. Add basic hotkey support to `studio_gui.py`
3. Build Breakpoint Manager as new panel
4. Integrate Disassembly View into split pane
5. Design scripting API surface

Let's start with Phase 1 and Phase 3 as they provide immediate value.
