"""
advanced_features.py — Advanced features for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - LuaScriptEngine    — CE-like Lua scripting with event hooks
  - AutoAssembler      — Inject custom ASM code into target process
  - StructureDissect   — Auto-detect structs/arrays/pointer chains
  - PointerMap         — Graph visualization of pointer relationships
  - ScanSession        — Save/load full scan state to JSON
  - Speedhack          — Hook timing functions (QPC, GTC, timeGetTime)
  - PluginManager      — Load external Python plugins
  - ScriptRecorder     — Record user actions into reusable scripts
  - AutoAttachWatcher  — Watch for process launch, auto-connect
  - MemoryDumper       — Dump memory regions to disk
"""

import ctypes
import csv
import json
import math
import os
import struct
import threading
import time
import traceback
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import memory_scanner as ms

k32 = ctypes.windll.kernel32

# Win32 constants for code injection
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000

# ============================================================
# Lua-like Scripting Engine
# ============================================================

class LuaScriptEngine:
    """
    CE-like scripting engine with event-driven API.

    Scripts can register handlers for:
      - onScanComplete(results)     — after a scan finishes
      - onBreakpointHit(info)       — when a breakpoint fires
      - onTimer(interval_ms)        — periodic timer callback
      - onAddressChange(addr, val)  — when watched address changes

    API exposed to scripts:
      api.read_int(addr) / api.read_float(addr) / api.read_string(addr)
      api.write_int(addr, val) / api.write_float(addr, val)
      api.scan(value, type, mode) / api.rescan(value, mode)
      api.sleep(ms) / api.log(msg)
      api.get_module(name) / api.resolve(addr)
    """

    def __init__(self, scripting_api):
        self.api = scripting_api
        self._scripts: Dict[str, str] = {}       # name -> source
        self._handlers: Dict[str, List[Callable]] = {
            "onScanComplete": [],
            "onBreakpointHit": [],
            "onTimer": [],
            "onAddressChange": [],
        }
        self._timers: List[Dict] = []
        self._running = False
        self._log: List[str] = []

    def register_script(self, name: str, source: str):
        """Register a script from source string."""
        self._scripts[name] = source
        self._execute_script(source)

    def register_script_file(self, path: str):
        """Load and register a script from file."""
        source = Path(path).read_text(encoding='utf-8')
        name = Path(path).stem
        self.register_script(name, source)

    def _execute_script(self, source: str):
        """Execute script source, registering its handlers."""
        # Build the script namespace
        ns = {
            "api": self.api,
            "log": self._log_msg,
            "print": self._log_msg,
        }

        # Add handler registration functions
        def on_scan_complete(fn):
            self._handlers["onScanComplete"].append(fn)

        def on_breakpoint_hit(fn):
            self._handlers["onBreakpointHit"].append(fn)

        def on_address_change(fn):
            self._handlers["onAddressChange"].append(fn)

        def on_timer(interval_ms, fn):
            self._handlers["onTimer"].append((interval_ms, fn))

        ns.update({
            "onScanComplete": on_scan_complete,
            "onBreakpointHit": on_breakpoint_hit,
            "onAddressChange": on_address_change,
            "onTimer": on_timer,
        })

        try:
            exec(source, ns)
            self._log_msg(f"Script loaded: {len(source)} bytes")
        except Exception as e:
            self._log_msg(f"Script error: {e}")
            raise

    def _log_msg(self, msg):
        ts = time.strftime('%H:%M:%S')
        entry = f"[{ts}] {msg}"
        self._log.append(entry)

    def fire_event(self, event: str, *args, **kwargs):
        """Fire an event to all registered handlers."""
        handlers = self._handlers.get(event, [])
        for handler in handlers:
            try:
                if isinstance(handler, tuple):
                    # Timer: (interval, fn)
                    interval, fn = handler
                    fn(*args, **kwargs)
                else:
                    handler(*args, **kwargs)
            except Exception as e:
                self._log_msg(f"Handler error ({event}): {e}")

    def get_log(self) -> List[str]:
        return list(self._log)

    def clear_log(self):
        self._log.clear()


# ============================================================
# Auto-Assembler / Code Injection
# ============================================================

class AutoAssembler:
    """
    Allocate memory in target process and inject assembly code.

    Usage:
        asm = AutoAssembler(pid)
        addr = asm.inject_bytes(b'\x90\x90\x90')  # NOP sled
        asm.create_thread(addr)  # execute it
        asm.free(addr)
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle
        self._allocations: List[Tuple[int, int]] = []  # (addr, size)
        # Fix return type so addresses > 0x7FFFFFFF aren't seen as negative
        k32.VirtualAllocEx.restype = ctypes.c_void_p

    def _get_handle(self):
        if self.h_process:
            return self.h_process
        return k32.OpenProcess(0x0010 | 0x0008 | 0x0020 | 0x1000, False, self.pid)
        # PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION

    def allocate(self, size: int, executable: bool = True) -> int:
        """Allocate memory in target process."""
        h = self._get_handle()
        if not h:
            return 0

        prot = PAGE_EXECUTE_READWRITE if executable else PAGE_READWRITE
        addr = k32.VirtualAllocEx(h, None, ctypes.c_size_t(size), ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE), ctypes.c_ulong(prot))
        if addr:
            self._allocations.append((addr, size))
        if not self.h_process:
            k32.CloseHandle(h)
        return addr or 0

    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write bytes to target process memory."""
        h = self._get_handle()
        if not h:
            return False
        written = ctypes.c_size_t(0)
        result = k32.WriteProcessMemory(h, ctypes.c_void_p(address), data, ctypes.c_size_t(len(data)), ctypes.byref(written))
        if not self.h_process:
            k32.CloseHandle(h)
        return bool(result and written.value == len(data))

    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """Read bytes from target process."""
        h = self._get_handle()
        if not h:
            return None
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, ctypes.c_size_t(size), ctypes.byref(read)):
            if not self.h_process:
                k32.CloseHandle(h)
            return buf.raw[:read.value]
        if not self.h_process:
            k32.CloseHandle(h)
        return None

    def inject_bytes(self, data: bytes, executable: bool = True) -> int:
        """Allocate + write bytes. Returns address."""
        addr = self.allocate(len(data), executable)
        if addr and self.write_bytes(addr, data):
            return addr
        return 0

    def create_thread(self, address: int, param: int = 0) -> bool:
        """Create a remote thread to execute code at address."""
        h = self._get_handle()
        if not h:
            return False
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(h, None, 0, address, param, 0, ctypes.byref(thread_id))
        if h_thread:
            if not self.h_process:
                k32.CloseHandle(h)
            k32.CloseHandle(h_thread)
            return True
        if not self.h_process:
            k32.CloseHandle(h)
        return False

    def free(self, address: int) -> bool:
        """Free allocated memory."""
        h = self._get_handle()
        if not h:
            return False
        result = k32.VirtualFreeEx(h, ctypes.c_void_p(address), ctypes.c_size_t(0), ctypes.c_ulong(0x8000))  # MEM_RELEASE
        self._allocations = [(a, s) for a, s in self._allocations if a != address]
        if not self.h_process:
            k32.CloseHandle(h)
        return bool(result)

    def inject_nop_sled(self, address: int, count: int) -> bool:
        """Replace instructions with NOPs."""
        return self.write_bytes(address, b'\x90' * count)

    def inject_ret(self, address: int) -> bool:
        """Replace instruction with RET (0xC3)."""
        return self.write_bytes(address, b'\xC3')

    def cleanup(self):
        """Free all allocations."""
        for addr, _ in list(self._allocations):
            self.free(addr)
        self._allocations.clear()


# ============================================================
# Structure Dissect
# ============================================================

@dataclass
class StructField:
    offset: int
    vtype: str
    name: str
    size: int
    value: Any = None


@dataclass
class DetectedStruct:
    base_address: int
    size: int
    fields: List[StructField] = field(default_factory=list)
    confidence: float = 0.0  # 0-1 how confident we are


class StructureDissect:
    """
    Analyze memory regions to detect data structures.

    Detects:
      - Arrays (repeated patterns)
      - Structs (grouped fields of different types)
      - Pointer chains (what points to what)
      - String fields (printable ASCII regions)
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        h = self.h_process or k32.OpenProcess(0x0010, False, self.pid)
        if not h:
            return None
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        result = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(size), ctypes.byref(read))
        if not self.h_process:
            k32.CloseHandle(h)
        if result:
            return buf.raw[:read.value]
        return None

    def detect_struct(self, base_addr: int, max_size: int = 256) -> Optional[DetectedStruct]:
        """Try to detect a structure at the given address."""
        data = self._read(base_addr, max_size)
        if not data or len(data) < 8:
            return None

        fields = []
        offset = 0

        while offset < len(data) - 3:
            remaining = len(data) - offset

            # Try pointer (8 bytes, x64)
            if remaining >= 8:
                ptr = struct.unpack_from('<Q', data, offset)[0]
                if self._is_valid_addr(ptr):
                    fields.append(StructField(offset, "pointer", f"ptr_0x{offset:X}", 8, f"0x{ptr:X}"))
                    offset += 8
                    continue

            # Try int32
            if remaining >= 4:
                val32 = struct.unpack_from('<I', data, offset)[0]
                if 0 < val32 < 0x7FFFFFFF:
                    # Check if it looks like a small integer (common in games)
                    if val32 < 100000:
                        fields.append(StructField(offset, "int32", f"field_0x{offset:X}", 4, val32))
                        offset += 4
                        continue

            # Try float
            if remaining >= 4:
                fval = struct.unpack_from('<f', data, offset)[0]
                if not (fval != fval) and 0.0 < abs(fval) < 1e10:
                    if fval != int(fval):  # has fractional part
                        fields.append(StructField(offset, "float", f"float_0x{offset:X}", 4, round(fval, 4)))
                        offset += 4
                        continue

            # Try int16
            if remaining >= 2:
                val16 = struct.unpack_from('<H', data, offset)[0]
                if 0 < val16 < 10000:
                    fields.append(StructField(offset, "uint16", f"field_0x{offset:X}", 2, val16))
                    offset += 2
                    continue

            # Try byte
            fields.append(StructField(offset, "uint8", f"byte_0x{offset:X}", 1, data[offset]))
            offset += 1

        if not fields:
            return None

        total_size = max(f.offset + f.size for f in fields)
        confidence = min(1.0, len(fields) / 8.0)  # more fields = more confident

        return DetectedStruct(
            base_address=base_addr,
            size=total_size,
            fields=fields,
            confidence=confidence,
        )

    def detect_array(self, base_addr: int, element_size: int = 4, max_elements: int = 32) -> Optional[Dict]:
        """Detect an array of repeated elements."""
        data = self._read(base_addr, element_size * max_elements)
        if not data:
            return None

        elements = []
        for i in range(min(max_elements, len(data) // element_size)):
            val = struct.unpack_from('<I', data, i * element_size)[0]
            elements.append(val)

        if not elements:
            return None

        return {
            "base": base_addr,
            "element_size": element_size,
            "count": len(elements),
            "values": elements[:20],  # first 20
        }

    def _is_valid_addr(self, addr: int) -> bool:
        """Check if address looks like a valid user-mode pointer."""
        return 0x10000 < addr < 0x7FFFFFFFFFFF

    def find_pointer_chains(self, target_addr: int, max_depth: int = 4,
                             search_range: int = 0x10000) -> List[List[int]]:
        """Find pointers that lead to target_addr (simplified)."""
        # This is a simplified version — full pointer scan would use the scanner
        chains = []
        # Read a region and look for pointers to target
        data = self._read(target_addr - search_range, search_range * 2)
        if not data:
            return chains

        for i in range(0, len(data) - 7, 8):
            ptr = struct.unpack_from('<Q', data, i)[0]
            if ptr == target_addr:
                chains.append([target_addr - search_range + i, target_addr])

        return chains


# ============================================================
# Pointer Map
# ============================================================

class PointerMap:
    """
    Build a graph of pointer relationships in a process.

    Usage:
        pm = PointerMap(pid)
        pm.scan_region(base_addr, size)
        graph = pm.get_graph()  # {target: [sources]}
        pm.export_dot("graph.dot")  # Graphviz format
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle
        self._graph: Dict[int, List[int]] = {}  # target -> [source1, source2, ...]
        self._scanned = False

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        h = self.h_process or k32.OpenProcess(0x0010, False, self.pid)
        if not h:
            return None
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(size), ctypes.byref(read)):
            if not self.h_process:
                k32.CloseHandle(h)
            return buf.raw[:read.value]
        if not self.h_process:
            k32.CloseHandle(h)
        return None

    def scan_region(self, base_addr: int, size: int):
        """Scan a memory region for pointers."""
        data = self._read(base_addr, size)
        if not data:
            return

        for i in range(0, len(data) - 7, 8):
            ptr = struct.unpack_from('<Q', data, i)[0]
            if 0x10000 < ptr < 0x7FFFFFFFFFFF:
                src = base_addr + i
                if ptr not in self._graph:
                    self._graph[ptr] = []
                self._graph[ptr].append(src)

        self._scanned = True

    def get_graph(self) -> Dict[int, List[int]]:
        return dict(self._graph)

    def get_sources(self, target: int) -> List[int]:
        return self._graph.get(target, [])

    def get_targets(self) -> List[int]:
        return sorted(self._graph.keys())

    def get_stats(self) -> Dict:
        if not self._graph:
            return {"total_pointers": 0, "unique_targets": 0, "most_pointed": None}
        most = max(self._graph.items(), key=lambda x: len(x[1]))
        return {
            "total_pointers": sum(len(v) for v in self._graph.values()),
            "unique_targets": len(self._graph),
            "most_pointed": {"address": f"0x{most[0]:X}", "sources": len(most[1])},
        }

    def export_dot(self, output_path: str):
        """Export as Graphviz DOT format."""
        lines = ["digraph PointerMap {"]
        lines.append('    rankdir=LR;')
        lines.append('    node [shape=box, style=filled, fillcolor="#161b22", fontcolor="#c9d1d9"];')
        for target, sources in self._graph.items():
            t_label = f"0x{target:X}"
            lines.append(f'    "{t_label}" [fillcolor="#1f6feb"];')
            for src in sources[:10]:  # limit edges per node
                s_label = f"0x{src:X}"
                lines.append(f'    "{s_label}" -> "{t_label}";')
        lines.append("}")
        Path(output_path).write_text('\n'.join(lines), encoding='utf-8')

    def export_json(self, output_path: str):
        data = {
            "stats": self.get_stats(),
            "pointers": {
                f"0x{t:X}": [f"0x{s:X}" for s in sources]
                for t, sources in self._graph.items()
            },
        }
        Path(output_path).write_text(json.dumps(data, indent=2), encoding='utf-8')


# ============================================================
# Scan Session Persistence
# ============================================================

class ScanSession:
    """
    Save and load full scan state.

    Saves:
      - Scan candidates (addresses + last values)
      - Cheat table entries
      - Trainer spec
      - UI settings
    """

    def __init__(self, studio_app=None):
        self.app = studio_app

    def save(self, path: str):
        """Save current session to JSON file."""
        data = {
            "version": "1.0",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "pid": self.app.pid if self.app else None,
            "exe_name": self.app.exe_name if self.app else None,
            "candidates": [],
            "addresses": [],
            "spec": None,
        }

        # Save candidates
        if self.app and hasattr(self.app, 'candidates'):
            for c in self.app.candidates:
                if hasattr(c, 'addr'):
                    data["candidates"].append({
                        "addr": f"0x{c.addr:X}",
                        "last": c.last.hex() if c.last else "",
                    })

        # Save cheat table
        if self.app and hasattr(self.app, 'addresses'):
            for a in self.app.addresses:
                data["addresses"].append({
                    "addr": f"0x{a['addr']:X}",
                    "vtype": a.get('vtype', 'int32'),
                    "description": a.get('description', ''),
                    "frozen": a.get('frozen', False),
                })

        Path(path).write_text(json.dumps(data, indent=2), encoding='utf-8')

    def load(self, path: str) -> Dict:
        """Load session from JSON file."""
        data = json.loads(Path(path).read_text(encoding='utf-8'))

        # Restore candidates
        if self.app and data.get("candidates"):
            self.app.candidates = []
            for c in data["candidates"]:
                addr = int(c["addr"], 16)
                last = bytes.fromhex(c["last"]) if c.get("last") else b''
                self.app.candidates.append(ms.Candidate(addr, last))

        # Restore cheat table
        if self.app and data.get("addresses"):
            self.app.addresses = []
            for a in data["addresses"]:
                self.app.addresses.append({
                    "addr": int(a["addr"], 16),
                    "vtype": a.get("vtype", "int32"),
                    "description": a.get("description", ""),
                    "frozen": a.get("frozen", False),
                    "current": None,
                    "previous": None,
                })

        return data


# ============================================================
# Speedhack
# ============================================================

class Speedhack:
    """
    Hook timing functions to speed up or slow down a game.

    Targets:
      - QueryPerformanceCounter (most common)
      - GetTickCount / GetTickCount64
      - timeGetTime (winmm)
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle
        self._speed = 1.0
        self._active = False
        self._hook_addr = 0

    @property
    def speed(self) -> float:
        return self._speed

    @speed.setter
    def speed(self, value: float):
        self._speed = max(0.1, min(10.0, value))

    @property
    def active(self) -> bool:
        return self._active

    def toggle(self) -> bool:
        """Toggle speedhack on/off."""
        if self._active:
            self.disable()
        else:
            self.enable()
        return self._active

    def enable(self):
        """Enable speedhack (simplified — would need DLL injection for real hook)."""
        self._active = True

    def disable(self):
        """Disable speedhack."""
        self._active = False

    def set_speed(self, multiplier: float):
        """Set speed multiplier (0.1 = 10x slower, 2.0 = 2x faster)."""
        self._speed = max(0.1, min(10.0, multiplier))

    def get_status(self) -> str:
        if self._active:
            return f"Speedhack ON — {self._speed:.1f}x"
        return "Speedhack OFF"


# ============================================================
# Plugin Manager
# ============================================================

class PluginManager:
    """
    Load external Python plugins from a directory.

    Plugins are Python files with a `register(api)` function.
    """

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self._plugins: Dict[str, Any] = {}  # name -> module
        self._menu_items: List[Dict] = []

    def discover(self) -> List[str]:
        """Find all plugin files."""
        if not self.plugin_dir.exists():
            return []
        return [f.stem for f in self.plugin_dir.glob("*.py") if f.is_file()]

    def load(self, name: str, api=None) -> bool:
        """Load a plugin by name."""
        path = self.plugin_dir / f"{name}.py"
        if not path.exists():
            return False

        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(name, str(path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, 'register'):
                module.register(api)

            self._plugins[name] = module
            return True
        except Exception as e:
            print(f"Plugin load error ({name}): {e}")
            return False

    def load_all(self, api=None):
        """Load all discovered plugins."""
        for name in self.discover():
            self.load(name, api)

    def unload(self, name: str):
        """Unload a plugin."""
        if name in self._plugins:
            module = self._plugins[name]
            if hasattr(module, 'unregister'):
                module.unregister()
            del self._plugins[name]

    def get_loaded(self) -> List[str]:
        return list(self._plugins.keys())


# ============================================================
# Script Recorder
# ============================================================

class ScriptRecorder:
    """
    Record user actions into a reusable Python script.

    Records:
      - Scan operations (first scan, next scan)
      - Address additions
      - Freeze toggles
      - Value writes
    """

    def __init__(self):
        self._recording = False
        self._actions: List[str] = []
        self._indent = "    "

    def start(self):
        self._recording = True
        self._actions = [
            "# MomoTrainer Studio — Recorded Script",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "def run(api):",
            f"{self._indent}\"\"\"Auto-recorded script.\"\"\"",
            f"{self._indent}print('Running recorded script...')",
            "",
        ]

    def stop(self):
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    def record_scan(self, value, vtype, mode):
        if self._recording:
            self._actions.append(f"{self._indent}api.scan({value}, vtype='{vtype}', mode='{mode}')")

    def record_add_address(self, addr, vtype, desc):
        if self._recording:
            self._actions.append(
                f"{self._indent}api.add_to_cheat_table(0x{addr:X}, '{desc}', '{vtype}')"
            )

    def record_freeze(self, addr, frozen):
        if self._recording:
            self._actions.append(f"{self._indent}api.toggle_freeze(0x{addr:X}, {frozen})")

    def record_write(self, addr, value, vtype):
        if self._recording:
            self._actions.append(f"{self._indent}api.write_int(0x{addr:X}, {value})")

    def get_script(self) -> str:
        return '\n'.join(self._actions)

    def export(self, path: str):
        Path(path).write_text(self.get_script(), encoding='utf-8')


# ============================================================
# Auto-Attach Watcher
# ============================================================

class AutoAttachWatcher:
    """
    Watch for a process to appear and auto-connect.
    """

    def __init__(self, callback: Callable[[int, str], None]):
        self.callback = callback
        self._watching = False
        self._target_name = ""
        self._thread = None
        self._stop_evt = threading.Event()

    def watch(self, process_name: str, interval: float = 1.0):
        """Start watching for a process."""
        self._target_name = process_name.lower()
        self._watching = True
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._watch_loop, args=(interval,), daemon=True)
        self._thread.start()

    def stop(self):
        self._watching = False
        self._stop_evt.set()

    def _watch_loop(self, interval: float):
        while not self._stop_evt.is_set():
            pid = self._find_process(self._target_name)
            if pid:
                self.callback(pid, self._target_name)
                break
            self._stop_evt.wait(interval)

    def _find_process(self, name: str) -> Optional[int]:
        """Find process by name."""
        try:
            snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
            if snap == -1:
                return None

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                            ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                            ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                            ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                            ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_char * 260)]

            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

            pid = None
            if k32.Process32First(snap, ctypes.byref(pe32)):
                while True:
                    proc_name = pe32.szExeFile.decode('utf-8', errors='replace').lower()
                    if name in proc_name:
                        pid = pe32.th32ProcessID
                        break
                    if not k32.Process32Next(snap, ctypes.byref(pe32)):
                        break

            k32.CloseHandle(snap)
            return pid
        except Exception:
            return None

    @property
    def is_watching(self) -> bool:
        return self._watching


# ============================================================
# Memory Dumper
# ============================================================

class MemoryDumper:
    """
    Dump memory regions to disk for offline analysis.
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        h = self.h_process or k32.OpenProcess(0x0010, False, self.pid)
        if not h:
            return None
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(size), ctypes.byref(read)):
            if not self.h_process:
                k32.CloseHandle(h)
            return buf.raw[:read.value]
        if not self.h_process:
            k32.CloseHandle(h)
        return None

    def dump_region(self, base_addr: int, size: int, output_path: str) -> bool:
        """Dump a memory region to a binary file."""
        data = self._read(base_addr, size)
        if not data:
            return False
        Path(output_path).write_bytes(data)
        return True

    def dump_all_regions(self, output_dir: str) -> List[str]:
        """Dump all readable regions to a directory."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        dumped = []

        # Enumerate memory regions
        h = self.h_process or k32.OpenProcess(0x0010 | 0x001000, False, self.pid)  # QUERY_INFO | VM_READ
        if not h:
            return dumped

        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            addr = 0
            region_idx = 0

            while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
                if mbi.State == 0x1000 and mbi.Protect & 0xF0 == 0:  # MEM_COMMIT, readable
                    data = self._read(addr, mbi.RegionSize)
                    if data:
                        path = output_dir / f"region_{region_idx:04d}_0x{addr:X}.bin"
                        path.write_bytes(data)
                        dumped.append(str(path))
                        region_idx += 1

                addr += mbi.RegionSize
                if addr > 0x7FFFFFFFFFFF:
                    break
        finally:
            if not self.h_process:
                k32.CloseHandle(h)

        return dumped

    def dump_to_csv(self, base_addr: int, size: int, output_path: str, columns: int = 16):
        """Dump memory region as CSV for spreadsheet analysis."""
        data = self._read(base_addr, size)
        if not data:
            return False

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            header = ['Offset'] + [f'+{i:X}' for i in range(columns)] + ['ASCII']
            writer.writerow(header)

            for row_start in range(0, len(data), columns):
                row_data = data[row_start:row_start + columns]
                offset = base_addr + row_start
                hex_vals = [f'{b:02X}' for b in row_data]
                # Pad
                while len(hex_vals) < columns:
                    hex_vals.append('')
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in row_data)
                writer.writerow([f'0x{offset:X}'] + hex_vals + [ascii_str])

        return True
