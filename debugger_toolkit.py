"""
debugger_toolkit.py — Advanced debugging features for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - ConditionalBreakpoint  — break only when register/memory matches
  - TraceRecorder          — single-step execution trace with disassembly
  - ModuleMap              — enumerate loaded modules + exports
  - ExportManager          — generate IDA Pro / Ghidra / x64dbg scripts

Builds on debugger_unified.py and call_stack_tracer.py.
"""

import ctypes
import json
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import call_stack_tracer as cst

# Win32 constants
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = -1

k32 = ctypes.windll.kernel32

# ntdll for NtQueryInformationProcess (module info)
ntdll = ctypes.windll.ntdll


# ============================================================
# Conditional Breakpoint
# ============================================================

@dataclass
class BreakCondition:
    """
    Condition that must be satisfied for a breakpoint to fire.

    Supported types:
      reg_equal     — register == value (e.g. RAX == 0x1234)
      reg_not_equal — register != value
      reg_greater   — register > value
      reg_less      — register < value
      mem_equal     — byte at address == value
      mem_dword_eq  — dword at address == value
      mem_string    — string at address contains substring
      hit_count     — break only on Nth hit (count >= N)
    """
    cond_type: str = "reg_equal"
    register: str = "RAX"
    value: int = 0
    address: int = 0
    string: str = ""
    hit_target: int = 1
    _hit_count: int = 0

    def evaluate(self, context: dict) -> bool:
        """Evaluate condition against a thread context dict."""
        ctype = self.cond_type

        if ctype == "reg_equal":
            return context.get(self.register.upper(), 0) == self.value
        elif ctype == "reg_not_equal":
            return context.get(self.register.upper(), 0) != self.value
        elif ctype == "reg_greater":
            return context.get(self.register.upper(), 0) > self.value
        elif ctype == "reg_less":
            return context.get(self.register.upper(), 0) < self.value
        elif ctype == "hit_count":
            self._hit_count += 1
            return self._hit_count >= self.hit_target
        elif ctype.startswith("mem_"):
            return self._eval_memory(context)

        return True  # no condition = always fire

    def _eval_memory(self, context: dict) -> bool:
        """Read process memory and compare."""
        pid = context.get("_pid")
        h = context.get("_handle")
        if not h and pid:
            h = k32.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
            if not h:
                return False
            close = True
        else:
            close = False

        try:
            if self.cond_type == "mem_equal":
                buf = ctypes.create_string_buffer(1)
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, self.address, buf, 1, ctypes.byref(read)):
                    return buf[0] == self.value
            elif self.cond_type == "mem_dword_eq":
                buf = ctypes.create_string_buffer(4)
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, self.address, buf, 4, ctypes.byref(read)):
                    return struct.unpack('<I', buf.raw)[0] == self.value
            elif self.cond_type == "mem_string":
                buf = ctypes.create_string_buffer(256)
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, self.address, buf, 256, ctypes.byref(read)):
                    data = buf.raw.split(b'\x00')[0]
                    return self.string.encode() in data
        finally:
            if close:
                k32.CloseHandle(h)

        return False

    def describe(self) -> str:
        """Human-readable description."""
        if self.cond_type == "reg_equal":
            return f"{self.register} == 0x{self.value:X}"
        elif self.cond_type == "reg_not_equal":
            return f"{self.register} != 0x{self.value:X}"
        elif self.cond_type == "reg_greater":
            return f"{self.register} > 0x{self.value:X}"
        elif self.cond_type == "reg_less":
            return f"{self.register} < 0x{self.value:X}"
        elif self.cond_type == "mem_equal":
            return f"byte[0x{self.address:X}] == 0x{self.value:02X}"
        elif self.cond_type == "mem_dword_eq":
            return f"dword[0x{self.address:X}] == 0x{self.value:X}"
        elif self.cond_type == "mem_string":
            return f"str[0x{self.address:X}] contains \"{self.string}\""
        elif self.cond_type == "hit_count":
            return f"hit #{self._hit_count}/{self.hit_target}"
        return "always"


# ============================================================
# Trace Recorder
# ============================================================

@dataclass
class TraceEntry:
    """Single execution trace record."""
    address: int
    thread_id: int
    timestamp: float
    disassembly: str = ""
    registers: Dict[str, int] = field(default_factory=dict)
    hit_breakpoint: Optional[int] = None  # address of BP that triggered


class TraceRecorder:
    """
    Records execution trace from single-step debugging.

    Usage:
        recorder = TraceRecorder(pid)
        recorder.start()
        # ... run game ...
        recorder.stop()
        entries = recorder.get_trace()
        recorder.export_ida("trace.py")
    """

    def __init__(self, pid: int, process_handle=None, max_entries: int = 10000):
        self.pid = pid
        self.h_process = process_handle
        self.max_entries = max_entries
        self._trace: List[TraceEntry] = []
        self._recording = False
        self._start_time: float = 0
        self._breakpoint_hits: Dict[int, int] = {}  # addr -> hit count

    def start(self):
        """Begin trace recording."""
        self._trace.clear()
        self._breakpoint_hits.clear()
        self._recording = True
        self._start_time = time.perf_counter()

    def stop(self):
        """Stop trace recording."""
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    def record_instruction(self, address: int, thread_id: int,
                            disasm: str = "", registers: Optional[Dict] = None):
        """Record a single instruction execution."""
        if not self._recording:
            return
        if len(self._trace) >= self.max_entries:
            self._recording = False  # auto-stop at cap
            return

        entry = TraceEntry(
            address=address,
            thread_id=thread_id,
            timestamp=time.perf_counter() - self._start_time,
            disassembly=disasm,
            registers=registers or {},
        )
        self._trace.append(entry)

    def record_breakpoint_hit(self, bp_address: int, rip: int, thread_id: int):
        """Record a breakpoint hit in the trace."""
        if not self._recording:
            return
        self._breakpoint_hits[bp_address] = self._breakpoint_hits.get(bp_address, 0) + 1
        if self._trace:
            self._trace[-1].hit_breakpoint = bp_address

    def get_trace(self) -> List[TraceEntry]:
        """Get recorded trace entries."""
        return list(self._trace)

    def get_breakpoint_stats(self) -> Dict[int, int]:
        """Get hit counts per breakpoint address."""
        return dict(self._breakpoint_hits)

    def get_hotspots(self, top_n: int = 20) -> List[Tuple[int, int]]:
        """Get most-executed addresses (address, count)."""
        counts: Dict[int, int] = {}
        for entry in self._trace:
            counts[entry.address] = counts.get(entry.address, 0) + 1
        sorted_addrs = sorted(counts.items(), key=lambda x: -x[1])
        return sorted_addrs[:top_n]

    def get_unique_addresses(self) -> List[int]:
        """Get sorted unique addresses visited."""
        return sorted(set(e.address for e in self._trace))

    def get_thread_ids(self) -> List[int]:
        """Get unique thread IDs in trace."""
        return sorted(set(e.thread_id for e in self._trace))

    def clear(self):
        """Clear all trace data."""
        self._trace.clear()
        self._breakpoint_hits.clear()

    @property
    def entry_count(self) -> int:
        return len(self._trace)

    @property
    def duration(self) -> float:
        """Total trace duration in seconds."""
        if not self._trace:
            return 0.0
        return self._trace[-1].timestamp

    # ---- Export methods ----

    def export_json(self, output_path: str):
        """Export trace as JSON for external analysis."""
        data = {
            "metadata": {
                "pid": self.pid,
                "entry_count": len(self._trace),
                "duration_seconds": self.duration,
                "unique_addresses": len(self.get_unique_addresses()),
                "threads": self.get_thread_ids(),
            },
            "breakpoint_hits": {f"0x{k:X}": v for k, v in self._breakpoint_hits.items()},
            "trace": [
                {
                    "addr": f"0x{e.address:X}",
                    "thread": e.thread_id,
                    "time": f"{e.timestamp:.6f}",
                    "disasm": e.disassembly,
                    "bp": f"0x{e.hit_breakpoint:X}" if e.hit_breakpoint else None,
                }
                for e in self._trace
            ],
        }
        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def export_ida_comments(self, output_path: str):
        """Export trace as IDA Python script with comments at visited addresses."""
        lines = [
            "# IDA Python — Execution trace comments",
            f"# Generated by MomoTrainer Studio — {len(self._trace)} entries",
            "",
            "import ida_bytes",
            "import ida_funcs",
            "",
            "def apply_trace():",
        ]

        # Count visits per address for frequency comments
        visit_counts: Dict[int, int] = {}
        for e in self._trace:
            visit_counts[e.address] = visit_counts.get(e.address, 0) + 1

        for addr, count in sorted(visit_counts.items(), key=lambda x: -x[1])[:500]:
            lines.append(f'    ida_bytes.set_cmt(0x{addr:X}, "trace: {count} visits", False)')

        lines.append("")
        lines.append("apply_trace()")
        lines.append('# print("Trace comments applied.")')

        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def export_ghidra_script(self, output_path: str):
        """Export trace as Ghidra script with plate comments."""
        lines = [
            "// Ghidra script — Execution trace comments",
            f"// Generated by MomoTrainer Studio — {len(self._trace)} entries",
            "// @category MomoTrainer",
            "",
            "import ghidra.program.model.listing as listing",
            "",
            "func = getCurrentProgram().getFunctionManager()",
            "listing = getCurrentProgram().getListing()",
            "",
        ]

        visit_counts: Dict[int, int] = {}
        for e in self._trace:
            visit_counts[e.address] = visit_counts.get(e.address, 0) + 1

        for addr, count in sorted(visit_counts.items(), key=lambda x: -x[1])[:500]:
            lines.append(
                f'addr = toAddr(0x{addr:X}); '
                f'insn = listing.getInstructionAt(addr); '
                f'if insn: insn.setComment(listing.PLATE_COMMENT, "trace: {count} visits")'
            )

        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def export_x64dbg(self, output_path: str):
        """Export breakpoint hit counts as x64dbg script."""
        lines = [
            f"// x64dbg script — Breakpoint stats from trace",
            f"// {len(self._trace)} instructions traced",
            "",
        ]
        for addr, count in sorted(self._breakpoint_hits.items(), key=lambda x: -x[1]):
            lines.append(f"setbp 0x{addr:X}  // {count} hits")
            lines.append(f"comment \"0x{addr:X}: {count} hits\", 0x{addr:X}")

        Path(output_path).write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# Module Map — enumerate loaded modules + exports
# ============================================================

@dataclass
class ModuleInfo:
    """Information about a loaded module."""
    name: str
    base: int
    size: int
    path: str = ""
    entry_point: int = 0
    exports: List[Tuple[str, int]] = field(default_factory=list)


class ModuleMap:
    """
    Enumerate loaded modules and their exports for a process.

    Usage:
        mm = ModuleMap(pid)
        modules = mm.snapshot()
        kernel = mm.get_module("kernel32.dll")
        exports = mm.get_exports(kernel)
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle
        self._modules: List[ModuleInfo] = []
        self._by_name: Dict[str, ModuleInfo] = {}

    def snapshot(self) -> List[ModuleInfo]:
        """Take a fresh snapshot of loaded modules."""
        self._modules.clear()
        self._by_name.clear()

        # Use CreateToolhelp32Snapshot for module enumeration
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        if snap == INVALID_HANDLE_VALUE:
            return []

        try:
            class MODULEENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("GlblcntUsage", ctypes.c_ulong),
                    ("ProccntUsage", ctypes.c_ulong),
                    ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                    ("modBaseSize", ctypes.c_ulong),
                    ("hModule", ctypes.c_void_p),
                    ("szModule", ctypes.c_char * 256),
                    ("szExePath", ctypes.c_char * 260),
                ]

            me32 = MODULEENTRY32()
            me32.dwSize = ctypes.sizeof(MODULEENTRY32)

            if k32.Module32First(snap, ctypes.byref(me32)):
                while True:
                    name = me32.szModule.decode("utf-8", errors="replace")
                    path = me32.szExePath.decode("utf-8", errors="replace")
                    base = ctypes.addressof(me32.modBaseAddr.contents)
                    size = me32.modBaseSize

                    mod = ModuleInfo(name=name, base=base, size=size, path=path)
                    self._modules.append(mod)
                    self._by_name[name.lower()] = mod

                    if not k32.Module32Next(snap, ctypes.byref(me32)):
                        break
        finally:
            k32.CloseHandle(snap)

        return list(self._modules)

    def get_module(self, name: str) -> Optional[ModuleInfo]:
        """Get module info by name (case-insensitive)."""
        return self._by_name.get(name.lower())

    def find_module_containing(self, address: int) -> Optional[ModuleInfo]:
        """Find which module contains the given address."""
        for mod in self._modules:
            if mod.base <= address < mod.base + mod.size:
                return mod
        return None

    def get_exports(self, module: ModuleInfo) -> List[Tuple[str, int]]:
        """
        Parse PE export table to get exported function names + addresses.
        Returns list of (name, address).
        """
        if module.exports:
            return module.exports

        h = self.h_process
        close = False
        if not h:
            h = k32.OpenProcess(0x0010 | 0x0008, False, self.pid)  # VM_READ | VM_OPERATION
            if not h:
                return []
            close = True

        try:
            exports = self._parse_exports(h, module)
            module.exports = exports
            return exports
        finally:
            if close:
                k32.CloseHandle(h)

    def _parse_exports(self, h, module: ModuleInfo) -> List[Tuple[str, int]]:
        """Parse PE export directory from module base."""
        try:
            # Read DOS header
            dos_buf = ctypes.create_string_buffer(64)
            read = ctypes.c_size_t(0)
            if not k32.ReadProcessMemory(h, module.base, dos_buf, 64, ctypes.byref(read)):
                return []
            e_lfanew = struct.unpack_from('<I', dos_buf.raw, 0x3C)[0]

            # Read PE signature + optional header magic
            pe_buf = ctypes.create_string_buffer(24)
            if not k32.ReadProcessMemory(h, module.base + e_lfanew, pe_buf, 24, ctypes.byref(read)):
                return []
            if pe_buf.raw[:4] != b'PE\x00\x00':
                return []

            # Determine 32/64-bit
            pe_format = struct.unpack_from('<H', pe_buf.raw, 4 + 20)[0]  # Magic in Optional Header
            is_64 = (pe_format == 0x20b)

            # Export directory RVA
            if is_64:
                # 64-bit: export dir is at e_lfanew + 4(COFF) + 20(OH-head) + 112(offset)
                export_rva_offset = e_lfanew + 4 + 20 + 112
            else:
                export_rva_offset = e_lfanew + 4 + 20 + 96

            exp_buf = ctypes.create_string_buffer(8)
            if not k32.ReadProcessMemory(h, module.base + export_rva_offset, exp_buf, 8, ctypes.byref(read)):
                return []
            export_rva, export_size = struct.unpack('<II', exp_buf.raw)
            if export_rva == 0:
                return []

            export_base = module.base + export_rva

            # Read export directory (40 bytes)
            dir_buf = ctypes.create_string_buffer(40)
            if not k32.ReadProcessMemory(h, export_base, dir_buf, 40, ctypes.byref(read)):
                return []

            names_rva, = struct.unpack_from('<I', dir_buf.raw, 20)  # AddressOfNames
            ordinals_rva, = struct.unpack_from('<I', dir_buf.raw, 24)  # AddressOfNameOrdinals
            functions_rva, = struct.unpack_from('<I', dir_buf.raw, 16)  # AddressOfFunctions
            num_names, = struct.unpack_from('<I', dir_buf.raw, 28)  # NumberOfNames

            if num_names == 0 or num_names > 65536:
                return []

            # Read name RVAs
            names_buf = ctypes.create_string_buffer(num_names * 4)
            if not k32.ReadProcessMemory(h, module.base + names_rva, names_buf, num_names * 4, ctypes.byref(read)):
                return []

            name_rvas = [struct.unpack_from('<I', names_buf.raw, i * 4)[0] for i in range(num_names)]

            # Read ordinals
            ord_buf = ctypes.create_string_buffer(num_names * 2)
            if not k32.ReadProcessMemory(h, module.base + ordinals_rva, ord_buf, num_names * 2, ctypes.byref(read)):
                return []

            ordinals = [struct.unpack_from('<H', ord_buf.raw, i * 2)[0] for i in range(num_names)]

            # Read function RVAs
            func_buf = ctypes.create_string_buffer(num_names * 4)
            if not k32.ReadProcessMemory(h, module.base + functions_rva, func_buf, num_names * 4, ctypes.byref(read)):
                return []

            func_rvas = [struct.unpack_from('<I', func_buf.raw, i * 4)[0] for i in range(num_names)]

            # Resolve names
            exports = []
            for i in range(num_names):
                # Read function name
                name_buf = ctypes.create_string_buffer(256)
                if k32.ReadProcessMemory(h, module.base + name_rvas[i], name_buf, 256, ctypes.byref(read)):
                    name = name_buf.raw.split(b'\x00')[0].decode('ascii', errors='replace')
                    if name:
                        addr = module.base + func_rvas[ordinals[i]]
                        exports.append((name, addr))

            return sorted(exports, key=lambda x: x[0])

        except Exception:
            return []

    def resolve_address(self, address: int) -> str:
        """Resolve address to module!symbol+offset string."""
        mod = self.find_module_containing(address)
        if not mod:
            return f"0x{address:X}"

        offset = address - mod.base
        exports = self.get_exports(mod)

        # Find closest export at or below this address
        best_name = ""
        best_addr = 0
        for name, exp_addr in exports:
            if exp_addr <= address and exp_addr > best_addr:
                best_name = name
                best_addr = exp_addr

        if best_name:
            delta = address - best_addr
            if delta == 0:
                return f"{mod.name}!{best_name}"
            return f"{mod.name}!{best_name}+0x{delta:X}"

        return f"{mod.name}+0x{offset:X}"

    def format_table(self) -> str:
        """Format module list as text table."""
        lines = [f"{'Base':<18} {'Size':>10} {'Name':<30} {'Path'}"]
        lines.append("-" * 90)
        for mod in sorted(self._modules, key=lambda m: m.base):
            lines.append(
                f"0x{mod.base:016X} {mod.size:>10,} {mod.name:<30} {mod.path}"
            )
        return "\n".join(lines)

    def export_json(self, output_path: str):
        """Export module map as JSON."""
        data = {
            "pid": self.pid,
            "module_count": len(self._modules),
            "modules": [
                {
                    "name": m.name,
                    "base": f"0x{m.base:X}",
                    "size": m.size,
                    "path": m.path,
                    "exports_count": len(self.get_exports(m)),
                }
                for m in self._modules
            ],
        }
        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def __len__(self):
        return len(self._modules)

    def __iter__(self):
        return iter(self._modules)
