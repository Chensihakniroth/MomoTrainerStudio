"""
scripting_api.py - Python Scripting API for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Read/write memory operations
  - Scanner operations (scan, rescan)
  - Debugger operations (set breakpoint, get hits)
  - Cheat table operations
  - Export utilities (IDA, signatures)

Usage:
    from scripting_api import MomoTrainerAPI
    
    api = MomoTrainerAPI(studio)
    api.set_breakpoint(0x140001000, mode='write')
    hits = api.get_breakpoint_hits(0x140001000)
    api.write_bytes(hits[0]['rip'], b'\\x90\\x90\\x90\\x90\\x90')
"""

import ctypes
import html
import json
import struct
from typing import Optional, List, Dict, Any, Union, Callable
from pathlib import Path

import memory_scanner as ms
import debugger_unified

k32 = ctypes.windll.kernel32


class MomoTrainerAPI:
    """
    Public API for MomoTrainer Studio scripting.
    
    Provides programmatic access to:
    - Memory read/write
    - Scanner operations
    - Debugger operations
    - Cheat table management
    - Export utilities
    """
    
    def __init__(self, studio=None, pid: Optional[int] = None,
                 process_handle=None, scanner=None, debugger=None):
        """
        Initialize API.
        
        studio: main Studio instance (optional, provides all components)
        pid: target process ID
        process_handle: open process handle
        scanner: memory scanner instance (unused — API calls ms.first_scan directly)
        debugger: unified debugger instance (unused — API manages its own)
        """
        self.studio = studio
        
        if studio:
            # Extract components from studio
            self.pid = getattr(studio, 'pid', pid)
            # GUI stores handle as self.h, not self.h_process
            self.process_handle = getattr(studio, 'h', None) or getattr(studio, 'h_process', process_handle)
        else:
            self.pid = pid
            self.process_handle = process_handle

        # --- scan state ---
        self._candidates: List[int] = []   # surviving addresses after last scan
        self._vtype: str = 'int32'         # value type used in last scan
        self._last_scan_count: int = 0

        # --- breakpoint state ---
        self._bp_manager: Optional[debugger_unified.MultiBreakpointManager] = None
            
    # ========== Memory Operations ==========
    
    def read_int(self, address: int, size: int = 4, signed: bool = True) -> int:
        """
        Read integer from address.
        
        address: memory address
        size: bytes to read (1, 2, 4, 8)
        signed: interpret as signed integer
        
        Returns integer value.
        """
        if size not in (1, 2, 4, 8):
            raise ValueError("integer size must be 1, 2, 4, or 8 bytes")
        data = self.read_bytes(address, size)
        if data is None or len(data) != size:
            raise ValueError(f"Failed to read memory at 0x{address:X}")
            
        fmt = {1: 'b' if signed else 'B', 2: 'h' if signed else 'H',
               4: 'i' if signed else 'I', 8: 'q' if signed else 'Q'}
               
        return struct.unpack('<' + fmt[size], data)[0]
        
    def read_uint8(self, address: int) -> int:
        """Read unsigned 8-bit integer."""
        return self.read_int(address, 1, signed=False)
        
    def read_uint16(self, address: int) -> int:
        """Read unsigned 16-bit integer."""
        return self.read_int(address, 2, signed=False)
        
    def read_uint32(self, address: int) -> int:
        """Read unsigned 32-bit integer."""
        return self.read_int(address, 4, signed=False)
        
    def read_uint64(self, address: int) -> int:
        """Read unsigned 64-bit integer."""
        return self.read_int(address, 8, signed=False)
        
    def read_int32(self, address: int) -> int:
        """Read signed 32-bit integer."""
        return self.read_int(address, 4, signed=True)
        
    def read_int64(self, address: int) -> int:
        """Read signed 64-bit integer."""
        return self.read_int(address, 8, signed=True)
        
    def read_float(self, address: int) -> float:
        """Read 32-bit float."""
        data = self.read_bytes(address, 4)
        if not data:
            raise ValueError(f"Failed to read memory at 0x{address:X}")
        return struct.unpack('<f', data)[0]
        
    def read_double(self, address: int) -> float:
        """Read 64-bit double."""
        data = self.read_bytes(address, 8)
        if not data:
            raise ValueError(f"Failed to read memory at 0x{address:X}")
        return struct.unpack('<d', data)[0]
        
    def read_string(self, address: int, max_length: int = 256,
                    encoding: str = 'utf-8') -> str:
        """
        Read null-terminated string.
        
        address: memory address
        max_length: maximum bytes to read
        encoding: string encoding (default utf-8)
        
        Returns string value.
        """
        data = self.read_bytes(address, max_length)
        if not data:
            return ""
            
        # Find null terminator
        null_pos = data.find(b'\x00')
        if null_pos >= 0:
            data = data[:null_pos]
            
        return data.decode(encoding, errors='replace')
        
    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """
        Read raw bytes from address.
        
        address: memory address
        size: number of bytes to read
        
        Returns bytes or None if failed.
        """
        try:
            address = int(address)
            size = int(size)
        except (TypeError, ValueError) as exc:
            raise ValueError("address and size must be integers") from exc
        if address < 0 or size < 1 or size > 16 * 1024 * 1024:
            raise ValueError("address must be non-negative and size must be 1-16MB")
        if self.process_handle:
            return self._read_with_handle(self.process_handle, address, size)
        elif self.pid:
            h = k32.OpenProcess(0x0010, False, self.pid)
            if not h:
                return None
            try:
                return self._read_with_handle(h, address, size)
            finally:
                k32.CloseHandle(h)
        return None

    # --- Win32 function prototypes (64-safe) ---
    _rpm = k32.ReadProcessMemory
    _rpm.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _rpm.restype = ctypes.c_bool

    _wpm = k32.WriteProcessMemory
    _wpm.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _wpm.restype = ctypes.c_bool

    _vpe = k32.VirtualProtectEx
    _vpe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    _vpe.restype = ctypes.c_bool

    def _read_with_handle(self, h, address: int, size: int) -> Optional[bytes]:
        """Read memory with given handle. 64-bit address safe via argtypes."""
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)

        if self._rpm(h, ctypes.c_void_p(address), buffer, ctypes.c_size_t(size), ctypes.byref(read)):
            return buffer.raw[:read.value]
        return None
        
    def write_int(self, address: int, value: int, size: int = 4):
        """
        Write integer to address.
        
        address: memory address
        value: integer value to write
        size: bytes to write (1, 2, 4, 8)
        """
        fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
        if size not in fmt:
            raise ValueError("integer size must be 1, 2, 4, or 8 bytes")
        value = int(value)
        data = struct.pack('<' + fmt[size], value & ((1 << (size * 8)) - 1))
        if not self.write_bytes(address, data):
            raise ValueError(f"Failed to write memory at 0x{int(address):X}")
        
    def write_uint8(self, address: int, value: int):
        """Write unsigned 8-bit integer."""
        self.write_int(address, value, 1)
        
    def write_uint16(self, address: int, value: int):
        """Write unsigned 16-bit integer."""
        self.write_int(address, value, 2)
        
    def write_uint32(self, address: int, value: int):
        """Write unsigned 32-bit integer."""
        self.write_int(address, value, 4)
        
    def write_uint64(self, address: int, value: int):
        """Write unsigned 64-bit integer."""
        self.write_int(address, value, 8)
        
    def write_float(self, address: int, value: float):
        """Write 32-bit float."""
        data = struct.pack('<f', value)
        self.write_bytes(address, data)
        
    def write_double(self, address: int, value: float):
        """Write 64-bit double."""
        data = struct.pack('<d', value)
        self.write_bytes(address, data)
        
    def write_string(self, address: int, value: str, encoding: str = 'utf-8'):
        """
        Write string (null-terminated).
        
        address: memory address
        value: string to write
        encoding: string encoding (default utf-8)
        """
        data = value.encode(encoding) + b'\x00'
        self.write_bytes(address, data)
        
    def write_bytes(self, address: int, data: bytes) -> bool:
        """
        Write raw bytes to address.
        
        address: memory address
        data: bytes to write
        
        Returns True if successful.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            raise ValueError("data must be a non-empty bytes-like value")
        address = int(address)
        if address < 0:
            raise ValueError("address must be non-negative")
        data = bytes(data)
        if self.process_handle:
            return self._write_with_handle(self.process_handle, address, data)
        elif self.pid:
            h = k32.OpenProcess(0x0020 | 0x0008, False, self.pid)
            if not h:
                return False
            try:
                return self._write_with_handle(h, address, data)
            finally:
                k32.CloseHandle(h)
        return False
        
    def _write_with_handle(self, h, address: int, data: bytes) -> bool:
        """Write memory with given handle. 64-bit address safe via argtypes."""
        # Change memory protection
        old_prot = ctypes.c_ulong(0)
        self._vpe(h, ctypes.c_void_p(address), ctypes.c_size_t(len(data)), ctypes.c_ulong(0x40), ctypes.byref(old_prot))
        
        written = ctypes.c_size_t(0)
        result = self._wpm(h, ctypes.c_void_p(address), data, ctypes.c_size_t(len(data)), ctypes.byref(written))
        
        # Restore protection (ignore failure — write already happened or not)
        dummy = ctypes.c_ulong(0)
        self._vpe(h, ctypes.c_void_p(address), ctypes.c_size_t(len(data)), old_prot.value, ctypes.byref(dummy))
        
        return bool(result and written.value == len(data))
        
    def write_nop(self, address: int, count: int = 1) -> bool:
        """
        Write NOP instructions.
        
        address: memory address
        count: number of NOPs to write
        
        Returns True if successful.
        """
        return self.write_bytes(address, b'\x90' * count)
        
    # ========== Scanner Operations ==========
    
    def scan(self, value: Union[int, float, str, bytes], vtype: str = 'int32',
             mode: str = 'exact') -> List[int]:
        """
        Run a fresh memory scan across the entire process address space.

        value: value to search for
        vtype: value type ('int8', 'int16', 'int32', 'int64', 'float', 'double', 'string', 'aob')
        mode: scan mode ('exact', 'greater', 'less', 'between', 'initial')

        Returns list of matching addresses.
        """
        if not self._has_process():
            raise RuntimeError("No process attached — call attach(pid) or pass pid to constructor")

        high = None  # scripting API keeps it simple; caller can use ms.rescan for between

        self._vtype = vtype
        raw = ms.first_scan(
            self._get_handle(), vtype, value,
            mode=mode, high=high, nthreads=self._nthreads(),
        )
        # first_scan returns Candidate namedtuples — store as-is, expose .addr
        self._candidates = list(raw)
        self._last_scan_count = len(self._candidates)
        return [c.addr if hasattr(c, 'addr') else c for c in self._candidates]

    def rescan(self, value: Union[int, float, str, bytes], mode: str = 'exact',
               high: Optional[Union[int, float]] = None) -> List[int]:
        """
        Narrow the previous result set by rescanning stored candidates.

        value: value (or threshold) to compare against
        mode: 'exact', 'greater', 'less', 'between', 'increased', 'decreased',
              'unchanged', 'changed'
        high: upper bound when mode='between'

        Returns updated list of surviving addresses.
        """
        if not self._candidates:
            raise RuntimeError("No candidates to rescan — run scan() first")
        if not self._has_process():
            raise RuntimeError("No process attached")

        self._candidates = list(ms.rescan(
            self._get_handle(), self._candidates, self._vtype, value,
            mode=mode, high=high, nthreads=self._nthreads(),
        ))
        self._last_scan_count = len(self._candidates)
        return [c.addr if hasattr(c, 'addr') else c for c in self._candidates]

    def get_scan_results(self, limit: int = 1000) -> List[int]:
        """Return up to *limit* addresses from the last scan/rescan."""
        trimmed = self._candidates[:limit]
        return [c.addr if hasattr(c, 'addr') else c for c in trimmed]

    def clear_scan_results(self):
        """Discard all scan candidates."""
        self._candidates.clear()
        self._last_scan_count = 0

    @property
    def scan_count(self) -> int:
        """Number of results from the most recent scan/rescan."""
        return self._last_scan_count

    # ========== Debugger Operations ==========

    def _ensure_bp_manager(self) -> debugger_unified.MultiBreakpointManager:
        """Lazily create the breakpoint manager (needs a valid pid)."""
        if self._bp_manager is None:
            if not self.pid:
                raise RuntimeError("No pid available for breakpoint manager")
            self._bp_manager = debugger_unified.MultiBreakpointManager(self.pid)
        return self._bp_manager

    def set_breakpoint(self, address: int, mode: str = 'write',
                       size: int = 4, callback: Optional[Callable] = None) -> bool:
        """
        Start monitoring an address for memory access.

        address: memory address to watch
        mode:   'access' (read+write) or 'write' (write-only)
        size:   1, 2, 4, or 8 bytes
        callback: optional function(hit_info) called on every hit

        Returns True if the breakpoint was added and started successfully.
        """
        mgr = self._ensure_bp_manager()
        if callback:
            mgr.on_hit = callback
        added = mgr.add_breakpoint(address, mode=mode, size=size)
        if added:
            mgr._debuggers[address].start()
        return added

    def remove_breakpoint(self, address: int):
        """Stop monitoring *address* and remove it from the breakpoint list."""
        if self._bp_manager:
            self._bp_manager.remove_breakpoint(address)

    def get_breakpoint_hits(self, address: int) -> List[Dict]:
        """
        Retrieve all recorded hits for a breakpoint.

        Returns list of hit dicts, each containing at minimum:
            - rip:          instruction pointer that triggered the hit
            - breakpoint_address: the watched address
            - thread_id:    thread id
            - timestamp:    time of hit
        """
        if not self._bp_manager:
            return []
        all_hits = self._bp_manager.get_all_hits()
        raw = all_hits.get(address, {})
        # UnifiedDebugger.get_hits() returns {rip: hit_info, ...}
        if isinstance(raw, dict):
            return [
                {**info, 'rip': rip}
                for rip, info in raw.items()
                if isinstance(info, dict)
            ]
        return raw if isinstance(raw, list) else []

    def get_all_breakpoints(self) -> List[int]:
        """List all actively monitored breakpoint addresses."""
        if not self._bp_manager:
            return []
        return self._bp_manager.list_breakpoints()

    def is_debugger_running(self) -> bool:
        """True if any breakpoint is currently active."""
        if not self._bp_manager:
            return False
        return any(
            udb.is_running()
            for udb in self._bp_manager._debuggers.values()
        )

    def stop_all_breakpoints(self):
        """Stop every active breakpoint (does not remove them)."""
        if self._bp_manager:
            self._bp_manager.stop_all()

    # ========== Helpers ==========

    def _get_handle(self):
        """Return an open process handle, opening one from pid if needed."""
        if self.process_handle:
            return self.process_handle
        if not self.pid:
            raise RuntimeError("No process attached")
        # PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
        handle = k32.OpenProcess(0x0010 | 0x0008 | 0x1000, False, self.pid)
        if not handle:
            raise RuntimeError(f"OpenProcess failed for pid {self.pid}")
        return handle

    def _has_process(self) -> bool:
        return bool(self.process_handle) or bool(self.pid)

    @staticmethod
    def _nthreads() -> int:
        import os
        return min(4, max(1, os.cpu_count() or 1))
        
    # ========== Cheat Table Operations ==========
    
    def add_to_cheat_table(self, address: int, description: str = "",
                           vtype: str = 'int32', freeze: bool = False):
        """
        Add address to cheat table.
        
        address: memory address
        description: entry description
        vtype: value type
        freeze: freeze value
        """
        if self.studio and hasattr(self.studio, 'add_to_cheat_table'):
            self.studio.add_to_cheat_table(address, description, vtype, freeze)
            
    def remove_from_cheat_table(self, address: int):
        """Remove address from cheat table."""
        if self.studio and hasattr(self.studio, 'remove_from_cheat_table'):
            self.studio.remove_from_cheat_table(address)
            
    def get_cheat_table(self) -> List[Dict]:
        """Get all cheat table entries."""
        if self.studio and hasattr(self.studio, 'get_cheat_table'):
            return self.studio.get_cheat_table()
        return []
        
    def toggle_freeze(self, address: int, freeze: Optional[bool] = None):
        """
        Toggle freeze state for address.
        
        address: memory address
        freeze: True to freeze, False to unfreeze, None to toggle
        """
        if self.studio and hasattr(self.studio, 'toggle_freeze'):
            self.studio.toggle_freeze(address, freeze)
            
    # ========== Export Operations ==========
    
    def export_to_ida_script(self, addresses: List[int], output_path: str,
                              comments: Optional[Dict[int, str]] = None):
        """
        Generate IDA Python script to mark addresses.
        
        addresses: list of addresses
        output_path: output file path
        comments: optional dict of address -> comment
        """
        lines = [
            "# IDA Python script - Generated by MomoTrainer Studio",
            "",
            "import idaapi",
            "import idc",
            "",
        ]
        
        for i, addr in enumerate(addresses):
            comment = comments.get(addr, f"Address_{i}") if comments else f"Address_{i}"
            lines.append(f"# {comment}")
            lines.append(f"idc.create_insn(0x{addr:X})")
            safe_comment = str(comment).replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f"idc.set_cmt(0x{addr:X}, \"{safe_comment}\", 0)")
            lines.append("")
            
        Path(output_path).write_text('\n'.join(lines), encoding='utf-8')
        
    def export_signatures(self, patterns: List[Dict], output_path: str):
        """
        Export AOB signatures.
        
        patterns: list of {'name': str, 'pattern': str, 'offset': int}
        output_path: output file path
        """
        lines = [
            "# AOB Signatures - Generated by MomoTrainer Studio",
            "# Format: name = pattern",
            "",
        ]
        
        for p in patterns:
            name = p.get('name', 'Unknown')
            pattern = p.get('pattern', '')
            offset = p.get('offset', 0)
            lines.append(f"{name} = {pattern} (offset: {offset})")
            
        Path(output_path).write_text('\n'.join(lines), encoding='utf-8')
        
    def export_cheat_table(self, output_path: str, format: str = 'ct'):
        """
        Export cheat table.
        
        output_path: output file path
        format: 'ct' (Cheat Engine) or 'json'
        """
        entries = self.get_cheat_table()
        
        if format.lower() == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)
        else:
            # CT format (simplified)
            lines = ["<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                     "<CheatTable>",
                     "  <CheatEntries>"]
            
            for entry in entries:
                addr = entry.get('address', 0)
                desc = entry.get('description', '')
                vtype = entry.get('type', 'int32')
                
                lines.append(f'    <CheatEntry>')
                lines.append(f'      <Description>"{html.escape(str(desc))}"</Description>')
                lines.append(f'      <Address>0x{addr:X}</Address>')
                lines.append(f'      <Type>{vtype}</Type>')
                lines.append(f'    </CheatEntry>')
                
            lines.extend(["  </CheatEntries>", "</CheatTable>"])
            
            Path(output_path).write_text('\n'.join(lines), encoding='utf-8')


# Convenience function for creating API instance
def create_api(pid: int, process_handle=None) -> MomoTrainerAPI:
    """
    Create API instance for a process.
    
    pid: target process ID
    process_handle: optional open process handle
    
    Returns MomoTrainerAPI instance.
    """
    return MomoTrainerAPI(pid=pid, process_handle=process_handle)


# Example usage script
EXAMPLE_SCRIPT = '''
"""
Example: Auto-NOP all writers to an address
"""

from scripting_api import MomoTrainerAPI
import time

# Create API instance
api = MomoTrainerAPI(studio)  # Or: api = create_api(pid)

# Target address
target = 0x140001000

# Set breakpoint to find writers
print(f"Setting breakpoint on 0x{target:X}...")
api.set_breakpoint(target, mode='write')

# Wait for hits
print("Waiting for writers... (5 seconds)")
time.sleep(5)

# Get all captured writers
hits = api.get_breakpoint_hits(target)
print(f"Found {len(hits)} unique writers")

# NOP each unique instruction
seen = set()
for hit in hits:
    rip = hit.get('rip', 0)
    if rip and rip not in seen:
        print(f"NOPing instruction at 0x{rip:X}")
        api.write_nop(rip, 5)  # 5 NOPs
        seen.add(rip)
        
print(f"NOPed {len(seen)} unique writers")

# Stop debugger
api.remove_breakpoint(target)
'''


if __name__ == '__main__':
    print("MomoTrainer Studio Scripting API")
    print("=" * 50)
    print("\nExample usage:")
    print(EXAMPLE_SCRIPT)
