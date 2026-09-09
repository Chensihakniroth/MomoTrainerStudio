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
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

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
        scanner: memory scanner instance
        debugger: unified debugger instance
        """
        self.studio = studio
        
        if studio:
            # Extract components from studio
            self.pid = getattr(studio, 'pid', pid)
            self.process_handle = getattr(studio, 'h_process', process_handle)
            self.scanner = getattr(studio, 'scanner', scanner)
            self.debugger = getattr(studio, 'debugger', debugger)
        else:
            self.pid = pid
            self.process_handle = process_handle
            self.scanner = scanner
            self.debugger = debugger
            
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
        
    def _read_with_handle(self, h, address: int, size: int) -> Optional[bytes]:
        """Read memory with given handle."""
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        
        if k32.ReadProcessMemory(h, address, buffer, size, ctypes.byref(read)):
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
        """Write memory with given handle."""
        # Change memory protection
        old_prot = ctypes.c_ulong(0)
        k32.VirtualProtectEx(h, address, len(data), 0x40, ctypes.byref(old_prot))  # PAGE_EXECUTE_READWRITE
        
        written = ctypes.c_size_t(0)
        result = k32.WriteProcessMemory(h, address, data, len(data), ctypes.byref(written))
        
        # Restore protection
        k32.VirtualProtectEx(h, address, len(data), old_prot.value, ctypes.byref(old_prot))
        
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
        Run a memory scan.
        
        value: value to search for
        vtype: value type ('int8', 'int16', 'int32', 'int64', 'float', 'double', 'string', 'bytes')
        mode: scan mode ('exact', 'bigger', 'smaller', 'changed', 'unchanged')
        
        Returns list of addresses.
        """
        if not self.scanner:
            raise RuntimeError("No scanner available")
            
        # Call scanner's scan method
        if hasattr(self.scanner, 'scan'):
            return self.scanner.scan(value, vtype, mode)
            
        raise NotImplementedError("Scanner does not implement scan()")
        
    def rescan(self, value: Union[int, float, str, bytes], mode: str = 'exact') -> List[int]:
        """
        Rescan previous results.
        
        value: value to search for
        mode: scan mode
        
        Returns list of addresses.
        """
        if not self.scanner:
            raise RuntimeError("No scanner available")
            
        if hasattr(self.scanner, 'rescan'):
            return self.scanner.rescan(value, mode)
            
        raise NotImplementedError("Scanner does not implement rescan()")
        
    def get_scan_results(self, limit: int = 1000) -> List[int]:
        """Get current scan results."""
        if not self.scanner:
            return []
            
        if hasattr(self.scanner, 'get_results'):
            return self.scanner.get_results(limit)
            
        return []
        
    def clear_scan_results(self):
        """Clear scan results."""
        if self.scanner and hasattr(self.scanner, 'clear_results'):
            self.scanner.clear_results()
            
    # ========== Debugger Operations ==========
    
    def set_breakpoint(self, address: int, mode: str = 'write',
                       size: int = 4, callback=None) -> bool:
        """
        Set a breakpoint.
        
        address: memory address to monitor
        mode: 'access' (read/write) or 'write' (write-only)
        size: monitored length in bytes (1, 2, 4, 8)
        callback: optional callback function(hit_info)
        
        Returns True if successful.
        """
        if not self.debugger:
            raise RuntimeError("No debugger available")
            
        # Check if using unified debugger
        if hasattr(self.debugger, 'add_breakpoint'):
            return self.debugger.add_breakpoint(address, mode, size)
            
        # Single debugger instance
        if hasattr(self.debugger, 'address'):
            self.debugger.address = address
            self.debugger.mode = mode
            self.debugger.size = size
            if callback:
                self.debugger.on_hit = callback
            self.debugger.start()
            return True
            
        raise NotImplementedError("Debugger does not support breakpoints")
        
    def remove_breakpoint(self, address: int):
        """Remove a breakpoint."""
        if not self.debugger:
            return
            
        if hasattr(self.debugger, 'remove_breakpoint'):
            self.debugger.remove_breakpoint(address)
        elif hasattr(self.debugger, 'stop'):
            self.debugger.stop()
            
    def get_breakpoint_hits(self, address: int) -> List[Dict]:
        """
        Get hit information for a breakpoint.
        
        address: breakpoint address
        
        Returns list of hit dictionaries.
        """
        if not self.debugger:
            return []
            
        if hasattr(self.debugger, 'get_hits'):
            hits = self.debugger.get_hits()
            return [hit for hit in hits.values()
                    if hit.get('breakpoint_address', address) == address
                    or hit.get('address', address) == address]
            
        if hasattr(self.debugger, 'hit_cache'):
            return [hit for hit in self.debugger.hit_cache.values()
                    if hit.get('breakpoint_address', address) == address
                    or hit.get('address', address) == address]
            
        return []
        
    def get_all_breakpoints(self) -> List[int]:
        """Get list of all breakpoint addresses."""
        if not self.debugger:
            return []
            
        if hasattr(self.debugger, 'list_breakpoints'):
            return self.debugger.list_breakpoints()
            
        if hasattr(self.debugger, 'address'):
            return [self.debugger.address]
            
        return []
        
    def is_debugger_running(self) -> bool:
        """Check if debugger is running."""
        if not self.debugger:
            return False
            
        if hasattr(self.debugger, 'is_running'):
            return self.debugger.is_running()
            
        return False
        
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
