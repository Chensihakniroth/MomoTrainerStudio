"""
MomoTrainerStudio Hybrid Memory Access Layer
Combines user-mode (ctypes) with kernel driver fallback
"""

import ctypes
import ctypes.wintypes as w
from ctypes import wintypes, WinDLL
import os
import sys
from typing import Optional, Tuple, Union
from enum import Enum

# ============================================================
#  Memory Protection Flags
# ============================================================

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100
PAGE_NOCACHE           = 0x200
PAGE_WRITECOMBINE      = 0x400

# ============================================================
#  Memory Types
# ============================================================

MEM_PRIVATE  = 0x20000
MEM_IMAGE    = 0x1000000
MEM_MAPPED   = 0x40000

# ============================================================
#  Process Access Rights
# ============================================================

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ      = 0x0010
PROCESS_VM_WRITE     = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION

# ============================================================
#  Memory Basic Information Structure
# ============================================================

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",      ctypes.c_void_p),
        ("AllocationBase",   ctypes.c_void_p),
        ("AllocationProtect", w.DWORD),
        ("PartitionId",      w.WORD),
        ("RegionSize",       ctypes.c_size_t),
        ("State",            w.DWORD),
        ("Protect",          w.DWORD),
        ("Type",             w.DWORD),
    ]

# ============================================================
#  Process Entry Structure
# ============================================================

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",             w.DWORD),
        ("cntUsage",           w.DWORD),
        ("th32ProcessID",      w.DWORD),
        ("th32DefaultHeapID",  ctypes.POINTER(w.ULONG)),
        ("th32ModuleID",       w.DWORD),
        ("cntThreads",         w.DWORD),
        ("th32ParentProcessID", w.DWORD),
        ("pcPriClassBase",     w.LONG),
        ("dwFlags",            w.DWORD),
        ("szExeFile",          w.CHAR * 260),
    ]

# ============================================================
#  Kernel Driver Interface
# ============================================================

try:
    from kernel_driver import MomoTrainerDriver
    DRIVER_AVAILABLE = True
except ImportError:
    DRIVER_AVAILABLE = False

# ============================================================
#  User-Mode Memory Scanner (existing Scanner logic)
# ============================================================

kernel32 = WinDLL('kernel32', use_last_error=True)
ntdll = WinDLL('ntdll', use_last_error=True)

# --- Process Snapshot ---
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
CreateToolhelp32Snapshot.restype = w.HANDLE

Process32First = kernel32.Process32FirstW
Process32First.argtypes = [w.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32First.restype = w.BOOL

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [w.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.restype = w.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [w.HANDLE]
CloseHandle.restype = w.BOOL

# --- Memory Operations ---
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = w.ULONG

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = w.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = w.BOOL

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD, ctypes.POINTER(w.DWORD)]
VirtualProtectEx.restype = w.BOOL

NtQuerySystemInformation = ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [w.ULONG, w.LPVOID, w.ULONG, w.PULONG]
NtQuerySystemInformation.restype = w.LONG

SYSTEM_PROCESS_INFORMATION = w.ULONG * 0x10000  # 64KB buffer

SnapshotHandle = 2  # TH32CS_SNAPPROCESS

class HybridMemory:
    """Hybrid memory access - user-mode primary, kernel driver fallback"""

    def __init__(self, use_driver: bool = True):
        self.use_driver = use_driver and DRIVER_AVAILABLE
        self.driver = MomoTrainerDriver() if self.use_driver else None
        self._opened_processes = {}
        self._current_process_id = None

    # ------------------------------------------------------------------
    #  Process Management
    # ------------------------------------------------------------------

    @staticmethod
    def list_processes() -> list[dict]:
        """Enumerate running processes"""
        processes = []
        snapshot = CreateToolhelp32Snapshot(SnapshotHandle, 0)
        if snapshot == w.HANDLE(-1).value:
            return processes

        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if Process32First(snapshot, ctypes.byref(entry)):
            while True:
                processes.append({
                    "pid": entry.th32ProcessID,
                    "name": entry.szExeFile.decode('utf-8', errors='replace'),
                })
                if not Process32Next(snapshot, ctypes.byref(entry)):
                    break

        CloseHandle(snapshot)
        return processes

    def open_process(self, pid: int) -> Optional[w.HANDLE]:
        """Open a process for memory access"""
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle or handle == w.HANDLE(-1).value:
            return None

        self._opened_processes[pid] = handle
        self._current_process_id = pid
        return handle

    def close_process(self, pid: int):
        """Close process handle"""
        handle = self._opened_processes.pop(pid, None)
        if handle:
            CloseHandle(handle)

    # ------------------------------------------------------------------
    #  Memory Query
    # ------------------------------------------------------------------

    def virtual_query(self, pid: int, address: int) -> Optional[MEMORY_BASIC_INFORMATION]:
        """Query memory region info"""
        handle = self._opened_processes.get(pid)
        if not handle:
            return None

        mbi = MEMORY_BASIC_INFORMATION()
        size = VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if size == 0:
            return None
        return mbi

    # ------------------------------------------------------------------
    #  Read / Write (Primary: user-mode, Fallback: kernel driver)
    # ------------------------------------------------------------------

    def read_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory from process - tries user-mode, falls back to driver"""
        handle = self._opened_processes.get(pid)
        if not handle:
            return None

        # Try user-mode first
        buf = (ctypes.c_byte * size)()
        bytes_read = ctypes.c_size_t(0)

        if ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)):
            if bytes_read.value > 0:
                return bytes(buf[:bytes_read.value])

        # User-mode failed - try kernel driver fallback
        if self.use_driver and self.driver and self.driver._is_open:
            return self.driver.read_memory(pid, address, size)

        return None

    def write_memory(self, pid: int, address: int, data: bytes) -> bool:
        """Write memory to process - tries user-mode, falls back to driver"""
        handle = self._opened_processes.get(pid)
        if not handle:
            return False

        # Try user-mode first
        bytes_written = ctypes.c_size_t(0)
        if WriteProcessMemory(handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written)):
            if bytes_written.value == len(data):
                return True

        # User-mode failed - try kernel driver fallback
        if self.use_driver and self.driver and self.driver._is_open:
            return self.driver.write_memory(pid, address, data)

        return False

    def write_protect_and_write(self, pid: int, address: int, data: bytes) -> bool:
        """Write to read-only memory by changing protection first"""
        handle = self._opened_processes.get(pid)
        if not handle:
            return False

        # Query current protection
        mbi = self.virtual_query(pid, address)
        if not mbi:
            return False

        old_protect = w.DWORD(0)
        new_protect = PAGE_READWRITE

        # Change protection to writable
        if not VirtualProtectEx(handle, ctypes.c_void_p(address), len(data), new_protect, ctypes.byref(old_protect)):
            return False

        try:
            # Write the data
            return self.write_memory(pid, address, data)
        finally:
            # Restore original protection
            VirtualProtectEx(handle, ctypes.c_void_p(address), len(data), old_protect, ctypes.byref(old_protect))

    # ------------------------------------------------------------------
    #  Pattern Scan (simplified — integrates with existing Scanner)
    # ------------------------------------------------------------------

    def scan_pattern(self, pid: int, base: int, size: int, pattern: bytes, mask: str) -> list[int]:
        """Simple pattern scanner - reads memory in chunks and scans"""
        results = []
        chunk_size = 0x100000  # 1MB chunks

        addr = base
        end = base + size

        while addr < end:
            read_size = min(chunk_size, end - addr)
            data = self.read_memory(pid, addr, read_size)

            if not data:
                addr += chunk_size
                continue

            # Byte-by-byte pattern match
            for i in range(len(data) - len(pattern)):
                match = True
                for j, pat_byte in enumerate(pattern):
                    if mask[j] == '?' or data[i + j] == pat_byte:
                        continue
                    match = False
                    break
                if match:
                    results.append(addr + i)

            addr += chunk_size

        return results

    # ------------------------------------------------------------------
    #  Cleanup
    # ------------------------------------------------------------------

    def close(self):
        """Close all handles and driver connection"""
        for pid, handle in list(self._opened_processes.items()):
            CloseHandle(handle)
        self._opened_processes.clear()

        if self.driver and self.driver._is_open:
            self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()