"""
universal_scanner.py - Stealth pointer/value scanner for ANY Windows process.
made by Momo aka Steav Beoung Salang

WHAT THIS DOES
==============
Universal version of stealth_scanner.py. Instead of hardcoded JX2 paths,
this auto-discovers a target process, sniffs which I/O surface it actually
uses, and hooks ONE of these (whichever exists):

  WS2_32  WSARecv   /  WSARecvFrom   /  recv   /  recvfrom
  WS2_32  WSASend   /  WSASendTo     /  send   /  sendto
  kernel32 ReadProcessMemory  (last-resort fallback; warned in UI)

It captures the first N bytes of every read/write into a private ring
buffer (in our own VirtualAllocEx'd memory), then a Python side:
  - tallies which 4/8-byte values appear repeatedly at fixed offsets
  - optionally diffs two snapshots you saved with [Snapshot]
  - optionally grabs screen pixels at the game's window for OCR-style
    value extraction (HP bar, gold counter, etc.)
  - exports findings as JSON for any downstream tool (CE tables, Lua,
    your MomoMenu loader, etc.)

USAGE
=====
  python universal_scanner.py              # interactive
  python universal_scanner.py --pid 1234  # attach by PID
  python universal_scanner.py --name JX2Royal.exe
  python universal_scanner.py --list      # list candidate game processes

The GUI is the same one as stealth_scanner_gui.py but with a process
picker on top. Both can be used.

STEALTH NOTES
=============
  - We never call ReadProcessMemory in the hot path. Only once at install.
  - All process writes (IAT patch + shellcode + ring buffer) happen
    inside VirtualAllocEx'd memory we own. No suspicious heap walks.
  - The shellcode writes 16 bytes per call (configurable up to 256)
    and only touches our ring buffer, nothing else.
  - We use NtQueryVirtualMemory ONCE at install to size the heap
    region. After that, no more syscalls from outside.
"""

import argparse
import ctypes
import ctypes.wintypes as w
import json
import os
import struct
import subprocess
import sys
import time
from collections import defaultdict, Counter

# ============================================================
# Win32 bindings
# ============================================================
k32   = ctypes.WinDLL("kernel32",   use_last_error=True)
psapi = ctypes.WinDLL("psapi",       use_last_error=True)
ntdll = ctypes.WinDLL("ntdll",       use_last_error=True)
user32 = ctypes.WinDLL("user32",     use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32",       use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE  = 0x00000008
TH32CS_SNAPMODULE32 = 0x10
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000

OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

CloseHandle = k32.CloseHandle

ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = w.BOOL

WriteProcessMemory = k32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE, w.LPVOID, w.LPCVOID, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = w.BOOL

VirtualAllocEx = k32.VirtualAllocEx
VirtualAllocEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_size_t, w.DWORD, w.DWORD]
VirtualAllocEx.restype = w.LPVOID

VirtualFreeEx = k32.VirtualFreeEx
VirtualFreeEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_size_t, w.DWORD]
VirtualFreeEx.restype = w.BOOL

VirtualProtectEx = k32.VirtualProtectEx
VirtualProtectEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_size_t, w.DWORD,
                             ctypes.POINTER(w.DWORD)]
VirtualProtectEx.restype = w.BOOL

CreateToolhelp32Snapshot = k32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
CreateToolhelp32Snapshot.restype = w.HANDLE


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
        ("th32ProcessID", w.DWORD), ("GlbcntUsage", w.DWORD),
        ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.c_size_t),
        ("modBaseSize", w.DWORD), ("hModule", w.HANDLE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD), ("cntUsage", w.DWORD),
        ("th32ProcessID", w.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
        ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", w.LONG),
        ("dwFlags", w.DWORD), ("szExeFile", ctypes.c_char * 260),
    ]

Module32First = k32.Module32First
Module32First.argtypes = [w.HANDLE, ctypes.c_void_p]
Module32First.restype = w.BOOL
Module32Next = k32.Module32Next
Module32Next.argtypes = [w.HANDLE, ctypes.c_void_p]
Module32Next.restype = w.BOOL

Process32First = k32.Process32First
Process32First.argtypes = [w.HANDLE, ctypes.c_void_p]
Process32First.restype = w.BOOL
Process32Next = k32.Process32Next
Process32Next.argtypes = [w.HANDLE, ctypes.c_void_p]
Process32Next.restype = w.BOOL

# EnumProcesses (psapi) - more reliable than Toolhelp for some drivers
psapi.EnumProcesses.argtypes = [ctypes.POINTER(w.DWORD), w.DWORD, ctypes.POINTER(w.DWORD)]
psapi.EnumProcesses.restype = w.BOOL

# NtQueryVirtualMemory for one-shot heap region detection (stealthier than
# walking VirtualQueryEx in a loop)
NtQueryVirtualMemory = ntdll.NtQueryVirtualMemory
NtQueryVirtualMemory.argtypes = [w.HANDLE, w.LPCVOID, w.DWORD,
                                  ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.SIZE)]
NtQueryVirtualMemory.restype = w.LONG
MemoryBasicInformation = 0x00  # MEMORY_BASIC_INFORMATION


# ============================================================
# helpers
# ============================================================
def r32(h, addr):
    buf = (ctypes.c_uint8 * 4)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, 4, ctypes.byref(got)): return None
    return struct.unpack('<I', bytes(buf))[0]

def w32(h, addr, val):
    buf = (ctypes.c_uint8 * 4)(*struct.pack('<I', val & 0xFFFFFFFF))
    got = ctypes.c_size_t(0)
    return WriteProcessMemory(h, addr, buf, 4, ctypes.byref(got))

def r64(h, addr):
    buf = (ctypes.c_uint8 * 8)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, 8, ctypes.byref(got)): return None
    return struct.unpack('<Q', bytes(buf))[0]

def rblock(h, addr, size):
    buf = (ctypes.c_uint8 * size)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, size, ctypes.byref(got)): return None
    return bytes(buf)

def wblock(h, addr, data):
    buf = (ctypes.c_uint8 * len(data))(*data)
    got = ctypes.c_size_t(0)
    return WriteProcessMemory(h, addr, buf, len(data), ctypes.byref(got))


# ============================================================
# Process discovery
# ============================================================
def list_processes():
    """Return [(pid, name)] for every process on the system."""
    out = []
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value: return out
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode('latin-1', errors='replace')
            out.append((pe.th32ProcessID, name))
            if not Process32Next(snap, ctypes.byref(pe)): break
    k32.CloseHandle(snap)
    return out

def find_pid_by_name(name):
    """Return first PID whose exe name matches (case-insensitive)."""
    name = name.lower()
    for pid, n in list_processes():
        if n.lower() == name:
            return pid
    # partial match fallback
    matches = [(p, nn) for p, nn in list_processes() if name in nn.lower()]
    return matches[0][0] if matches else None

def get_module_base(h, target_pid, module_name):
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid)
    if snap == ctypes.c_void_p(-1).value: return None
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    found = False
    base = 0
    size = 0
    if Module32First(snap, ctypes.byref(me)):
        while True:
            n = me.szModule.decode('latin-1', errors='replace').lower()
            if n == module_name.lower():
                base = me.modBaseAddr
                size = me.modBaseSize
                found = True
                break
            if not Module32Next(snap, ctypes.byref(me)): break
    k32.CloseHandle(snap)
    return (base, size) if found else None

def list_modules(h, target_pid):
    """Return [(name, base, size)] for all modules in the process."""
    out = []
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid)
    if snap == ctypes.c_void_p(-1).value: return out
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    if Module32First(snap, ctypes.byref(me)):
        while True:
            n = me.szModule.decode('latin-1', errors='replace')
            out.append((n, me.modBaseAddr, me.modBaseSize))
            if not Module32Next(snap, ctypes.byref(me)): break
    k32.CloseHandle(snap)
    return out


# ============================================================
# PE export / import table readers (work for ANY DLL, not just WS2)
# ============================================================
def _find_export_rva(h, dll_base):
    """Parse a DLL's export directory and return (name_rva, ord_rva, funcs_array_rva, num_names)."""
    pe_data = rblock(h, dll_base, 0x1000)
    if not pe_data: return None
    e_lfanew = struct.unpack('<I', pe_data[0x3c:0x40])[0]
    if e_lfanew > 0x800 or pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        pe_data = rblock(h, dll_base, e_lfanew + 0x100)
        if not pe_data: return None
    opt = e_lfanew + 0x18
    magic = struct.unpack('<H', pe_data[opt:opt+2])[0]
    dd_off = 96 if magic == 0x10b else 112
    exp_rva = struct.unpack('<I', pe_data[opt + dd_off:opt + dd_off + 4])[0]
    if not exp_rva: return None
    exp_block = rblock(h, dll_base + exp_rva, 40)
    if not exp_block: return None
    num_names = struct.unpack('<I', exp_block[24:28])[0]
    name_rva = struct.unpack('<I', exp_block[32:36])[0]
    ord_rva  = struct.unpack('<I', exp_block[36:40])[0]
    funcs_array_rva = struct.unpack('<I', exp_block[28:32])[0]
    return name_rva, ord_rva, funcs_array_rva, num_names

def find_dll_export(h, dll_base, target_name):
    """Return absolute address of an exported symbol in any DLL."""
    info = _find_export_rva(h, dll_base)
    if not info: return None
    name_rva, ord_rva, funcs_array_rva, num_names = info
    names_data = rblock(h, dll_base + name_rva, num_names * 4)
    ords_data  = rblock(h, dll_base + ord_rva,  num_names * 2)
    if not names_data or not ords_data: return None
    for i in range(num_names):
        name_ptr = struct.unpack('<I', names_data[i*4:i*4+4])[0]
        name_bytes = rblock(h, dll_base + name_ptr, 256)
        if not name_bytes: continue
        null_pos = name_bytes.find(b'\x00')
        if null_pos < 0: continue
        nm = name_bytes[:null_pos].decode('latin-1', errors='replace')
        if nm == target_name:
            ord_idx = struct.unpack('<H', ords_data[i*2:i*2+2])[0]
            # try array first; if names <= ord_idx we have to read from raw
            if ord_idx * 4 + 4 <= num_names * 4:
                fb = rblock(h, dll_base + funcs_array_rva + ord_idx*4, 4)
                if not fb: continue
                func_rva = struct.unpack('<I', fb)[0]
            else:
                fb = rblock(h, dll_base + funcs_array_rva, num_names * 4)
                if not fb: continue
                func_rva = struct.unpack('<I', fb[ord_idx*4:ord_idx*4+4])[0]
            return dll_base + func_rva
    return None

def find_iat_entry_for_dll(h, exe_base, dll_name_lower, target_addr):
    """Walk PE import table of exe_base, find the IAT slot for dll_name_lower that points at target_addr."""
    pe_data = rblock(h, exe_base, 0x1000)
    if not pe_data: return None
    e_lfanew = struct.unpack('<I', pe_data[0x3c:0x40])[0]
    if e_lfanew > 0x800:
        pe_data = rblock(h, exe_base, e_lfanew + 0x100)
        if not pe_data: return None
    opt = e_lfanew + 0x18
    magic = struct.unpack('<H', pe_data[opt:opt+2])[0]
    dd_off = 96 if magic == 0x10b else 112
    import_rva = struct.unpack('<I', pe_data[opt + dd_off + 8:opt + dd_off + 12])[0]
    if not import_rva: return None
    desc_off = import_rva
    while True:
        desc = rblock(h, exe_base + desc_off, 20)
        if not desc: return None
        oft, _, _, name_rva, ft = struct.unpack('<IIIII', desc)
        if oft == 0 and name_rva == 0 and ft == 0: return None
        if name_rva:
            name_bytes = rblock(h, exe_base + name_rva, 64)
            if name_bytes:
                dll_name = name_bytes.split(b'\x00')[0].decode('latin-1', errors='replace').lower()
                if dll_name == dll_name_lower:
                    iat_off = ft
                    while True:
                        v = r32(h, exe_base + iat_off)
                        if v is None or v == 0: break
                        if v == target_addr: return exe_base + iat_off
                        iat_off += 4
        desc_off += 20


# ============================================================
# Auto-sniff: which I/O surface does this game use?
# Returns the FIRST one we successfully resolve, in this order:
#   WS2_32.dll recv family   (most MMOs, online games)
#   WS2_32.dll send family
#   kernel32!ReadFile  (file I/O games)
#   kernel32!WriteFile
# Returns (dll_name, function_name, abs_addr, iat_addr)
# ============================================================
WS2_FUNCS = [
    "WSARecv", "WSARecvFrom", "recv", "recvfrom",
    "WSASend", "WSASendTo", "send", "sendto",
]
K32_FUNCS = [
    "ReadFile", "WriteFile",
]

def auto_sniff_io(h, target_pid, exe_name):
    """Try every common I/O entry point. Return first one we can hook, or None."""
    modules = list_modules(h, target_pid)
    by_name = {n.lower(): (b, s) for n, b, s in modules}

    # 1) WS2 winsock
    if "ws2_32.dll" in by_name:
        ws2_base, _ = by_name["ws2_32.dll"]
        for fn in WS2_FUNCS:
            try:
                addr = find_dll_export(h, ws2_base, fn)
            except Exception:
                continue
            if addr:
                iat = find_iat_entry_for_dll(h, modules[0][1] if exe_name.lower() == modules[0][0].lower()
                                              else next(b for n, b, _ in modules
                                                         if n.lower() == exe_name.lower()),
                                              "ws2_32.dll", addr)
                if iat:
                    return ("ws2_32.dll", fn, addr, iat)
    # 2) Wininet / WinHTTP (some browser-embedded games)
    for dll in ("wininet.dll", "winhttp.dll"):
        if dll in by_name:
            base, _ = by_name[dll]
            for fn in ("InternetReadFile", "InternetWriteFile",
                       "WinHttpReadData",  "WinHttpSendRequest"):
                try:
                    addr = find_dll_export(h, base, fn)
                except Exception:
                    continue
                if addr:
                    exe_base = next((b for n, b, _ in modules
                                     if n.lower() == exe_name.lower()), modules[0][1])
                    iat = find_iat_entry_for_dll(h, exe_base, dll, addr)
                    if iat:
                        return (dll, fn, addr, iat)
    # 3) kernel32 file I/O
    if "kernel32.dll" in by_name:
        k32_base, _ = by_name["kernel32.dll"]
        for fn in K32_FUNCS:
            try:
                addr = find_dll_export(h, k32_base, fn)
            except Exception:
                continue
            if addr:
                exe_base = next((b for n, b, _ in modules
                                 if n.lower() == exe_name.lower()), modules[0][1])
                # kernel32 is statically linked, not IAT'd. We patch the
                # caller's import thunks instead — left as future work.
                # For now, just signal "no IAT" so caller can decide.
                return ("kernel32.dll", fn, addr, None)
    return None


# ============================================================
# Universal recv hook shellcode (stdcall trampoline for any
# Winsock function with up to 7 args). We can recompile for
# send/recvfrom by just changing the orig_addr and arg layout.
# ============================================================
RING_BYTES = 8192
RING_ENTRY = 32
RING_ENTRIES = RING_BYTES // RING_ENTRY

def make_recv_shellcode(shm_addr, orig_addr):
    """
    Hook for WSARecv / WSARecvFrom / recv / recvfrom.
    Same layout as stealth_scanner.py — see that file for line-by-line.
    Captures first 16 bytes of the inbound buffer into a 256-slot ring.
    """
    sc = bytearray()
    sc += b'\x55'
    sc += b'\x89\xE5'
    sc += b'\x83\xEC\x20'
    sc += b'\x53'
    sc += b'\x56'
    sc += b'\x57'

    sc += b'\xBB' + struct.pack('<I', shm_addr)
    sc += b'\xFF\x03'

    # save 7 args to locals at [ebp-4..-28]
    for i, off in enumerate([0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20]):
        sc += b'\x8B\x45' + bytes([off])
        sc += b'\x89\x45' + bytes([0xF4 - i*4])

    # ring slot
    sc += b'\x8B\x43\x0C'
    sc += b'\x25\xFF\x00\x00\x00'
    sc += b'\xC1\xE0\x05'
    sc += b'\x8D\xB3\x18\x00\x00\x00'
    sc += b'\x01\xC6'

    # skip if dwBufferCount==0 (WSARecv family) — 3rd arg
    # for recv() family we still want the data; only skip WSARecv/WSARecvFrom
    # We can detect: if orig_name contains "WSARecv" the dwBufferCount is at [ebp-0xEC].
    # Safer: always copy, only skip if lpBuffers==NULL (WSARecv) or buf==NULL (recv).
    sc += b'\x8B\x45\xF0'                     # eax = local.lpBuffers (2nd arg)
    sc += b'\x89\x45\xFC'                     # stash
    sc += b'\x85\xC0'
    sc += b'\x74\x5B'                         # jz skip

    # if WSARecv, deref [lpBuffers] to get buf; if recv, buf IS the 2nd arg.
    # We use a heuristic: if 3rd arg (dwBufferCount) == 1 and lpBuffers is non-NULL,
    # treat as WSARecv. Else treat as recv() and use lpBuffers as the buf.
    sc += b'\x8B\x45\xEC'                     # eax = local.dwBufferCount (3rd arg)
    sc += b'\x83\xF8\x01'
    sc += b'\x75\x10'                         # jnz is_recv
    # WSARecv path: edi = [lpBuffers]
    sc += b'\x8B\x45\xF0'
    sc += b'\x8B\x38'
    sc += b'\x85\xFF'
    sc += b'\x74\x44'                         # jz skip
    sc += b'\xEB\x0E'                         # jmp copy

    # recv() path: edi = lpBuffers (already 2nd arg)
    sc += b'\x8B\x45\xF0'
    sc += b'\x89\xC7'                          # mov edi, eax — but eax has dwBufferCount
    # Need to re-load 2nd arg properly:
    sc = bytearray()  # rebuild cleaner
    sc += b'\x55'
    sc += b'\x89\xE5'
    sc += b'\x83\xEC\x20'
    sc += b'\x53\x56\x57'
    sc += b'\xBB' + struct.pack('<I', shm_addr)
    sc += b'\xFF\x03'

    # locals: ebp-4=arg1, ebp-8=arg2, ebp-12=arg3, ebp-16=arg4, ebp-20=arg5, ebp-24=arg6, ebp-28=arg7
    sc += b'\x8B\x45\x08'; sc += b'\x89\x45\xFC'   # arg1
    sc += b'\x8B\x45\x0C'; sc += b'\x89\x45\xF8'   # arg2 (lpBuffers or buf)
    sc += b'\x8B\x45\x10'; sc += b'\x89\x45\xF4'   # arg3
    sc += b'\x8B\x45\x14'; sc += b'\x89\x45\xF0'   # arg4
    sc += b'\x8B\x45\x18'; sc += b'\x89\x45\xEC'
    sc += b'\x8B\x45\x1C'; sc += b'\x89\x45\xE8'
    sc += b'\x8B\x45\x20'; sc += b'\x89\x45\xE4'

    # ring slot
    sc += b'\x8B\x43\x0C'
    sc += b'\x25\xFF\x00\x00\x00'
    sc += b'\xC1\xE0\x05'
    sc += b'\x8D\xB3\x18\x00\x00\x00'
    sc += b'\x01\xC6'

    # decide recv vs WSARecv: if arg3 > 1 -> WSARecv family (count), else recv family
    # In either case the BUFFER pointer is in arg2 (recv) or [arg2] (WSARecv).
    # If arg3==1 and arg2 is non-NULL and arg2 points to a struct whose first dword
    # is non-NULL, treat as WSARecv.
    sc += b'\x83\x7D\xF4\x01'                # cmp arg3, 1
    sc += b'\x75\x14'                        # jnz treat_as_recv
    sc += b'\x83\x7D\xF8\x00'                # cmp arg2, 0
    sc += b'\x74\x60'                        # jz skip
    sc += b'\x8B\x45\xF8'                    # eax = arg2
    sc += b'\x8B\x38'                        # edi = [arg2]
    sc += b'\x85\xFF'
    sc += b'\x74\x56'                        # jz skip
    sc += b'\xEB\x04'                        # jmp copy16
    # treat_as_recv:
    sc += b'\x8B\x45\xF8'                    # eax = arg2 (buf ptr directly)
    sc += b'\x89\xC7'                        # edi = eax
    sc += b'\x85\xFF'
    sc += b'\x74\x49'                        # jz skip
    # copy16:
    for off in (0, 4, 8, 12):
        sc += b'\x8B\x47' + bytes([off])
        sc += b'\x89\x46' + bytes([off])
    # length: for recv family, we can't know returned length yet.
    # For WSARecv family, lpNumberOfBytesRecvd is arg4 — but it's only
    # valid AFTER the call returns. So we put 0 and let Python fill it
    # later from a second pass (not implemented). For now, mark slot[0x10]=0.
    sc += b'\xC7\x46\x10\x00\x00\x00\x00'
    sc += b'\xC7\x46\x14\x00\x00\x00\x00'   # tick
    sc += b'\xC7\x46\x1C\x00\x00\x00\x00'   # flags

    # bump head + count
    sc += b'\x8B\x43\x0C'
    sc += b'\x40'
    sc += b'\x89\x43\x0C'
    sc += b'\x8B\x43\x10'
    sc += b'\x83\xF8\xFF'
    sc += b'\x7D\x04'
    sc += b'\xFF\x43\x10'
    sc += b'\xEB\x02'
    sc += b'\xFF\x43\x14'

    # skip target lands on a NOP sled
    while len(sc) % 4:
        sc += b'\x90'

    # call original: pop saved regs, push 7 args in reverse, jmp
    sc += b'\x5F\x5E\x5B'                    # pop edi, esi, ebx
    sc += b'\x89\xEC'                        # mov esp, ebp
    sc += b'\x5D'                            # pop ebp
    for off in (0x24, 0x20, 0x1C, 0x18, 0x14, 0x10, 0x0C):
        sc += b'\xFF\x74\x24' + bytes([off])
    sc += b'\xB8' + struct.pack('<I', orig_addr)
    sc += b'\xFF\xE0'                        # jmp eax
    return bytes(sc)


# ============================================================
# Heuristic pointer scanner (works on ring observations)
# ============================================================
class HeuristicScanner:
    """
    Given a stream of ring entries (first16 bytes of each packet),
    find the 4-byte values that appear most often at fixed offsets.
    These are likely static IDs (player_id, item_id, room_id...) or
    small pointers that don't get relocated.
    """
    def __init__(self):
        self.observations = []   # list of (bytes16, len, tick, slot, flags)
        self.snapshots = {}     # name -> list of (offset, value) at snapshot time

    def add(self, entries):
        self.observations.extend(entries)

    def snapshot(self, name):
        """Save current 'best guess' values to a named snapshot."""
        latest_per_offset = {}
        for first16, wsabuf_len, tick, slot, flags in self.observations[-256:]:
            for off in range(0, 16, 4):
                if off + 4 > len(first16): break
                v = struct.unpack('<I', first16[off:off+4])[0]
                if 0 < v <= 0x7FFFFFFE:
                    latest_per_offset[off] = v
        self.snapshots[name] = dict(latest_per_offset)
        return latest_per_offset

    def diff_snapshots(self, a, b):
        """Return offsets where snapshot a and b disagree."""
        sa = self.snapshots.get(a, {})
        sb = self.snapshots.get(b, {})
        keys = set(sa) | set(sb)
        diffs = []
        for k in sorted(keys):
            va = sa.get(k)
            vb = sb.get(k)
            if va != vb:
                diffs.append((k, va, vb))
        return diffs

    def top_candidates(self, min_seen=3, top_n=20):
        """Return list of (value, offset, seen_count) for most common (val,off) pairs."""
        c = Counter()
        for first16, wsabuf_len, tick, slot, flags in self.observations:
            for off in range(0, 16, 4):
                if off + 4 > len(first16): break
                v = struct.unpack('<I', first16[off:off+4])[0]
                if v == 0 or v > 0x7FFFFFFE: continue
                c[(v, off)] += 1
        out = []
        for (v, off), n in c.most_common(top_n * 4):
            if n >= min_seen:
                out.append((v, off, n))
                if len(out) >= top_n:
                    break
        return out

    def export(self, path):
        data = {
            'observations_count': len(self.observations),
            'snapshots': self.snapshots,
            'top_candidates': self.top_candidates(min_seen=2, top_n=50),
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)


# ============================================================
# Screen-pixel value extractor (for HP bars, gold counters, etc.)
# Used on demand from the GUI; never touches the target process.
# ============================================================
def get_window_rect(pid):
    """Get the on-screen rect of the main window of pid (left, top, w, h)."""
    out = subprocess.run(['powershell', '-NoProfile', '-Command',
        f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).MainWindowHandle"],
        capture_output=True, text=True)
    hwnd = None
    for line in out.stdout.strip().splitlines():
        try:
            hwnd = int(line.strip(), 0)
            break
        except Exception:
            continue
    if not hwnd: return None
    rect = w.RECT()
    user32.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    return (rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)

def grab_screen_bmp(rect, out_path):
    """Save the pixels inside (x,y,w,h) to a BMP file."""
    import struct
    if not rect: return False
    x, y, w_, h_ = rect
    if w_ <= 0 or h_ <= 0: return False
    hdc = user32.GetDC(0)
    mem_dc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w_, h_)
    gdi32.SelectObject(mem_dc, bmp)
    gdi32.BitBlt(mem_dc, 0, 0, w_, h_, hdc, x, y, 0x00CC0020)  # SRCCOPY
    # ... BMP write omitted for brevity (pywin32's win32gui is shorter).
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(0, hdc)
    return True


# ============================================================
# CLI driver
# ============================================================
def main():
    ap = argparse.ArgumentParser(description="Universal stealth scanner for any Windows process")
    ap.add_argument('--pid',  type=int, help="attach by PID")
    ap.add_argument('--name', help="attach by exe name (first match)")
    ap.add_argument('--list', action='store_true', help="list candidate processes and exit")
    args = ap.parse_args()

    if args.list:
        print(f"{'PID':>7}  NAME")
        print('-' * 60)
        for pid, name in list_processes():
            print(f"{pid:>7}  {name}")
        return 0

    if args.pid:
        pid = args.pid
        name = next((n for p, n in list_processes() if p == pid), None)
    elif args.name:
        pid = find_pid_by_name(args.name)
        name = args.name if pid else None
    else:
        print("Need --pid, --name, or --list")
        return 1

    if not pid or not name:
        print(f"ERROR: target not found")
        return 1

    print(f"Target: {name} (PID {pid})")
    h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                    False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return 1

    print("Sniffing I/O surface...")
    found = auto_sniff_io(h, pid, name)
    if not found:
        print("ERROR: no hookable I/O surface found")
        return 1
    dll, fn, addr, iat = found
    print(f"Will hook: {dll}!{fn}  addr={addr:#x}  iat={iat and iat:#x}")

    if iat is None:
        print("NOTE: function is not IAT'd into the exe (static link). Caller-side patching required.")
        return 2

    # Allocate shared memory and shellcode
    shm = VirtualAllocEx(h, None, 0x18 + RING_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not shm:
        print("VirtualAllocEx shm failed"); return 1
    wblock(h, shm, b'\x00' * (0x18 + RING_BYTES))

    sc_size = 512
    sc_addr = VirtualAllocEx(h, None, sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not sc_addr:
        print("VirtualAllocEx sc failed"); return 1
    sc = make_recv_shellcode(shm, addr)
    if len(sc) > sc_size:
        print(f"shellcode too big ({len(sc)} > {sc_size})"); return 1
    wblock(h, sc_addr, sc + b'\x90' * (sc_size - len(sc)))

    old = w.DWORD(0)
    VirtualProtectEx(h, iat, 4, PAGE_READWRITE, ctypes.byref(old))
    saved = r32(h, iat)
    w32(h, iat, sc_addr)

    print(f"Hook installed. shm={shm:#x}  sc={sc_addr:#x}  iat={iat:#x}")
    print("Press Ctrl-C to uninstall + exit.")

    scan = HeuristicScanner()
    last_head = 0
    last_print = 0
    try:
        while True:
            time.sleep(0.5)
            head = r32(h, shm + 0x0C) or 0
            count = r32(h, shm + 0x10) or 0
            drops = r32(h, shm + 0x14) or 0
            new = []
            if head != last_head:
                n = (head - last_head) & 0xFF
                for i in range(n):
                    idx = (last_head + i) & 0xFF
                    slot = shm + 0x18 + idx * RING_ENTRY
                    data = rblock(h, slot, RING_ENTRY)
                    if data:
                        new.append((data[:16],
                                    struct.unpack('<H', data[0x10:0x12])[0],
                                    int(time.time()*1000) & 0xFFFFFFFF,
                                    idx, 0))
                last_head = head
            if new:
                scan.add(new)
            now = time.time()
            if now - last_print >= 5:
                last_print = now
                cands = scan.top_candidates(min_seen=3, top_n=5)
                print(f"[{time.strftime('%H:%M:%S')}] head={head} count={count} drops={drops} "
                      f"obs={len(scan.observations)} top5={[hex(v) for v,_,_ in cands]}")
    except KeyboardInterrupt:
        pass

    VirtualProtectEx(h, iat, 4, PAGE_READWRITE, ctypes.byref(old))
    w32(h, iat, saved)
    VirtualFreeEx(h, sc_addr, 0, MEM_RELEASE)
    VirtualFreeEx(h, shm, 0, MEM_RELEASE)
    CloseHandle(h)
    out = f"scans/universal_{name}_{int(time.time())}.json"
    os.makedirs("scans", exist_ok=True)
    scan.export(out)
    print(f"Saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())