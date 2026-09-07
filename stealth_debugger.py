"""
stealth_debugger.py - Anti-Cheat Proof Stealth Page Guard & VEH Debugger
made by Momo aka Steav Beoung Salang

Features:
  - "Find out what accesses this address" (Read + Write PAGE_GUARD monitoring)
  - "Find out what writes to this address" (Write-only PAGE_GUARD monitoring)
  - Zero Windows Debugging API: NEVER calls DebugActiveProcess or DebugSetProcessKillOnExit
  - Undetectable by anti-cheat: IsDebuggerPresent(), CheckRemoteDebuggerPresent(), and PEB.BeingDebugged remain 0
  - CPU Debug Registers (DR0-DR7) remain untouched and zero
  - Uses VirtualProtectEx (PAGE_GUARD) + injected Vectored Exception Handler (VEH) ring buffer
  - Disassembly of intercepted instructions via Capstone engine
  - Live CPU register snapshot capture (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS)
  - "Replace with NOPs" (Code patcher)
  - 100% safe detachment: never terminates or crashes target process on detach
"""

import ctypes
import ctypes.wintypes as w
import os
import struct
import threading
import time
from collections import OrderedDict

import capstone

k32 = ctypes.windll.kernel32
adv = ctypes.windll.advapi32
ntdll = ctypes.windll.ntdll

# ============================================================
# Windows Constants & Structures
# ============================================================
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_CREATE_THREAD = 0x0002

THREAD_ALL_ACCESS = 0x1FFFFF
THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004

INFINITE = 0xFFFFFFFF
STILL_ACTIVE = 259

# Type definitions for kernel32 calls
k32.VirtualAllocEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p

k32.VirtualFreeEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD]
k32.VirtualFreeEx.restype = w.BOOL

k32.VirtualProtectEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD, ctypes.POINTER(w.DWORD)]
k32.VirtualProtectEx.restype = w.BOOL

k32.CreateRemoteThread.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
k32.CreateRemoteThread.restype = w.HANDLE

k32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
k32.WaitForSingleObject.restype = w.DWORD

k32.CloseHandle.argtypes = [w.HANDLE]
k32.CloseHandle.restype = w.BOOL

k32.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
k32.GetExitCodeProcess.restype = w.BOOL

k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = w.BOOL

k32.WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = w.BOOL


def _create_stealth_thread(h_process, start_addr, param):
    """
    Spawns thread using NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER (0x04).
    This tells the kernel to hide the thread from debuggers, clear ETW debug trace flags,
    and bypass standard userland hooks on CreateRemoteThread.
    Falls back to CreateRemoteThread only if NtCreateThreadEx fails.
    """
    h_thread = w.HANDLE(0)
    try:
        status = ntdll.NtCreateThreadEx(
            ctypes.byref(h_thread),
            THREAD_ALL_ACCESS,
            None,
            h_process,
            ctypes.c_void_p(start_addr),
            ctypes.c_void_p(param),
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0,
            0,
            0,
            None
        )
        if status == 0 and h_thread.value:
            return h_thread.value
    except Exception:
        pass

    return k32.CreateRemoteThread(
        h_process,
        None,
        0,
        ctypes.c_void_p(start_addr),
        ctypes.c_void_p(param),
        0,
        None
    )



class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t


# ============================================================
# Memory Helpers
# ============================================================
def _read_mem(h, addr, size):
    """Safely read memory from target process."""
    buf = (ctypes.c_uint8 * size)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return b''
    return bytes(buf)[:got.value]


def _write_mem_nop(h, addr, size):
    """Write NOP (0x90) instructions to address with VirtualProtectEx."""
    old_prot = w.DWORD(0)
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)):
        return False
    nop_bytes = b'\x90' * size
    written = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), nop_bytes, size, ctypes.byref(written))
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size, old_prot.value, ctypes.byref(old_prot))
    return ok != 0


# ============================================================
# Stealth VEH Shellcode Generator (x86-64)
# ============================================================
# Memory Map of the 0x2000 remote buffer:
# 0x0000 - 0x00FF: Config Header (104 bytes, padded to 256 bytes)
#   0x00: magic (uint32) - 0x4D4F4D4F
#   0x04: active (uint32) - 1 = active, 0 = inactive
#   0x08: mode (uint32) - 0 = access, 1 = write
#   0x0C: hit_count (uint32)
#   0x10: watch_addr (uint64)
#   0x18: watch_size (uint64)
#   0x20: page_addr (uint64)
#   0x28: page_size (uint64)
#   0x30: orig_prot (uint32)
#   0x34: padding (uint32)
#   0x38: veh_handle (uint64)
#   0x40: pfn_VirtualProtect (uint64)
#   0x48: pfn_AddVectoredExceptionHandler (uint64)
#   0x50: pfn_RemoveVectoredExceptionHandler (uint64)
#   0x58: ring_head (uint32)
#   0x5C: ring_tail (uint32)
# 0x0000 - 0x0FFF: Page 0 - Data Page (PAGE_READWRITE)
#   0x0000 - 0x00FF: Config Header (104 bytes, padded to 256 bytes)
#   0x0100 - 0x0AFF: Hit Ring Buffer (16 slots * 160 bytes = 2560 bytes)
# 0x1000 - 0x1FFF: Page 1 - Code Page (PAGE_EXECUTE_READ)
#   0x1000: VehHandler
#   0x1400: InitThread
#   0x1600: CleanupThread

def _build_veh_package_x64():
    """Generates the position-independent x64 shellcode for VEH handler, init, and cleanup."""
    # 1. VehHandler at 0x1000 (Page 1)
    veh = bytearray()
    
    # Prologue: check ExceptionCode
    # rcx = pExceptionInfo
    # [rcx] = pRecord
    # [rcx + 8] = pContext
    veh += bytes([
        0x48, 0x8B, 0x01,                         # mov rax, [rcx] (pRecord)
        0x8B, 0x10,                               # mov edx, [rax] (ExceptionCode)
        0x81, 0xFA, 0x01, 0x00, 0x00, 0x80,       # cmp edx, 0x80000001 (STATUS_GUARD_PAGE_VIOLATION)
        0x74, 0x12,                               # je guard_page (patched)
        0x81, 0xFA, 0x04, 0x00, 0x00, 0x80,       # cmp edx, 0x80000004 (STATUS_SINGLE_STEP)
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,       # jz single_step (patched)
        0x31, 0xC0,                               # xor eax, eax (EXCEPTION_CONTINUE_SEARCH)
        0xC3                                      # ret
    ])
    
    guard_page_offset = len(veh)
    veh[12] = guard_page_offset - 13
    
    # In guard_page:
    # r8 = pContext = [rcx + 8]
    # r9 = fault_addr = [rax + 40]
    # r10d = access_type = [rax + 32]
    veh += bytes([
        0x4C, 0x8B, 0x41, 0x08,                   # mov r8, [rcx + 8]
        0x4C, 0x8B, 0x48, 0x28,                   # mov r9, [rax + 40]
        0x44, 0x8B, 0x50, 0x20                    # mov r10d, [rax + 32]
    ])
    
    # RIP-relative lea r11, [rip - delta] to find cfg base at 0x0000
    curr_veh_addr = 0x1000 + len(veh)
    disp = (-curr_veh_addr - 7) & 0xFFFFFFFF
    veh += bytes([0x4C, 0x8D, 0x1D]) + struct.pack('<I', disp)
    
    # Check active: cmp dword ptr [r11 + 4], 1; jne pass_search (at offset 26)
    veh += bytes([
        0x41, 0x83, 0x7B, 0x04, 0x01,             # cmp dword ptr [r11 + 4], 1
        0x0F, 0x85
    ])
    veh += struct.pack('<i', 26 - (len(veh) + 4))
    
    # Check if fault_addr is on OUR page [page_addr, page_addr + page_size):
    # 1. cmp r9, [r11 + 0x20] (page_addr); jb pass_search
    veh += bytes([0x4D, 0x3B, 0x4B, 0x20, 0x0F, 0x82])
    veh += struct.pack('<i', 26 - (len(veh) + 4))
    
    # 2. mov rax, [r11 + 0x20]; add rax, [r11 + 0x28]; cmp r9, rax; jae pass_search
    veh += bytes([
        0x49, 0x8B, 0x43, 0x20,                   # mov rax, [r11 + 0x20]
        0x49, 0x03, 0x43, 0x28,                   # add rax, [r11 + 0x28]
        0x49, 0x39, 0xC1,                         # cmp r9, rax
        0x0F, 0x83                                # jae pass_search
    ])
    veh += struct.pack('<i', 26 - (len(veh) + 4))
    
    # FAULT IS ON OUR GUARDED PAGE!
    # Record diagnostic telemetry in x64:
    # 0x68: page_faults (uint32)
    # 0x6C: last_fault_addr (uint64)
    # 0x74: last_fault_rip (uint64)
    veh += bytes([
        0xF0, 0x41, 0xFF, 0x43, 0x68,             # lock inc dword ptr [r11 + 0x68]
        0x4D, 0x89, 0x4B, 0x6C,                   # mov [r11 + 0x6C], r9 (last_fault_addr)
        0x49, 0x8B, 0x80, 0xF8, 0x00, 0x00, 0x00, # mov rax, [r8 + 0xF8] (Rip from CONTEXT)
        0x49, 0x89, 0x43, 0x74                    # mov [r11 + 0x74], rax (last_fault_rip)
    ])
    
    # Check if fault_addr >= watch_addr
    veh += bytes([
        0x4D, 0x3B, 0x4B, 0x10,                   # cmp r9, [r11 + 0x10]
        0x0F, 0x82, 0x00, 0x00, 0x00, 0x00        # jb finish_guard
    ])
    jmp_below_watch_idx = len(veh) - 4
    
    # Check if fault_addr < watch_addr + watch_size
    veh += bytes([
        0x49, 0x8B, 0x43, 0x10,                   # mov rax, [r11 + 0x10]
        0x49, 0x03, 0x43, 0x18,                   # add rax, [r11 + 0x18]
        0x49, 0x39, 0xC1,                         # cmp r9, rax
        0x0F, 0x83, 0x00, 0x00, 0x00, 0x00        # jae finish_guard
    ])
    jmp_above_watch_idx = len(veh) - 4
    
    # Check mode: cmp dword ptr [r11 + 8], 1 (write mode)
    veh += bytes([
        0x41, 0x83, 0x7B, 0x08, 0x01,             # cmp dword ptr [r11 + 8], 1
        0x75, 0x0A,                               # jne do_record (+10 bytes to mov eax, 1)
        0x41, 0x83, 0xFA, 0x01,                   # cmp r10d, 1 (is write?)
        0x0F, 0x85, 0x00, 0x00, 0x00, 0x00        # jne finish_guard
    ])
    jmp_not_write_idx = len(veh) - 4
    
    # do_record:
    # Atomic slot index: lock xadd [r11 + 0x58], eax
    veh += bytes([
        0xB8, 0x01, 0x00, 0x00, 0x00,             # mov eax, 1
        0xF0, 0x41, 0x0F, 0xC1, 0x43, 0x58,       # lock xadd [r11 + 0x58], eax
        0x25, 0x0F, 0x00, 0x00, 0x00,             # and eax, 15 (16 slots)
        0x69, 0xC0, 0xA0, 0x00, 0x00, 0x00,       # imul eax, eax, 160
        0x4D, 0x8D, 0x93, 0x00, 0x01, 0x00, 0x00, # lea r10, [r11 + 0x100] (ring base)
        0x49, 0x01, 0xC2                          # add r10, rax -> r10 = slot ptr
    ])
    
    # Write slot data from pContext (r8)
    veh += bytes([
        0x49, 0x8B, 0x80, 0xF8, 0x00, 0x00, 0x00, # mov rax, [r8 + 248] (Rip)
        0x49, 0x89, 0x02,                         # mov [r10 + 0], rax
        0x4D, 0x89, 0x4A, 0x08,                   # mov [r10 + 8], r9 (fault_addr)
        0x49, 0x8B, 0x40, 0x44,                   # mov rax, [r8 + 68] (Eflags)
        0x49, 0x89, 0x42, 0x18,                   # mov [r10 + 0x18], rax
        0x49, 0x8B, 0x80, 0x78, 0x00, 0x00, 0x00, # mov rax, [r8 + 120] (Rax)
        0x49, 0x89, 0x42, 0x20,                   # mov [r10 + 0x20], rax
        0x49, 0x8B, 0x80, 0x90, 0x00, 0x00, 0x00, # mov rax, [r8 + 144] (Rbx)
        0x49, 0x89, 0x42, 0x28,                   # mov [r10 + 0x28], rax
        0x49, 0x8B, 0x80, 0x80, 0x00, 0x00, 0x00, # mov rax, [r8 + 128] (Rcx)
        0x49, 0x89, 0x42, 0x30,                   # mov [r10 + 0x30], rax
        0x49, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, # mov rax, [r8 + 136] (Rdx)
        0x49, 0x89, 0x42, 0x38,                   # mov [r10 + 0x38], rax
        0x49, 0x8B, 0x80, 0xA8, 0x00, 0x00, 0x00, # mov rax, [r8 + 168] (Rsi)
        0x49, 0x89, 0x42, 0x40,                   # mov [r10 + 0x40], rax
        0x49, 0x8B, 0x80, 0xB0, 0x00, 0x00, 0x00, # mov rax, [r8 + 176] (Rdi)
        0x49, 0x89, 0x42, 0x48,                   # mov [r10 + 0x48], rax
        0x49, 0x8B, 0x80, 0xA0, 0x00, 0x00, 0x00, # mov rax, [r8 + 160] (Rbp)
        0x49, 0x89, 0x42, 0x50,                   # mov [r10 + 0x50], rax
        0x49, 0x8B, 0x80, 0x98, 0x00, 0x00, 0x00, # mov rax, [r8 + 152] (Rsp)
        0x49, 0x89, 0x42, 0x58,                   # mov [r10 + 0x58], rax
        0x49, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, # mov rax, [r8 + 184] (R8)
        0x49, 0x89, 0x42, 0x60,                   # mov [r10 + 0x60], rax
        0x49, 0x8B, 0x80, 0xC0, 0x00, 0x00, 0x00, # mov rax, [r8 + 192] (R9)
        0x49, 0x89, 0x42, 0x68,                   # mov [r10 + 0x68], rax
        0x49, 0x8B, 0x80, 0xC8, 0x00, 0x00, 0x00, # mov rax, [r8 + 200] (R10)
        0x49, 0x89, 0x42, 0x70,                   # mov [r10 + 0x70], rax
        0x49, 0x8B, 0x80, 0xD0, 0x00, 0x00, 0x00, # mov rax, [r8 + 208] (R11)
        0x49, 0x89, 0x42, 0x78,                   # mov [r10 + 0x78], rax
        0x49, 0x8B, 0x80, 0xD8, 0x00, 0x00, 0x00, # mov rax, [r8 + 216] (R12)
        0x49, 0x89, 0x82, 0x80, 0x00, 0x00, 0x00, # mov [r10 + 0x80], rax
        0x49, 0x8B, 0x80, 0xE0, 0x00, 0x00, 0x00, # mov rax, [r8 + 224] (R13)
        0x49, 0x89, 0x82, 0x88, 0x00, 0x00, 0x00, # mov [r10 + 0x88], rax
        0x49, 0x8B, 0x80, 0xE8, 0x00, 0x00, 0x00, # mov rax, [r8 + 232] (R14)
        0x49, 0x89, 0x82, 0x90, 0x00, 0x00, 0x00, # mov [r10 + 0x90], rax
        0x49, 0x8B, 0x80, 0xF0, 0x00, 0x00, 0x00, # mov rax, [r8 + 240] (R15)
        0x49, 0x89, 0x82, 0x98, 0x00, 0x00, 0x00, # mov [r10 + 0x98], rax
        0xF0, 0x41, 0xFF, 0x43, 0x0C              # lock inc dword ptr [r11 + 0x0C] (hit_count)
    ])
    
    # finish_guard:
    finish_guard_offset = len(veh)
    for idx in (jmp_below_watch_idx, jmp_above_watch_idx, jmp_not_write_idx):
        rel32 = finish_guard_offset - (idx + 4)
        veh[idx:idx+4] = struct.pack('<i', rel32)
    
    # Set Trap Flag (0x100) in ContextRecord->EFlags (offset 68 = 0x44)
    veh += bytes([
        0x41, 0x81, 0x48, 0x44, 0x00, 0x01, 0x00, 0x00, # or dword ptr [r8 + 0x44], 0x100
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                   # mov eax, 0xFFFFFFFF (EXCEPTION_CONTINUE_EXECUTION)
        0xC3                                            # ret
    ])
    
    # single_step handler
    single_step_offset = len(veh)
    rel32_step = single_step_offset - 25
    veh[21:25] = struct.pack('<i', rel32_step)
    
    # In single_step:
    # 1. Clear Trap Flag: and dword ptr [r8 + 0x44], ~0x100
    veh += bytes([
        0x4C, 0x8B, 0x41, 0x08,                          # mov r8, [rcx + 8]
        0x41, 0x81, 0x60, 0x44, 0xFF, 0xFE, 0xFF, 0xFF  # and dword ptr [r8 + 0x44], ~0x100
    ])
    
    # 2. Get cfg base via RIP-relative
    curr_veh_addr = 0x1000 + len(veh)
    disp = (-curr_veh_addr - 7) & 0xFFFFFFFF
    veh += bytes([0x4C, 0x8D, 0x1D]) + struct.pack('<I', disp)
    
    # Check if cfg->active == 1; if not active, pass_search (at offset 26)
    veh += bytes([
        0x41, 0x83, 0x7B, 0x04, 0x01,             # cmp dword ptr [r11 + 4], 1
        0x0F, 0x85
    ])
    veh += struct.pack('<i', 26 - (len(veh) + 4))
    
    # Re-apply PAGE_GUARD via VirtualProtect:
    veh += bytes([
        0x48, 0x83, 0xEC, 0x38,                   # sub rsp, 0x38
        0x45, 0x8B, 0x43, 0x30,                   # mov r8d, [r11 + 0x30] (orig_prot)
        0x41, 0x81, 0xC8, 0x00, 0x01, 0x00, 0x00, # or r8d, 0x100
        0x49, 0x8B, 0x53, 0x28,                   # mov rdx, [r11 + 0x28] (page_size)
        0x49, 0x8B, 0x4B, 0x20,                   # mov rcx, [r11 + 0x20] (page_addr)
        0x4C, 0x8D, 0x4C, 0x24, 0x28,             # lea r9, [rsp + 0x28]
        0x41, 0xFF, 0x53, 0x40,                   # call [r11 + 0x40] (pfn_VirtualProtect)
        0x48, 0x83, 0xC4, 0x38                    # add rsp, 0x38
    ])
    
    # finish_step:
    veh += bytes([
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,             # mov eax, 0xFFFFFFFF
        0xC3                                      # ret
    ])
    
    # 2. InitThread at 0x1400 (Page 1)
    init_code = bytearray([
        0x48, 0x83, 0xEC, 0x38,                         # sub rsp, 0x38
        0x48, 0x89, 0x4C, 0x24, 0x20,                   # mov [rsp+0x20], rcx (cfg)
        0x48, 0x8D, 0x91, 0x00, 0x10, 0x00, 0x00,       # lea rdx, [rcx + 0x1000] (VehHandler at 0x1000)
        0xB9, 0x01, 0x00, 0x00, 0x00,                   # mov ecx, 1
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xFF, 0x50, 0x48,                               # call [rax + 0x48] (pfn_AddVectoredExceptionHandler)
        0x48, 0x8B, 0x4C, 0x24, 0x20,                   # mov rcx, [rsp+0x20]
        0x48, 0x89, 0x41, 0x38,                         # mov [rcx + 0x38], rax (veh_handle)
        0x48, 0x8B, 0x4C, 0x24, 0x20,                   # mov rcx, [rsp+0x20]
        0x44, 0x8B, 0x41, 0x30,                         # mov r8d, [rcx + 0x30] (orig_prot)
        0x41, 0x81, 0xC8, 0x00, 0x01, 0x00, 0x00,       # or r8d, 0x100
        0x48, 0x8B, 0x51, 0x28,                         # mov rdx, [rcx + 0x28] (page_size)
        0x48, 0x8B, 0x49, 0x20,                         # mov rcx, [rcx + 0x20] (page_addr)
        0x4C, 0x8D, 0x4C, 0x24, 0x28,                   # lea r9, [rsp+0x28]
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xFF, 0x50, 0x40,                               # call [rax + 0x40] (pfn_VirtualProtect)
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xC7, 0x40, 0x04, 0x01, 0x00, 0x00, 0x00,       # mov dword ptr [rax+4], 1 (active = 1)
        0x31, 0xC0,                                     # xor eax, eax
        0x48, 0x83, 0xC4, 0x38,                         # add rsp, 0x38
        0xC3                                            # ret
    ])
    
    # 3. CleanupThread at 0x1600 (Page 1)
    cleanup_code = bytearray([
        0x48, 0x83, 0xEC, 0x38,                         # sub rsp, 0x38
        0x48, 0x89, 0x4C, 0x24, 0x20,                   # mov [rsp+0x20], rcx
        0x48, 0x8B, 0x49, 0x38,                         # mov rcx, [rcx + 0x38] (veh_handle)
        0x48, 0x85, 0xC9,                               # test rcx, rcx
        0x74, 0x15,                                     # jz skip_remove (+21 bytes)
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xFF, 0x50, 0x50,                               # call [rax + 0x50] (pfn_RemoveVectoredExceptionHandler)
        0x48, 0x8B, 0x4C, 0x24, 0x20,                   # mov rcx, [rsp+0x20]
        0x48, 0xC7, 0x41, 0x38, 0x00, 0x00, 0x00, 0x00, # mov qword ptr [rcx + 0x38], 0
        # skip_remove (at +0x27):
        0x48, 0x8B, 0x4C, 0x24, 0x20,                   # mov rcx, [rsp+0x20]
        0x44, 0x8B, 0x41, 0x30,                         # mov r8d, [rcx + 0x30] (orig_prot)
        0x48, 0x8B, 0x51, 0x28,                         # mov rdx, [rcx + 0x28] (page_size)
        0x48, 0x8B, 0x49, 0x20,                         # mov rcx, [rcx + 0x20] (page_addr)
        0x4C, 0x8D, 0x4C, 0x24, 0x28,                   # lea r9, [rsp+0x28]
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xFF, 0x50, 0x40,                               # call [rax + 0x40] (pfn_VirtualProtect)
        0x48, 0x8B, 0x44, 0x24, 0x20,                   # mov rax, [rsp+0x20]
        0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00,       # mov dword ptr [rax+4], 0 (active = 0)
        0x31, 0xC0,                                     # xor eax, eax
        0x48, 0x83, 0xC4, 0x38,                         # add rsp, 0x38
        0xC3                                            # ret
    ])
    
    return bytes(veh), bytes(init_code), bytes(cleanup_code)


def _build_veh_package_x86():
    """Generates position-independent 32-bit (x86) shellcode for VEH handler, init, and cleanup."""
    veh = bytearray()
    
    # 1. VehHandler at 0x0B00: __stdcall int Handler(PEXCEPTION_POINTERS pExc)
    # [ebp + 8] = pExc
    veh += bytes([0x55, 0x89, 0xE5, 0x53, 0x56, 0x57]) # push ebp; mov ebp, esp; push ebx, esi, edi
    
    # mov eax, [ebp + 8] (pExc)
    veh += bytes([0x8B, 0x45, 0x08])
    # test eax, eax; jz pass_search
    veh += bytes([0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])
    jmp_null_exc = len(veh) - 4
    
    # mov edx, [eax] (pRecord)
    # mov ecx, [eax + 4] (pContext)
    veh += bytes([0x8B, 0x10, 0x8B, 0x48, 0x04])
    # test edx, edx; jz pass_search; test ecx, ecx; jz pass_search
    veh += bytes([0x85, 0xD2, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])
    jmp_null_rec = len(veh) - 4
    veh += bytes([0x85, 0xC9, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])
    jmp_null_ctx = len(veh) - 4
    
    # mov eax, [edx] (ExceptionCode)
    veh += bytes([0x8B, 0x02])
    # cmp eax, 0x80000001 (STATUS_GUARD_PAGE_VIOLATION)
    veh += bytes([0x3D, 0x01, 0x00, 0x00, 0x80])
    # je guard_page
    veh += bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])
    jmp_to_guard = len(veh) - 4
    
    # cmp eax, 0x80000004 (STATUS_SINGLE_STEP)
    veh += bytes([0x3D, 0x04, 0x00, 0x00, 0x80])
    # je single_step
    veh += bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])
    jmp_to_step = len(veh) - 4
    
    # pass_search label:
    pass_search_offset = len(veh)
    veh += bytes([
        0x31, 0xC0,             # xor eax, eax (EXCEPTION_CONTINUE_SEARCH = 0)
        0x5F, 0x5E, 0x5B, 0x5D, # pop edi, esi, ebx, ebp
        0xC2, 0x04, 0x00        # ret 4
    ])
    
    # Patch jumps to pass_search
    for jmp_idx in [jmp_null_exc, jmp_null_rec, jmp_null_ctx]:
        disp = pass_search_offset - (jmp_idx + 4)
        struct.pack_into('<i', veh, jmp_idx, disp)
        
    # guard_page label:
    guard_page_offset = len(veh)
    struct.pack_into('<i', veh, jmp_to_guard, guard_page_offset - (jmp_to_guard + 4))
    
    # Delta trick to find cfg base at 0x0000:
    # call +0 (5 bytes) pushes address of next instruction (pop ebx at offset len(veh)+5)
    veh += bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B]) # call +0; pop ebx
    pc_offset_in_page = 0x1000 + len(veh) - 1 # offset of pop ebx in Page 1 (0x1000)
    veh += bytes([0x81, 0xEB]) + struct.pack('<I', pc_offset_in_page) # sub ebx, pc_offset
    
    # Check if active == 1: cmp dword ptr [ebx + 4], 1; jne pass_search
    veh += bytes([0x83, 0x7B, 0x04, 0x01, 0x0F, 0x85])
    veh += struct.pack('<i', pass_search_offset - (len(veh) + 4))
    
    # esi = fault address: mov esi, [edx + 0x18]
    veh += bytes([0x8B, 0x72, 0x18])
    
    # Check if fault is within OUR page [page_addr, page_addr + page_size):
    # 1. cmp esi, [ebx + 0x20] (page_addr); jb pass_search (not our page e.g. stack guard)
    veh += bytes([0x3B, 0x73, 0x20, 0x0F, 0x82])
    veh += struct.pack('<i', pass_search_offset - (len(veh) + 4))
    
    # 2. mov eax, [ebx + 0x20]; add eax, [ebx + 0x28]; cmp esi, eax; jae pass_search
    veh += bytes([
        0x8B, 0x43, 0x20,       # mov eax, [ebx + 0x20] (page_addr)
        0x03, 0x43, 0x28,       # add eax, [ebx + 0x28] (page_size)
        0x39, 0xC6,             # cmp esi, eax
        0x0F, 0x83              # jae pass_search
    ])
    veh += struct.pack('<i', pass_search_offset - (len(veh) + 4))
    
    # FAULT IS ON OUR GUARDED PAGE!
    # Record diagnostic telemetry:
    # 0x68: page_faults (uint32)
    # 0x6C: last_fault_addr (uint32)
    # 0x70: last_fault_rip (uint32)
    veh += bytes([
        0xF0, 0xFF, 0x43, 0x68,                   # lock inc dword ptr [ebx + 0x68]
        0x89, 0x73, 0x6C,                         # mov [ebx + 0x6C], esi (last_fault_addr)
        0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,       # mov eax, [ecx + 0xB8] (Eip from CONTEXT)
        0x89, 0x43, 0x70                          # mov [ebx + 0x70], eax (last_fault_rip)
    ])
    
    # Check if esi >= [ebx + 0x10] (watch_addr)
    veh += bytes([0x3B, 0x73, 0x10, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00]) # jb finish_guard
    jmp_below_watch = len(veh) - 4
    
    # Check if esi < [ebx + 0x10] + [ebx + 0x18] (watch_addr + watch_size)
    veh += bytes([
        0x8B, 0x43, 0x10,                         # mov eax, [ebx + 0x10]
        0x03, 0x43, 0x18,                         # add eax, [ebx + 0x18]
        0x39, 0xC6,                               # cmp esi, eax
        0x0F, 0x83, 0x00, 0x00, 0x00, 0x00        # jae finish_guard
    ])
    jmp_above_watch = len(veh) - 4
    
    # Check mode: cmp dword ptr [ebx + 8], 1 (write mode)
    veh += bytes([
        0x83, 0x7B, 0x08, 0x01,                   # cmp dword ptr [ebx + 8], 1
        0x75, 0x0A,                               # jne do_record (+10 bytes to mov eax, 1)
        0x83, 0x7A, 0x14, 0x01,                   # cmp dword ptr [edx + 0x14], 1 (is write?)
        0x0F, 0x85, 0x00, 0x00, 0x00, 0x00        # jne finish_guard
    ])
    jmp_not_write = len(veh) - 4
    
    # do_record:
    veh += bytes([
        0xB8, 0x01, 0x00, 0x00, 0x00,       # mov eax, 1
        0xF0, 0x0F, 0xC1, 0x43, 0x58,       # lock xadd [ebx + 0x58], eax
        0x25, 0x0F, 0x00, 0x00, 0x00,       # and eax, 15
        0x69, 0xC0, 0xA0, 0x00, 0x00, 0x00, # imul eax, eax, 160
        0x8D, 0xBB, 0x00, 0x01, 0x00, 0x00, # lea edi, [ebx + 0x100]
        0x01, 0xC7                          # add edi, eax -> edi = slot ptr
    ])
    
    # Write slot values:
    # 0x00: Eip: mov eax, [ecx + 0xB8]; mov [edi], eax; mov dword ptr [edi+4], 0
    veh += bytes([0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00, 0x89, 0x07, 0xC7, 0x47, 0x04, 0x00, 0x00, 0x00, 0x00])
    # 0x08: fault_addr: mov [edi + 8], esi; mov dword ptr [edi+12], 0
    veh += bytes([0x89, 0x77, 0x08, 0xC7, 0x47, 0x0C, 0x00, 0x00, 0x00, 0x00])
    # 0x10: access_type: mov eax, [edx + 0x14]; mov [edi + 0x10], eax
    veh += bytes([0x8B, 0x42, 0x14, 0x89, 0x47, 0x10])
    # 0x18: eflags: mov eax, [ecx + 0xC0]; mov [edi + 0x18], eax; mov dword ptr [edi+0x1C], 0
    veh += bytes([0x8B, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x89, 0x47, 0x18, 0xC7, 0x47, 0x1C, 0x00, 0x00, 0x00, 0x00])
    # 0x20: Eax: [ecx + 0xB0]
    veh += bytes([0x8B, 0x81, 0xB0, 0x00, 0x00, 0x00, 0x89, 0x47, 0x20, 0xC7, 0x47, 0x24, 0x00, 0x00, 0x00, 0x00])
    # 0x28: Ebx: [ecx + 0xA4]
    veh += bytes([0x8B, 0x81, 0xA4, 0x00, 0x00, 0x00, 0x89, 0x47, 0x28, 0xC7, 0x47, 0x2C, 0x00, 0x00, 0x00, 0x00])
    # 0x30: Ecx: [ecx + 0xAC]
    veh += bytes([0x8B, 0x81, 0xAC, 0x00, 0x00, 0x00, 0x89, 0x47, 0x30, 0xC7, 0x47, 0x34, 0x00, 0x00, 0x00, 0x00])
    # 0x38: Edx: [ecx + 0xA8]
    veh += bytes([0x8B, 0x81, 0xA8, 0x00, 0x00, 0x00, 0x89, 0x47, 0x38, 0xC7, 0x47, 0x3C, 0x00, 0x00, 0x00, 0x00])
    # 0x40: Esi: [ecx + 0xA0]
    veh += bytes([0x8B, 0x81, 0xA0, 0x00, 0x00, 0x00, 0x89, 0x47, 0x40, 0xC7, 0x47, 0x44, 0x00, 0x00, 0x00, 0x00])
    # 0x48: Edi: [ecx + 0x9C]
    veh += bytes([0x8B, 0x81, 0x9C, 0x00, 0x00, 0x00, 0x89, 0x47, 0x48, 0xC7, 0x47, 0x4C, 0x00, 0x00, 0x00, 0x00])
    # 0x50: Ebp: [ecx + 0xB4]
    veh += bytes([0x8B, 0x81, 0xB4, 0x00, 0x00, 0x00, 0x89, 0x47, 0x50, 0xC7, 0x47, 0x54, 0x00, 0x00, 0x00, 0x00])
    # 0x58: Esp: [ecx + 0xC4]
    veh += bytes([0x8B, 0x81, 0xC4, 0x00, 0x00, 0x00, 0x89, 0x47, 0x58, 0xC7, 0x47, 0x5C, 0x00, 0x00, 0x00, 0x00])
    
    # Increment hit count: lock inc dword ptr [ebx + 0x0C]
    veh += bytes([0xF0, 0xFF, 0x43, 0x0C])
    
    # finish_guard label:
    finish_guard_offset = len(veh)
    for jmp_idx in [jmp_below_watch, jmp_above_watch, jmp_not_write]:
        disp = finish_guard_offset - (jmp_idx + 4)
        struct.pack_into('<i', veh, jmp_idx, disp)
        
    # Set Trap Flag: or dword ptr [ecx + 0xC0], 0x100
    veh += bytes([0x81, 0x89, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
    
    # Return EXCEPTION_CONTINUE_EXECUTION (-1)
    veh += bytes([
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, # mov eax, -1
        0x5F, 0x5E, 0x5B, 0x5D,       # pop edi, esi, ebx, ebp
        0xC2, 0x04, 0x00              # ret 4
    ])
    
    # single_step label:
    single_step_offset = len(veh)
    struct.pack_into('<i', veh, jmp_to_step, single_step_offset - (jmp_to_step + 4))
    
    # Delta trick for step
    veh += bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B]) # call +0; pop ebx
    pc_offset_step = 0x1000 + len(veh) - 1
    veh += bytes([0x81, 0xEB]) + struct.pack('<I', pc_offset_step)
    
    # Check if active == 1: if not active, jump to pass_search!
    veh += bytes([0x83, 0x7B, 0x04, 0x01, 0x0F, 0x85])
    veh += struct.pack('<i', pass_search_offset - (len(veh) + 4))
    
    # Clear Trap Flag: and dword ptr [ecx + 0xC0], 0xFFFFFEFF
    veh += bytes([0x81, 0xA1, 0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0xFF, 0xFF])
    
    # Call VirtualProtect(page_addr, page_size, orig_prot | 0x100, &scratch)
    # push &old_prot (scratch at ebx + 0x34)
    veh += bytes([0x8D, 0x43, 0x34, 0x50])
    # push orig_prot | 0x100
    veh += bytes([0x8B, 0x43, 0x30, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50])
    # push page_size [ebx + 0x28]
    veh += bytes([0xFF, 0x73, 0x28])
    # push page_addr [ebx + 0x20]
    veh += bytes([0xFF, 0x73, 0x20])
    # call [ebx + 0x40]
    veh += bytes([0xFF, 0x53, 0x40])
    
    # finish_step:
    veh += bytes([
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, # mov eax, -1
        0x5F, 0x5E, 0x5B, 0x5D,       # pop edi, esi, ebx, ebp
        0xC2, 0x04, 0x00              # ret 4
    ])
    
    # 2. InitThread at 0x1400 (Page 1): DWORD WINAPI InitThread(LPVOID lpParam)
    init = bytearray([
        0x55, 0x89, 0xE5, 0x53,         # push ebp; mov ebp, esp; push ebx
        0x8B, 0x5D, 0x08,               # mov ebx, [ebp + 8] (cfg)
        # AddVectoredExceptionHandler(1, VehHandler):
        0x8D, 0x83, 0x00, 0x10, 0x00, 0x00, # lea eax, [ebx + 0x1000] (VehHandler at 0x1000)
        0x50,                           # push eax (Handler)
        0x6A, 0x01,                     # push 1 (First)
        0xFF, 0x53, 0x48,               # call [ebx + 0x48] (pfn_AddVEH)
        0x89, 0x43, 0x38,               # mov [ebx + 0x38], eax (veh_handle)
        0xC7, 0x43, 0x3C, 0x00, 0x00, 0x00, 0x00, # mov [ebx + 0x3C], 0
        # VirtualProtect(page_addr, page_size, orig_prot | 0x100, &scratch):
        0x8D, 0x43, 0x34, 0x50,         # lea eax, [ebx + 0x34]; push eax
        0x8B, 0x43, 0x30, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50, # push orig_prot | 0x100
        0xFF, 0x73, 0x28,               # push [ebx + 0x28]
        0xFF, 0x73, 0x20,               # push [ebx + 0x20]
        0xFF, 0x53, 0x40,               # call [ebx + 0x40] (pfn_VP)
        # Set active = 1:
        0xC7, 0x43, 0x04, 0x01, 0x00, 0x00, 0x00,
        0x31, 0xC0,                     # xor eax, eax
        0x5B, 0x5D,                     # pop ebx; pop ebp
        0xC2, 0x04, 0x00                # ret 4
    ])
    
    # 3. CleanupThread at 0x1600 (Page 1): DWORD WINAPI CleanupThread(LPVOID lpParam)
    cleanup = bytearray([
        0x55, 0x89, 0xE5, 0x53,         # push ebp; mov ebp, esp; push ebx
        0x8B, 0x5D, 0x08,               # mov ebx, [ebp + 8] (cfg)
        # Check if veh_handle != 0:
        0x8B, 0x43, 0x38,
        0x85, 0xC0,
        0x74, 0x0C,                     # jz skip_rem (+12 bytes)
        0x50,                           # push eax (veh_handle)
        0xFF, 0x53, 0x50,               # call [ebx + 0x50] (pfn_RemVEH)
        0xC7, 0x43, 0x38, 0x00, 0x00, 0x00, 0x00, # veh_handle = 0
        # skip_rem:
        # VirtualProtect(page_addr, page_size, orig_prot, &scratch):
        0x8D, 0x43, 0x34, 0x50,
        0xFF, 0x73, 0x30,               # push orig_prot
        0xFF, 0x73, 0x28,               # push page_size
        0xFF, 0x73, 0x20,               # push page_addr
        0xFF, 0x53, 0x40,               # call [ebx + 0x40]
        # Set active = 0:
        0xC7, 0x43, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0x5B, 0x5D,
        0xC2, 0x04, 0x00
    ])
    
    return bytes(veh), bytes(init), bytes(cleanup)


def _resolve_wow64_apis(pid):
    """
    Resolve 32-bit function pointers for VirtualProtect and RtlAdd/RemoveVectoredExceptionHandler
    in a 32-bit WOW64 target process.
    """
    snap = k32.CreateToolhelp32Snapshot(0x08 | 0x10, pid) # TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    if not snap or snap == -1 or snap == 0xFFFFFFFFFFFFFFFF:
        return None, None, None

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ('dwSize', w.DWORD), ('th32ModuleID', w.DWORD), ('th32ProcessID', w.DWORD),
            ('GlblcntUsage', w.DWORD), ('ProccntUsage', w.DWORD),
            ('modBaseAddr', ctypes.c_void_p), ('modBaseSize', w.DWORD),
            ('hModule', w.HMODULE), ('szModule', ctypes.c_char * 256),
            ('szExePath', ctypes.c_char * 260),
        ]

    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    k32_base = None
    ntdll_base = None

    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            mod = me.szModule.decode('latin-1').lower()
            path = me.szExePath.decode('latin-1').lower()
            base = me.modBaseAddr or 0
            if mod == 'kernel32.dll' and 'syswow64' in path:
                k32_base = base
            elif mod == 'ntdll.dll' and 'syswow64' in path:
                ntdll_base = base
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)

    if not k32_base or not ntdll_base:
        return None, None, None

    try:
        import pefile
        syswow64 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64')
        pe_k32 = pefile.PE(os.path.join(syswow64, 'kernel32.dll'), fast_load=True)
        pe_k32.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        exp_k32 = {exp.name.decode('latin-1'): exp.address for exp in pe_k32.DIRECTORY_ENTRY_EXPORT.symbols if exp.name}

        pe_nt = pefile.PE(os.path.join(syswow64, 'ntdll.dll'), fast_load=True)
        pe_nt.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        exp_nt = {exp.name.decode('latin-1'): exp.address for exp in pe_nt.DIRECTORY_ENTRY_EXPORT.symbols if exp.name}

        pfn_vp = k32_base + exp_k32.get('VirtualProtect', 0)
        pfn_add_veh = ntdll_base + exp_nt.get('RtlAddVectoredExceptionHandler', 0)
        pfn_rem_veh = ntdll_base + exp_nt.get('RtlRemoveVectoredExceptionHandler', 0)
        return pfn_vp, pfn_add_veh, pfn_rem_veh
    except Exception:
        return None, None, None



# ============================================================
# Stealth Debugger
# ============================================================
class StealthDebugger:
    """
    Stealth memory access/write debugger using VirtualProtectEx(PAGE_GUARD)
    and an injected Vectored Exception Handler (VEH).
    
    Completely avoids Windows Debugging APIs (DebugActiveProcess, WaitForDebugEvent)
    making it invisible to anti-cheat scanners (IsDebuggerPresent, PEB check, DR0-DR7).
    """

    def __init__(self, pid, address, mode='access', size=4, on_hit=None, on_status=None):
        """
        pid: target process ID
        address: memory address to monitor
        mode: 'access' (read/write) or 'write' (write-only)
        size: monitored length in bytes (1, 2, 4, 8)
        on_hit: callback function(hit_dict) called when memory is accessed
        on_status: callback function(status_string)
        """
        self.pid = pid
        self.address = address & 0xFFFFFFFFFFFFFFFF
        self.mode = mode
        self.size = size if size in (1, 2, 4, 8) else 4
        self.on_hit = on_hit
        self.on_status = on_status

        self.h_process = None
        self.is_64 = True
        self.remote_stub = None
        self.page_base = 0
        self.page_size = 4096
        self.orig_prot = PAGE_READWRITE
        self.veh_handle = 0
        self.has_error = False
        self.is_active = False

        self.stop_requested = threading.Event()
        self.worker_thread = None
        self.hit_cache = OrderedDict()  # rip -> dict(count, rip, insn, regs, bytes)

        # Disassemblers
        self.disasm_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disasm_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def _log(self, msg):
        if self.on_status:
            try:
                self.on_status(msg)
            except Exception:
                pass

    def start(self):
        """Start the stealth debugger loop in a background worker thread."""
        self.worker_thread = threading.Thread(
            target=self._debug_loop,
            daemon=True,
            name=f"stealthdbg-{self.pid}"
        )
        self.worker_thread.start()

    def stop(self):
        """Stop monitoring, safely detach VEH, restore page protection, and free remote memory."""
        self.stop_requested.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.5)

    def is_running(self):
        return self.worker_thread is not None and self.worker_thread.is_alive()

    def replace_with_nops(self, addr, size):
        """Overwrite instruction at addr with NOPs (0x90)."""
        if self.h_process:
            return _write_mem_nop(self.h_process, addr, size)
        return False

    def _determine_architecture(self):
        is_wow64 = w.BOOL(False)
        if hasattr(k32, 'IsWow64Process'):
            k32.IsWow64Process(self.h_process, ctypes.byref(is_wow64))
        is_os_64 = (ctypes.sizeof(ctypes.c_void_p) == 8)
        if is_os_64:
            self.is_64 = not is_wow64.value
        else:
            self.is_64 = False

    def _query_target_page(self):
        """Query memory protection and compute page-aligned boundaries."""
        mbi = MEMORY_BASIC_INFORMATION()
        res = k32.VirtualQueryEx(
            self.h_process,
            ctypes.c_void_p(self.address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        if not res or mbi.State != MEM_COMMIT:
            self.page_base = (self.address & ~0xFFF) & 0xFFFFFFFFFFFFFFFF
            self.page_size = 4096
            self.orig_prot = PAGE_READWRITE
        else:
            self.page_base = (self.address & ~0xFFF) & 0xFFFFFFFFFFFFFFFF
            self.page_size = 4096
            # Avoid compound protection flags without base RW/RX
            prot = mbi.Protect & ~PAGE_GUARD
            self.orig_prot = prot if prot else PAGE_READWRITE

    def _debug_loop(self):
        """Main stealth debugger setup and polling loop."""
        # 1. Open target process without debug privileges
        desired_access = (
            PROCESS_VM_OPERATION |
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION |
            PROCESS_CREATE_THREAD
        )
        self.h_process = k32.OpenProcess(desired_access, False, self.pid)
        if not self.h_process:
            # Fallback to PROCESS_ALL_ACCESS if permitted
            self.h_process = k32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

        if not self.h_process:
            err = ctypes.get_last_error()
            self._log(f"Failed to open target PID {self.pid} (Error {err})")
            return

        self._determine_architecture()
        self._query_target_page()
        arch_name = "64-bit" if self.is_64 else "32-bit WOW64"
        self._log(
            f"Stealth Debugger attaching to PID {self.pid} ({arch_name}, Target Page: 0x{self.page_base:X}, OrigProt: 0x{self.orig_prot:X})..."
        )

        # 2. Allocate remote buffer for configuration, ring buffer, and VEH shellcode
        # Allocate initially as PAGE_READWRITE (pure data, zero RWX!)
        stub_size = 0x2000  # 8192 bytes (Page 0: 4KB Data RW, Page 1: 4KB Code RX)
        self.remote_stub = k32.VirtualAllocEx(
            self.h_process,
            None,
            stub_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
        if not self.remote_stub:
            err = ctypes.get_last_error()
            self.has_error = True
            self._log(f"Failed to allocate remote stub in PID {self.pid} (Error {err})")
            self._cleanup()
            return

        # 3. Assemble shellcode package & resolve API pointers
        if self.is_64:
            veh_code, init_code, cleanup_code = _build_veh_package_x64()
            pfn_vp = ctypes.cast(k32.VirtualProtect, ctypes.c_void_p).value
            pfn_add_veh = ctypes.cast(k32.AddVectoredExceptionHandler, ctypes.c_void_p).value
            pfn_rem_veh = ctypes.cast(k32.RemoveVectoredExceptionHandler, ctypes.c_void_p).value
            is_64_val = 1
        else:
            veh_code, init_code, cleanup_code = _build_veh_package_x86()
            pfn_vp, pfn_add_veh, pfn_rem_veh = _resolve_wow64_apis(self.pid)
            if not pfn_vp or not pfn_add_veh or not pfn_rem_veh:
                self.has_error = True
                self._log(f"Failed to resolve 32-bit system APIs for PID {self.pid}")
                self._cleanup()
                return
            is_64_val = 0

        # Build Config Header (104 bytes)
        magic = 0x4D4F4D4F  # "MOMO"
        active = 0
        mode_val = 1 if self.mode == 'write' else 0
        hit_count = 0
        watch_addr = self.address
        watch_size = self.size
        page_addr = self.page_base
        page_size = self.page_size
        orig_prot = self.orig_prot
        padding = 0
        veh_handle = 0
        ring_head = 0
        ring_tail = 0
        ring_capacity = 16

        cfg_header = struct.pack(
            '<IIIIQQQQIIQQQQIIII',
            magic, active, mode_val, hit_count,
            watch_addr, watch_size, page_addr, page_size,
            orig_prot, padding,
            veh_handle, pfn_vp, pfn_add_veh, pfn_rem_veh,
            ring_head, ring_tail, ring_capacity, is_64_val
        )

        # 4. Write config, ring buffer, and shellcode to remote process
        written = ctypes.c_size_t(0)
        # Config header at 0x0000 (Page 0: Data)
        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(self.remote_stub), cfg_header, len(cfg_header), ctypes.byref(written))
        # Clear ring buffer (0x0100 - 0x0AFF, Page 0: Data)
        zero_buf = b'\x00' * (16 * 160)
        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(self.remote_stub + 0x0100), zero_buf, len(zero_buf), ctypes.byref(written))
        # VehHandler at 0x1000 (Page 1: Code)
        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(self.remote_stub + 0x1000), veh_code, len(veh_code), ctypes.byref(written))
        # InitThread at 0x1400 (Page 1: Code)
        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(self.remote_stub + 0x1400), init_code, len(init_code), ctypes.byref(written))
        # CleanupThread at 0x1600 (Page 1: Code)
        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(self.remote_stub + 0x1600), cleanup_code, len(cleanup_code), ctypes.byref(written))

        # Separate protection:
        # Page 0 (0x0000 - 0x0FFF) remains PAGE_READWRITE (RW Data).
        # Page 1 (0x1000 - 0x1FFF) toggled to PAGE_EXECUTE_READ (RX Code).
        # ZERO RWX memory exists in the entire process!
        old_prot = w.DWORD(0)
        k32.VirtualProtectEx(
            self.h_process,
            ctypes.c_void_p(self.remote_stub + 0x1000),
            0x1000,
            PAGE_EXECUTE_READ,
            ctypes.byref(old_prot)
        )

        # 5. Execute InitThread in target process via stealth thread
        # (NtCreateThreadEx + THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
        init_thread = _create_stealth_thread(
            self.h_process,
            self.remote_stub + 0x1400,
            self.remote_stub
        )
        if not init_thread:
            err = ctypes.get_last_error()
            self.has_error = True
            self._log(f"Failed to create InitThread in PID {self.pid} (Error {err})")
            self._cleanup()
            return

        k32.WaitForSingleObject(init_thread, 3000)
        k32.CloseHandle(init_thread)

        # Read back config to check if VEH handle was installed
        read_cfg = _read_mem(self.h_process, self.remote_stub, 104)
        if len(read_cfg) >= 104:
            unpacked = struct.unpack('<IIIIQQQQIIQQQQIIII', read_cfg)
            self.veh_handle = unpacked[10]
            is_active = unpacked[1]
            if not is_active or not self.veh_handle:
                self.has_error = True
                self._log(f"Error: VEH handler installation failed (active={is_active}, handle=0x{self.veh_handle:X}).")
                self._cleanup()
                return
            else:
                self.is_active = True
        else:
            self.has_error = True
            self._log("Failed to read back remote config from target.")
            self._cleanup()
            return

        # Arm PAGE_GUARD on target page directly from Python
        old_prot = w.DWORD(0)
        guard_ok = k32.VirtualProtectEx(
            self.h_process,
            ctypes.c_void_p(self.page_base),
            self.page_size,
            self.orig_prot | PAGE_GUARD,
            ctypes.byref(old_prot)
        )
        if not guard_ok:
            err = ctypes.get_last_error()
            self.has_error = True
            self._log(f"Failed to arm PAGE_GUARD on 0x{self.page_base:X} (Error {err})")
            self._cleanup()
            return

        self._log(
            f"Stealth VEH debugger active! Monitoring 0x{self.address:X} ({self.mode}) via PAGE_GUARD [{arch_name}]."
        )

        # 6. Polling loop: read ring buffer hits
        last_tail = 0
        last_page_faults = 0
        ring_base = self.remote_stub + 0x0100
        slot_size = 160

        try:
            while not self.stop_requested.is_set():
                # Check target process liveness
                exit_code = w.DWORD(0)
                if not k32.GetExitCodeProcess(self.h_process, ctypes.byref(exit_code)) or exit_code.value != STILL_ACTIVE:
                    self._log("Target process terminated.")
                    break

                # Read telemetry: page_faults (0x68), last_addr, last_rip
                if self.is_64:
                    diag_raw = _read_mem(self.h_process, self.remote_stub + 0x68, 24)
                    if diag_raw and len(diag_raw) >= 24:
                        page_faults, pad, last_addr, last_rip = struct.unpack('<IIQQ', diag_raw)
                        if page_faults != last_page_faults:
                            last_page_faults = page_faults
                            if not self.hit_cache:
                                self._log(f"Watching 0x{self.address:X} | Page touched {page_faults:,}x (Last: 0x{last_addr:X} by 0x{last_rip:X})")
                else:
                    diag_raw = _read_mem(self.h_process, self.remote_stub + 0x68, 12)
                    if diag_raw and len(diag_raw) >= 12:
                        page_faults, last_addr, last_rip = struct.unpack('<III', diag_raw)
                        if page_faults != last_page_faults:
                            last_page_faults = page_faults
                            if not self.hit_cache:
                                self._log(f"Watching 0x{self.address:X} | Page touched {page_faults:,}x (Last: 0x{last_addr:X} by 0x{last_rip:X})")

                # Read ring_head from remote config (offset 88 = 0x58)
                head_raw = _read_mem(self.h_process, self.remote_stub + 0x58, 4)
                if not head_raw:
                    time.sleep(0.05)
                    continue

                remote_head = struct.unpack('<I', head_raw)[0]
                if remote_head != last_tail:
                    # Catch up on pending hits
                    pending_count = remote_head - last_tail
                    if pending_count > 16:
                        # Ring buffer overflowed; advance to latest 16
                        last_tail = remote_head - 16

                    while last_tail < remote_head:
                        slot_idx = last_tail % 16
                        slot_addr = ring_base + slot_idx * slot_size
                        slot_raw = _read_mem(self.h_process, slot_addr, slot_size)
                        last_tail += 1

                        if len(slot_raw) >= slot_size:
                            self._process_hit(slot_raw)

                # Responsive sleep
                time.sleep(0.02)

        except Exception as e:
            self._log(f"Stealth debugger loop error: {e}")
        finally:
            self._cleanup()

    def _process_hit(self, slot_raw):
        """Parse slot data, disassemble instruction at RIP, and invoke callbacks."""
        try:
            # Slot format:
            # 0x00: rip (uint64)
            # 0x08: fault_addr (uint64)
            # 0x10: access_type (uint32)
            # 0x14: reserved (uint32)
            # 0x18: eflags (uint64)
            # 0x20: rax (uint64)
            # 0x28: rbx (uint64)
            # 0x30: rcx (uint64)
            # 0x38: rdx (uint64)
            # 0x40: rsi (uint64)
            # 0x48: rdi (uint64)
            # 0x50: rbp (uint64)
            # 0x58: rsp (uint64)
            # 0x60: r8 (uint64)
            # 0x68: r9 (uint64)
            # 0x70: r10 (uint64)
            # 0x78: r11 (uint64)
            # 0x80: r12 (uint64)
            # 0x88: r13 (uint64)
            # 0x90: r14 (uint64)
            # 0x98: r15 (uint64)
            (
                rip, fault_addr, access_type, reserved, eflags,
                rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
                r8, r9, r10, r11, r12, r13, r14, r15
            ) = struct.unpack('<QQIIQQQQQQQQQQQQQQQQQ', slot_raw)

            if not rip:
                return

            # Read memory at RIP to disassemble
            raw_insn = _read_mem(self.h_process, rip, 16)
            insn_text = "???"
            insn_bytes = b""
            insn_size = 1

            if raw_insn:
                disasm = self.disasm_64 if self.is_64 else self.disasm_32
                dis = list(disasm.disasm(raw_insn, rip, count=1))
                if dis:
                    insn = dis[0]
                    insn_text = f"{insn.mnemonic} {insn.op_str}"
                    insn_bytes = bytes(insn.bytes)
                    insn_size = insn.size

            if self.is_64:
                regs = {
                    'RAX': f"0x{rax:016X}",
                    'RBX': f"0x{rbx:016X}",
                    'RCX': f"0x{rcx:016X}",
                    'RDX': f"0x{rdx:016X}",
                    'RSI': f"0x{rsi:016X}",
                    'RDI': f"0x{rdi:016X}",
                    'RBP': f"0x{rbp:016X}",
                    'RSP': f"0x{rsp:016X}",
                    'R8':  f"0x{r8:016X}",
                    'R9':  f"0x{r9:016X}",
                    'R10': f"0x{r10:016X}",
                    'R11': f"0x{r11:016X}",
                    'R12': f"0x{r12:016X}",
                    'R13': f"0x{r13:016X}",
                    'R14': f"0x{r14:016X}",
                    'R15': f"0x{r15:016X}",
                    'RIP': f"0x{rip:016X}",
                    'EFLAGS': f"0x{eflags:08X}",
                }
            else:
                regs = {
                    'EAX': f"0x{rax & 0xFFFFFFFF:08X}",
                    'EBX': f"0x{rbx & 0xFFFFFFFF:08X}",
                    'ECX': f"0x{rcx & 0xFFFFFFFF:08X}",
                    'EDX': f"0x{rdx & 0xFFFFFFFF:08X}",
                    'ESI': f"0x{rsi & 0xFFFFFFFF:08X}",
                    'EDI': f"0x{rdi & 0xFFFFFFFF:08X}",
                    'EBP': f"0x{rbp & 0xFFFFFFFF:08X}",
                    'ESP': f"0x{rsp & 0xFFFFFFFF:08X}",
                    'EIP': f"0x{rip & 0xFFFFFFFF:08X}",
                    'EFLAGS': f"0x{eflags & 0xFFFFFFFF:08X}",
                }

            # Update cache
            if rip not in self.hit_cache:
                self.hit_cache[rip] = {
                    'rip': rip,
                    'count': 1,
                    'insn': insn_text,
                    'bytes': insn_bytes,
                    'size': insn_size,
                    'regs': regs,
                }
            else:
                self.hit_cache[rip]['count'] += 1
                self.hit_cache[rip]['regs'] = regs

            if self.on_hit:
                try:
                    self.on_hit(self.hit_cache[rip])
                except Exception:
                    pass

        except Exception as e:
            self._log(f"Error processing hit: {e}")

    def _cleanup(self):
        """Restore memory protection, uninstall VEH, and free allocated memory in remote process."""
        if not self.h_process:
            return

        # 1. Immediately remove PAGE_GUARD from the watched page
        if self.page_base:
            try:
                old_prot = w.DWORD(0)
                k32.VirtualProtectEx(
                    self.h_process,
                    ctypes.c_void_p(self.page_base),
                    self.page_size,
                    self.orig_prot,
                    ctypes.byref(old_prot)
                )
            except Exception:
                pass

        # 2. Run CleanupThread in target process to call RemoveVectoredExceptionHandler
        if self.remote_stub:
            try:
                clean_thread = _create_stealth_thread(
                    self.h_process,
                    self.remote_stub + 0x1600,
                    self.remote_stub
                )
                if clean_thread:
                    k32.WaitForSingleObject(clean_thread, 2000)
                    k32.CloseHandle(clean_thread)
            except Exception:
                pass

            # 3. Free the allocated remote stub page
            try:
                k32.VirtualFreeEx(
                    self.h_process,
                    ctypes.c_void_p(self.remote_stub),
                    0,
                    MEM_RELEASE
                )
            except Exception:
                pass
            self.remote_stub = None

        # 4. Close target process handle
        try:
            k32.CloseHandle(self.h_process)
        except Exception:
            pass
        self.h_process = None

        if not self.has_error and self.is_active:
            self._log("Stealth debugger detached cleanly. PAGE_GUARD removed and VEH uninstalled.")
