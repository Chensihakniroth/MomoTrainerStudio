"""
debugger.py - Cheat Engine-style Hardware Breakpoint Debugger
made by Momo aka Steav Beoung Salang

Features:
  - "Find out what accesses this address" (Read + Write hardware breakpoint)
  - "Find out what writes to this address" (Write-only hardware breakpoint)
  - Hardware breakpoints via CPU Debug Registers (DR0 and DR7)
  - Windows Debugging API (DebugActiveProcess + DebugSetProcessKillOnExit + WaitForDebugEvent)
  - Non-invasive attachment: detaching or closing NEVER terminates the target process
  - Disassembly of intercepted instructions via Capstone engine
  - Live CPU register snapshot capture (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS)
  - "Replace with NOPs" (Code patcher)
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

# ============================================================
# Windows Constants & Structures
# ============================================================
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003

THREAD_ALL_ACCESS = 0x001F03FF
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL_64 = CONTEXT_AMD64 | 0x01
CONTEXT_INTEGER_64 = CONTEXT_AMD64 | 0x02
CONTEXT_DEBUG_64   = CONTEXT_AMD64 | 0x10
CONTEXT_ALL_64     = CONTEXT_AMD64 | 0x1F

CONTEXT_i386 = 0x00010000
CONTEXT_CONTROL_32 = CONTEXT_i386 | 0x01
CONTEXT_INTEGER_32 = CONTEXT_i386 | 0x02
CONTEXT_DEBUG_32   = CONTEXT_i386 | 0x10
CONTEXT_ALL_32     = CONTEXT_i386 | 0x3F

PAGE_EXECUTE_READWRITE = 0x40


class EXCEPTION_RECORD(ctypes.Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', w.DWORD),
    ('ExceptionFlags', w.DWORD),
    ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', w.DWORD),
    ('ExceptionInformation', ctypes.c_size_t * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('ExceptionRecord', EXCEPTION_RECORD),
        ('dwFirstChance', w.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('hThread', w.HANDLE),
        ('lpThreadLocalBase', ctypes.c_void_p),
        ('lpStartAddress', ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('hFile', w.HANDLE),
        ('hProcess', w.HANDLE),
        ('hThread', w.HANDLE),
        ('lpBaseOfImage', ctypes.c_void_p),
        ('dwDebugInfoFileOffset', w.DWORD),
        ('nDebugInfoSize', w.DWORD),
        ('lpThreadLocalBase', ctypes.c_void_p),
        ('lpStartAddress', ctypes.c_void_p),
        ('lpImageName', ctypes.c_void_p),
        ('fUnicode', w.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('dwExitCode', w.DWORD)]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('dwExitCode', w.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('hFile', w.HANDLE),
        ('lpBaseOfDll', ctypes.c_void_p),
        ('dwDebugInfoFileOffset', w.DWORD),
        ('nDebugInfoSize', w.DWORD),
        ('lpImageName', ctypes.c_void_p),
        ('fUnicode', w.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ('lpDebugStringData', ctypes.c_void_p),
        ('fUnicode', w.WORD),
        ('nDebugStringLength', w.WORD),
    ]


class RIP_INFO(ctypes.Structure):
    _fields_ = [('dwError', w.DWORD), ('dwType', w.DWORD)]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ('Exception', EXCEPTION_DEBUG_INFO),
        ('CreateThread', CREATE_THREAD_DEBUG_INFO),
        ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
        ('ExitThread', EXIT_THREAD_DEBUG_INFO),
        ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
        ('LoadDll', LOAD_DLL_DEBUG_INFO),
        ('UnloadDll', UNLOAD_DLL_DEBUG_INFO),
        ('DebugString', OUTPUT_DEBUG_STRING_INFO),
        ('RipInfo', RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ('dwDebugEventCode', w.DWORD),
        ('dwProcessId', w.DWORD),
        ('dwThreadId', w.DWORD),
        ('u', _DEBUG_EVENT_UNION),
    ]


# 64-bit Context
class M128A(ctypes.Structure):
    _fields_ = [('Low', ctypes.c_uint64), ('High', ctypes.c_int64)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ('ControlWord', w.WORD),
        ('StatusWord', w.WORD),
        ('TagWord', ctypes.c_uint8),
        ('Reserved1', ctypes.c_uint8),
        ('ErrorOpcode', w.WORD),
        ('ErrorOffset', w.DWORD),
        ('ErrorSelector', w.WORD),
        ('Reserved2', w.WORD),
        ('DataOffset', w.DWORD),
        ('DataSelector', w.WORD),
        ('Reserved3', w.WORD),
        ('MxCsr', w.DWORD),
        ('MxCsr_Mask', w.DWORD),
        ('FloatRegisters', M128A * 8),
        ('XmmRegisters', M128A * 16),
        ('Reserved4', ctypes.c_uint8 * 96),
    ]


class CONTEXT64(ctypes.Structure):
    _align_ = 16
    _fields_ = [
        ('P1Home', ctypes.c_uint64),
        ('P2Home', ctypes.c_uint64),
        ('P3Home', ctypes.c_uint64),
        ('P4Home', ctypes.c_uint64),
        ('P5Home', ctypes.c_uint64),
        ('P6Home', ctypes.c_uint64),
        ('ContextFlags', w.DWORD),
        ('MxCsr', w.DWORD),
        ('SegCs', w.WORD),
        ('SegDs', w.WORD),
        ('SegEs', w.WORD),
        ('SegFs', w.WORD),
        ('SegGs', w.WORD),
        ('SegSs', w.WORD),
        ('EFlags', w.DWORD),
        ('Dr0', ctypes.c_uint64),
        ('Dr1', ctypes.c_uint64),
        ('Dr2', ctypes.c_uint64),
        ('Dr3', ctypes.c_uint64),
        ('Dr6', ctypes.c_uint64),
        ('Dr7', ctypes.c_uint64),
        ('Rax', ctypes.c_uint64),
        ('Rcx', ctypes.c_uint64),
        ('Rdx', ctypes.c_uint64),
        ('Rbx', ctypes.c_uint64),
        ('Rsp', ctypes.c_uint64),
        ('Rbp', ctypes.c_uint64),
        ('Rsi', ctypes.c_uint64),
        ('Rdi', ctypes.c_uint64),
        ('R8',  ctypes.c_uint64),
        ('R9',  ctypes.c_uint64),
        ('R10', ctypes.c_uint64),
        ('R11', ctypes.c_uint64),
        ('R12', ctypes.c_uint64),
        ('R13', ctypes.c_uint64),
        ('R14', ctypes.c_uint64),
        ('R15', ctypes.c_uint64),
        ('Rip', ctypes.c_uint64),
        ('FltSave', XMM_SAVE_AREA32),
        ('VectorRegister', M128A * 26),
        ('VectorControl', ctypes.c_uint64),
        ('DebugControl', ctypes.c_uint64),
        ('LastBranchToRip', ctypes.c_uint64),
        ('LastBranchFromRip', ctypes.c_uint64),
        ('LastExceptionToRip', ctypes.c_uint64),
        ('LastExceptionFromRip', ctypes.c_uint64),
    ]


# 32-bit (WOW64) Context
class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ('ControlWord', w.DWORD),
        ('StatusWord', w.DWORD),
        ('TagWord', w.DWORD),
        ('ErrorOffset', w.DWORD),
        ('ErrorSelector', w.DWORD),
        ('DataOffset', w.DWORD),
        ('DataSelector', w.DWORD),
        ('RegisterArea', ctypes.c_uint8 * 80),
        ('Cr0NpxState', w.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('ContextFlags', w.DWORD),
        ('Dr0', w.DWORD),
        ('Dr1', w.DWORD),
        ('Dr2', w.DWORD),
        ('Dr3', w.DWORD),
        ('Dr6', w.DWORD),
        ('Dr7', w.DWORD),
        ('FloatSave', WOW64_FLOATING_SAVE_AREA),
        ('SegGs', w.DWORD),
        ('SegFs', w.DWORD),
        ('SegEs', w.DWORD),
        ('SegDs', w.DWORD),
        ('Edi', w.DWORD),
        ('Esi', w.DWORD),
        ('Ebx', w.DWORD),
        ('Edx', w.DWORD),
        ('Ecx', w.DWORD),
        ('Eax', w.DWORD),
        ('Ebp', w.DWORD),
        ('Eip', w.DWORD),
        ('SegCs', w.DWORD),
        ('EFlags', w.DWORD),
        ('Esp', w.DWORD),
        ('SegSs', w.DWORD),
        ('ExtendedRegisters', ctypes.c_uint8 * 512),
    ]


def _read_mem(h, addr, size):
    buf = (ctypes.c_uint8 * size)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, addr, buf, size, ctypes.byref(got)):
        return b''
    return bytes(buf)[:got.value]


def _write_mem_nop(h, addr, size):
    """Write NOP (0x90) instructions to address with VirtualProtectEx."""
    old_prot = w.DWORD(0)
    if not k32.VirtualProtectEx(h, addr, size, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)):
        return False
    nop_bytes = b'\x90' * size
    written = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, addr, nop_bytes, size, ctypes.byref(written))
    k32.VirtualProtectEx(h, addr, size, old_prot.value, ctypes.byref(old_prot))
    return ok != 0


def split_watch_range(address, size):
    """Split an arbitrary watch range into CE-compatible aligned segments.

    x86 debug registers have alignment requirements for 2/4/8-byte watches.
    Cheat Engine splits an unaligned range into smaller hardware breakpoints;
    doing the same avoids silently missing the first or last bytes.
    """
    if address < 0 or size not in (1, 2, 4, 8):
        raise ValueError("hardware watch address/size is invalid")

    segments = []
    current = int(address)
    remaining = int(size)
    for _ in range(8):
        if remaining <= 0:
            break
        choices = (8, 4, 2, 1)
        segment_size = next(
            candidate for candidate in choices
            if candidate <= remaining and current % candidate == 0
        )
        segments.append((current, segment_size))
        current += segment_size
        remaining -= segment_size
    if remaining:
        raise ValueError("hardware watch range requires more than four debug registers")
    if len(segments) > 4:
        raise ValueError("hardware watch range requires more than four debug registers")
    return tuple(segments)


def debug_register_control(segments, mode):
    """Return the local DR7 value for a list of aligned watch segments."""
    rw_bits = 0b11 if mode == 'access' else 0b01
    length_bits = {1: 0b00, 2: 0b01, 8: 0b10, 4: 0b11}
    dr7 = 0x00000400  # architectural DR7 bit 10 is reserved and must be 1
    for slot, (_address, size) in enumerate(segments):
        shift = slot * 4
        dr7 |= 1 << (slot * 2)  # local enable (L0..L3)
        dr7 |= rw_bits << (16 + shift)
        dr7 |= length_bits[size] << (18 + shift)
    return dr7


# ============================================================
# Hardware Breakpoint Debugger
# ============================================================
class HardwareDebugger:
    """Manages a single hardware breakpoint debugging session on a target process."""

    def __init__(self, pid, address, mode='access', size=4, on_hit=None, on_status=None):
        """
        pid: target process ID
        address: linear address to watch
        mode: 'access' (read/write) or 'write' (write-only)
        size: watched length in bytes (1, 2, 4, 8)
        on_hit: callback function(hit_info_dict) called when breakpoint trips
        on_status: callback function(status_string)
        """
        self.pid = pid
        self.address = address
        self.mode = mode
        self.size = size if size in (1, 2, 4, 8) else 4
        self.on_hit = on_hit
        self.on_status = on_status

        self.h_process = None
        self.is_64 = True
        self.threads = {}  # tid -> handle
        self._original_debug_state = {}  # tid -> (DR0, DR1, DR2, DR3, DR7)
        self.watch_segments = split_watch_range(address, self.size)
        self.stop_requested = threading.Event()
        self.worker_thread = None
        self.hit_cache = OrderedDict()  # rip -> dict(count, rip, insn, regs, bytes)
        self._hit_lock = threading.RLock()

        # Capstone disassembler
        self.disasm_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disasm_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def _log(self, msg):
        if self.on_status:
            try:
                self.on_status(msg)
            except Exception:
                pass

    def start(self):
        """Start the debugger loop in a background thread."""
        self.worker_thread = threading.Thread(target=self._debug_loop, daemon=True, name=f"hwdbg-{self.pid}")
        self.worker_thread.start()

    def stop(self):
        """Stop debugging session, clear hardware breakpoints, and detach safely."""
        self.stop_requested.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)

    def is_running(self):
        return self.worker_thread is not None and self.worker_thread.is_alive()

    def clear_hits(self):
        """Clear the instruction history without changing the breakpoint."""
        with self._hit_lock:
            self.hit_cache.clear()

    def _determine_architecture(self):
        is_wow64 = w.BOOL(False)
        if hasattr(k32, 'IsWow64Process'):
            k32.IsWow64Process(self.h_process, ctypes.byref(is_wow64))
        # If running on 64-bit Windows, is_wow64=True means 32-bit app
        is_os_64 = (ctypes.sizeof(ctypes.c_void_p) == 8)
        if is_os_64:
            self.is_64 = not is_wow64.value
        else:
            self.is_64 = False

    def _calc_dr7(self):
        """Compute DR7 for the aligned segments covering the watch range."""
        return debug_register_control(self.watch_segments, self.mode)

    @staticmethod
    def _debug_registers(ctx):
        return (int(ctx.Dr0), int(ctx.Dr1), int(ctx.Dr2), int(ctx.Dr3), int(ctx.Dr7))

    def _apply_hw_bp(self, h_thread, tid=None):
        """Set the CE-style local data breakpoints on one thread."""
        dr7 = self._calc_dr7()
        if self.is_64:
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_DEBUG_64
            if k32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                if tid is not None and tid not in self._original_debug_state:
                    self._original_debug_state[tid] = self._debug_registers(ctx)
                registers = [0, 0, 0, 0]
                for index, (segment_address, _segment_size) in enumerate(self.watch_segments):
                    registers[index] = segment_address
                ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 = registers
                ctx.Dr6 = 0
                ctx.Dr7 = dr7
                k32.SetThreadContext(h_thread, ctypes.byref(ctx))
        else:
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_32
            if hasattr(k32, 'Wow64GetThreadContext'):
                if k32.Wow64GetThreadContext(h_thread, ctypes.byref(ctx)):
                    if tid is not None and tid not in self._original_debug_state:
                        self._original_debug_state[tid] = self._debug_registers(ctx)
                    registers = [0, 0, 0, 0]
                    for index, (segment_address, _segment_size) in enumerate(self.watch_segments):
                        registers[index] = segment_address & 0xFFFFFFFF
                    ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 = registers
                    ctx.Dr6 = 0
                    ctx.Dr7 = dr7 & 0xFFFFFFFF
                    k32.Wow64SetThreadContext(h_thread, ctypes.byref(ctx))

    def _clear_hw_bp(self, h_thread, tid=None):
        """Restore the thread's original debug registers on detach."""
        if self.is_64:
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_DEBUG_64
            if k32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                original = self._original_debug_state.get(tid)
                if original:
                    ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr7 = original
                else:
                    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
                    ctx.Dr7 = 0
                ctx.Dr6 = 0
                k32.SetThreadContext(h_thread, ctypes.byref(ctx))
        else:
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_32
            if hasattr(k32, 'Wow64GetThreadContext'):
                if k32.Wow64GetThreadContext(h_thread, ctypes.byref(ctx)):
                    original = self._original_debug_state.get(tid)
                    if original:
                        ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr7 = original
                    else:
                        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
                        ctx.Dr7 = 0
                    ctx.Dr6 = 0
                    k32.Wow64SetThreadContext(h_thread, ctypes.byref(ctx))

    def _debug_loop(self):
        """Main debugger event pump."""
        # 1. Attach to process
        if not k32.DebugActiveProcess(self.pid):
            err = ctypes.get_last_error()
            self._log(f"Failed to attach debugger to PID {self.pid} (Error {err})")
            return

        # Crucial: ensure game does NOT close when debugger detaches
        if hasattr(k32, 'DebugSetProcessKillOnExit'):
            k32.DebugSetProcessKillOnExit(False)

        segment_text = ', '.join(f'0x{addr:X}/{size}' for addr, size in self.watch_segments)
        self._log(
            f"Hardware debugger attached to PID {self.pid}. "
            f"Monitoring 0x{self.address:X}+{self.size} ({self.mode}; {segment_text})..."
        )

        dbg_event = DEBUG_EVENT()

        try:
            while not self.stop_requested.is_set():
                if not k32.WaitForDebugEvent(ctypes.byref(dbg_event), 100):
                    continue

                code = dbg_event.dwDebugEventCode
                tid = dbg_event.dwThreadId
                continue_status = DBG_CONTINUE

                if code == CREATE_PROCESS_DEBUG_EVENT:
                    self.h_process = dbg_event.u.CreateProcessInfo.hProcess
                    h_thread = dbg_event.u.CreateProcessInfo.hThread
                    self._determine_architecture()
                    self.threads[tid] = h_thread
                    self._apply_hw_bp(h_thread, tid)

                elif code == CREATE_THREAD_DEBUG_EVENT:
                    h_thread = dbg_event.u.CreateThread.hThread
                    self.threads[tid] = h_thread
                    self._apply_hw_bp(h_thread, tid)

                elif code == EXIT_THREAD_DEBUG_EVENT:
                    if tid in self.threads:
                        h_thread = self.threads.pop(tid)
                        try:
                            self._clear_hw_bp(h_thread, tid)
                        except Exception:
                            pass
                        self._original_debug_state.pop(tid, None)
                        try:
                            k32.CloseHandle(h_thread)
                        except Exception:
                            pass

                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    self._log("Target process terminated.")
                    k32.ContinueDebugEvent(dbg_event.dwProcessId, tid, DBG_CONTINUE)
                    break

                elif code == EXCEPTION_DEBUG_EVENT:
                    exc = dbg_event.u.Exception.ExceptionRecord
                    exc_code = exc.ExceptionCode

                    if exc_code == EXCEPTION_SINGLE_STEP:
                        # Hardware breakpoint triggered!
                        self._handle_single_step(tid)
                        continue_status = DBG_CONTINUE
                    elif exc_code == EXCEPTION_BREAKPOINT:
                        # Initial attach breakpoint; ignore and continue
                        continue_status = DBG_CONTINUE
                    else:
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

                k32.ContinueDebugEvent(dbg_event.dwProcessId, tid, continue_status)

        except Exception as e:
            self._log(f"Debugger error: {e}")
        finally:
            self._cleanup()

    def _decode_access_instruction(self, instruction_pointer):
        """Decode the instruction ending at a data-breakpoint RIP.

        A CPU data breakpoint traps after the memory instruction has executed,
        so the context RIP normally points to the next instruction.  Decode a
        short window backwards and choose the longest instruction ending at the
        saved RIP, matching Cheat Engine's opcode-oriented result list.
        """
        disassembler = self.disasm_64 if self.is_64 else self.disasm_32
        matches = []
        for distance in range(1, 16):
            candidate = instruction_pointer - distance
            if candidate < 0:
                break
            raw = _read_mem(self.h_process, candidate, 16)
            if not raw:
                continue
            decoded = next(iter(disassembler.disasm(raw, candidate, count=1)), None)
            if decoded is not None and decoded.address + decoded.size == instruction_pointer:
                matches.append(decoded)
        if matches:
            return max(matches, key=lambda item: item.size)

        raw = _read_mem(self.h_process, instruction_pointer, 16)
        return next(iter(disassembler.disasm(raw, instruction_pointer, count=1)), None) if raw else None

    def _handle_single_step(self, tid):
        """Capture a CE-style access hit from a hardware data breakpoint."""
        h_thread = self.threads.get(tid)
        if not h_thread:
            h_thread = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
            if h_thread:
                self.threads[tid] = h_thread

        if not h_thread:
            return

        if self.is_64:
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_ALL_64
            if not k32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                return
            debug_status = int(ctx.Dr6)
            rip_after = int(ctx.Rip)
            instruction = self._decode_access_instruction(rip_after)
            instruction_address = int(instruction.address) if instruction else rip_after
            regs = {
                'RAX': f"0x{ctx.Rax:016X}", 'RBX': f"0x{ctx.Rbx:016X}",
                'RCX': f"0x{ctx.Rcx:016X}", 'RDX': f"0x{ctx.Rdx:016X}",
                'RSI': f"0x{ctx.Rsi:016X}", 'RDI': f"0x{ctx.Rdi:016X}",
                'RBP': f"0x{ctx.Rbp:016X}", 'RSP': f"0x{ctx.Rsp:016X}",
                'R8': f"0x{ctx.R8:016X}", 'R9': f"0x{ctx.R9:016X}",
                'R10': f"0x{ctx.R10:016X}", 'R11': f"0x{ctx.R11:016X}",
                'R12': f"0x{ctx.R12:016X}", 'R13': f"0x{ctx.R13:016X}",
                'R14': f"0x{ctx.R14:016X}", 'R15': f"0x{ctx.R15:016X}",
                'RIP': f"0x{ctx.Rip:016X}", 'EFLAGS': f"0x{ctx.EFlags:08X}",
            }
            ctx.Dr6 = 0
            k32.SetThreadContext(h_thread, ctypes.byref(ctx))
        else:
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = CONTEXT_ALL_32
            if not hasattr(k32, 'Wow64GetThreadContext') or not k32.Wow64GetThreadContext(h_thread, ctypes.byref(ctx)):
                return
            debug_status = int(ctx.Dr6)
            rip_after = int(ctx.Eip)
            instruction = self._decode_access_instruction(rip_after)
            instruction_address = int(instruction.address) if instruction else rip_after
            regs = {
                'EAX': f"0x{ctx.Eax:08X}", 'EBX': f"0x{ctx.Ebx:08X}",
                'ECX': f"0x{ctx.Ecx:08X}", 'EDX': f"0x{ctx.Edx:08X}",
                'ESI': f"0x{ctx.Esi:08X}", 'EDI': f"0x{ctx.Edi:08X}",
                'EBP': f"0x{ctx.Ebp:08X}", 'ESP': f"0x{ctx.Esp:08X}",
                'EIP': f"0x{ctx.Eip:08X}", 'EFLAGS': f"0x{ctx.EFlags:08X}",
            }
            ctx.Dr6 = 0
            k32.Wow64SetThreadContext(h_thread, ctypes.byref(ctx))

        # Ignore single-step events unrelated to our allocated debug slots.
        if not (debug_status & 0xF):
            return

        insn_text = f"{instruction.mnemonic} {instruction.op_str}" if instruction else "???"
        insn_bytes = bytes(instruction.bytes) if instruction else b''
        insn_size = instruction.size if instruction else 1
        now = time.time()
        with self._hit_lock:
            if instruction_address not in self.hit_cache:
                self.hit_cache[instruction_address] = {
                    'rip': instruction_address,
                    'rip_after': rip_after,
                    'count': 1,
                    'insn': insn_text,
                    'bytes': insn_bytes,
                    'size': insn_size,
                    'regs': regs,
                    'thread_id': tid,
                    'access_type': 'write' if self.mode == 'write' else 'access',
                    'target': self.address,
                    'target_size': self.size,
                    'debug_status': debug_status,
                    'last_seen': now,
                }
            else:
                hit = self.hit_cache[instruction_address]
                hit['count'] += 1
                hit['regs'] = regs
                hit['thread_id'] = tid
                hit['rip_after'] = rip_after
                hit['debug_status'] = debug_status
                hit['last_seen'] = now
            hit = dict(self.hit_cache[instruction_address])
            hit['regs'] = dict(hit.get('regs', {}))

        if self.on_hit:
            try:
                self.on_hit(hit)
            except Exception:
                pass

    def replace_with_nops(self, addr, size):
        """Overwrite instruction at addr with NOPs (0x90)."""
        if self.h_process:
            return _write_mem_nop(self.h_process, addr, size)
        return False

    def _cleanup(self):
        """Clear hardware breakpoints and cleanly detach."""
        for tid, h in list(self.threads.items()):
            try:
                self._clear_hw_bp(h, tid)
            except Exception:
                pass
            try:
                k32.CloseHandle(h)
            except Exception:
                pass
        self.threads.clear()
        self._original_debug_state.clear()

        try:
            k32.DebugActiveProcessStop(self.pid)
            self._log("Debugger detached cleanly.")
        except Exception:
            pass
        if self.h_process:
            try:
                k32.CloseHandle(self.h_process)
            except Exception:
                pass
            self.h_process = None
