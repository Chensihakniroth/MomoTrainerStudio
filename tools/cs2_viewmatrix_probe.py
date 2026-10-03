"""What is actually stored at dwViewMatrix / dwViewAngles?

The RVA is proven correct (live and static resolution agree, zero drift), yet
reading base+RVA yields a non-pointer value. Test the remaining explanations:
  1. the global holds an inline matrix rather than a pointer
  2. the global is uninitialised in this game state
  3. the value is a pointer to a CViewMatrix with a header before the floats
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.restype = wt.BOOL
k32.Module32FirstW.restype = wt.BOOL
k32.Module32NextW.restype = wt.BOOL


class PE32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


class ME32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
                ("szModule", wt.WCHAR * 256), ("szExePath", wt.WCHAR * 260)]


def find_pid(name):
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
    pid = 0
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name:
                pid = pe.th32ProcessID; break
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return pid


def module_base(pid, module):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    base = size = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == module:
                base, size = me.modBaseAddr or 0, me.modBaseSize; break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


VIEW_MATRIX = o.VIEW_MATRIX   # was 0x2566910; cs2_header_offsets.py
VIEW_ANGLES = o.VIEW_ANGLES   # was 0x25767E8; cs2_header_offsets.py
CSGO_INPUT = 0x2576160
VIEW_RENDER = 0x2565D20
PREDICTION = 0x25605A0


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
    base, size = module_base(pid, "client.dll")
    print(f"pid={pid} client.dll 0x{base:X} size={size:,}")

    def rd(va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return buf.raw

    print("\n-- raw 32 bytes at each global (as 4 little-endian qwords) --")
    for label, rva in [("dwViewMatrix", VIEW_MATRIX), ("dwViewAngles", VIEW_ANGLES),
                       ("dwCSGOInput", CSGO_INPUT), ("dwViewRender", VIEW_RENDER),
                       ("dwPrediction", PREDICTION)]:
        raw = rd(base + rva, 32)
        print(f"\n  {label} @ rva 0x{rva:08X} (va 0x{base+rva:X})")
        if raw is None:
            print("     UNREADABLE"); continue
        qs = struct.unpack("<4Q", raw)
        for i, q in enumerate(qs):
            kind = "ptr?" if 0x10000 < q < 0x7FFFFFFFFFF and (q >> 40) == 0 else "     "
            print(f"     +{i*8:02X}  0x{q:016X}  {kind}")

    print("\n-- interpretation 1: is the matrix stored INLINE at the global? --")
    raw = rd(base + VIEW_MATRIX, 64)
    if raw:
        f = struct.unpack("<16f", raw)
        sane = all(v == v and abs(v) < 1e5 for v in f)
        print(f"     16 floats directly at dwViewMatrix, all sane: {sane}")
        for r in range(4):
            print("       " + "  ".join(f"{f[r*4+c]:12.4f}" for c in range(4)))

    print("\n-- interpretation 2: pointer, then matrix at +0/+16/+64 offsets --")
    p = rd(base + VIEW_MATRIX, 8)
    if p:
        ptr = struct.unpack("<Q", p)[0]
        print(f"     pointer value 0x{ptr:016X}")
        for delta in (0x0, 0x8, 0x10, 0x18, 0x20, 0x40, 0x64, 0x100):
            raw = rd(ptr + delta, 64)
            if raw is None:
                print(f"     +0x{delta:02X}: unreadable"); continue
            f = struct.unpack("<16f", raw)
            sane = all(v == v and abs(v) < 1e5 for v in f)
            first = "  ".join(f"{f[i]:10.4f}" for i in range(4))
            print(f"     +0x{delta:02X}: sane={sane}  [{first} ]")

    print("\n-- control: a known-good pointer global, for comparison --")
    raw = rd(base + VIEW_RENDER, 8)
    if raw:
        ptr = struct.unpack("<Q", raw)[0]
        print(f"     dwViewRender -> 0x{ptr:016X}")
        for delta in (0x0, 0x10, 0x64, 0x100, 0x140):
            raw = rd(ptr + delta, 64)
            if raw is None:
                print(f"     +0x{delta:02X}: unreadable"); continue
            f = struct.unpack("<16f", raw)
            sane = all(v == v and abs(v) < 1e5 for v in f)
            first = "  ".join(f"{f[i]:10.4f}" for i in range(4))
            print(f"     +0x{delta:02X}: sane={sane}  [{first} ]")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())