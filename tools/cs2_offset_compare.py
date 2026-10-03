"""Test the proposed offsets against the dumper's, live.

Proposed by the user (from a video the assistant could not extract):
    m_hPlayerPawn    0x7EC   (dumper/schema: 0x92C)
    m_iHealth        0x32C   (dumper/schema: 0x34C)
    m_iszPlayerName  0x640   (dumper/schema: 0x6FC)

All three are read here so the comparison is evidence, not opinion. m_iHealth is
expected to show health at 0x34C; m_iszPlayerName should decode as ASCII.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

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

LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py


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


def module_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    b = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == name:
                b = me.modBaseAddr or 0; break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return b


def show(raw):
    if raw is None:
        return "<unreadable>"
    i32 = struct.unpack("<i", raw[:4])[0]
    u16 = struct.unpack("<HH", raw[:4])
    txt = raw.split(b"\x00")[0]
    try:
        s = txt.decode("ascii")
        s = s if s.isprintable() else repr(txt[:16])
    except UnicodeDecodeError:
        s = repr(txt[:16])
    return f"i32={i32:<12d} u16={u16}  ascii={s}"


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0410, False, pid)
    base = module_base(pid, "client.dll")

    def rd(va, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), b, n,
                                     ctypes.byref(g)) or g.value != n:
            return None
        return b.raw

    def rq(va):
        r = rd(va, 8)
        return struct.unpack("<Q", r)[0] if r else 0

    pawn = rq(base + LOCAL_PAWN)
    ctl = rq(base + LOCAL_CONTROLLER)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn     0x{pawn:X}")
    print(f"controller     0x{ctl:X}")
    if not (pawn and ctl):
        print("need a live round"); return 1

    print("\n== m_iHealth ==")
    for off, label in ((0x32C, "proposed"), (0x34C, "dumper/schema")):
        print(f"  pawn+0x{off:03X} ({label:14})  {show(rd(pawn + off, 32))}")

    print("\n== m_iszPlayerName ==")
    for off, label in ((0x640, "proposed"), (0x6FC, "dumper/schema")):
        print(f"  ctl +0x{off:03X} ({label:14})  {show(rd(ctl + off, 32))}")

    print("\n== m_hPlayerPawn ==")
    for off, label in ((0x7EC, "proposed"), (0x92C, "dumper/schema")):
        raw = rd(ctl + off, 8)
        if raw is None:
            print(f"  ctl +0x{off:03X} ({label:14})  <unreadable>")
            continue
        u32 = struct.unpack("<I", raw[:4])[0]
        nxt = struct.unpack("<I", raw[4:8])[0]
        print(f"  ctl +0x{off:03X} ({label:14})  u32=0x{u32:08X} "
              f"(index {u32 & 0x3FFF}, serial {u32 >> 14})   next u32={nxt}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())