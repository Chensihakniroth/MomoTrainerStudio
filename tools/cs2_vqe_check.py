"""Why does VirtualQueryEx report these addresses as unmapped?

The pool scan rejected every candidate because `mapped()` returned False for
addresses that ReadProcessMemory reads successfully. If mapped() is broken then
the earlier "dwEntityList is empty, page pointer 0x2BA98C90008 is unmapped"
conclusion is also wrong and has to be re-checked.
"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def main():
    print(f"sizeof(MBI) = {ctypes.sizeof(MBI)}  (48 expected)")
    for name in ("BaseAddress", "AllocationProtect", "PartitionId", "RegionSize",
                 "State", "Protect"):
        f = getattr(MBI, name)
        print(f"  {name:18} offset 0x{getattr(MBI, name).offset:X}")
    print()

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.OpenProcess.restype = wt.HANDLE
    k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k.ReadProcessMemory.restype = wt.BOOL
    k.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_size_t]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k.Process32FirstW.restype = wt.BOOL
    k.Process32NextW.restype = wt.BOOL

    class P32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                    ("szExeFile", wt.WCHAR * 260)]

    s = k.CreateToolhelp32Snapshot(0x2, 0)
    pe = P32()
    pe.dwSize = ctypes.sizeof(P32)
    pid = 0
    if k.Process32FirstW(s, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == "cs2.exe":
                pid = pe.th32ProcessID
                break
            if not k.Process32NextW(s, ctypes.byref(pe)):
                break
    k.CloseHandle(s)
    if not pid:
        print("cs2.exe not running")
        return 2
    h = k.OpenProcess(0x0410, False, pid)
    print(f"pid={pid}\n")

    targets = [
        ("scene node (reads fine)", 0x2BAC74C3880),
        ("entityList page ptr", 0x2BA98C90008),
        ("entitySystem", 0x2BA7B542800),
        ("local pawn", 0x2BB0568B800),
        ("local controller", 0x2BA688D8E00),
        ("definitely bogus", 0x7FFFFFFFFFFF),
    ]
    for label, va in targets:
        buf = ctypes.create_string_buffer(8)
        g = ctypes.c_size_t(0)
        rpm = k.ReadProcessMemory(h, ctypes.c_void_p(va), buf, 8, ctypes.byref(g))
        ctypes.set_last_error(0)
        m = MBI()
        n = k.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                             ctypes.sizeof(MBI))
        err = ctypes.get_last_error()
        print(f"{label:24} 0x{va:016X}")
        print(f"    ReadProcessMemory ok={bool(rpm and g.value == 8)}")
        print(f"    VirtualQueryEx   ret={n} err={err}"
              f"  State=0x{m.State:X} Protect=0x{m.Protect:X} "
              f"RegionSize=0x{m.RegionSize:X}")
        if n:
            print(f"    -> committed={m.State == 0x1000} "
                  f"readable={bool(int(m.Protect) & 0x02)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())