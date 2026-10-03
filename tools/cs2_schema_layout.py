"""Where is the type-scope vector inside this build's SchemaSystem?

Dumps the structure as qwords and hunts for a UtlVector (canonical data pointer
with a small count) anywhere in the first 8 KiB, plus any plausible int32
registration count. Prints the layout so the next offset can be read off it.
"""
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

SS_GLOBAL_RVA = 0x76710


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


def module(pid, name):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    base = size = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == name:
                base, size = me.modBaseAddr or 0, me.modBaseSize
                break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0410, False, pid)
    ss_base, ss_size = module(pid, "schemasystem.dll")

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

    def ri(va):
        r = rd(va, 4)
        return struct.unpack("<i", r)[0] if r else 0

    ss = rq(ss_base + SS_GLOBAL_RVA)
    print(f"schemasystem.dll 0x{ss_base:X}   SchemaSystem* = 0x{ss:X}")
    print(f"SchemaSystem is inside the module image: "
          f"{ss_base <= ss < ss_base + ss_size}")

    blob = rd(ss, 0x8000)
    if blob is None:
        print("could not read 32 KiB at SchemaSystem"); return 1

    print("\n-- qword layout (first 0x200) --")
    for row in range(0, 0x200, 0x40):
        cells = []
        for k in range(4):
            q = struct.unpack_from("<Q", blob, row + k * 8)[0]
            tag = ""
            if ss_base <= q < ss_base + ss_size:
                tag = " [mod]"
            elif 0x10000 < q < (1 << 47):
                tag = " [heap]"
            cells.append(f"0x{q:016X}{tag}")
        print(f"  +0x{row:03X}  " + "  ".join(cells))

    print("\n-- UtlVector candidates (canonical data + small count) --")
    found = 0
    for o in range(0, len(blob) - 16, 8):
        d = struct.unpack_from("<Q", blob, o)[0]
        c = struct.unpack_from("<i", blob, o + 8)[0]
        if 0x10000 < d < (1 << 47) and 0 < c < 1024:
            first = rq(d)
            nm = None
            if 0x10000 < first < (1 << 47):
                raw = rd(first, 0x120)
                if raw:
                    z = raw.find(b"\x00")
                    if 0 < z < 60:
                        try:
                            nm = raw[:z].decode("ascii")
                        except UnicodeDecodeError:
                            nm = None
            print(f"  +0x{o:04X}  data=0x{d:X} count={c} cap={ri(ss + o + 12)}"
                  f"  first=0x{first:X}  name={nm!r}")
            found += 1
            if found > 25:
                print("  ... truncated")
                break
    if not found:
        print("  NONE - the type scope vector is not a plain UtlVector here")
        print("  (it may be a CUtlTSHash, or the object is not SchemaSystem)")

    print("\n-- int32 values in 500..100000 (registration count?) --")
    hits = []
    for o in range(0, len(blob) - 4, 4):
        v = struct.unpack_from("<i", blob, o)[0]
        if 500 <= v <= 100000:
            hits.append((o, v))
    print("  " + ", ".join(f"+0x{o:X}={v}" for o, v in hits[:20]) or "  none")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())