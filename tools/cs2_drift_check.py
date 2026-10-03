"""Is the running cs2.exe the same build as the client.dll on disk?

Reads the live module's bytes at the AOB match site and compares them to the
file. If they differ, every statically-resolved RVA is meaningless against this
process and offsets must be resolved from the live image instead.

Also re-resolves the CS2 AOB patterns against LIVE memory, so a drifted build is
detected and corrected in one pass instead of reading garbage.
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402
from evolution_offset_dumper import load_pe, rva_to_file_off  # noqa: E402

DISK = Path(r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive"
            r"\game\csgo\bin\win64\client.dll")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL

from importlib import import_module
probe = import_module("tools.cs2_live_probe".replace("tools.", "")) if False else None


def find_pid(name="cs2.exe"):
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Process32FirstW.restype = wt.BOOL
    k32.Process32NextW.restype = wt.BOOL

    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                    ("szExeFile", wt.WCHAR * 260)]

    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PE32()
    pe.dwSize = ctypes.sizeof(PE32)
    pid = 0
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return pid


def module_base(pid, module="client.dll"):
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Module32FirstW.restype = wt.BOOL
    k32.Module32NextW.restype = wt.BOOL

    class ME32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                    ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                    ("ProccntUsage", wt.DWORD),
                    ("modBaseAddr", ctypes.c_void_p),
                    ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
                    ("szModule", wt.WCHAR * 256),
                    ("szExePath", wt.WCHAR * 260)]

    snap = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    me = ME32()
    me.dwSize = ctypes.sizeof(ME32)
    base = size = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == module.lower():
                base, size = me.modBaseAddr or 0, me.modBaseSize
                break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


def main():
    pid = find_pid()
    if not pid:
        print("cs2.exe is not running")
        return 2
    base, size = module_base(pid)
    if not base:
        print("client.dll not mapped")
        return 2
    print(f"pid={pid} client.dll base=0x{base:X} size={size:,}")

    h = k32.OpenProcess(0x0010 | 0x0400 | 0x1000, False, pid)
    if not h:
        print(f"OpenProcess failed err={ctypes.get_last_error()}")
        return 2

    def rd(va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return buf.raw

    pe, raw, meta = load_pe(str(DISK))
    print(f"disk client.dll sha256 {meta['sha256_short']}  size {len(raw):,}")

    # 1. Do the live module's .text match the file at the same RVA?
    print("\n-- live vs disk byte comparison at known AOB match sites --")
    sites = {
        "dwViewMatrix match": 0xC13F83,
        "dwLocalPlayerController match": None,
    }
    mapper = c2.make_rva_mapper(pe, len(raw))
    for name, pat in c2.PATTERNS["client.dll"].items():
        m, sv = c2.find_pattern(c2.parse_pattern(pat), raw, pe, len(raw))
        if m is not None:
            sites[f"{name} (match rva 0x{m:X})"] = m

    drift = 0
    checked = 0
    for label, rva in sites.items():
        if rva is None:
            continue
        f = rva_to_file_off(pe, rva)
        if f is None:
            continue
        disk_bytes = raw[f:f + 16]
        live_bytes = rd(base + rva, 16)
        checked += 1
        if live_bytes is None:
            print(f"  [unreadable] {label}")
            continue
        same = live_bytes == disk_bytes
        if not same:
            drift += 1
        print(f"  [{'same' if same else 'DRIFT'}] {label}")
        print(f"      disk  {disk_bytes.hex(' ')}")
        print(f"      live  {live_bytes.hex(' ')}")

    print(f"\n{checked - drift}/{checked} sites match disk; {drift} drifted")

    # Re-resolve the patterns against the LIVE module image. The whole image is
    # needed, not just .text: a rip-relative bookmark lands in .data, so a
    # .text-only buffer makes every bookmarked pattern resolve to nothing.
    print("\n-- re-resolving patterns against LIVE client.dll memory --")
    live_image = rd(base, size)
    if live_image is None:
        print("  could not read the live module image")
        k32.CloseHandle(h)
        return 2
    print(f"  read live image: {len(live_image):,} bytes at base 0x{base:X}")

    def live_mapper(rva):
        if 0 <= rva < size:
            return rva          # the image is mapped at base, so rva == index
        return None

    # Resolve the static set ONCE. Calling resolve_module() per pattern would
    # re-scan the whole 39 MB binary for every name (16x the work) and made this
    # script look like it had hung.
    static_offsets = c2.resolve_module("client.dll", str(DISK))["offsets"]
    for name, pat in c2.PATTERNS["client.dll"].items():
        atoms = c2.parse_pattern(pat)
        needle, _ = c2._anchor(atoms)
        hits = []
        pos = 0
        while True:
            hit = live_image.find(needle, pos, size)
            if hit < 0:
                break
            pos = hit + 1
            sv = c2._match_at(atoms, live_image, hit, live_mapper)
            if sv is not None:
                hits.append((hit, sv))
        static_rva = static_offsets.get(name)
        s_txt = f"0x{static_rva:08X}" if static_rva is not None else "-"
        if not hits:
            print(f"  {name:<38} DEAD in live image   static={s_txt}")
        else:
            # _match_at returns the save list only (no match rva prepended), so
            # the first bookmark is sv[0]. Indexing sv[1] here reported a
            # spurious "DIFFERS FROM STATIC" on every single pattern.
            live_rva = hits[0][1][0] if hits[0][1] else 0
            flag = "" if live_rva == static_rva else "   <== DIFFERS FROM STATIC"
            n = f"  ({len(hits)} hits)" if len(hits) > 1 else ""
            print(f"  {name:<38} live=0x{live_rva:08X} static={s_txt}{n}{flag}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
