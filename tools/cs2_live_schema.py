"""Read the LIVE CS2 schema system out of the running process.

Ported from D:\\cs2-dumper (src/analysis/schemas.rs and the schema_system/*,
tier1/utl_ts_hash.rs structs). The Rust dumper needs memflow; this needs only
ReadProcessMemory, which means the schema can be re-read on demand instead of
depending on a saved output/ run.

Chain:
  schemasystem.dll  --AOB '4c8d35${'} 0f2845'-->  SchemaSystem*
  SchemaSystem.type_scopes            UtlVector at +0x190
  SchemaSystemTypeScope.name          inline char[256] at +0x08
  SchemaSystemTypeScope.class_bindings UtlTsHash at +0x560
  UtlTsHash.entry_mem                  memory pool (0x60 bytes)
  UtlTsHash.buckets[256]               at +0x60, 0x18 bytes each
  bucket.first / .first_uncommitted    at +0x08 / +0x10
  UtlTsHashFixedData.data              at +0x10  -> SchemaClassInfoData*
  SchemaClassInfoData.name/+0x08  size/+0x20  field_count/+0x24  fields/+0x30
  SchemaClassFieldData.name/+0x00 type/+0x08 offset/+0x10
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import struct
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402

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

SCHEMA_PATTERN = "4c8d35${'} 0f2845"

SS_TYPE_SCOPES = 0x190
TS_NAME = 0x08
TS_CLASS_BINDINGS = 0x560
TS_ENUM_BINDINGS = 0x1DD0
HASH_ENTRY_MEM = 0x00
HASH_BUCKETS = 0x60
BUCKET_SIZE = 0x18
BUCKET_FIRST = 0x08
BUCKET_FIRST_UNCOMMITTED = 0x10
NODE_DATA = 0x10
NODE_NEXT = 0x08
CLS_NAME = 0x08
CLS_MODULE = 0x18
CLS_SIZE = 0x20
CLS_FIELD_COUNT = 0x24
CLS_FIELDS = 0x30
FLD_NAME = 0x00
FLD_TYPE = 0x08
FLD_OFFSET = 0x10


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


def canonical(v):
    return 0x10000 < v < (1 << 47)


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)

    def rd(va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return buf.raw

    def rq(va):
        raw = rd(va, 8)
        return struct.unpack("<Q", raw)[0] if raw else 0

    def ri(va):
        raw = rd(va, 4)
        return struct.unpack("<i", raw)[0] if raw else 0

    def cstr(p, cap=128):
        if not canonical(p):
            return None
        raw = rd(p, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        try:
            return s.decode("utf-8")
        except UnicodeDecodeError:
            return None

    ss_base, ss_size = module(pid, "schemasystem.dll")
    print(f"pid={pid}")
    print(f"schemasystem.dll 0x{ss_base:X} ({ss_size:,} bytes)")
    if not ss_base:
        print("schemasystem.dll is not loaded")
        return 1

    # Resolve the schema system pointer from the live module image.
    live = rd(ss_base, ss_size)
    if live is None:
        print("could not read schemasystem.dll")
        return 1

    def live_mapper(rva):
        return rva if 0 <= rva < ss_size else None

    hits = []
    atoms = c2.parse_pattern(SCHEMA_PATTERN)
    needle, _ = c2._anchor(atoms)
    pos = 0
    while True:
        i = live.find(needle, pos)
        if i < 0:
            break
        pos = i + 1
        sv = c2._match_at(atoms, live, i, live_mapper)
        if sv is not None:
            hits.append((i, sv))
    print(f"schema system pattern: {len(hits)} hit(s)")
    if not hits:
        print("PATTERN DEAD - schemasystem.dll changed")
        return 1
    for m, sv in hits:
        print(f"   match rva 0x{m:X} -> global rva 0x{sv[0]:X}")

    ss_ptr_rva = hits[0][1][0]
    ss_ptr = rq(ss_base + ss_ptr_rva)
    print(f"SchemaSystem* = 0x{ss_ptr:X}")
    if not canonical(ss_ptr):
        print("schema system pointer is null (game still loading?)")
        return 1

    # The Rust dumper's field offsets (+0x190 type_scopes, +0x280 count) are
    # pinned to the build it was written against. On this build they read as
    # garbage, so locate the UtlVector by SHAPE instead: a plausible vector is a
    # canonical data pointer with a small count, and its first element must be a
    # pointer to a struct whose head decodes as an ASCII module name.
    ss_blob = rd(ss_ptr, 0x1000)
    if ss_blob is None:
        print("could not read SchemaSystem")
        return 1
    print(f"SchemaSystem blob {len(ss_blob)} bytes, first 64 bytes:")
    print("   " + " ".join(f"{b:02x}" for b in ss_blob[:64]))

    def module_name_at(ts):
        raw = rd(ts, 0x120)
        if not raw:
            return None
        # the name is an inline char[256]; find the first NUL
        z = raw.find(b"\x00")
        if z <= 0:
            return None
        try:
            s = raw[:z].decode("ascii")
        except UnicodeDecodeError:
            return None
        return s if s.replace(".", "").replace("_", "").isalnum() and len(s) > 3 else None

    vec = None
    for off in range(0, len(ss_blob) - 16, 8):
        data = struct.unpack_from("<Q", ss_blob, off)[0]
        cnt = struct.unpack_from("<i", ss_blob, off + 8)[0]
        if not canonical(data) or not (0 < cnt < 512):
            continue
        first = rq(data)
        if not canonical(first):
            continue
        nm = module_name_at(first)
        if nm:
            vec = (off, data, cnt, first, nm)
            break

    if not vec:
        print("no UtlVector with a plausible type-scope vector found in +0x1000")
        print("scanning a wider window...")
        for off in range(0, 0x2000, 8):
            data = rq(ss_ptr + off)
            cnt = ri(ss_ptr + off + 8)
            if not canonical(data) or not (0 < cnt < 512):
                continue
            first = rq(data)
            if not canonical(first):
                continue
            nm = module_name_at(first)
            if nm:
                vec = (off, data, cnt, first, nm)
                break
    if not vec:
        print("FAILED to locate the type scope vector")
        k32.CloseHandle(h)
        return 1

    off, ts_data, ts_count, first_ts, first_name = vec
    print(f"\ntype_scopes vector at SchemaSystem+0x{off:X}")
    print(f"   data=0x{ts_data:X} count={ts_count}  first scope name={first_name!r}")

    all_classes = {}
    for ti in range(ts_count):
        ts_ptr = rq(ts_data + ti * 8)
        if not canonical(ts_ptr):
            continue
        raw = rd(ts_ptr + TS_NAME, 256)
        mod_name = raw.split(b"\x00")[0].decode("utf-8", "replace") if raw else "?"
        buckets = ts_ptr + TS_CLASS_BINDINGS + HASH_BUCKETS
        seen_nodes = set()
        data_ptrs = []
        for b in range(256):
            for field in (BUCKET_FIRST_UNCOMMITTED, BUCKET_FIRST):
                node = rq(buckets + b * BUCKET_SIZE + field)
                guard = 0
                while canonical(node) and node not in seen_nodes and guard < 10000:
                    seen_nodes.add(node)
                    guard += 1
                    d = rq(node + NODE_DATA)
                    if canonical(d):
                        data_ptrs.append(d)
                    node = rq(node + NODE_NEXT)
        if not data_ptrs:
            continue
        got = 0
        for cp in data_ptrs:
            cname = cstr(rq(cp + CLS_NAME))
            if not cname:
                continue
            got += 1
            fields = {}
            fc = struct.unpack("<h", rd(cp + CLS_FIELD_COUNT, 2) or b"\0\0")[0]
            farr = rq(cp + CLS_FIELDS)
            if canonical(farr) and 0 < fc < 4096:
                for fi in range(fc):
                    fp = rq(farr + fi * 0x18)
                    if not canonical(fp):
                        continue
                    fname = cstr(rq(fp + FLD_NAME))
                    if not fname:
                        continue
                    fields[fname] = ri(fp + FLD_OFFSET)
            all_classes[cname] = {
                "module": f"{mod_name}.dll" if not mod_name.endswith(".dll") else mod_name,
                "size": ri(cp + CLS_SIZE),
                "fields": fields,
            }
        print(f"  scope {mod_name:22} {got:4} classes")

    print(f"\ntotal live classes: {len(all_classes)}")

    # What we came for.
    wanted = [n for n in all_classes
              if any(k in n.lower() for k in
                     ("entitylist", "entitysystem", "entityidentit",
                      "entityinstance", "identitypool"))]
    print(f"\n=== entity infrastructure classes found live: {len(wanted)} ===")
    for n in sorted(wanted):
        info = all_classes[n]
        print(f"\n{n}   (module {info['module']}, size 0x{info['size']:X})")
        for fname, off in sorted(info["fields"].items(), key=lambda x: x[1]):
            print(f"    0x{off:04X}  {fname}")

    out = Path(ROOT) / "cs2_live_schema.json"
    out.write_text(json.dumps(all_classes, indent=1), encoding="utf-8")
    print(f"\nwrote {out}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())