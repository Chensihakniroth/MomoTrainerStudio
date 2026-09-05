"""
memory_scanner.py - CE-style fast memory scanner
made by Momo aka Steav Beoung Salang

How CE scans memory fast:
  1. NtQueryVirtualMemory for the entire address space -> pages list
  2. Skip PAGE_GUARD / PAGE_NOACCESS regions
  3. Bulk ReadProcessMemory on aligned regions (4KB chunks)
  4. Filter values via SSE2-friendly Python loops
  5. Re-scan only the surviving candidates each round

This module:
  - scan_value(h, value, vtype, mode)        -> first scan
  - rescan_value(h, candidates, value, mode) -> subsequent scans
  - pointer_scan(h, target, max_depth, ...)  -> find static pointers to target
  - read_pointer_chain(h, base, offsets)     -> walk a chain

Value types: 'int8','uint8','int16','uint16','int32','uint32',
             'int64','uint64','float','double','string'
Scan modes:  'exact','greater','less','between','increased','decreased',
             'changed','unchanged','initial' (only on first scan)
"""

import ctypes
import ctypes.wintypes as w
import struct
import time
from collections import namedtuple

# ------------------- Win32 -------------------
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

VirtualQueryEx = k32.VirtualQueryEx

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_size_t),
        ("AllocationBase",    ctypes.c_size_t),
        ("AllocationProtect", w.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             w.DWORD),
        ("Protect",           w.DWORD),
        ("Type",              w.DWORD),
    ]

VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p,
                              ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype  = ctypes.c_size_t

ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype  = w.BOOL

WriteProcessMemory = k32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype  = w.BOOL


# ------------------- constants -------------------
PAGE_NOACCESS      = 0x01
PAGE_GUARD         = 0x100
PAGE_READWRITE     = 0x04
PAGE_READONLY      = 0x02
PAGE_EXECUTE_READ  = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_WRITECOPY     = 0x08

MEM_COMMIT     = 0x1000
MEM_PRIVATE    = 0x20000
MEM_MAPPED     = 0x40000
MEM_IMAGE      = 0x1000000

VALID_PROTECTS = {PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ,
                  PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY}

VTYPES = {
    'int8':   (1, 'b'),
    'uint8':  (1, 'B'),
    'int16':  (2, 'h'),
    'uint16': (2, 'H'),
    'int32':  (4, 'i'),
    'uint32': (4, 'I'),
    'int64':  (8, 'q'),
    'uint64': (8, 'Q'),
    'float':  (4, 'f'),
    'double': (8, 'd'),
    # string is special
}
SCAN_MODES = ('exact', 'greater', 'less', 'between',
              'changed', 'unchanged', 'increased', 'decreased', 'initial')

# A candidate: (address, last_value_bytes)
Candidate = namedtuple('Candidate', ['addr', 'last'])


# ------------------- page walker -------------------
def list_pages(h):
    """Yield (base, size, protect) for every readable+committed page."""
    addr = 0
    info = MEMORY_BASIC_INFORMATION()
    seen_bases = set()
    while True:
        got = VirtualQueryEx(h, addr, ctypes.byref(info), ctypes.sizeof(info))
        if got == 0:
            break
        base = info.BaseAddress
        size = info.RegionSize
        if base in seen_bases or size == 0:
            break
        seen_bases.add(base)
        # On x64 with PROCESS_QUERY_INFORMATION, the first VirtualQueryEx
        # at addr=0 returns the whole address space as a single FREE region.
        # In that case, query at a small non-zero address to get real pages.
        if base == 0 and size > 0x100000000 and info.State == 0x10000:
            addr = 0x10000  # skip the meta-region
            continue
        if (info.State == MEM_COMMIT
                and (info.Protect & PAGE_NOACCESS) == 0
                and (info.Protect & PAGE_GUARD)   == 0
                and info.Protect in VALID_PROTECTS):
            yield (base, size, info.Protect)
        # advance
        nxt = base + size
        if nxt <= addr or nxt >= 0x7FFF00000000:
            break
        addr = nxt


# ------------------- read helpers -------------------
def r32(h, addr):
    buf = (ctypes.c_uint8 * 4)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, 4, ctypes.byref(got)): return None
    return struct.unpack('<I', bytes(buf))[0]

def rblock(h, addr, n):
    buf = (ctypes.c_uint8 * n)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, n, ctypes.byref(got)): return None
    return bytes(buf)


# ------------------- value-type pack/unpack -------------------
def pack_value(vtype, value):
    size, fmt = VTYPES[vtype]
    return struct.pack('<' + fmt, value)

def unpack_value(vtype, blob):
    size, fmt = VTYPES[vtype]
    return struct.unpack('<' + fmt, blob)[0]

def scan_size(vtype):
    if vtype == 'string':
        return 0  # special-cased
    return VTYPES[vtype][0]


# ------------------- first scan -------------------
def first_scan(h, vtype, value, mode='exact', high=None,
               progress_cb=None, stop_cb=None):
    """
    First scan across whole memory.
    Returns list of Candidate(addr, last_value_bytes).
    """
    size = scan_size(vtype)
    if vtype == 'string':
        return _first_scan_string(h, value, progress_cb, stop_cb)

    needle = pack_value(vtype, value)
    out = []
    pages = list(list_pages(h))
    total_bytes = sum(s for _, s, _ in pages)
    scanned = 0
    t0 = time.time()
    for base, psize, prot in pages:
        if stop_cb and stop_cb():
            break
        # Read whole page in 64KB chunks
        offset = 0
        while offset < psize:
            if stop_cb and stop_cb():
                break
            chunk = 64 * 1024
            if offset + chunk > psize:
                chunk = psize - offset
            data = rblock(h, base + offset, chunk)
            if data is None or len(data) < size:
                offset += chunk
                continue
            # search
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                addr = base + offset + idx
                out.append(Candidate(addr, needle))
                start = idx + 1
            offset += chunk
        scanned += psize
        if progress_cb:
            progress_cb(scanned, total_bytes, len(out))
    return out


def rescan(h, candidates, vtype, value, mode='exact', high=None,
           prev_values=None, progress_cb=None, stop_cb=None):
    """
    Re-scan against an existing candidate list. Filters in place.
    prev_values is a dict addr -> bytes snapshot for 'changed'/'unchanged'
    Returns the filtered list.
    """
    if not candidates:
        return []
    size = scan_size(vtype)
    if vtype == 'string':
        return _rescan_string(h, candidates, value, progress_cb, stop_cb)

    needle = pack_value(vtype, value) if mode == 'exact' else None
    new_out = []
    total = len(candidates)
    for i, cand in enumerate(candidates):
        if stop_cb and stop_cb():
            break
        addr, last = cand.addr, cand.last
        cur = rblock(h, addr, size)
        if cur is None:
            continue
        try:
            cur_v = unpack_value(vtype, cur)
        except Exception:
            continue
        old_v = unpack_value(vtype, last)
        ok = _compare(mode, cur_v, old_v, value, high, prev_values, addr)
        if ok:
            new_out.append(Candidate(addr, cur))
        if progress_cb and (i % 1000 == 0):
            progress_cb(i, total, len(new_out))
    if progress_cb:
        progress_cb(total, total, len(new_out))
    return new_out


def _compare(mode, cur, old, value, high, prev_values, addr):
    if mode == 'exact':
        return cur == value
    if mode == 'greater':
        return cur > value
    if mode == 'less':
        return cur < value
    if mode == 'between':
        return value <= cur <= (high if high is not None else value)
    if mode == 'changed':
        if prev_values is not None and addr in prev_values:
            try:
                return cur != prev_values[addr]
            except Exception:
                return False
        return cur != old
    if mode == 'unchanged':
        if prev_values is not None and addr in prev_values:
            return cur == prev_values[addr]
        return cur == old
    if mode == 'increased':
        return cur > old
    if mode == 'decreased':
        return cur < old
    if mode == 'initial':
        return cur == value
    return False


# ------------------- string scan (UTF-8 ASCII) -------------------
def _first_scan_string(h, needle, progress_cb=None, stop_cb=None):
    out = []
    needle_b = needle.encode('utf-8') if isinstance(needle, str) else needle
    pages = list(list_pages(h))
    total_bytes = sum(s for _, s, _ in pages)
    scanned = 0
    for base, psize, prot in pages:
        if stop_cb and stop_cb():
            break
        offset = 0
        while offset < psize:
            chunk = 64 * 1024
            if offset + chunk > psize:
                chunk = psize - offset
            data = rblock(h, base + offset, chunk)
            if data:
                start = 0
                while True:
                    idx = data.find(needle_b, start)
                    if idx < 0: break
                    addr = base + offset + idx
                    out.append(Candidate(addr, needle_b))
                    start = idx + 1
            offset += chunk
        scanned += psize
        if progress_cb:
            progress_cb(scanned, total_bytes, len(out))
    return out

def _rescan_string(h, cands, needle, progress_cb=None, stop_cb=None):
    needle_b = needle.encode('utf-8') if isinstance(needle, str) else needle
    nlen = len(needle_b)
    out = []
    for i, c in enumerate(cands):
        if stop_cb and stop_cb():
            break
        cur = rblock(h, c.addr, nlen)
        if cur == needle_b:
            out.append(Candidate(c.addr, cur))
        if progress_cb and i % 1000 == 0:
            progress_cb(i, len(cands), len(out))
    return out


# ------------------- pointer scanner (walks chains) -------------------
def pointer_scan(h, target_value_bytes, max_depth=5, max_offset=0x1000,
                 progress_cb=None, stop_cb=None):
    """
    For each readable page, try to find a uintptr_t-sized pointer that,
    when added to one of the offsets in [0..max_offset), equals the
    address where target_value_bytes lives. We return dict:
       addr -> [static_addr, offset]   (depth 1)
    Only depth 1 for now; depth 2+ is exponential.
    """
    size = len(target_value_bytes)
    # First find addresses that hold target_value_bytes (small candidate set
    # if value is rare; if common we use a max-cap heuristic).
    addr_list = first_scan(h, 'uint32' if size == 4 else 'uint64',
                            struct.unpack('<I' if size==4 else '<Q',
                                          target_value_bytes)[0],
                            progress_cb=lambda d,t,n: None)
    # For very common values we cap to avoid runaway
    if len(addr_list) > 50000:
        addr_list = addr_list[:50000]
    target_addrs = {c.addr for c in addr_list}

    found = {}  # static_addr -> (offset, target_addr)
    pages = list(list_pages(h))
    total = sum(s for _, s, _ in pages)
    scanned = 0
    needle = struct.pack('<Q' if ctypes.sizeof(ctypes.c_void_p)==8 else '<I', 0)  # placeholder

    for base, psize, prot in pages:
        if stop_cb and stop_cb():
            break
        offset = 0
        while offset < psize:
            chunk = 32 * 1024
            if offset + chunk > psize:
                chunk = psize - offset
            data = rblock(h, base + offset, chunk)
            if data is None:
                offset += chunk; continue
            # scan for pointers landing in target_addrs
            step = ctypes.sizeof(ctypes.c_void_p)
            for i in range(0, len(data) - step + 1, step):
                ptr = struct.unpack('<Q' if step==8 else '<I', data[i:i+step])[0]
                if ptr == 0:
                    continue
                for off_try in range(0, max_offset + 1, 4):
                    if (ptr + off_try) in target_addrs:
                        found[base + offset + i] = (off_try, ptr + off_try)
                        break
            offset += chunk
        scanned += psize
        if progress_cb:
            progress_cb(scanned, total, len(found))
    return found


# ------------------- utils -------------------
def format_value(vtype, raw_bytes):
    if vtype == 'string':
        try: return raw_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        except Exception: return repr(raw_bytes)
    try:
        return str(unpack_value(vtype, raw_bytes))
    except Exception:
        return '?'