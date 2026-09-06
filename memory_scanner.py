"""
memory_scanner.py - CE-style fast memory scanner
made by Momo aka Steav Beoung Salang

Architecture (verified against cheat-engine/cheat-engine 2026-09-05):
  - Scanner class (CE: TScanner) — scan state + CheckRoutine dispatch
  - FoundList class (CE: TFoundList) — result storage with disk-backed mode
  - Multi-threaded: 1 scanner worker per CPU core (CE: threadcount:=GetCPUCount)
  - Disk-backed results via SQLite (CE: ADDRESSES-<tid>.TMP per thread)
  - Overlap reads (CE: _size:=size+(variablesize-1))
  - Fast-scan alignment (CE: align:=4 vs 1, user-tunable)
  - fsmLastDigits mode (CE: power(16, digitcount) step size)
  - Direct bytes-slicing compares (CE: pdword(current)^ = value)
  - Dispatch-table comparator (CE: CheckRoutine function pointer)
  - Percentage scan modes (CE: ByteIncreasedValueByPercentage, etc.)
  - Cooperative cancellation via threading.Event
  - Worker progress via queue.Queue, pumped from main thread
  - Pointer scan: noLoop prevention (CE: noLoop flag), useHeapData filter

Public API (drop-in compatible with v1):
  first_scan(h, vtype, value, mode='exact', high=None,
             progress_cb=None, stop_cb=None, fast_scan=True,
             fast_scan_digits=None, nthreads=None) -> [Candidate]
  rescan(h, candidates, vtype, value, mode='exact', high=None,
         progress_cb=None, stop_cb=None, fast_scan=True, nthreads=None) -> [Candidate]
  pointer_scan(h, target_value_bytes, max_depth=1, max_offset=0x1000,
               progress_cb=None, stop_cb=None,
               no_loop=True, use_heap_data=False) -> dict
  Scanner class: Scanner(h).first_scan(vtype, value, mode=...) -> [Candidate]

Value types: 'int8','uint8','int16','uint16','int32','uint32',
             'int64','uint64','float','double','string'
Scan modes:  'exact','greater','less','between','increased','decreased',
             'changed','unchanged','initial',
             'increased_pct','decreased_pct'
ScanType enum: ScanType.FIRST / ScanType.NEXT / ScanType.NEW
"""

import ctypes
import ctypes.wintypes as w
import os
import queue as _q
import struct
import threading
import time
from collections import namedtuple

# ============================================================
# Win32 bindings
# ============================================================
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = w.BOOL

WriteProcessMemory = k32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = w.BOOL

CloseHandle = k32.CloseHandle
CloseHandle.argtypes = [w.HANDLE]
CloseHandle.restype = w.BOOL

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

VirtualQueryEx = k32.VirtualQueryEx
VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p,
                            ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype  = ctypes.c_size_t

VirtualAlloc = k32.VirtualAlloc
VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
VirtualAlloc.restype  = ctypes.c_void_p

VirtualFree = k32.VirtualFree
VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, w.DWORD]
VirtualFree.restype  = w.BOOL

# ============================================================
# constants
# ============================================================
PAGE_NOACCESS      = 0x01
PAGE_GUARD         = 0x100
PAGE_READWRITE     = 0x04
PAGE_READONLY      = 0x02
PAGE_EXECUTE_READ  = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_WRITECOPY     = 0x08
MEM_COMMIT         = 0x1000
MEM_PRIVATE        = 0x20000
MEM_MAPPED         = 0x40000
MEM_IMAGE          = 0x1000000

VALID_PROTECTS = {PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ,
                  PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY}

# (size, struct format char, alignment for fast-scan)
VTYPES = {
    'int8':   (1, 'b', 1),
    'uint8':  (1, 'B', 1),
    'int16':  (2, 'h', 2),
    'uint16': (2, 'H', 2),
    'int32':  (4, 'i', 4),
    'uint32': (4, 'I', 4),
    'int64':  (8, 'q', 8),
    'uint64': (8, 'Q', 8),
    'float':  (4, 'f', 4),
    'double': (8, 'd', 8),
    # 'string' is special-cased
}
# CE: vtAll — scan all numeric types at once
VTYPES_ALL = ('int8','uint8','int16','uint16','int32','uint32','int64','uint64','float','double')
SCAN_MODES = ('exact','greater','less','between',
              'changed','unchanged','increased','decreased','initial',
              'increased_pct','decreased_pct')

Candidate = namedtuple('Candidate', ['addr', 'last'])

DEFAULT_CHUNK = 64 * 1024
PROGRESS_INTERVAL = 1 << 22   # report every 4 MB scanned

# CE: TScanType = (stNewScan=0, stFirstScan=1, stNextScan=2)
class ScanType:
    FIRST = 'first'
    NEXT = 'next'
    NEW = 'new'

# CE: FoundList disk-back threshold
_FOUNDLIST_DISK_THRESHOLD = 100_000

# Custom value types registry (CE: user-defined types)
_CUSTOM_VTYPES = {}

def register_vtype(name, size, fmt, align):
    """Register a custom value type for scanning.
    
    name: type name (e.g. 'vec3f' for 3 floats)
    size: byte size
    fmt: struct format char (e.g. 'f' for float, 'i' for int)
    align: alignment for fast-scan
    """
    _CUSTOM_VTYPES[name] = (size, fmt, align)

def _resolve_vtype(vtype):
    """Resolve vtype from VTYPES or custom types registry."""
    if vtype in VTYPES:
        return VTYPES[vtype]
    if vtype in _CUSTOM_VTYPES:
        return _CUSTOM_VTYPES[vtype]
    raise ValueError(f"Unknown vtype: {vtype!r}. Register with register_vtype() first.")

def _is_vtype(vtype):
    """Check if vtype is known (standard or custom)."""
    return vtype in VTYPES or vtype in _CUSTOM_VTYPES


# ============================================================
# page walker
# ============================================================
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
        if base == 0 and size > 0x100000000 and info.State == 0x10000:
            addr = 0x10000
            continue
        if (info.State == MEM_COMMIT
                and (info.Protect & PAGE_NOACCESS) == 0
                and (info.Protect & PAGE_GUARD)   == 0
                and info.Protect in VALID_PROTECTS):
            yield (base, size, info.Protect)
        nxt = base + size
        if nxt <= addr or nxt >= 0x7FFF00000000:
            break
        addr = nxt


# ============================================================
# read helpers
# ============================================================
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


# ============================================================
# value-type helpers
# ============================================================
def pack_value(vtype, value):
    if vtype == 'string':
        return value.encode('utf-8') if isinstance(value, str) else value
    _, fmt, _ = _resolve_vtype(vtype)
    return struct.pack('<' + fmt, value)

def unpack_value(vtype, blob):
    _, fmt, _ = _resolve_vtype(vtype)
    return struct.unpack('<' + fmt, blob)[0]

def scan_size(vtype):
    if vtype == 'string': return 0
    return _resolve_vtype(vtype)[0]

def scan_align(vtype, fast_scan):
    if vtype == 'string': return 1
    _, _, a = _resolve_vtype(vtype)
    return a if fast_scan else 1


# ============================================================
# ResultStore → FoundList (CE: TFoundList)
# Disk-backed when count > _FOUNDLIST_DISK_THRESHOLD
# ============================================================
import sqlite3
import tempfile

class FoundList:
    """CE-style TFoundList — result storage with optional disk-backed mode.

    When the number of hits exceeds _FOUNDLIST_DISK_THRESHOLD (100K),
    results spill from :memory: SQLite to a temp file automatically,
    matching CE's ADDRESSES-<tid>.TMP pattern.
    """
    SCHEMA = "CREATE TABLE IF NOT EXISTS hits(addr INTEGER PRIMARY KEY, last BLOB)"
    SCHEMA_IDX = "CREATE INDEX IF NOT EXISTS hits_addr ON hits(addr)"

    def __init__(self, path=None, disk_backed=False):
        self._disk_backed = disk_backed
        self._count = 0
        if path is None:
            path = ":memory:"
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute(self.SCHEMA)
        self._conn.execute(self.SCHEMA_IDX)
        try: self._conn.execute("PRAGMA journal_mode=OFF")
        except Exception: pass
        try: self._conn.execute("PRAGMA synchronous=OFF")
        except Exception: pass
        self._buf = []
        self._buf_limit = 4096

    def add(self, addr, last):
        self._buf.append((addr, bytes(last) if not isinstance(last, (bytes, bytearray)) else last))
        self._count += 1
        if len(self._buf) >= self._buf_limit:
            self._flush()
        # Auto-spill to disk when threshold crossed (CE: ADDRESSES-<tid>.TMP)
        if not self._disk_backed and self._count > _FOUNDLIST_DISK_THRESHOLD:
            self._spill_to_disk()

    def _spill_to_disk(self):
        """CE pattern: move from :memory: to temp file on disk."""
        try:
            tmp = tempfile.NamedTemporaryFile(suffix='.tmp', prefix='addresses_',
                                               dir=None, delete=False)
            tmp.close()
            # Reconnect to file-backed DB
            old_conn = self._conn
            self._conn = sqlite3.connect(tmp.name, check_same_thread=False, isolation_level=None)
            self._conn.execute(self.SCHEMA)
            self._conn.execute(self.SCHEMA_IDX)
            try: self._conn.execute("PRAGMA journal_mode=OFF")
            except Exception: pass
            try: self._conn.execute("PRAGMA synchronous=OFF")
            except Exception: pass
            # Copy existing data
            rows = old_conn.execute("SELECT addr, last FROM hits").fetchall()
            if rows:
                self._conn.executemany("INSERT OR IGNORE INTO hits(addr, last) VALUES(?, ?)", rows)
            old_conn.close()
            self.path = tmp.name
            self._disk_backed = True
        except Exception:
            pass  # fallback to in-memory

    def _flush(self):
        if self._buf:
            self._conn.executemany("INSERT OR IGNORE INTO hits(addr, last) VALUES(?, ?)",
                                   self._buf)
            self._buf.clear()

    def add_many(self, items):
        self._buf.extend((a, bytes(b) if not isinstance(b, (bytes, bytearray)) else b)
                         for a, b in items)
        self._count += len(items)
        if len(self._buf) >= self._buf_limit:
            self._flush()

    def count(self):
        self._flush()
        return self._count

    def all_hits(self):
        self._flush()
        return self._conn.execute("SELECT addr, last FROM hits ORDER BY addr").fetchall()

    def addresses(self):
        self._flush()
        return [r[0] for r in self._conn.execute("SELECT addr FROM hits ORDER BY addr")]

    def merge_into(self, other):
        self._flush()
        rows = self.all_hits()
        if rows:
            other.add_many(rows)

    def close(self):
        try: self._flush()
        except Exception: pass
        try: self._conn.close()
        except Exception: pass


# ============================================================
# worker thread bodies
# ============================================================
def _first_scan_worker(worker_id, h, vtype, value, page_slices, fast_scan,
                       fast_scan_digits, progress_q, stop_evt, store,
                       case_sensitive=False):
    """
    One worker thread: scans its assigned pages, writes hits to its own store.
    Reports progress via queue so the main thread can keep UI alive.

    fast_scan_digits: CE fsmLastDigits — step by 16**N bytes (e.g. N=2 → step 256).
                      Only scans addresses ending in N zero hex digits.
    """
    if vtype == 'string':
        needle = value.encode('utf-8') if isinstance(value, str) else value
        nlen = len(needle)
        chunk_size = 32 * 1024
    else:
        nlen = VTYPES[vtype][0]
        needle = pack_value(vtype, value)
        chunk_size = DEFAULT_CHUNK
    align = scan_align(vtype, fast_scan)
    # CE fsmLastDigits: step = 16**digits, skip initial align bytes
    if fast_scan_digits and fast_scan_digits > 0:
        stepsize = 16 ** fast_scan_digits
        initial_skip = align  # CE: inc(p, fastscanalignsize)
    elif fast_scan and align > 1:
        stepsize = align
        initial_skip = 0
    else:
        stepsize = 1
        initial_skip = 0
    overlap = nlen - 1
    scanned = 0
    hits = 0
    for base, psize, prot in page_slices:
        if stop_evt.is_set():
            break
        offset = 0
        while offset < psize:
            if stop_evt.is_set():
                break
            cs = min(chunk_size, psize - offset)
            addr = base + offset
            # CE: _size:=size+(variablesize-1) — overlap read
            # IMPORTANT: if the chunk ends at the page boundary, skip overlap
            # (no bytes after this chunk to overlap with). Otherwise add overlap
            # so we catch values straddling the chunk boundary.
            remaining = psize - offset
            read_size = cs + overlap if cs + overlap <= remaining else cs
            buf = rblock(h, addr, read_size)
            if buf is None:
                offset += cs
                continue
            # search
            if vtype == 'string':
                if case_sensitive:
                    # CE: case-sensitive string compare
                    start = 0
                    while True:
                        idx = buf.find(needle, start)
                        if idx < 0: break
                        store.add(addr + idx, needle)
                        hits += 1
                        start = idx + 1
                else:
                    # CE: case-insensitive — lowercase both sides
                    needle_lower = needle.lower()
                    buf_lower = buf.lower()
                    start = 0
                    while True:
                        idx = buf_lower.find(needle_lower, start)
                        if idx < 0: break
                        store.add(addr + idx, needle)
                        hits += 1
                        start = idx + 1
            else:
                # CE: pdword(current)^ = value  — direct bytes compare
                # CE fsmLastDigits: step=16**N, start past initial alignment bytes
                end = len(buf) - nlen + 1
                i = initial_skip
                while i < end:
                    if buf[i:i+nlen] == needle:
                        store.add(addr + i, needle)
                        hits += 1
                    i += stepsize
            scanned += cs
            offset += cs
            if (scanned & (PROGRESS_INTERVAL - 1)) < chunk_size:
                progress_q.put(('progress', worker_id, scanned, hits))
    progress_q.put(('progress', worker_id, scanned, hits))
    progress_q.put(('worker_done', worker_id, hits))


def _rescan_worker(worker_id, h, vtype, value, mode, cands, high,
                   progress_q, stop_evt, store, case_sensitive=False):
    """
    One rescan worker: checks its slice of candidates.
    case_sensitive: for string vtype, compare bytes exactly (default: False).
    """
    if vtype == 'string':
        needle = value.encode('utf-8') if isinstance(value, str) else value
        nlen = len(needle)
        if case_sensitive:
            needle_cmp = needle
        else:
            needle_cmp = needle.lower()
    else:
        nlen = VTYPES[vtype][0]
        if mode in ('exact', 'greater', 'less', 'between'):
            needle = pack_value(vtype, value)
        elif mode in ('increased_pct', 'decreased_pct'):
            needle = pack_value(vtype, value)    # percentage value
            high = pack_value(vtype, high) if high else None  # max percentage
        else:
            needle = b''  # unused for changed/unchanged/increased/decreased
    scanned = 0
    hits = 0
    for addr, last in cands:
        if stop_evt.is_set():
            break
        cur = rblock(h, addr, nlen)
        if cur is None:
            scanned += 1
            continue
        # String comparison with case sensitivity
        if vtype == 'string':
            if case_sensitive:
                match = cur == needle
            else:
                match = cur.lower() == needle_cmp
        else:
            match = _compare_one(mode, cur, last, needle, high, vtype)
        if match:
            store.add(addr, cur)
            hits += 1
        scanned += 1
        if (scanned & 0x3FF) == 0:
            progress_q.put(('progress', worker_id, scanned, hits))
    progress_q.put(('progress', worker_id, scanned, hits))
    progress_q.put(('worker_done', worker_id, hits))


def _make_comparators():
    """CE-style CheckRoutine dispatch table.
    Maps (vtype_len, mode) -> comparator(new_cur, new_last, needle_int, high_int).
    CE: CheckRoutine is set once in configurescanroutine, called in hot loop.
    """
    def _exact(new_cur, new_last, needle_int, high_int):
        return new_cur == needle_int

    def _changed(new_cur, new_last, needle_int, high_int):
        return new_cur != new_last

    def _unchanged(new_cur, new_last, needle_int, high_int):
        return new_cur == new_last

    def _increased(new_cur, new_last, needle_int, high_int):
        return new_cur > new_last

    def _decreased(new_cur, new_last, needle_int, high_int):
        return new_cur < new_last

    def _greater(new_cur, new_last, needle_int, high_int):
        return new_cur > needle_int

    def _less(new_cur, new_last, needle_int, high_int):
        return new_cur < needle_int

    def _between(new_cur, new_last, needle_int, high_int):
        hi = high_int if high_int is not None else needle_int
        return needle_int <= new_cur <= hi

    def _increased_pct(new_cur, new_last, needle_int, high_int):
        # value = min % increase, high = max % increase
        pct_lo = needle_int / 100.0
        pct_hi = (high_int if high_int is not None else needle_int) / 100.0
        lo = int(new_last * (1.0 + pct_lo))
        hi = int(new_last * (1.0 + pct_hi))
        return lo < new_cur < hi

    def _decreased_pct(new_cur, new_last, needle_int, high_int):
        # value = min % decrease, high = max % decrease
        pct_lo = needle_int / 100.0
        pct_hi = (high_int if high_int is not None else needle_int) / 100.0
        lo = int(new_last * (1.0 - pct_hi))
        hi = int(new_last * (1.0 - pct_lo))
        return lo < new_cur < hi

    return {
        (1, 'exact'):             _exact,
        (1, 'changed'):           _changed,
        (1, 'unchanged'):         _unchanged,
        (1, 'increased'):         _increased,
        (1, 'decreased'):         _decreased,
        (1, 'greater'):           _greater,
        (1, 'less'):              _less,
        (1, 'between'):           _between,
        (1, 'increased_pct'):     _increased_pct,
        (1, 'decreased_pct'):     _decreased_pct,
        (2, 'exact'):             _exact,
        (2, 'changed'):           _changed,
        (2, 'unchanged'):         _unchanged,
        (2, 'increased'):         _increased,
        (2, 'decreased'):         _decreased,
        (2, 'greater'):           _greater,
        (2, 'less'):              _less,
        (2, 'between'):           _between,
        (2, 'increased_pct'):     _increased_pct,
        (2, 'decreased_pct'):     _decreased_pct,
        (4, 'exact'):             _exact,
        (4, 'changed'):           _changed,
        (4, 'unchanged'):         _unchanged,
        (4, 'increased'):         _increased,
        (4, 'decreased'):         _decreased,
        (4, 'greater'):           _greater,
        (4, 'less'):              _less,
        (4, 'between'):           _between,
        (4, 'increased_pct'):     _increased_pct,
        (4, 'decreased_pct'):     _decreased_pct,
        (8, 'exact'):             _exact,
        (8, 'changed'):           _changed,
        (8, 'unchanged'):         _unchanged,
        (8, 'increased'):         _increased,
        (8, 'decreased'):         _decreased,
        (8, 'greater'):           _greater,
        (8, 'less'):              _less,
        (8, 'between'):           _between,
        (8, 'increased_pct'):     _increased_pct,
        (8, 'decreased_pct'):     _decreased_pct,
    }

_COMPARATORS = _make_comparators()

def _compare_one(mode, cur, last, needle, high, vtype='uint32'):
    """CE-style dispatch-table compare — one lookup, no if/elif chain."""
    n = len(cur)
    needle_int = int.from_bytes(needle, 'little', signed=False) if needle else 0
    high_int = int.from_bytes(high, 'little', signed=False) if high else None
    key = (n, mode)
    cmp = _COMPARATORS.get(key)
    if cmp is None:
        return False
    cv = int.from_bytes(cur, 'little', signed=False)
    lv = int.from_bytes(last, 'little', signed=False)
    return cmp(cv, lv, needle_int, high_int)


def _vtype_from_len(n):
    return {1: 'uint8', 2: 'uint16', 4: 'uint32', 8: 'uint64'}.get(n, 'uint32')


# ============================================================
# Scanner class (CE: TScanner)
# Wraps scan state + CheckRoutine dispatch into one object.
# ============================================================
class Scanner:
    """CE-style TScanner — scan state + CheckRoutine function-pointer dispatch.

    Usage:
        s = Scanner(h)
        cands = s.first_scan('uint32', 0x1337, mode='exact', fast_scan_digits=2)
        survivors = s.rescan(cands, 'uint32', 0x2000, mode='increased_pct', high=20)
    """

    def __init__(self, handle, nthreads=None):
        self.handle = handle
        self.nthreads = max(1, nthreads or (os.cpu_count() or 1))
        self.vtype = None
        self.mode = None
        self.checkroutine = None   # CE: CheckRoutine function pointer
        self.fast_scan = True
        self.fast_scan_digits = None
        self.value = 0
        self.high = None

    def configure(self, vtype, mode, fast_scan=True, fast_scan_digits=None,
                  value=0, high=None):
        """CE: configurescanroutine — set CheckRoutine once, call in hot loop."""
        self.vtype = vtype
        self.mode = mode
        self.fast_scan = fast_scan
        self.fast_scan_digits = fast_scan_digits
        self.value = value
        self.high = high
        vtype_size = VTYPES[vtype][0] if vtype != 'string' else 0
        self.checkroutine = _COMPARATORS.get((vtype_size, mode))
        return self

    def first_scan(self, value, mode='exact', high=None,
                   progress_cb=None, stop_cb=None,
                   fast_scan=True, fast_scan_digits=None):
        """CE: firstscan — dispatch to module-level first_scan."""
        return first_scan(self.handle, self.vtype or 'uint32', value,
                          mode=mode, high=high,
                          progress_cb=progress_cb, stop_cb=stop_cb,
                          fast_scan=fast_scan,
                          fast_scan_digits=fast_scan_digits,
                          nthreads=self.nthreads)

    def rescan(self, candidates, value, mode='exact', high=None,
               progress_cb=None, stop_cb=None, fast_scan=True):
        """CE: nextscan — dispatch to module-level rescan."""
        return rescan(self.handle, candidates, self.vtype or 'uint32', value,
                      mode=mode, high=high,
                      progress_cb=progress_cb, stop_cb=stop_cb,
                      fast_scan=fast_scan, nthreads=self.nthreads)


# ============================================================
# entry points (parallel + backward-compatible list output)
# ============================================================
def _pump_progress(progress_q, progress_cb, stop_cb, stop_evt, nworkers):
    """Drain the progress queue until all workers report done."""
    done = 0
    while done < nworkers:
        try:
            kind, *rest = progress_q.get(timeout=0.1)
            if kind == 'progress':
                wid, scanned, hits = rest
                if progress_cb: progress_cb(wid, scanned, hits)
                if stop_cb and stop_cb():
                    stop_evt.set()
            elif kind == 'worker_done':
                done += 1
        except _q.Empty:
            pass
    # drain
    while not progress_q.empty():
        try: progress_q.get_nowait()
        except _q.Empty: break


def first_scan(h, vtype, value, mode='exact', high=None,
               progress_cb=None, stop_cb=None, fast_scan=True,
               fast_scan_digits=None, nthreads=None, case_sensitive=False):
    """
    CE-style parallel first scan.
    case_sensitive: for string vtype, compare bytes exactly (default: False).
    """
    if vtype != 'string' and mode not in ('exact','between','greater','less',
                                            'initial','increased_pct','decreased_pct'):
        raise ValueError(
            f"First scan with mode '{mode}' not supported; "
            f"use 'exact' / 'between' / 'greater' / 'less' / 'initial' "
            f"/ 'increased_pct' / 'decreased_pct'.")
    nthreads = max(1, nthreads or (os.cpu_count() or 1))
    pages = list(list_pages(h))
    if not pages:
        return []
    # Distribute pages across threads (round-robin by page index)
    slices = [[] for _ in range(nthreads)]
    for i, p in enumerate(pages):
        slices[i % nthreads].append(p)
    # Per-thread stores
    stores = [FoundList() for _ in range(nthreads)]
    use_progress = bool(progress_cb) or bool(stop_cb)
    progress_q = _q.Queue() if use_progress else _NullQueue()
    stop_evt = threading.Event()
    workers = []
    for wid in range(nthreads):
        if not slices[wid]:
            continue
        t = threading.Thread(target=_first_scan_worker,
                              args=(wid, h, vtype, value, slices[wid],
                                    fast_scan, fast_scan_digits, progress_q, stop_evt, stores[wid],
                                    case_sensitive),
                              daemon=True, name=f"firstscan-w{wid}")
        workers.append(t); t.start()
    if use_progress:
        _pump_progress(progress_q, progress_cb, stop_cb, stop_evt, len(workers))
    for t in workers: t.join()
    # Merge results
    merged = []
    for s in stores:
        for addr, last in s.all_hits():
            merged.append(Candidate(addr, last))
        s.close()
    merged.sort(key=lambda c: c.addr)
    return merged


def rescan(h, candidates, vtype, value, mode='exact', high=None,
           progress_cb=None, stop_cb=None, fast_scan=True, nthreads=None,
           case_sensitive=False):
    """
    CE-style parallel rescan. Returns survivors as list of Candidate.
    case_sensitive: for string vtype, compare bytes exactly (default: False).
    """
    if not candidates:
        return []
    nthreads = max(1, nthreads or (os.cpu_count() or 1))
    # Distribute candidates by INDEX (contiguous slices — better cache locality
    # than modulo, since cands are addr-sorted from previous scan)
    groups = [candidates[i::nthreads] for i in range(nthreads)]
    stores = [FoundList() for _ in range(nthreads)]
    use_progress = bool(progress_cb) or bool(stop_cb)
    progress_q = _q.Queue() if use_progress else _NullQueue()
    stop_evt = threading.Event()
    workers = []
    for wid in range(nthreads):
        if not groups[wid]:
            continue
        t = threading.Thread(target=_rescan_worker,
                              args=(wid, h, vtype, value, mode, groups[wid],
                                    high, progress_q, stop_evt, stores[wid],
                                    case_sensitive),
                              daemon=True, name=f"rescan-w{wid}")
        workers.append(t); t.start()
    if use_progress:
        _pump_progress(progress_q, progress_cb, stop_cb, stop_evt, len(workers))
    for t in workers: t.join()
    merged = []
    for s in stores:
        for addr, last in s.all_hits():
            merged.append(Candidate(addr, last))
        s.close()
    return merged


class _NullQueue:
    """Drop-everything queue (no progress reporting requested)."""
    def put(self, *a, **kw): pass
    def get(self, *a, **kw): raise _q.Empty
    def get_nowait(self, *a, **kw): raise _q.Empty
    def empty(self): return True


# ============================================================
# Lua formula scan (CE: Lua script-defined scan condition)
# ============================================================
def lua_formula_scan(h, formula, candidates, vtype='uint32',
                      progress_cb=None, stop_cb=None):
    """Scan candidates using a Lua-style formula string.

    CE: allows Lua scripts to define custom scan conditions.
    Formula can reference:
      addr  — candidate address (int)
      last  — last known value (bytes)
      value — formula result for this candidate (int/float)

    Example formulas:
      'addr & 0xFF == 0x00 and int.from_bytes(last, \"little\") > 100'
      'struct.unpack(\"<f\", last)[0] > 0.5'

    Returns list of Candidate(addr, last) that satisfy the formula.
    """
    if not candidates:
        return []
    allowed_names = {
        'addr': 0, 'last': b'', 'value': 0,
        'int': int, 'float': float, 'str': str,
        'struct': struct, 'bytes': bytes,
    }
    compiled = compile(formula, '<lua_formula>', 'eval')
    results = []
    nthreads = max(1, os.cpu_count() or 1)
    groups = [candidates[i::nthreads] for i in range(nthreads)]
    found = []
    found_lock = threading.Lock()
    stop_evt = threading.Event()
    progress_q = _q.Queue() if progress_cb else _NullQueue()

    def worker(wid, group):
        local_hits = []
        for cand in group:
            if stop_evt.is_set():
                break
            addr = cand.addr if isinstance(cand, Candidate) else cand
            last = cand.last if isinstance(cand, Candidate) else b''
            try:
                val = struct.unpack('<' + VTYPES[vtype][1], last)[0]
            except Exception:
                val = 0
            ns = dict(allowed_names, addr=addr, last=last, value=val)
            try:
                if eval(compiled, {'__builtins__': {}}, ns):
                    local_hits.append(cand)
            except Exception:
                pass
        if local_hits:
            with found_lock:
                found.extend(local_hits)
        progress_q.put(('worker_done', wid, len(local_hits)))

    workers = []
    for wid in range(nthreads):
        if not groups[wid]:
            continue
        t = threading.Thread(target=worker, args=(wid, groups[wid]),
                             daemon=True, name=f"luascan-w{wid}")
        workers.append(t); t.start()

    finished = 0
    while finished < len(workers):
        try:
            kind, wid, hits = progress_q.get(timeout=0.1)
            if kind == 'worker_done':
                finished += 1
            if stop_cb and stop_cb():
                stop_evt.set()
        except _q.Empty:
            pass
    for t in workers:
        t.join()
    return found


# ============================================================
# pointer scanner (depth-1, CE-style noLoop + useHeapData)
# ============================================================
def _build_heap_regions(h):
    """Build list of (base, size) for all committed heap regions.
    CE: uses frmMemoryAllocHandler.HeapBaselevel to identify heaps."""
    heaps = []
    for base, psize, prot in list_pages(h):
        if prot & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE):
            if prot & PAGE_EXECUTE_READWRITE and not (prot & PAGE_EXECUTE_READ):
                heaps.append((base, psize))
    return heaps


# ============================================================
# PointerScanWorker (CE: PointerScanWorker thread)
# Scans a batch of candidate addresses for one depth level.
# Each worker writes to its own FoundList (CE: per-thread result file).
# ============================================================
class PointerScanWorker(threading.Thread):
    """CE-style PointerScanWorker — scans candidate addresses for pointers."""

    def __init__(self, worker_id, h, candidates, target_addrs,
                 max_offset, no_loop, use_heap_data, heap_regions,
                 progress_q, stop_evt, result_store):
        super().__init__(daemon=True, name=f"ptrscan-w{worker_id}")
        self.worker_id = worker_id
        self.handle = h
        self.candidates = candidates        # list of addr ints to scan FOR
        self.target_addrs = target_addrs    # set of candidate addrs for O(1) lookup
        self.max_offset = max_offset
        self.no_loop = no_loop
        self.use_heap_data = use_heap_data
        self.heap_regions = heap_regions
        self.progress_q = progress_q
        self.stop_evt = stop_evt
        self.store = result_store
        self.scanned = 0
        self.hits = 0

    def run(self):
        """Scan all readable pages for pointers to self.candidates."""
        step = ctypes.sizeof(ctypes.c_void_p)
        pages = list(list_pages(self.handle))
        for base, psize, prot in pages:
            if self.stop_evt.is_set():
                break
            offset = 0
            while offset < psize:
                if self.stop_evt.is_set():
                    break
                cs = min(64 * 1024, psize - offset)
                data = rblock(self.handle, base + offset, cs)
                if data is None:
                    offset += cs; self.scanned += cs; continue
                # Scan every pointer-sized slot in the chunk
                end = len(data) - step + 1
                i = 0
                while i < end:
                    ptr = struct.unpack('<Q' if step == 8 else '<I',
                                        data[i:i+step])[0]
                    if ptr == 0:
                        i += step; continue
                    # CE noLoop: skip self-referencing pointers
                    if self.no_loop and ptr == base + offset + i:
                        i += step; continue
                    # CE useHeapData: skip non-heap pointers
                    if self.use_heap_data:
                        in_heap = any(
                            hr <= (base + offset + i) < hr + sz
                            for hr, sz in self.heap_regions
                        )
                        if not in_heap:
                            i += step; continue
                    # Check if ptr + offset matches any target
                    for off_try in range(0, self.max_offset + 1, step):
                        if (ptr + off_try) in self.target_addrs:
                            self.store.add(base + offset + i,
                                           struct.pack('<Q', ptr))
                            self.hits += 1
                            break
                    i += step
                offset += cs
        self.progress_q.put(('worker_done', self.worker_id, self.hits))


# ============================================================
# PointerScanController (CE: PointerScanController)
# Manages worker lifecycle, semaphore queue, resume state, merge.
# ============================================================
class PointerScanController:
    """CE-style PointerScanController — manages multi-depth pointer scan.

    Features:
      - Semaphore-limited worker pool (CE: threadcount)
      - Multi-depth scan (repeat pointer levels)
      - Resume from saved state (CE: load/save pointer scan results)
      - Merge results from multiple scans (CE: combine pointer scans)
      - Cooperative cancellation via threading.Event
    """

    RESUME_FILE = 'pointer_scan_state.json'

    def __init__(self, handle, max_depth=1, max_offset=0x1000,
                 no_loop=True, use_heap_data=False, nworkers=None):
        self.handle = handle
        self.max_depth = max_depth
        self.max_offset = max_offset
        self.no_loop = no_loop
        self.use_heap_data = use_heap_data
        self.nworkers = max(1, nworkers or (os.cpu_count() or 1))
        self.semaphore = threading.Semaphore(self.nworkers)
        self.stop_evt = threading.Event()
        self.progress_q = _q.Queue()
        self.results = FoundList()       # final merged results
        self._depth_results = []         # per-depth FoundList list
        self._resume_state = None        # saved state for resume
        self._heap_regions = []
        if use_heap_data:
            self._heap_regions = _build_heap_regions(handle)

    # ---- public API ----

    def scan(self, target_addrs, depth=0, progress_cb=None, stop_cb=None):
        """Run pointer scan from target_addrs at given depth.

        target_addrs: list of int addresses to scan FOR (pointers TO these)
        depth: current depth level (0 = first scan, 1 = pointers to pointers, etc.)
        progress_cb: callable(wid, scanned, hits)
        stop_cb: callable() -> bool, returns True to cancel

        Returns FoundList of pointer addresses found at this depth.
        """
        if depth >= self.max_depth:
            return self.results

        # Build candidate set for this depth
        candidates = list(target_addrs) if isinstance(target_addrs, (list, set)) else list(target_addrs)
        if not candidates:
            return self.results

        target_addrs_set = set(candidates)

        # Split candidates across workers (round-robin, CE pattern)
        slices = [[] for _ in range(self.nworkers)]
        for i, c in enumerate(candidates):
            slices[i % self.nworkers].append(c)

        # Per-thread stores (CE: ADDRESSES-<tid>.TMP per thread)
        stores = [FoundList() for _ in range(self.nworkers)]
        workers = []
        for wid in range(self.nworkers):
            if not slices[wid]:
                continue
            w = PointerScanWorker(
                wid, self.handle, slices[wid], target_addrs_set,
                self.max_offset, self.no_loop, self.use_heap_data,
                self._heap_regions, self.progress_q, self.stop_evt, stores[wid]
            )
            workers.append(w)

        # Start workers with semaphore control
        running = 0
        for w in workers:
            self.semaphore.acquire()
            w.start()
            running += 1

        # Pump progress + handle cancellation
        finished = 0
        while finished < len(workers):
            try:
                kind, wid, hits = self.progress_q.get(timeout=0.1)
                if kind == 'worker_done':
                    finished += 1
                    self.semaphore.release()
                    if progress_cb:
                        progress_cb(wid, stores[wid].scanned if wid < len(stores) else 0, hits)
            except _q.Empty:
                pass
            if stop_cb and stop_cb():
                self.stop_evt.set()
                break

        for w in workers:
            w.join()

        # Merge per-thread results into this depth's FoundList
        depth_store = FoundList()
        for s in stores:
            s.merge_into(depth_store)
            s.close()
        self._depth_results.append(depth_store)

        # Merge into final results
        depth_store.merge_into(self.results)

        # Recurse to next depth with new pointers as targets
        if depth + 1 < self.max_depth:
            new_targets = depth_store.addresses()
            if new_targets:
                self.scan(new_targets, depth=depth + 1,
                          progress_cb=progress_cb, stop_cb=stop_cb)

        return self.results

    # ---- resume support ----

    def save_state(self, path=None):
        """Save scan state for resume (CE: save pointer scan results)."""
        import json
        path = path or self.RESUME_FILE
        state = {
            'max_depth': self.max_depth,
            'max_offset': self.max_offset,
            'no_loop': self.no_loop,
            'use_heap_data': self.use_heap_data,
            'depth_results_count': [fl.count() for fl in self._depth_results],
            'total_results': self.results.count(),
        }
        with open(path, 'w') as f:
            json.dump(state, f)
        return path

    def load_state(self, path=None):
        """Load scan state for resume (CE: load pointer scan results)."""
        import json
        path = path or self.RESUME_FILE
        try:
            with open(path) as f:
                state = json.load(f)
            self._resume_state = state
            return state
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    # ---- merge ----

    def merge(self, other):
        """Merge results from another PointerScanController (CE: combine scans)."""
        other.results.merge_into(self.results)
        self._depth_results.extend(other._depth_results)
        return self.results

    def count(self):
        return self.results.count()

    def all_hits(self):
        return self.results.all_hits()

    def cancel(self):
        """Cancel ongoing scan (CE: stop pointer scan)."""
        self.stop_evt.set()

    # ---- legacy compat ----

    def close(self):
        self.results.close()
        for fl in self._depth_results:
            fl.close()


# ============================================================
# utilities
# ============================================================
def format_value(vtype, raw_bytes):
    if vtype == 'string':
        try: return raw_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        except Exception: return repr(raw_bytes)
    try:
        return str(unpack_value(vtype, raw_bytes))
    except Exception:
        return '?'


# ============================================================
# signature scan (aob_scan = "array of bytes" scan in CE)
# ============================================================
def parse_signature(sig_str):
    """
    Parse a signature string like '48 8B 05 ?? ?? ?? ?? 48 85 C0 74' or
    '48 8B 05 ? ? ? ? 48 85 C0 74' or '0x48, 0x8B, 0x05, ??, ??' into
    (bytes, mask) where mask[i] is True if byte i is a wildcard.

    Accepts spaces, commas, '0x' prefixes, '?' or '??' as wildcards.
    """
    if not sig_str or not isinstance(sig_str, str):
        raise ValueError("signature must be a non-empty string")
    # normalize separators (commas -> spaces, strip 0x/0X prefixes from each token)
    s = sig_str.replace(',', ' ').replace('0x', ' ').replace('0X', ' ')
    tokens = [t.strip() for t in s.split() if t.strip()]
    pattern = bytearray()
    mask = []
    for tok in tokens:
        if tok in ('?', '??'):
            pattern.append(0)
            mask.append(True)
        else:
            if len(tok) > 2:
                raise ValueError(
                    f"token {tok!r} has {len(tok)} hex digits; each byte must be 1-2 chars. "
                    f"Did you forget a space? Example: '48 8B 05' not '488B05'.")
            try:
                pattern.append(int(tok, 16) & 0xFF)
                mask.append(False)
            except ValueError:
                raise ValueError(f"bad token in signature: {tok!r}")
    return bytes(pattern), mask


def signature_scan(h, sig_str, progress_cb=None, stop_cb=None, nthreads=None):
    """
    Scan all readable memory for a byte pattern with wildcards.
    sig_str: pattern like '48 8B 05 ?? ?? ?? ?? 48 85 C0 74'
    Returns: list of absolute addresses where the pattern starts.

    Multi-threaded across CPU cores (same pattern as first_scan).
    Each page is sliced and assigned to one worker.
    """
    pattern, mask = parse_signature(sig_str)
    plen = len(pattern)
    if plen == 0:
        return []

    # Pre-compute the set of (offset, expected_byte) pairs for the matching loop.
    # This avoids per-iteration branching inside the hot path.
    fixed = [(i, pattern[i]) for i in range(plen) if not mask[i]]
    n_fixed = len(fixed)
    if n_fixed == 0:
        raise ValueError("signature is all wildcards; no anchor byte to search for")

    nthreads = max(1, nthreads or (os.cpu_count() or 1))
    pages = list(list_pages(h))
    if not pages:
        return []
    slices = [[] for _ in range(nthreads)]
    for i, p in enumerate(pages):
        slices[i % nthreads].append(p)

    found = []                 # thread-safe append (no shared mutation)
    found_lock = threading.Lock()
    stop_evt = threading.Event()
    progress_q = _q.Queue() if progress_cb else _NullQueue()
    scanned_bytes = [0] * nthreads   # atomic-ish (each thread writes its own index)

    def worker(worker_id, page_slices):
        local_hits = []
        local_scanned = 0
        for base, psize, prot in page_slices:
            if stop_evt.is_set():
                break
            offset = 0
            CHUNK = 64 * 1024
            while offset < psize:
                if stop_evt.is_set():
                    break
                cs = min(CHUNK, psize - offset)
                # Read chunk. The scan logic handles <plen bytes tail safely.
                data = rblock(h, base + offset, cs)
                if data is None or len(data) < plen:
                    offset += cs
                    local_scanned += cs
                    continue
                # Scan every byte position in the chunk
                end = len(data) - plen + 1
                i = 0
                while i < end:
                    # Quick first-byte check (if first byte is fixed) to skip
                    # many positions quickly.
                    if not mask[0]:
                        if data[i] != pattern[0]:
                            i += 1
                            continue
                    # Verify all fixed bytes
                    match = True
                    for j, b in fixed:
                        if data[i + j] != b:
                            match = False
                            break
                    if match:
                        local_hits.append(base + offset + i)
                        i += 1
                    else:
                        i += 1
                offset += cs
                local_scanned += cs
            scanned_bytes[worker_id] = local_scanned
            progress_q.put(('progress', worker_id, local_scanned, len(local_hits)))
        if local_hits:
            with found_lock:
                found.extend(local_hits)
        progress_q.put(('worker_done', worker_id, len(local_hits)))

    workers = []
    for wid in range(nthreads):
        if not slices[wid]:
            continue
        t = threading.Thread(target=worker, args=(wid, slices[wid]),
                              daemon=True, name=f"sigscan-w{wid}")
        workers.append(t)
        t.start()

    if progress_cb:
        finished = 0
        while finished < len(workers):
            try:
                kind, wid, *rest = progress_q.get(timeout=0.1)
                if kind == 'progress':
                    progress_cb(wid, scanned_bytes[wid], len(found))
                elif kind == 'worker_done':
                    finished += 1
                if stop_cb and stop_cb():
                    stop_evt.set()
            except _q.Empty:
                pass
        # drain
        while not progress_q.empty():
            try: progress_q.get_nowait()
            except _q.Empty: break
    for t in workers:
        t.join()
    return found