"""
memory_scanner.py - CE-style fast memory scanner
made by Momo aka Steav Beoung Salang

Architecture (verified against cheat-engine/cheat-engine 2026-09-05):
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

Value types: 'int8','uint8','int16','uint16','int32','uint32',
             'int64','uint64','float','double','string'
Scan modes:  'exact','greater','less','between','increased','decreased',
             'changed','unchanged','initial',
             'increased_pct','decreased_pct'
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
SCAN_MODES = ('exact', 'greater', 'less', 'between',
              'changed', 'unchanged', 'increased', 'decreased', 'initial',
              'increased_pct', 'decreased_pct')

Candidate = namedtuple('Candidate', ['addr', 'last'])

DEFAULT_CHUNK = 64 * 1024
PROGRESS_INTERVAL = 1 << 22   # report every 4 MB scanned


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
    _, fmt, _ = VTYPES[vtype]
    return struct.pack('<' + fmt, value)

def unpack_value(vtype, blob):
    _, fmt, _ = VTYPES[vtype]
    return struct.unpack('<' + fmt, blob)[0]

def scan_size(vtype):
    if vtype == 'string': return 0
    return VTYPES[vtype][0]

def scan_align(vtype, fast_scan):
    if vtype == 'string': return 1
    _, _, a = VTYPES[vtype]
    return a if fast_scan else 1


# ============================================================
# ResultStore: SQLite-backed, thread-safe per-thread
# Each scanner worker has its OWN store. We merge at the end.
# (CE pattern: ADDRESSES-<threadid>.TMP per thread)
# ============================================================
import sqlite3

class ResultStore:
    SCHEMA = "CREATE TABLE IF NOT EXISTS hits(addr INTEGER PRIMARY KEY, last BLOB)"
    SCHEMA_IDX = "CREATE INDEX IF NOT EXISTS hits_addr ON hits(addr)"

    def __init__(self, path=None):
        if path is None:
            path = f":memory:"
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute(self.SCHEMA)
        self._conn.execute(self.SCHEMA_IDX)
        try: self._conn.execute("PRAGMA journal_mode=OFF")
        except Exception: pass
        try: self._conn.execute("PRAGMA synchronous=OFF")
        except Exception: pass
        # Per-thread buffer to batch writes (CE-style: each thread has its own file,
        # we batch in RAM and flush periodically for the same effect).
        self._buf = []
        self._buf_limit = 4096

    def add(self, addr, last):
        self._buf.append((addr, bytes(last) if not isinstance(last, (bytes, bytearray)) else last))
        if len(self._buf) >= self._buf_limit:
            self._flush()

    def _flush(self):
        if self._buf:
            self._conn.executemany("INSERT OR IGNORE INTO hits(addr, last) VALUES(?, ?)",
                                    self._buf)
            self._buf.clear()

    def add_many(self, items):
        self._buf.extend((a, bytes(b) if not isinstance(b, (bytes, bytearray)) else b)
                         for a, b in items)
        if len(self._buf) >= self._buf_limit:
            self._flush()

    def count(self):
        self._flush()
        return self._conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]

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
                       fast_scan_digits, progress_q, stop_evt, store):
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
                start = 0
                while True:
                    idx = buf.find(needle, start)
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
                   progress_q, stop_evt, store):
    """
    One rescan worker: checks its slice of candidates.
    """
    if vtype == 'string':
        needle = value.encode('utf-8') if isinstance(value, str) else value
        nlen = len(needle)
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
        if _compare_one(mode, cur, last, needle, high, vtype):
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
               fast_scan_digits=None, nthreads=None):
    """
    CE-style parallel first scan.
    Returns list of Candidate(addr, last_bytes) — same shape as v1.

    fast_scan_digits: CE fsmLastDigits — step by 16**N (e.g. N=2 → step 256).
                       Only scans addresses ending in N zero hex digits.
                        None = normal fast-scan alignment only.
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
    stores = [ResultStore() for _ in range(nthreads)]
    use_progress = bool(progress_cb) or bool(stop_cb)
    progress_q = _q.Queue() if use_progress else _NullQueue()
    stop_evt = threading.Event()
    workers = []
    for wid in range(nthreads):
        if not slices[wid]:
            continue
        t = threading.Thread(target=_first_scan_worker,
                              args=(wid, h, vtype, value, slices[wid],
                                    fast_scan, fast_scan_digits, progress_q, stop_evt, stores[wid]),
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
           progress_cb=None, stop_cb=None, fast_scan=True, nthreads=None):
    """
    CE-style parallel rescan. Returns survivors as list of Candidate.
    """
    if not candidates:
        return []
    nthreads = max(1, nthreads or (os.cpu_count() or 1))
    # Distribute candidates by INDEX (contiguous slices — better cache locality
    # than modulo, since cands are addr-sorted from previous scan)
    groups = [candidates[i::nthreads] for i in range(nthreads)]
    stores = [ResultStore() for _ in range(nthreads)]
    use_progress = bool(progress_cb) or bool(stop_cb)
    progress_q = _q.Queue() if use_progress else _NullQueue()
    stop_evt = threading.Event()
    workers = []
    for wid in range(nthreads):
        if not groups[wid]:
            continue
        t = threading.Thread(target=_rescan_worker,
                              args=(wid, h, vtype, value, mode, groups[wid],
                                    high, progress_q, stop_evt, stores[wid]),
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
# pointer scanner (depth-1, CE-style noLoop + useHeapData)
# ============================================================
def _build_heap_regions(h):
    """Build list of (base, size) for all committed heap regions.
    CE: uses frmMemoryAllocHandler.HeapBaselevel to identify heaps."""
    heaps = []
    for base, psize, prot in list_pages(h):
        if prot & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE):
            # Heaps are typically READWRITE, not executable
            if prot & PAGE_EXECUTE_READWRITE and not (prot & PAGE_EXECUTE_READ):
                heaps.append((base, psize))
    return heaps


def pointer_scan(h, target_value_bytes, max_depth=1, max_offset=0x1000,
                 progress_cb=None, stop_cb=None,
                 no_loop=True, use_heap_data=False):
    """
    CE-style pointer scan.
    For each readable page, look for a uintptr_t-sized value that, when
    added to one of the offsets in [0..max_offset), equals an address
    where target_value_bytes lives. Returns dict: addr -> (offset, target_addr).

    no_loop: CE noLoop flag — skip pointers that point to themselves (self-ref).
    use_heap_data: CE useHeapData — only return pointers into heap regions.
    """
    size = len(target_value_bytes)
    addr_list = first_scan(h, 'uint32' if size == 4 else 'uint64',
                            struct.unpack('<I' if size == 4 else '<Q', target_value_bytes)[0],
                            progress_cb=lambda *_: None)
    if len(addr_list) > 50000:
        addr_list = addr_list[:50000]
    target_addrs = {c.addr for c in addr_list}

    # CE useHeapData: build heap region list once
    heap_regions = []
    if use_heap_data:
        heap_regions = _build_heap_regions(h)

    found = {}
    pages = list(list_pages(h))
    total = sum(s for _, s, _ in pages)
    done = 0
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
            step = ctypes.sizeof(ctypes.c_void_p)
            for i in range(0, len(data) - step + 1, step):
                ptr = struct.unpack('<Q' if step == 8 else '<I', data[i:i+step])[0]
                if ptr == 0:
                    continue
                # CE noLoop: skip self-referencing pointers
                if no_loop and ptr == base + offset + i:
                    continue
                for off_try in range(0, max_offset + 1, 4):
                    if (ptr + off_try) in target_addrs:
                        found_addr = base + offset + i
                        # CE useHeapData: only keep heap pointers
                        if use_heap_data:
                            in_heap = any(
                                hr <= found_addr < hr + sz
                                for hr, sz in heap_regions
                            )
                            if not in_heap:
                                break
                        found[found_addr] = (off_try, ptr + off_try)
                        break
            offset += chunk
        done += psize
        if progress_cb:
            progress_cb(done, total, len(found))
    return found


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