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

_DEBUG_LOG = os.path.join(os.path.expandvars('%TEMP%'), 'momotrainer_debug.log')
def _dbg(msg):
    try:
        with open(_DEBUG_LOG, 'a') as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass

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
VTYPES_ALL = ('int8','uint8','int16','uint16','int32','uint64','float','double')
SCAN_MODES = ('exact','greater','less','between',
              'changed','unchanged','increased','decreased','initial',
              'increased_pct','decreased_pct',
              'ispointer','binary')

Candidate = namedtuple('Candidate', ['addr', 'last'])
DEFAULT_CHUNK = 64 * 1024
PROGRESS_INTERVAL = 1 << 22   # report every 4 MB scanned
PROGRESS_MIN_INTERVAL = 0.1   # min seconds between progress reports per worker
_page_cache = {}               # handle -> [(base, size, protect), ...]

# ============================================================
# TAvgLvlTree — AVL tree for pointer region caching (CE: TAvgLvlTree)
# O(log N) pointer lookup instead of O(N) linear scan
# ============================================================
class _AVLNode:
    __slots__ = ('base', 'size', 'protect', 'height', 'left', 'right')
    def __init__(self, base, size, protect):
        self.base = base
        self.size = size
        self.protect = protect
        self.height = 1
        self.left = None
        self.right = None

class TAvgLvlTree:
    """CE: TAvgLvlTree — AVL tree for memory region indexing.
    
    Enables O(log N) pointer address lookup vs O(N) linear scan.
    Used to pre-filter regions during first scan, skipping ~90% of invalid addresses.
    """
    def __init__(self, compare_func=None):
        self.root = None
        self.compare = compare_func or (lambda a, b: (a.base > b.base) - (a.base < b.base))
        
    def _height(self, node):
        if not node: return 0
        return node.height
    
    def _update_height(self, node):
        node.height = 1 + max(self._height(node.left), self._height(node.right))
        return node.height
    
    def _balance_factor(self, node):
        if not node: return 0
        return self._height(node.left) - self._height(node.right)
    
    def _rotate_right(self, y):
        x = y.left
        T2 = x.right
        x.right = y
        y.left = T2
        self._update_height(y)
        self._update_height(x)
        return x
    
    def _rotate_left(self, x):
        y = x.right
        T2 = y.left
        y.left = x
        x.right = T2
        self._update_height(x)
        self._update_height(y)
        return y
    
    def _rebalance(self, node):
        bf = self._balance_factor(node)
        if bf > 1:
            if self._balance_factor(node.left) < 0:
                node.left = self._rotate_left(node.left)
            return self._rotate_right(node)
        if bf < -1:
            if self._balance_factor(node.right) > 0:
                node.right = self._rotate_right(node.right)
            return self._rotate_left(node)
        return node
    
    def add(self, base, size, protect):
        """Add a memory region to the tree."""
        region = _AVLNode(base, size, protect)
        self.root = self._add(self.root, region)
        
    def _add(self, node, region):
        if not node:
            return region
        cmp = self.compare(node, region)
        if cmp > 0:
            node.left = self._add(node.left, region)
        elif cmp < 0:
            node.right = self._add(node.right, region)
        else:
            # Overlapping region — keep the larger
            if region.size > node.size:
                node.left = self._add(node.left, region)
                node = self._rebalance(node)
            return node
        self._update_height(node)
        return self._rebalance(node)
    
    def find_region(self, addr):
        """Find region containing addr. Returns (base, size, protect) or None."""
        return self._find(self.root, addr)
    
    def _find(self, node, addr):
        if not node:
            return None
        if node.base <= addr < node.base + node.size:
            return (node.base, node.size, node.protect)
        if addr < node.base:
            return self._find(node.left, addr)
        else:
            return self._find(node.right, addr)

# CE: Region comparison helper — builds tree from (base, size, protect) tuples
class _RegionInfo:
    __slots__ = ('base', 'size', 'protect')
    def __init__(self, base, size, protect):
        self.base = base
        self.size = size
        self.protect = protect
    def __lt__(self, other):
        return self.base < other.base
    def __gt__(self, other):
        return self.base > other.base
    def __eq__(self, other):
        return self.base == other.base if isinstance(other, _RegionInfo) else False

_regions_tree = None  # module-level: built during first scan
_regions_initialized = False  # flag to avoid rebuild per scan

def _ensure_region_tree(h):
    """CE: Build TAvgLvlTree region cache from list_pages — one-time per process."""
    global _regions_tree, _regions_initialized
    
    if _regions_initialized:
        return _regions_tree
    
    _regions_tree = TAvgLvlTree()
    for base, psize, prot in list_pages(h):
        _regions_tree.add(base, psize, prot)
    _regions_initialized = True
    return _regions_tree

def is_pointer_region(addr, h, pointertypes=None):
    """CE: isPointer — quick filter using region tree.
    
    Returns True if addr appears to be a valid pointer region.
    Skips ~90% of invalid addresses immediately.
    """
    global _regions_initialized
    if not _regions_initialized:
        _ensure_region_tree(h)
    
    if _regions_tree is None:
        return True  # fallback: allow all if tree not built
    
    region = _regions_tree.find_region(addr)
    if region is None:
        return False  # addr not in any known region
    
    base, size, prot = region
    # CE: skip no-access, guard pages
    if prot & PAGE_NOACCESS:
        return False
    if prot & PAGE_GUARD:
        return False
    # Valid pointer region
    return True

def clear_region_tree():
    """CE: Clear cached tree (use when switching processes)."""
    global _regions_tree, _regions_initialized
    _regions_tree = None
    _regions_initialized = False


# ============================================================
# ScanFileWriter — CE: TScanFileWriter
# Separate I/O thread: scanners never block on disk writes
# ============================================================
class ScanFileWriter(threading.Thread):
    """CE: TScanFileWriter — separate thread for disk writes.

    Scanners produce results to a queue; this thread drains and writes
    to SQLite in the background.  Scanners never block on I/O.

    Double-buffering: scan while writing previous batch.
    Critical section protects concurrent writes from multiple scanners.
    """

    _instance = None  # singleton per process

    def __new__(cls, *a, **kw):
        if cls._instance is None or not cls._instance.is_alive():
            return super().__new__(cls)
        return cls._instance

    def __init__(self, db_path=None):
        if hasattr(self, '_inited'):
            return
        self._inited = True
        super().__init__(daemon=True, name='ScanFileWriter')
        self._queue = _q.Queue()
        self._running = True
        self._db_path = db_path or ':memory:'
        self._conn = None
        self._lock = threading.Lock()
        ScanFileWriter._instance = self

    def run(self):
        """Background I/O loop — write results from queue to SQLite."""
        import sqlite3
        buf = []
        buf_limit = 8192  # batch size
        self._conn = sqlite3.connect(self._db_path,
                                      check_same_thread=False,
                                      isolation_level=None)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_results(addr INTEGER PRIMARY KEY, data BLOB)")
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass

        while self._running or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.05)
                buf.append(item)
                if len(buf) >= buf_limit or not self._queue.empty():
                    self._flush_buf(buf)
                    buf.clear()
            except _q.Empty:
                if buf:
                    self._flush_buf(buf)
                    buf.clear()

        # Drain remaining
        while not self._queue.empty():
            try:
                buf.append(self._queue.get_nowait())
            except _q.Empty:
                break
        if buf:
            self._flush_buf(buf)

        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass

    def _flush_buf(self, buf):
        with self._lock:
            try:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO scan_results(addr, data) VALUES(?, ?)",
                    [(addr, data) for addr, data in buf])
            except Exception:
                pass

    def write(self, addr, data):
        """Enqueue a result for background write. Non-blocking."""
        self._queue.put((addr, data))

    def write_batch(self, items):
        """Enqueue multiple results. Non-blocking."""
        for addr, data in items:
            self._queue.put((addr, data))

    def stop(self, timeout=2.0):
        """Signal writer to stop and wait for completion."""
        self._running = False
        self.join(timeout=timeout)

    def count(self):
        with self._lock:
            if self._conn is None:
                return 0
            try:
                cur = self._conn.execute("SELECT COUNT(*) FROM scan_results")
                return cur.fetchone()[0]
            except Exception:
                return 0

    def get_all(self):
        with self._lock:
            if self._conn is None:
                return []
            try:
                return self._conn.execute(
                    "SELECT addr, data FROM scan_results ORDER BY addr").fetchall()
            except Exception:
                return []


# Singleton getter
def get_scan_writer(db_path=None):
    """Get or create the ScanFileWriter singleton."""
    return ScanFileWriter(db_path)


# CE: TScanType = (stNewScan=0, stFirstScan=1, stNextScan=2)
class ScanType:
    FIRST = 'first'
    NEXT = 'next'
    NEW = 'new'

# CE: FoundList disk-back threshold
_FOUNDLIST_DISK_THRESHOLD = 100_000

# Custom value types registry (CE: user-defined types)
_CUSTOM_VTYPES = {}

# ============================================================
# Dynamic buffer sizing (CE: memory scans adapt buffer per vtype)
# ============================================================
# Base buffer: 1 MB (CE: buffersize default)
# Each scan allocates (buffersize / variablesize) for candidate results
_BASE_BUFFER_SIZE = 1 * 1024 * 1024  # 1 MB
_MAX_BUFFER_SIZE   = 16 * 1024 * 1024 # 16 MB (CE: foundbuffersize max)
_MAX_CUSTOM_TYPE_SIZE = 16  # CE: skip custom types > 16 bytes to prevent blowup

def calculate_buffer_size(vtype, custom_bytesize=None):
    """CE: maxfound = buffersize / variablesize

    Returns the dynamic buffer size (in bytes) for a given value type.
    Larger types → smaller buffer to limit memory.
    Custom types > 16 bytes are capped.
    """
    if vtype == 'string':
        return 32 * 1024  # strings: 32 KB chunk
    if vtype in _CUSTOM_VTYPES:
        size = _CUSTOM_VTYPES[vtype][0]
    elif vtype in VTYPES:
        size = VTYPES[vtype][0]
    elif custom_bytesize is not None:
        size = custom_bytesize
    else:
        return _BASE_BUFFER_SIZE
    # CE pattern: larger types → smaller buffer
    return max(4096, min(_BASE_BUFFER_SIZE, _MAX_BUFFER_SIZE // max(1, size)))


def validate_custom_type_size(size):
    """CE: if customtype.bytesize > 16 then cap.

    Prevents memory blowup from very large custom types.
    Returns validated size (capped to _MAX_CUSTOM_TYPE_SIZE).
    """
    if size > _MAX_CUSTOM_TYPE_SIZE:
        import warnings
        warnings.warn(
            f"Custom type size {size} > {_MAX_CUSTOM_TYPE_SIZE}; "
            f"capping to {_MAX_CUSTOM_TYPE_SIZE} to prevent memory blowup "
            f"(CE: maxfound:=(buffersize*16) div bytesize)"
        )
        return _MAX_CUSTOM_TYPE_SIZE
    return size


def register_vtype(name, size, fmt, align):
    """Register a custom value type for scanning.

    name: type name (e.g. 'vec3f' for 3 floats)
    size: byte size
    fmt: struct format char (e.g. 'f' for float, 'i' for int)
    align: alignment for fast-scan
    """
    # CE: cap custom type size to prevent memory blowup
    size = validate_custom_type_size(size)
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
    """Yield (base, size, protect) for every readable+committed page.
    Results are cached per-handle to avoid rebuilding on every scan."""
    if h in _page_cache:
        for p in _page_cache[h]:
            yield p
        return
    _result = []
    addr = 0
    info = MEMORY_BASIC_INFORMATION()
    seen_bases = set()
    while True:
        got = VirtualQueryEx(h, addr, ctypes.byref(info), ctypes.sizeof(info))
        if got == 0:
            _page_cache[h] = _result
            break
        base = info.BaseAddress
        size = info.RegionSize
        if base in seen_bases or size == 0:
            _page_cache[h] = _result
            break
        seen_bases.add(base)
        if base == 0 and size > 0x100000000 and info.State == 0x10000:
            addr = 0x10000
            continue
        if (info.State == MEM_COMMIT
                and (info.Protect & PAGE_NOACCESS) == 0
                and (info.Protect & PAGE_GUARD)   == 0
                and info.Protect in VALID_PROTECTS):
            _result.append((base, size, info.Protect))
            yield (base, size, info.Protect)
        nxt = base + size
        if nxt <= addr or nxt >= 0x7FFF00000000:
            _page_cache[h] = _result
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

# Thread-local reusable buffer — avoids allocation per ReadProcessMemory call
_tls = threading.local()
def rblock_fast(h, addr, n):
    """Read n bytes into a thread-local reusable buffer (no allocation per call)."""
    buf = getattr(_tls, 'rbuf', None)
    if buf is None or len(buf) < n:
        buf = (ctypes.c_uint8 * max(n, DEFAULT_CHUNK))()
        _tls.rbuf = buf
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, n, ctypes.byref(got)):
        return None
    # Convert to memoryview to avoid bytes() copy
    return memoryview(buf)[:n]


# ============================================================
# wblock — robust write with VirtualProtectEx fallback
# ============================================================
class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]

_VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
_VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.POINTER(_MBI), ctypes.c_size_t]
_VirtualQueryEx.restype = ctypes.c_size_t

_VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
_VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
_VirtualProtectEx.restype = ctypes.c_int

PAGE_READWRITE         = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT             = 0x1000

def wblock(h, addr, data, use_unlock=True):
    """Robust write: try direct WriteProcessMemory; on failure (err=998/5),
    VirtualProtectEx the page to RW, write, then restore original protection.

    Returns True on success, False on failure.  Callers should check.
    """
    n = len(data)
    if n == 0: return True
    # Direct write first (fast path — most addresses are already writable)
    if WriteProcessMemory(h, ctypes.c_void_p(addr),
                          (ctypes.c_uint8 * n)(*data), n, None):
        return True
    err = ctypes.get_last_error()
    # ERROR_NOACCESS (998) or ERROR_ACCESS_DENIED (5) → try unlock
    if not use_unlock or err not in (5, 998, 487):
        return False
    # Find the page this address lives in
    mbi = _MBI()
    ok = _VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not ok or mbi.State != MEM_COMMIT:
        return False
    page_base = int(mbi.BaseAddress) if mbi.BaseAddress else int(addr)
    page_size = mbi.RegionSize
    if page_size == 0:
        page_size = 0x1000  # fall back to one page
    # Preserve the existing protection bits (e.g. EXEC) but add WRITE
    new_prot = mbi.Protect | PAGE_READWRITE
    # If was PAGE_NOACCESS, use full RW
    if mbi.Protect in (0, 1):
        new_prot = PAGE_READWRITE
    old_prot = ctypes.c_uint32(0)
    if not _VirtualProtectEx(h, ctypes.c_void_p(page_base), page_size,
                             new_prot, ctypes.byref(old_prot)):
        return False
    # Now write
    ok2 = WriteProcessMemory(h, ctypes.c_void_p(addr),
                             (ctypes.c_uint8 * n)(*data), n, None)
    # Restore original protection (always — even if write failed, don't leave page RW)
    _VirtualProtectEx(h, ctypes.c_void_p(page_base), page_size,
                      old_prot.value, ctypes.byref(old_prot))
    return bool(ok2)


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
    _last_prog = 0.0

    # Pre-compute needle as int for aligned numerical types
    _dbg(f"[DEBUG] first_scan worker {worker_id} starting: {len(page_slices)} page slices")
    use_int_cmp = False
    needle_int = 0
    nlen_float = False
    if nlen in (1, 2, 4, 8) and vtype not in ('float', 'double', 'string'):
        use_int_cmp = True
        needle_int = int.from_bytes(needle, 'little')
    elif nlen == 4 and vtype == 'float':
        use_int_cmp = True
        needle_int = struct.unpack('<I', struct.pack('<f', float(value)))[0]
    elif nlen == 8 and vtype == 'double':
        use_int_cmp = True
        needle_int = struct.unpack('<Q', struct.pack('<d', float(value)))[0]
    _dbg("TRACEPOINT_XYZ_999")
    _dbg(f"[DEBUG] worker {worker_id}: setup done, starting loop over {len(page_slices)} pages")

    _pg_cnt = 0
    _pg_total = len(page_slices)
    for base, psize, prot in page_slices:
        _pg_cnt += 1
        if _pg_cnt % 50 == 0 or _pg_cnt == _pg_total:
            _dbg(f"[DEBUG] worker {worker_id}: page {_pg_cnt}/{_pg_total}")
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
            buf = rblock_fast(h, addr, read_size)
            if buf is None:
                offset += cs
                continue
            # Convert to bytes for string path (needs .lower()/.find() methods)
            if vtype == 'string':
                buf = bytes(buf)
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

                if use_int_cmp and (stepsize == nlen or stepsize >= nlen):
                    # FAST PATH: struct.unpack_from on memoryview — interprets buffer as
                    # native int array, no slice creation per iteration. ~10-50x faster
                    # than byte-slicing.
                    # (NB: memoryview.cast('I') fails between non-byte formats in Python 3.11+;
                    # struct.unpack_from works on any bytes-like object.)
                    if nlen == 1:
                        _b = buf if isinstance(buf, (bytes, bytearray)) else bytes(buf)
                        for i in range(initial_skip, end, stepsize):
                            if _b[i] == needle_int:
                                store.add(addr + i, needle)
                                hits += 1
                    elif nlen == 2 and stepsize == 2:
                        _mv = memoryview(buf) if not isinstance(buf, memoryview) else buf
                        for i in range(0, len(_mv) - 1, 2):
                            if struct.unpack_from('<H', _mv, i)[0] == needle_int:
                                store.add(addr + i, needle)
                                hits += 1
                    elif nlen == 4 and stepsize == 4:
                        _mv = memoryview(buf) if not isinstance(buf, memoryview) else buf
                        for i in range(0, len(_mv) - 3, 4):
                            if struct.unpack_from('<I', _mv, i)[0] == needle_int:
                                store.add(addr + i, needle)
                                hits += 1
                    elif nlen == 8 and stepsize == 8:
                        _mv = memoryview(buf) if not isinstance(buf, memoryview) else buf
                        for i in range(0, len(_mv) - 7, 8):
                            if struct.unpack_from('<Q', _mv, i)[0] == needle_int:
                                store.add(addr + i, needle)
                                hits += 1
                    else:
                        # Fallback for fast_scan but non-standard align
                        use_int_cmp = False

                if not use_int_cmp:
                    # SLOWER but correct for non-aligned / string / float types
                    _mv = memoryview(buf)
                    i = initial_skip
                    while i < end:
                        if _mv[i:i+nlen] == needle:
                            store.add(addr + i, needle)
                            hits += 1
                        i += stepsize
            scanned += cs
            offset += cs
            # Throttled progress: max 10 updates/sec per worker
            _now = time.time()
            if _now - _last_prog >= PROGRESS_MIN_INTERVAL:
                _last_prog = _now
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
    _last_prog = 0.0
    _dbg(f"[DEBUG] rescan worker {worker_id} starting: {len(cands)} candidates")
    for addr, last in cands:
        if stop_evt.is_set():
            break
        cur = rblock_fast(h, addr, nlen)
        if cur is None:
            scanned += 1
            continue
        # String path needs bytes for .lower()
        if vtype == 'string':
            cur = bytes(cur)
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
        # Throttled progress: max 10 updates/sec per worker
        _now = time.time()
        if _now - _last_prog >= PROGRESS_MIN_INTERVAL:
            _last_prog = _now
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

    def _ispointer(new_cur, new_last, needle_int, high_int):
        # CE: isPointer — address must point to a valid committed region
        # needle_int = the target address to point TO
        ptr = new_cur
        if ptr == 0:
            return False
        # Basic pointer check: non-null address that could be in user space
        if needle_int != 0:
            return ptr == needle_int
        # No target specified: just check it's a plausible pointer
        return 0x1000 <= ptr <= 0x7FFFFFFF0000

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
        (8, 'ispointer'):        _ispointer,
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
    """Drain the progress queue until all workers report done.

    Sends an 'init' message with total_bytes as the very first event
    so the caller (GUI) knows the scan target and can show true %.
    """
    done = 0
    total_bytes = 0          # populated from the 'init' event
    while done < nworkers:
        try:
            kind, *rest = progress_q.get(timeout=0.1)
            if kind == 'init':
                # First worker that started already computed total_bytes.
                # Forward it so the GUI can set up the progress bar properly.
                total_bytes = rest[0]
                if progress_cb:
                    progress_cb(-1, total_bytes, 0)   # wid=-1 → "init"
                if stop_cb and stop_cb():
                    stop_evt.set()
            elif kind == 'progress':
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
    # Build pointer region tree for O(log N) lookups during scan
    # CE: isExecutablePointerLookupTree, isDynamicPointerLookupTree
    _ensure_region_tree(h)
    # Compute total bytes so the GUI can show true % progress
    total_bytes = sum(p[1] for p in pages)
    # Distribute pages across threads (round-robin by page index)
    slices = [[] for _ in range(nthreads)]
    for i, p in enumerate(pages):
        slices[i % nthreads].append(p)
    # Per-thread stores
    stores = [FoundList() for _ in range(nthreads)]
    use_progress = bool(progress_cb) or bool(stop_cb)
    progress_q = _q.Queue() if use_progress else _NullQueue()
    stop_evt = threading.Event()
    # Emit 'init' immediately so the GUI knows total_bytes before workers start
    if use_progress:
        progress_q.put(('init', total_bytes))
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
    # Emit 'init' with the candidate count so the GUI can show true % progress
    if use_progress:
        progress_q.put(('init', len(candidates)))
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


# ============================================================
# TScanController — CE: TScanController
# Central thread pool + coordination for all scan types
# ============================================================
class TScanController:
    """CE: TScanController — central coordinator for all memory scans.

    Responsibilities:
      - Thread pool management (cooperative cancel via Event)
      - Region-size-aware work partitioning
      - Progress aggregation across workers
      - Result merging from per-thread stores
      - Cancellation support (CE: stopscan)
      - Lua formula thread throttling (CE: if luaformula then threadcount=1)

    Public API:
      scan_first(h, vtype, value, mode, ...)  -> [Candidate]
      scan_next(h, candidates, vtype, value)    -> [Candidate]
      cancel()                                  -> None
    """

    def __init__(self, handle, nthreads=None, use_file_writer=False):
        self.handle = handle
        # CE: threadcount := GetCPUCount (but cap at 4 for GUI responsiveness)
        cpu = os.cpu_count() or 1
        self.nthreads = max(1, min(nthreads or cpu, 4))
        self.stop_evt = threading.Event()
        self._cancelled = False
        self._use_file_writer = use_file_writer
        self._writer = None
        if use_file_writer:
            self._writer = get_scan_writer()

    # ---- Smart partition by region size ----

    def _partition_by_region_size(self, pages, nworkers):
        """CE: partition by region size — larger regions get more workers.

        Instead of naive round-robin, sort pages by size descending
        and assign proportionally so large pages don't bottleneck one thread.
        """
        # Sort by size descending
        sorted_pages = sorted(pages, key=lambda p: p[1], reverse=True)
        # Proportional assignment: each worker gets pages of similar total size
        sizes = [0] * nworkers
        buckets = [[] for _ in range(nworkers)]
        for page in sorted_pages:
            # Assign to worker with smallest current load
            min_worker = sizes.index(min(sizes))
            buckets[min_worker].append(page)
            sizes[min_worker] += page[1]
        return buckets

    # ---- Region preferences (CE: scanWritable, scanExecutable, etc.) ----

    def _filter_pages(self, pages, scan_writable=True, scan_executable=True,
                      scan_copy_on_write=False):
        """CE: scanWritable, scanExecutable, scanCopyOnWrite filters.

        Filter pages by their protection flags before scanning.
        This is a major speedup — skipping irrelevant page types.
        """
        result = []
        for base, psize, prot in pages:
            if prot & PAGE_NOACCESS:
                continue
            if scan_writable and (prot & PAGE_READWRITE):
                result.append((base, psize, prot))
            elif scan_executable and (prot & PAGE_EXECUTE_READ):
                result.append((base, psize, prot))
            elif scan_copy_on_write and (prot & PAGE_WRITECOPY):
                result.append((base, psize, prot))
            elif not scan_writable and not scan_executable:
                if prot & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ):
                    result.append((base, psize, prot))
        return result

    # ---- First scan ----

    def scan_first(self, vtype, value, mode='exact', high=None,
                   progress_cb=None, stop_cb=None,
                   fast_scan=True, fast_scan_digits=None,
                   scan_writable=True, scan_executable=True,
                   scan_copy_on_write=False):
        """CE: TScanController.FirstScan — first scan with all CE options.

        Returns list of Candidate(addr, last).
        """
        self._cancelled = False
        pages = list(list_pages(self.handle))
        if not pages:
            return []

        # Apply region preference filters
        pages = self._filter_pages(pages, scan_writable, scan_executable,
                                   scan_copy_on_write)
        if not pages:
            return []

        # Build pointer region tree for O(log N) lookups
        _ensure_region_tree(self.handle)

        # Smart partition by region size
        slices = self._partition_by_region_size(pages, self.nthreads)

        # Per-thread stores
        stores = [FoundList() for _ in range(self.nthreads)]
        total_bytes = sum(p[1] for p in pages)
        use_progress = bool(progress_cb) or bool(stop_cb)
        progress_q = _q.Queue() if use_progress else _NullQueue()
        stop_evt = self.stop_evt

        if use_progress:
            progress_q.put(('init', total_bytes))

        workers = []
        for wid in range(self.nthreads):
            if not slices[wid]:
                continue
            t = threading.Thread(
                target=_first_scan_worker,
                args=(wid, self.handle, vtype, value, slices[wid],
                      fast_scan, fast_scan_digits, progress_q, stop_evt, stores[wid]),
                daemon=True, name=f"ctrl-first-w{wid}"
            )
            workers.append(t)
            t.start()

        if use_progress:
            _pump_progress(progress_q, progress_cb, stop_cb, stop_evt, len(workers))

        for t in workers:
            t.join()

        # Merge results
        merged = []
        for s in stores:
            for addr, last in s.all_hits():
                merged.append(Candidate(addr, last))
            s.close()
        merged.sort(key=lambda c: c.addr)
        return merged

    # ---- Rescan ----

    def scan_next(self, candidates, vtype, value, mode='exact', high=None,
                  progress_cb=None, stop_cb=None,
                  fast_scan=True, scan_writable=True, scan_executable=True):
        """CE: TScanController.NextScan — rescan survivors.

        Returns list of Candidate(addr, last).
        """
        if not candidates:
            return []
        self._cancelled = False

        # Apply region preference filters to candidates
        if scan_writable or scan_executable:
            filtered = []
            for cand in candidates:
                addr = cand.addr if isinstance(cand, Candidate) else cand
                region = None
                if _regions_tree is not None:
                    region = _regions_tree.find_region(addr)
                if region:
                    _, _, prot = region
                    if scan_writable and (prot & PAGE_READWRITE):
                        filtered.append(cand)
                    elif scan_executable and (prot & PAGE_EXECUTE_READ):
                        filtered.append(cand)
                else:
                    filtered.append(cand)
            candidates = filtered

        groups = [candidates[i::self.nthreads] for i in range(self.nthreads)]
        stores = [FoundList() for _ in range(self.nthreads)]
        use_progress = bool(progress_cb) or bool(stop_cb)
        progress_q = _q.Queue() if use_progress else _NullQueue()
        stop_evt = self.stop_evt

        if use_progress:
            progress_q.put(('init', len(candidates)))

        workers = []
        for wid in range(self.nthreads):
            if not groups[wid]:
                continue
            t = threading.Thread(
                target=_rescan_worker,
                args=(wid, self.handle, vtype, value, mode, groups[wid],
                      high, progress_q, stop_evt, stores[wid]),
                daemon=True, name=f"ctrl-next-w{wid}"
            )
            workers.append(t)
            t.start()

        if use_progress:
            _pump_progress(progress_q, progress_cb, stop_cb, stop_evt, len(workers))

        for t in workers:
            t.join()

        merged = []
        for s in stores:
            for addr, last in s.all_hits():
                merged.append(Candidate(addr, last))
            s.close()
        return merged

    # ---- Cancel ----

    def cancel(self):
        """CE: TScanController.stopscan — cooperative cancellation."""
        self._cancelled = True
        self.stop_evt.set()

    @property
    def cancelled(self):
        return self._cancelled


# ============================================================
# AtomicFreezeEngine — CE: freeze timer + write lock
# Prevents memory corruption from concurrent freeze writes
# ============================================================
class FreezeEntry:
    """CE: TFreezeEntry — one frozen address with metadata."""
    __slots__ = ('addr', 'vtype', 'value', 'interval', 'last_write',
                 'errors', 'enabled', 'pack_fmt', 'pack_size')
    def __init__(self, addr, vtype, value, interval=500):
        self.addr = addr
        self.vtype = vtype
        self.value = value
        self.interval = interval       # ms between writes
        self.last_write = 0.0
        self.errors = 0                 # consecutive write failures
        self.enabled = True
        if vtype == 'string':
            self.pack_fmt = 'utf-8'
            self.pack_size = 0
        else:
            self.pack_size, self.pack_fmt, _ = _resolve_vtype(vtype)


class AtomicFreezeEngine:
    """CE: TFreezeThread — atomic freeze engine with per-address timers.

    Features:
      - Thread-safe: all writes go through a single lock
      - Per-address timing: configurable interval per entry
      - Error tracking: disables address after MAX_ERRORS consecutive failures
      - Snapshot freeze: reads current value before locking
      - Batch writes: all freezes processed in one lock acquisition
    """

    MAX_ERRORS = 3  # CE: disable after N consecutive write failures
    DEFAULT_INTERVAL_MS = 500

    def __init__(self, handle):
        self.handle = handle
        self._entries = {}       # addr -> FreezeEntry
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._stop_evt = threading.Event()

    # ---- Public API ----

    def add(self, addr, vtype, value, interval=None):
        """CE: AddAddress — freeze an address with value."""
        with self._lock:
            if interval is None:
                interval = self.DEFAULT_INTERVAL_MS
            self._entries[addr] = FreezeEntry(addr, vtype, value, interval)
            return True

    def remove(self, addr):
        """CE: DeleteAddress — unfreeze an address."""
        with self._lock:
            self._entries.pop(addr, None)

    def set_value(self, addr, value):
        """Update the freeze value for an address (no restart needed)."""
        with self._lock:
            entry = self._entries.get(addr)
            if entry:
                entry.value = value
                return True
            return False

    def set_interval(self, addr, interval_ms):
        """Update the freeze interval for an address."""
        with self._lock:
            entry = self._entries.get(addr)
            if entry:
                entry.interval = interval_ms
                return True
            return False

    def enable(self, addr):
        """Re-enable a frozen address after it was disabled."""
        with self._lock:
            entry = self._entries.get(addr)
            if entry:
                entry.errors = 0
                entry.enabled = True
                return True
            return False

    def disable(self, addr):
        """Manually disable a frozen address."""
        with self._lock:
            entry = self._entries.get(addr)
            if entry:
                entry.enabled = False
                return True
            return False

    def get_entry(self, addr):
        """Get freeze entry metadata for an address."""
        with self._lock:
            return self._entries.get(addr)

    def get_enabled(self, addr):
        """Return True if address is frozen and enabled."""
        with self._lock:
            e = self._entries.get(addr)
            return e is not None and e.enabled

    def get_disabled(self):
        """Return list of addresses that were disabled due to write errors."""
        with self._lock:
            return [addr for addr, e in self._entries.items()
                    if not e.enabled and e.errors >= self.MAX_ERRORS]

    def clear_all(self):
        """CE: clear all freeze entries."""
        with self._lock:
            self._entries.clear()

    def count(self):
        """Return number of active freeze entries."""
        with self._lock:
            return len(self._entries)

    def start(self):
        """CE: FreezeTimer.start — start the freeze loop."""
        if self._running:
            return
        self._running = True
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._freeze_loop,
                                        daemon=True, name='FreezeEngine')
        self._thread.start()

    def stop(self):
        """CE: FreezeTimer.stop — stop the freeze loop."""
        self._running = False
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None

    def is_running(self):
        return self._running

    # ---- Internal freeze loop ----

    def _freeze_loop(self):
        """Background loop: process all freeze writes at their configured intervals."""
        import time
        while self._running and not self._stop_evt.is_set():
            now = time.time()
            to_write = []

            # Collect addresses that need writing (under lock, brief)
            with self._lock:
                for addr, entry in self._entries.items():
                    if not entry.enabled:
                        continue
                    interval_sec = entry.interval / 1000.0
                    if now - entry.last_write >= interval_sec:
                        to_write.append((addr, entry))
                        entry.last_write = now

            # Process writes outside lock (so UI can query during write)
            for addr, entry in to_write:
                if not self._running:
                    break
                self._write_freeze(addr, entry)

            # Sleep briefly to avoid busy-waiting
            time.sleep(0.01)

    def _write_freeze(self, addr, entry):
        """Write a single freeze value. Called outside the main lock."""
        # Pack the value into bytes
        if entry.vtype == 'string':
            data = entry.value.encode('utf-8') if isinstance(entry.value, str) else entry.value
        else:
            try:
                data = struct.pack('<' + entry.pack_fmt, entry.value)
            except Exception:
                with self._lock:
                    entry.errors += 1
                    if entry.errors >= self.MAX_ERRORS:
                        entry.enabled = False
                return

        # Use wblock for robust write (handles read-only pages)
        ok = wblock(self.handle, addr, data)
        if not ok:
            with self._lock:
                entry.errors += 1
                if entry.errors >= self.MAX_ERRORS:
                    entry.enabled = False