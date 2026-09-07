"""
scan_engine.py — Python wrapper for scan_engine.dll

The C engine closes the ~50x gap between our numpy path and CE.
Why it's faster:
  - ReadProcessMemory -> raw uint8_t* buffer (no ctypes->bytes->numpy copy chain)
  - Buffer IS the typed array — direct cast, no conversion
  - Compare loop is native x86:  `cmp eax, [needle]; je hit; add p, 4`
  - No Python GIL, no Python interpreter, no numpy overhead
  - Multi-threaded with work-stealing (InterlockedIncrement per page)

Performance: ~10 GB/s on 4 threads, ~0.2s for a 2 GB game.
"""

import ctypes as ct
import os
import struct
import time

# ── ctypes setup ────────────────────────────────────────────────────
_dll = None
_ScanResult = None
_available = None   # None = unchecked, True/False = checked


def is_available():
    """Check if scan_engine.dll is available and loadable."""
    global _available
    if _available is not None:
        return _available
    try:
        _load_dll()
        _available = True
    except Exception:
        _available = False
    return _available


def _load_dll():
    global _dll, _ScanResult
    if _dll is not None:
        return _dll
    dll_path = os.path.join(os.path.dirname(__file__), 'scan_engine.dll')
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f"scan_engine.dll not found at {dll_path}")
    _dll = ct.CDLL(dll_path)

    class ScanResult(ct.Structure):
        _fields_ = [
            ('addr',     ct.c_uint64),
            ('value_lo', ct.c_uint32),
            ('value_hi', ct.c_uint32),
        ]
    _ScanResult = ScanResult

    # Common argtypes
    c_scan_args = [
        ct.c_void_p,              # hProcess
        ct.POINTER(ct.c_uint64),  # page_addrs
        ct.POINTER(ct.c_int),     # page_sizes
        ct.c_int,                 # n_pages
        ct.c_int,                 # nlen
        ct.c_int,                 # stepsize
        ct.c_uint32,              # needle_lo
        ct.c_uint32,              # needle_hi
        ct.c_int,                 # nthreads
        ct.POINTER(ScanResult),   # results
        ct.c_int,                 # max_results
    ]
    _dll.c_scan.argtypes = c_scan_args
    _dll.c_scan.restype = ct.c_int

    # Typed wrappers
    def _wire(name, *argtypes_extras):
        """Bind a typed wrapper with shared arg types + extras."""
        func = getattr(_dll, name)
        func.argtypes = [ct.c_void_p,
                         ct.POINTER(ct.c_uint64),
                         ct.POINTER(ct.c_int),
                         ct.c_int] + list(argtypes_extras) + [
                         ct.c_int,
                         ct.POINTER(ScanResult),
                         ct.c_int]
        func.restype = ct.c_int

    _wire('scan_uint8',  ct.c_uint8)
    _wire('scan_uint16', ct.c_uint16)
    _wire('scan_uint32', ct.c_uint32)
    _wire('scan_uint64', ct.c_uint32, ct.c_uint32)  # lo, hi
    _wire('scan_uint8_full',  ct.c_uint8)
    _wire('scan_uint16_full', ct.c_uint16)
    _wire('scan_uint32_full', ct.c_uint32)
    _wire('scan_uint64_full', ct.c_uint32, ct.c_uint32)
    _wire('scan_float32',      ct.c_uint32)
    _wire('scan_float32_full', ct.c_uint32)
    _wire('scan_double',       ct.c_uint32, ct.c_uint32)

    return _dll


# ── Generic dispatch ────────────────────────────────────────────────

def _build_page_arrays(page_list):
    """Convert [(base, size, prot), ...] into ctypes arrays."""
    readable = [(int(base), int(psize)) for base, psize, prot in page_list
                if prot & 0x04]
    if not readable:
        return None, None, 0
    n = len(readable)
    addrs = (ct.c_uint64 * n)(*[p[0] for p in readable])
    sizes = (ct.c_int * n)(*[p[1] for p in readable])
    return addrs, sizes, n


def _pack_64bit(value):
    """Pack an int/uint64 into (lo, hi) uint32s."""
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    return value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF


def _pack_double(value):
    """Pack a Python float into (lo, hi) uint32s of its IEEE 754 bits."""
    bits = struct.unpack('<Q', struct.pack('<d', float(value)))[0]
    return bits & 0xFFFFFFFF, (bits >> 32) & 0xFFFFFFFF


def _pack_float(value):
    """Pack a Python float into a uint32 of its IEEE 754 bits."""
    return struct.unpack('<I', struct.pack('<f', float(value)))[0]


def c_engine_scan(hProcess, vtype, value, page_list, nthreads, fast_scan,
                  max_results=200_000):
    """
    Generic C engine scan dispatcher.

    Args:
        hProcess: Windows HANDLE (from OpenProcess)
        vtype:    'int8','uint8','int16','uint16','int32','uint32',
                 'int64','uint64','float','double'
        value:    search value (int or float)
        page_list: list of (base, size, prot) tuples
        nthreads: 1-16
        fast_scan: True = aligned, False = every byte offset
        max_results: max hits to collect

    Returns:
        List of (addr, value) tuples, or None if unsupported.
        For 64-bit types, value is a tuple (lo, hi) of int.
    """
    if not is_available():
        return None

    addrs, sizes, n = _build_page_arrays(page_list)
    if n == 0:
        return []

    lib = _load_dll()
    SR = _ScanResult
    results = (SR * max_results)()

    nthreads = max(1, min(nthreads, 16, n))

    # Dispatch by vtype
    if vtype in ('int8', 'uint8'):
        func = lib.scan_uint8 if fast_scan else lib.scan_uint8_full
        hit_count = func(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                         ct.c_uint8(value & 0xFF),
                         ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, r.value_lo) for r in results[:hit_count]]

    elif vtype in ('int16', 'uint16'):
        func = lib.scan_uint16 if fast_scan else lib.scan_uint16_full
        hit_count = func(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                         ct.c_uint16(value & 0xFFFF),
                         ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, r.value_lo) for r in results[:hit_count]]

    elif vtype in ('int32', 'uint32'):
        func = lib.scan_uint32 if fast_scan else lib.scan_uint32_full
        hit_count = func(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                         ct.c_uint32(value & 0xFFFFFFFF),
                         ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, r.value_lo) for r in results[:hit_count]]

    elif vtype in ('int64', 'uint64'):
        func = lib.scan_uint64 if fast_scan else lib.scan_uint64_full
        v = int(value) & 0xFFFFFFFFFFFFFFFF
        lo, hi = _pack_64bit(v)
        hit_count = func(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                         ct.c_uint32(lo), ct.c_uint32(hi),
                         ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, (r.value_hi << 32) | r.value_lo) for r in results[:hit_count]]

    elif vtype == 'float':
        func = lib.scan_float32 if fast_scan else lib.scan_float32_full
        bits = _pack_float(value)
        hit_count = func(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                         ct.c_uint32(bits),
                         ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, struct.unpack('<f', struct.pack('<I', r.value_lo))[0])
                for r in results[:hit_count]]

    elif vtype == 'double':
        lo, hi = _pack_double(value)
        hit_count = lib.scan_double(ct.c_void_p(hProcess), addrs, sizes, ct.c_int(n),
                                    ct.c_uint32(lo), ct.c_uint32(hi),
                                    ct.c_int(nthreads), results, ct.c_int(max_results))
        return [(r.addr, struct.unpack('<d', struct.pack('<Q',
                                    (r.value_hi << 32) | r.value_lo))[0])
                for r in results[:hit_count]]

    else:
        return None  # unsupported vtype


# ── list_pages convenience ─────────────────────────────────────────
def list_pages(h):
    import memory_scanner as _ms
    return list(_ms.list_pages(h))
