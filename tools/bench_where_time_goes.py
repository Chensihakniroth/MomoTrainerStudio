"""
Diagnose where wall-clock time is spent in first_scan.
Isolate: (a) ReadProcessMemory, (b) numpy comparison, (c) progress queue, (d) SQLite writes.
"""
import ctypes, ctypes.wintypes, struct, time, os, sys
import numpy as np

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

pages = list(ms.list_pages(h))
readable = [p for p in pages if p[2] & 0x04]
total_bytes = sum(p[1] for p in readable)
CHUNK = 32 * 1024  # same as memory_scanner.py

print(f"Total readable: {total_bytes/1024/1024:.1f} MB, {len(readable)} pages")
print()

# ── A) RPM bandwidth ceiling (just ReadProcessMemory, no comparison)
print("A) ReadProcessMemory bandwidth ceiling")
data = (ctypes.c_uint8 * CHUNK)()
read_bytes = ctypes.c_size_t(0)
t0 = time.time()
total_rpm = 0
rpm_pages = [p for p in readable[:20]]  # just first 20 pages for quick test
for base, psize, prot in rpm_pages:
    offset = 0
    while offset < psize:
        cs = min(CHUNK, psize - offset)
        addr = base + offset
        k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data, cs,
                              ctypes.byref(read_bytes))
        total_rpm += read_bytes.value
        offset += cs
t1 = time.time()
mb_s = total_rpm / 1024 / 1024 / (t1 - t0)
print(f"  20 pages ({total_rpm/1024/1024:.1f} MB) raw RPM: {t1-t0:.3f}s = {mb_s:.0f} MB/s")
print()

# ── B) RPM + numpy comparison only (no queue, no store)
print("B) RPM + pure numpy comparison (no progress queue, no SQLite)")
needle_int = 12345
nlen = 4
trim = CHUNK  # already aligned
arr = np.empty(CHUNK // 4, dtype='<u4')  # pre-allocated output
t0 = time.time()
total_cmp = 0
for base, psize, prot in readable[:20]:
    offset = 0
    while offset < psize:
        cs = min(CHUNK, psize - offset)
        addr = base + offset
        k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data, cs,
                              ctypes.byref(read_bytes))
        if read_bytes.value == cs:
            buf = bytes(data[:cs])
            trim_sz = (len(buf) // nlen) * nlen
            if trim_sz > 0:
                a = np.frombuffer(buf[:trim_sz], dtype='<u4')
                hits = np.where(a == needle_int)[0]
            total_cmp += cs
        offset += cs
t1 = time.time()
mb_s = total_cmp / 1024 / 1024 / (t1 - t0)
print(f"  20 pages ({total_cmp/1024/1024:.1f} MB) RPM+numpy: {t1-t0:.3f}s = {mb_s:.0f} MB/s")
print()

# ── C) RPM + numpy + store.add() (no queue)
print("C) RPM + numpy + store.add() (no progress queue, no SQLite)")
from memory_scanner import FoundList, PAGE_SIZE
store = FoundList(PAGE_SIZE)
t0 = time.time()
hits = 0
for base, psize, prot in readable[:20]:
    offset = 0
    while offset < psize:
        cs = min(CHUNK, psize - offset)
        addr = base + offset
        k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data, cs,
                              ctypes.byref(read_bytes))
        if read_bytes.value == cs:
            buf = bytes(data[:cs])
            trim_sz = (len(buf) // nlen) * nlen
            if trim_sz > 0:
                a = np.frombuffer(buf[:trim_sz], dtype='<u4')
                indices = np.where(a == needle_int)[0]
                for i in indices:
                    store.add(addr + int(i) * nlen, struct.pack('<I', needle_int))
                    hits += 1
        offset += cs
t1 = time.time()
mb_s = total_cmp / 1024 / 1024 / (t1 - t0)
print(f"  20 pages: {t1-t0:.3f}s, {hits} hits, effective={mb_s:.0f} MB/s")
print(f"  store backend: {store._backend_type}")
store.close()
print()

# ── D) Same as C but with progress queue (like the real code)
print("D) RPM + numpy + store + progress queue (real path, 20 pages)")
import queue
q = queue.Queue()
t0 = time.time()
hits = 0
store = FoundList(PAGE_SIZE)
for base, psize, prot in readable[:20]:
    offset = 0
    while offset < psize:
        cs = min(CHUNK, psize - offset)
        addr = base + offset
        k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data, cs,
                              ctypes.byref(read_bytes))
        if read_bytes.value == cs:
            buf = bytes(data[:cs])
            trim_sz = (len(buf) // nlen) * nlen
            if trim_sz > 0:
                a = np.frombuffer(buf[:trim_sz], dtype='<u4')
                indices = np.where(a == needle_int)[0]
                for i in indices:
                    store.add(addr + int(i) * 0x1000 + int(i) * nlen, struct.pack('<I', needle_int))
                    hits += 1
        offset += cs
        # throttled progress (like memory_scanner)
        if offset % (CHUNK * 5) == 0:
            try:
                q.put_nowait(('progress', 0, total_bytes, 0))
            except queue.Full:
                pass
t1 = time.time()
mb_s = total_cmp / 1024 / 1024 / (t1 - t0)
print(f"  20 pages: {t1-t0:.3f}s, {hits} hits, effective={mb_s:.0f} MB/s")
store.close()
print()

# ── E) Full list_pages + full scan
print("E) FULL first_scan (all pages, numpy path, 4 threads) — this is what the user feels")
for nthreads in [1, 4]:
    t0 = time.time()
    hits = list(ms.first_scan(h, 'uint32', 12345, mode='exact',
                              nthreads=nthreads, fast_scan=True))
    t1 = time.time()
    mb_s = total_bytes / 1024 / 1024 / (t1 - t0)
    print(f"  {nthreads} thread(s): {t1-t0:.3f}s, {len(hits)} hits, {mb_s:.0f} MB/s")

# ── F) Full scan but skip the progress queue entirely (instrument)
print()
print("F) Where does time go?  Full scan with timestamps")
import threading as _t
_q = _q = queue.Queue()

# Patch: time each chunk
chunk_times = []
def timed_worker(worker_id, h, vtype, value, page_slices, fast_scan,
                 fast_scan_digits, progress_q, stop_evt, store,
                 case_sensitive=False):
    import numpy as _np
    import struct as _st
    nlen = 4
    needle_int = 12345
    CHUNK = 32 * 1024
    for base, psize, prot in page_slices:
        if stop_evt.is_set():
            break
        offset = 0
        while offset < psize:
            if stop_evt.is_set():
                break
            cs = min(CHUNK, psize - offset)
            addr = base + offset
            # Time RPM
            t_rpm = time.perf_counter()
            data_buf = (ctypes.c_uint8 * cs)()
            rb = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data_buf, cs,
                                       ctypes.byref(rb))
            t_rpm_end = time.perf_counter()
            if ok and rb.value == cs:
                buf = bytes(data_buf)
                trim_sz = (len(buf) // nlen) * nlen
                t_cmp = time.perf_counter()
                if trim_sz > 0:
                    arr = _np.frombuffer(buf[:trim_sz], dtype='<u4')
                    idx = _np.where(arr == needle_int)[0]
                t_cmp_end = time.perf_counter()
                t_store = time.perf_counter()
                for i in idx:
                    store.add(addr + int(i) * nlen, _st.pack('<I', needle_int))
                t_store_end = time.perf_counter()
                chunk_times.append((t_rpm_end-t_rpm, t_cmp_end-t_cmp, t_store_end-t_store))
            offset += cs

store2 = FoundList(PAGE_SIZE)
stop = _t.Event()
pages_slice = readable[:30]  # 30 pages = ~120 MB
import queue as _q2
t0 = time.time()
# single threaded instrumented
timed_worker(0, h, 'uint32', 12345, pages_slice, True, None, _q2, stop, store2)
t1 = time.time()
store2.close()

if chunk_times:
    rpm = sum(x[0] for x in chunk_times)
    cmp_ = sum(x[1] for x in chunk_times)
    store_t = sum(x[2] for x in chunk_times)
    total = sum(sum(x) for x in chunk_times)
    mb_scanned = sum(p[1] for p in pages_slice) / 1024 / 1024
    print(f"\n  30 pages ({mb_scanned:.0f} MB), {len(chunk_times)} chunks:")
    print(f"  RPM time:        {rpm:.3f}s ({rpm/total*100:.0f}%)")
    print(f"  numpy time:     {cmp_:.3f}s ({cmp_/total*100:.0f}%)")
    print(f"  store.add time: {store_t:.3f}s ({store_t/total*100:.0f}%)")
    print(f"  Total:          {t1-t0:.3f}s")

k32.CloseHandle(h)
