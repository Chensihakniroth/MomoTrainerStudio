"""
Detailed breakdown: where does the 450ms actually go?
Instruments _first_scan_worker to measure each phase per chunk.
"""
import ctypes, struct, time, sys, threading
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

pages = list(ms.list_pages(h))
rw = [p for p in pages if p[2] & 0x04]
print(f"Pages: {len(rw)}, Total: {sum(p[1] for p in rw)/1024/1024:.1f} MB")

# Manual single-threaded scan with timing per phase
vtype = 'uint32'
value = 0x12345678
nlen = 4
align = ms.scan_align(vtype, True)  # fast_scan=True
stepsize = align
needle = struct.pack('<I', value)
needle_int = struct.unpack('<I', needle)[0]
overlap = nlen - 1
chunk_size = 64 * 1024

t_rpm = t_np = t_store = t_other = 0
n_chunks = 0
import numpy as np

# TLS buffer
_tls = threading.local()
def rblock_fast(h, addr, n):
    buf = getattr(_tls, 'rbuf', None)
    if buf is None or len(buf) < n:
        buf = (ctypes.c_uint8 * max(n, chunk_size))()
        _tls.rbuf = buf
    got = ctypes.c_size_t(0)
    if not ms.ReadProcessMemory(h, addr, buf, n, ctypes.byref(got)):
        return None
    return memoryview(buf)[:n]

for base, psize, prot in rw[:20]:  # First 20 pages
    offset = 0
    while offset < psize:
        cs = min(chunk_size, psize - offset)
        addr = base + offset
        remaining = psize - offset
        read_size = cs + overlap if cs + overlap <= remaining else cs

        # Phase 1: RPM
        t0 = time.perf_counter()
        buf = rblock_fast(h, addr, read_size)
        t_rpm += time.perf_counter() - t0
        n_chunks += 1
        if buf is None:
            offset += cs
            continue

        # Phase 2: numpy fast path
        t0 = time.perf_counter()
        _raw = bytes(buf) if isinstance(buf, memoryview) else buf
        # Trim to multiple of 4 so np.frombuffer doesn't complain
        trim = len(_raw) & ~3
        arr = np.frombuffer(_raw[:trim], dtype='<u4')
        indices = np.where(arr == needle_int)[0]
        t_np += time.perf_counter() - t0

        # Phase 3: store
        t0 = time.perf_counter()
        hits = 0
        for _i in indices:
            hits += 1
        t_store += time.perf_counter() - t0

        offset += cs

t_total = t_rpm + t_np + t_store + t_other
print(f"\n=== PER-CHUNK BREAKDOWN (20 pages, {n_chunks} chunks) ===")
print(f"Phase        | Time      | %     | Per chunk")
print(f"-------------|-----------|-------|----------")
print(f"RPM          | {t_rpm*1000:7.2f}ms | {t_rpm/t_total*100:5.1f}% | {t_rpm/n_chunks*1000:.4f}ms")
print(f"Numpy scan   | {t_np*1000:7.2f}ms | {t_np/t_total*100:5.1f}% | {t_np/n_chunks*1000:.4f}ms")
print(f"Store result | {t_store*1000:7.2f}ms | {t_store/t_total*100:5.1f}% | {t_store/n_chunks*1000:.4f}ms")
print(f"TOTAL        | {t_total*1000:7.2f}ms | 100.0%")
print(f"\nExtrap. full scan ({sum(p[1] for p in rw)/1024/1024:.1f} MB): {t_total*1000*(len(rw)/20):.0f}ms")

# How fast is pure numpy on all pages in memory?
print(f"\n=== PURE NUMPY SPEED ===")
all_buf = bytearray(sum(p[1] for p in rw[:20]))
print(f"Read all 20 pages: {len(all_buf)/1024/1024:.2f} MB")
import struct as st
st.pack_into('<I', all_buf, 100, value)  # put needle
t0 = time.perf_counter()
arr = np.frombuffer(all_buf, dtype='<u4')
indices = np.where(arr == needle_int)[0]
t1 = time.perf_counter()
print(f"np.where on {len(all_buf)/1024/1024:.1f} MB: {(t1-t0)*1000:.4f}ms")
print(f"Throughput: {len(all_buf)/(1024*1024)/(t1-t0):.0f} GB/s")

# What about just numpy on 64KB chunks?
t_np_total = 0
for base, psize, prot in rw[:20]:
    offset = 0
    while offset < psize:
        cs = min(chunk_size, psize - offset)
        buf = rblock_fast(h, base + offset, cs)
        if buf:
            t0 = time.perf_counter()
            arr = np.frombuffer(bytes(buf), dtype='<u4')
            np.where(arr == needle_int)
            t_np_total += time.perf_counter() - t0
        offset += cs
print(f"\nNumpy on all 20 pages (chunked): {t_np_total*1000:.2f}ms ({sum(p[1] for p in rw[:20])/1024/1024:.1f}MB)")
print(f"Expected full scan time if only RPM+numpy: {t_np_total*len(rw)/20*1000:.0f}ms")

k32.CloseHandle(h)