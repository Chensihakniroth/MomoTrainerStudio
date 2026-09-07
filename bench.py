"""
Benchmark our first_scan vs CE-style ceiling.
- Measures: pages read, total bytes scanned, time, MB/s throughput.
- Compares: fast_scan=True vs fast_scan=False (raw byte path), aligned nlen=4.
- Per-thread timing breakdown.
"""
import ctypes, ctypes.wintypes, struct, time, sys

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

pages = list(ms.list_pages(h))
total_bytes = sum(p[1] for p in pages if p[2] & 0x04)
print(f"Total readable memory: {total_bytes/1024/1024:.1f} MB across {sum(1 for p in pages if p[2] & 0x04)} pages")

val = 0x12345678
needle = struct.pack('<I', val)

print(f"\nNeedle: {needle.hex()} (uint32 0x{val:X})")

# 1) Fast scan
for nthreads in [1, 4]:
    t0 = time.time()
    hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=nthreads, fast_scan=True))
    t1 = time.time()
    mb_s = total_bytes / (1024*1024) / (t1-t0)
    print(f"  FAST scan (nthreads={nthreads}): {len(hits)} hits, {t1-t0:.3f}s, {mb_s:.1f} MB/s")

# 2) Skip full scan by default (too slow on Python heap); show with timeout flag
import sys
if '--with-full' in sys.argv:
    for nthreads in [1, 4]:
        t0 = time.time()
        hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=nthreads, fast_scan=False))
        t1 = time.time()
        mb_s = total_bytes / (1024*1024) / (t1-t0)
        print(f"  FULL scan (nthreads={nthreads}): {len(hits)} hits, {t1-t0:.3f}s, {mb_s:.1f} MB/s")

# 3) Reference: pure Python str.find on a buffer (what naive impl looks like)
buf = b"\x00" * (4 * 1024 * 1024)  # 4 MB
n_iter = 50
t0 = time.time()
for _ in range(n_iter):
    idx = buf.find(needle)
t1 = time.time()
mb_s = (len(buf) * n_iter / (1024*1024)) / (t1-t0)
print(f"\n  REFERENCE: bytes.find in {len(buf)/1024/1024:.1f} MB: {mb_s:.1f} MB/s")

# 4) Reference: struct.unpack_from loop (our "fast path")
import struct as st
t0 = time.time()
needle_int = st.unpack('<I', needle)[0]
for _ in range(n_iter):
    mv = memoryview(buf)
    end = len(mv) - 3
    for i in range(0, end, 4):
        if st.unpack_from('<I', mv, i)[0] == needle_int:
            pass
t1 = time.time()
mb_s = (len(buf) * n_iter / (1024*1024)) / (t1-t0)
print(f"  REFERENCE: struct.unpack_from loop: {mb_s:.1f} MB/s")

# 5) Reference: numpy search
try:
    import numpy as np
    arr = np.frombuffer(buf, dtype='<u4')
    t0 = time.time()
    for _ in range(n_iter):
        np.where(arr == needle_int)
    t1 = time.time()
    mb_s = (len(buf) * n_iter / (1024*1024)) / (t1-t0)
    print(f"  REFERENCE: numpy uint32 == scan: {mb_s:.1f} MB/s")
except ImportError:
    print("  REFERENCE: numpy not available")

k32.CloseHandle(h)
print("\n=== BENCHMARK DONE ===")