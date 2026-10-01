"""
Break down where time goes in the scan:
1. ReadProcessMemory overhead per chunk
2. Comparison loop time
3. Result store (SQLite insert)
4. Thread coordination overhead
"""
import ctypes, struct, time, sys, threading
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

# Read ALL readable pages once to get a single chunk
pages = list(ms.list_pages(h))
rw = [p for p in pages if p[2] & 0x04]
total_bytes = sum(p[1] for p in rw)
print(f"Total: {total_bytes/1024/1024:.1f} MB in {len(rw)} pages")

CHUNK = 64 * 1024
# Time just ReadProcessMemory (no comparison)
_t0 = time.perf_counter()
count = 0
for base, psize, prot in rw:
    offset = 0
    while offset < psize:
        cs = min(CHUNK, psize - offset)
        buf = ms.rblock(h, base + offset, cs)
        offset += cs
        count += 1
rpm_time = time.perf_counter() - _t0
print(f"\nReadProcessMemory ONLY ({count} chunks of {CHUNK//1024}KB):")
print(f"  Time: {rpm_time*1000:.1f}ms")
print(f"  Throughput: {total_bytes/1024/1024/rpm_time:.1f} MB/s")
print(f"  Per-chunk RPM: {rpm_time/count*1000:.3f}ms")

# Time comparison loop alone (numpy)
import numpy as np
buf = bytes(CHUNK)
struct.pack_into('<I', buf, 0, 0x12345678)
needle_int = struct.unpack('<I', struct.pack('<I', 0x12345678))[0]
N = 10000
_t0 = time.perf_counter()
for _ in range(N):
    arr = np.frombuffer(buf, dtype='<u4')
    indices = np.where(arr == needle_int)[0]
    for _i in indices:
        pass  # count store.add() time separately
numpy_time = time.perf_counter() - _t0
numpy_throughput = CHUNK * N / (1024*1024) / numpy_time
print(f"\nNumpy comparison only ({CHUNK//1024}KB chunks x {N}):")
print(f"  Time: {numpy_time*1000:.1f}ms")
print(f"  Throughput: {numpy_throughput/1024:.1f} GB/s")
print(f"  Per-chunk: {numpy_time/N*1000:.4f}ms")

# What fraction of wall-clock is RPM?
print(f"\n=== BREAKDOWN ===")
full_wall = 0.45  # from bench: ~0.45s for fast scan
rpm_pct = rpm_time / full_wall * 100
numpy_pct = (numpy_time / N * count) / full_wall * 100
print(f"Estimated RPM fraction: {rpm_pct:.0f}% of wall-clock")
print(f"Estimated comparison fraction: {numpy_pct:.2f}% of wall-clock")
print(f"Other (thread sync, store, overhead): ~{100 - rpm_pct - numpy_pct:.0f}%")

# Does the comparison loop matter at all?
comp_only = (numpy_time / N * count)
print(f"\nComparison for all {count} chunks: {comp_only*1000:.2f}ms")
print(f"RPM for all {count} chunks: {rpm_time*1000:.1f}ms")
print(f"Ratio: RPM is {rpm_time/comp_only:.0f}x slower than comparison")

# What would happen with larger chunks?
for new_chunk in [256*1024, 1024*1024]:
    # Re-time RPM with different chunk size
    _t0 = time.perf_counter()
    cnt = 0
    for base, psize, prot in rw:
        offset = 0
        while offset < psize:
            cs = min(new_chunk, psize - offset)
            ms.rblock(h, base + offset, cs)
            offset += cs
            cnt += 1
    t = time.perf_counter() - _t0
    print(f"\nRPM with {new_chunk//1024}KB chunks ({cnt} reads):")
    print(f"  Time: {t*1000:.1f}ms  ({total_bytes/1024/1024/t:.1f} MB/s)")

k32.CloseHandle(h)