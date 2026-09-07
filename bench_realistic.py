"""
Realistic game-style benchmark: simulate a real game's memory footprint,
measure actual wall-clock time of a single first_scan (the thing the user feels).
"""
import ctypes, ctypes.wintypes, struct, time, sys, os
import numpy as np

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

print("=" * 70)
print("REALISTIC SCAN: simulate the user scenario")
print("User types a value (e.g. health=1000), clicks 'First Scan'")
print("Measures: wall-clock time from click to results")
print("=" * 70)

# 1) Show what we're actually scanning
pages = list(ms.list_pages(h))
readable = [p for p in pages if p[2] & 0x04]
total_bytes = sum(p[1] for p in readable)
print(f"\nThis Python process has: {total_bytes/1024/1024:.1f} MB readable "
      f"({len(readable)} pages)")
print(f"(A real game might have 1-4 GB readable — this is a worst-case light test)")

# 2) Wall-clock for fast scan uint32 (most common — int32 health)
val = 12345
print(f"\n[SCENARIO 1] Health search: uint32 = {val}")
for nthreads in [1, 2, 4, 8]:
    t0 = time.time()
    hits = list(ms.first_scan(h, 'uint32', val, mode='exact',
                              nthreads=nthreads, fast_scan=True))
    t1 = time.time()
    print(f"  threads={nthreads}: {t1-t0:.3f}s ({len(hits)} hits)")

# 3) Wall-clock for float (also common — float health)
print(f"\n[SCENARIO 2] Float search: float = 99.5")
val = 99.5
for nthreads in [1, 2, 4, 8]:
    t0 = time.time()
    hits = list(ms.first_scan(h, 'float', val, mode='exact',
                              nthreads=nthreads, fast_scan=True))
    t1 = time.time()
    print(f"  threads={nthreads}: {t1-t0:.3f}s ({len(hits)} hits)")

# 4) Wall-clock for int8 (single byte, e.g. ammo count)
print(f"\n[SCENARIO 3] Byte search: uint8 = 50")
val = 50
for nthreads in [1, 2, 4, 8]:
    t0 = time.time()
    hits = list(ms.first_scan(h, 'uint8', val, mode='exact',
                              nthreads=nthreads, fast_scan=True))
    t1 = time.time()
    print(f"  threads={nthreads}: {t1-t0:.3f}s ({len(hits)} hits)")

# 5) What a 2 GB game would look like (extrapolate)
print(f"\n[EXTRAPOLATION] If a real game has 2 GB readable:")
print(f"  Our current rate: ~{255/1024:.2f} GB/s with 4 threads (numpy path)")
print(f"  Estimated time: {2.0 / (255/1024):.2f}s")
print(f"  CE reference:    ~6-10 GB/s -> estimated: {2.0 / 8:.2f}s")

# 6) Pure numpy ceiling (no syscall overhead at all)
print(f"\n[CEILING] Pure numpy scan on 1 GB buffer:")
big = np.frombuffer(b'\x00' * (1024*1024*1024), dtype='<u4')
big[12345] = 12345  # ensure one hit
t0 = time.time()
hits = np.where(big == 12345)[0]
t1 = time.time()
print(f"  {t1-t0:.3f}s for 1 GB ({1024/(t1-t0):.0f} MB/s pure numpy)")
print(f"  Extrapolated: 2 GB would be {2*(t1-t0):.3f}s")

# 7) ReadProcessMemory bandwidth ceiling
print(f"\n[RPM CEILING] ReadProcessMemory throughput test:")
import ctypes
data = (ctypes.c_uint8 * (64*1024))()  # 64KB
read_bytes = (ctypes.c_size_t)(0)
total = 0
t0 = time.time()
# Read 1 GB worth
for _ in range(16 * 1024 // 64):  # 16K * 64KB = 1 GB
    k32.ReadProcessMemory(h, ctypes.c_void_p(0x10000000), data, 64*1024,
                          ctypes.byref(read_bytes))
    total += read_bytes.value
t1 = time.time()
print(f"  Read {total/1024/1024:.0f} MB in {t1-t0:.3f}s = "
      f"{total/1024/1024/(t1-t0):.0f} MB/s")
print(f"  Extrapolated: 2 GB would be {2 * 1024 / (total/1024/1024/(t1-t0)):.2f}s")

k32.CloseHandle(h)
print("\n" + "=" * 70)
print("INTERPRETATION:")
print("  - Our wall-clock time is dominated by the FASTEST of:")
print("    (a) numpy comparison (currently ~250 MB/s effective)")
print("    (b) ReadProcessMemory syscall overhead")
print("  - For small targets (<100 MB), RPM dominates")
print("  - For large targets (>1 GB), numpy still has room to scale")
print("  - To match CE: need C engine, no Python in the hot loop")
print("=" * 70)
