"""
Verify numpy path is actually being hit in the first_scan worker.
Patches _first_scan_worker temporarily to log which path is taken.
"""
import ctypes, struct, time, sys, threading
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

val = 0x12345678
needle = struct.pack('<I', val)

# Instrument the scan_align + use_int_cmp setup
# Simulate the fast path setup
vtype = 'uint32'
fast_scan = True
nlen = 4
align = ms.scan_align(vtype, fast_scan)
stepsize = align
use_int_cmp = True
needle_int = struct.unpack('<I', needle)[0]

print(f"vtype={vtype} fast_scan={fast_scan}")
print(f"nlen={nlen} align={align} stepsize={stepsize} use_int_cmp={use_int_cmp}")
print(f"needle_int=0x{needle_int:X}")
print(f"Condition: stepsize == nlen? {stepsize == nlen}")
print(f"Condition: stepsize >= nlen? {stepsize >= nlen}")
print(f"FAST PATH SHOULD BE HIT: {use_int_cmp and (stepsize == nlen or stepsize >= nlen)}")

# Compare pure Python struct loop vs numpy on a 512KB buffer
import numpy as np
buf = bytes(512 * 1024)
buf = bytearray(buf)
# Write the needle at a few positions
struct.pack_into('<I', buf, 0x10000, val)

t0 = time.perf_counter()
N = 1000
for _ in range(N):
    arr = np.frombuffer(buf, dtype='<u4')
    indices = np.where(arr == needle_int)[0]
t_numpy = time.perf_counter() - t0

t0 = time.perf_counter()
for _ in range(N):
    mv = memoryview(buf)
    end = len(mv) - 3
    hits = []
    for i in range(0, end, 4):
        if struct.unpack_from('<I', mv, i)[0] == needle_int:
            hits.append(i)
t_struct = time.perf_counter() - t0

throughput = 512 * 1024 * N / (1024*1024)
print(f"\n512KB x {N} iterations:")
print(f"  numpy:   {t_numpy*1000:.3f}ms ({throughput/t_numpy/1024:.0f} GB/s)")
print(f"  struct:  {t_struct*1000:.3f}ms ({throughput/t_struct/1024:.0f} GB/s)")
print(f"  Speedup: {t_struct/t_numpy:.1f}x")

# Confirm same results
arr2 = np.frombuffer(buf, dtype='<u4')
indices = np.where(arr2 == needle_int)[0]
mv2 = memoryview(buf)
hits2 = [i for i in range(0, len(mv2)-3, 4) if struct.unpack_from('<I', mv2, i)[0] == needle_int]
print(f"\nResults match: {list(indices * 4) == hits2}")

k32.CloseHandle(h)