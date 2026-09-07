"""
Instrument the actual first_scan to find where the 450ms goes.
Patches memory_scanner to add timing at each phase.
"""
import ctypes, struct, time, sys, threading
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

# Patch rblock_fast to instrument it
_orig_rblock_fast = ms.rblock_fast
_rpm_times = []
def timed_rblock_fast(h, addr, n):
    t0 = time.perf_counter()
    r = _orig_rblock_fast(h, addr, n)
    _rpm_times.append(time.perf_counter() - t0)
    return r
ms.rblock_fast = timed_rblock_fast

# Patch FoundList.add to instrument it
_orig_add = None
_store_times = []
_orig_foundlist_init = ms.FoundList.__init__
def timed_foundlist_init(self, *args, **kwargs):
    _orig_foundlist_init(self, *args, **kwargs)
    self._add_times = []
_orig_add_orig = ms.FoundList.add
def timed_add(self, addr, last):
    t0 = time.perf_counter()
    _orig_add_orig(self, addr, last)
    self._add_times.append(time.perf_counter() - t0)
ms.FoundList.add = timed_add

# Patch the comparison loop too (indirectly via numpy import)
# Actually, let's patch numpy call overhead
_np_times = []
_orig_np_where = None

# Just measure full scan timing and compare to breakdown expectations
val = 0x12345678

print("Running first_scan (fast, 1 thread)...")
t0 = time.perf_counter()
hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=1, fast_scan=True))
t1 = time.perf_counter()
total = t1 - t0

print(f"\nActual first_scan: {total*1000:.1f}ms for {len(hits)} hits")
print(f"RPM calls: {len(_rpm_times)}")
if _rpm_times:
    print(f"RPM time: {sum(_rpm_times)*1000:.2f}ms ({sum(_rpm_times)/total*100:.1f}% of total)")
    print(f"  Per-call avg: {sum(_rpm_times)/len(_rpm_times)*1000:.4f}ms")
    print(f"  Max: {max(_rpm_times)*1000:.4f}ms")
    print(f"  Min: {min(_rpm_times)*1000:.4f}ms")

# How much of wall-clock is RPM?
if _rpm_times:
    non_rpm = total - sum(_rpm_times)
    print(f"\nWall-clock breakdown:")
    print(f"  RPM: {sum(_rpm_times)*1000:.1f}ms ({sum(_rpm_times)/total*100:.1f}%)")
    print(f"  Everything else: {non_rpm*1000:.1f}ms ({non_rpm/total*100:.1f}%)")

k32.CloseHandle(h)