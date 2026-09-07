"""
debug_c_engine.py — figure out why C engine finds more hits than numpy
"""
import ctypes, ctypes.wintypes, struct, time, os
import numpy as np
import memory_scanner as ms
import scan_engine as se

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

pages = list(ms.list_pages(h))
readable = [p for p in pages if p[2] & 0x04]
print(f"Total pages: {len(readable)}")

val = 12345

# 1) Get C hits and numpy hits
c_hits = se.fast_scan_uint32(h, val, nthreads=1, max_results=200_000)
np_hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=1, fast_scan=True))

c_addrs = set(addr for addr, _ in c_hits)
np_addrs = set(c.addr for c in np_hits)
print(f"C found:  {len(c_addrs)} unique addresses")
print(f"numpy:    {len(np_addrs)} unique addresses")
print(f"overlap:  {len(c_addrs & np_addrs)} addresses")
print(f"C-only:   {len(c_addrs - np_addrs)} addresses (in C, not in numpy)")
print(f"np-only:  {len(np_addrs - c_addrs)} addresses (in numpy, not in C)")

# 2) Check a few "C only" addresses manually
c_only_sample = list(c_addrs - np_addrs)[:5]
print(f"\nSample 'C only' addresses:")
for addr in c_only_sample:
    # Read it directly
    buf = (ctypes.c_uint8 * 8)()
    rb = ctypes.c_size_t(0)
    k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, 8, ctypes.byref(rb))
    val_at = struct.unpack('<I', bytes(buf[:4]))[0]
    print(f"  0x{addr:016X}  value=0x{val_at:08X} ({val_at})  matches={val_at == val}")

# 3) Is C scanning pages that numpy skipped?
# list_pages returns all regions with read access. Check if numpy's list_pages is filtered.
def list_pages_like_c(h):
    """Return the same kind of list that scan_engine uses."""
    return [(int(base), int(psize)) for base, psize, prot in readable]

# Manually scan a single page with both engines
print(f"\nSingle-page test (page 0):")
base0, psize0, prot0 = readable[0]
print(f"  page: base=0x{base0:X} size={psize0}")

# Scan only this page with C
c_hits_p0 = se.fast_scan_uint32(h, val, page_list=[(base0, psize0, prot0)],
                                  nthreads=1, max_results=200_000)
print(f"  C found {len(c_hits_p0)} hits on page 0")

# Scan only this page with numpy
# Patch list_pages to return only this one
orig_list_pages = ms.list_pages
ms.list_pages = lambda h_iter: [(base0, psize0, prot0)]
np_hits_p0 = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=1, fast_scan=True))
ms.list_pages = orig_list_pages
print(f"  numpy found {len(np_hits_p0)} hits on page 0")

# 4) What does numpy do differently? Check the chunk size
print(f"\nmemory_scanner DEFAULT_CHUNK = {ms.DEFAULT_CHUNK}")
print(f"memory_scanner overlap = ?")

# 5) The issue is likely that numpy's `frombuffer` trims to multiple of nlen=4.
# C doesn't trim, so it scans 3 extra bytes at the end of each chunk.
# For pages with size NOT a multiple of 4, the last 1-3 bytes are scanned by C but not numpy.

# 6) Real test: does C correctly read 1.5 GB in < 1 second?
total_bytes = sum(p[1] for p in readable)
print(f"\n[REAL WORKLOAD] {total_bytes/1024/1024:.0f} MB in 1 thread: ")
t0 = time.time()
hits = se.fast_scan_uint32(h, val, nthreads=1, max_results=200_000)
t1 = time.time()
print(f"  C 1-thread: {t1-t0:.3f}s for {len(hits)} hits ({total_bytes/1024/1024/(t1-t0):.0f} MB/s)")

k32.CloseHandle(h)
