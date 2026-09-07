"""Debug: why full scan finds 0 but fast scan finds 12."""
import ctypes, ctypes.wintypes, struct, time, sys
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)

import memory_scanner as ms

pages = list(ms.list_pages(h))
rw = [p for p in pages if p[2] & 0x04]
base = rw[0][0] + 0x200
val = 0x12345678
buf = struct.pack('<I', val)
ms.wblock(h, base, buf)

verify = ms.rblock(h, base, 4)
print(f"Value at 0x{base:X}: {verify.hex()} (expected {buf.hex()})")

needle = ms.pack_value('uint32', val)
print(f"pack_value('uint32', 0x{val:X}) = {needle.hex()}")
print(f"needle == buf: {needle == buf}")

print(f"\nscan_align('uint32', False) = {ms.scan_align('uint32', False)}")
print(f"scan_align('uint32', True) = {ms.scan_align('uint32', True)}")

# Test: what does the full scan see?
# Manually replicate what _first_scan_worker does for the marker page
for pbase, psize, prot in rw:
    if pbase <= base < pbase + psize:
        print(f"\nMarker is in page 0x{pbase:X} size=0x{psize:X} prot=0x{prot:X}")
        # Read the whole page
        page_data = ms.rblock(h, pbase, psize)
        if page_data:
            # Check at exact marker offset
            off = base - pbase
            print(f"  Offset in page: 0x{off:X}")
            print(f"  Bytes at marker: {page_data[off:off+4].hex()}")
            print(f"  Match: {page_data[off:off+4] == needle}")
            # Check if needle appears anywhere in page
            idx = page_data.find(needle)
            print(f"  First occurrence of needle in page: {idx} (0x{pbase+idx:X})")
        break

print("\n--- Full scan (fast_scan=False) ---")
t0 = time.time()
hits_full = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=4, fast_scan=False))
t1 = time.time()
print(f"  {len(hits_full)} candidates in {t1-t0:.2f}s")
for cand in hits_full[:5]:
    print(f"    0x{cand.addr:X}")

print("\n--- Fast scan (fast_scan=True) ---")
t0 = time.time()
hits_fast = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=4, fast_scan=True))
t1 = time.time()
print(f"  {len(hits_fast)} candidates in {t1-t0:.2f}s")
for cand in hits_fast[:5]:
    print(f"    0x{cand.addr:X}")

print(f"\nMarker in fast: {any(c.addr == base for c in hits_fast)}")
print(f"Marker in full: {any(c.addr == base for c in hits_full)}")