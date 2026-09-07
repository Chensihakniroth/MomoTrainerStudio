"""
End-to-end scan test against this Python process (simulates dist behavior).
Tests: list_pages -> first_scan -> rescan -> write -> rescan changed.
"""
import ctypes, ctypes.wintypes, struct, time, sys
k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.wintypes.LPVOID

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, mypid)
print(f"My PID={mypid} handle={h}")
if not h:
    print(f"FAIL: OpenProcess err={ctypes.get_last_error()}"); sys.exit(1)

import memory_scanner as ms

pages = list(ms.list_pages(h))
print(f"Total pages: {len(pages)}")

from collections import Counter
prot_counts = Counter()
for p in pages:
    prot = p[2]  # tuple is (base, size, protect)
    names = []
    if prot & 0x04: names.append('R')
    if prot & 0x02: names.append('W')
    if prot & 0x10: names.append('X')
    prot_counts['+'.join(names) if names else 'NONE'] += 1
for k, v in sorted(prot_counts.items()):
    print(f"  {k}: {v}")

rw = [p for p in pages if p[2] & 0x04]  # readable — tuple is (base, size, protect)
print(f"\nReadable pages: {len(rw)}")

if not rw:
    print("FAIL: No readable pages!")
    k32.CloseHandle(h)
    sys.exit(1)

# Write marker to first readable page
base = rw[0][0] + 0x200
val = 0x12345678
buf = struct.pack('<I', val)
ok = ms.wblock(h, base, buf)
err = ctypes.get_last_error()
print(f"wblock(0x{base:X}, 0x{val:X}): ok={ok}, err={err}")

if not ok:
    if err == 5: print("  NOTE: err=5 ACCESS_DENIED (UAC/admin required for self-write)")
    if err == 998: print("  NOTE: err=998 NOACCESS (page read-only, VirtualProtectEx unlock needed)")
    print("WARNING: Cannot write to process memory.")
    print("This is the bug - wblock needs VirtualProtectEx to unlock read-only pages.")
    k32.CloseHandle(h)
    # Still try fast scan on read-only pages
    print(f"\nfirst_scan for 0x{val:X} (read-only)...")
    hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=4))
    print(f"  {len(hits)} candidates (0 expected since no writable memory)")
    k32.CloseHandle(h)
    sys.exit(0)

# Read back
data = ms.rblock(h, base, 4)
print(f"rblock: {data.hex() if data else 'None'}")

# FAST scan (aligned only, same as GUI)
print(f"\nfirst_scan (fast/aligned) for 0x{val:X}...")
t0 = time.time()
hits = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=4))
t1 = time.time()
print(f"  {len(hits)} candidates in {t1-t0:.2f}s")

# Full scan (all offsets)
print(f"\nfirst_scan (full/all offsets) for 0x{val:X}...")
t0 = time.time()
hits2 = list(ms.first_scan(h, 'uint32', val, mode='exact', nthreads=4, fast_scan=False))
t1 = time.time()
print(f"  {len(hits2)} candidates in {t1-t0:.2f}s")

found = [h for h in hits if h.addr == base]
found2 = [h for h in hits2 if h.addr == base]
print(f"  Found marker (fast): {bool(found)}")
print(f"  Found marker (full): {bool(found2)}")

if not found:
    print("\nBUG: Fast scan missed our marker!")
    print("This is why GUI returns 0 results - fast_scan=True skips unaligned hits.")
else:
    # Rescan equal
    res = list(ms.rescan(h, hits, 'uint32', val, mode='exact', nthreads=4))
    print(f"\nrescan exact: {len(res)} matches")

    # Scan for different (should be less than total)
    res2 = list(ms.rescan(h, hits, 'uint32', val, mode='notEqual', nthreads=4))
    print(f"rescan notEqual: {len(res2)} matches (< {len(hits)})")

    # Write new value
    new_val = 0xDEADBEEF
    ok2 = ms.wblock(h, base, struct.pack('<I', new_val))
    print(f"\nwblock(0x{base:X}, 0x{new_val:X}): ok={ok2}")

    # Rescan for new value
    res3 = list(ms.rescan(h, hits, 'uint32', new_val, mode='exact', nthreads=4))
    print(f"rescan 0x{new_val:X}: {len(res3)} matches")
    print(f"  Marker in res3: {base in {h.addr for h in res3}}")

    # Restore
    ms.wblock(h, base, buf)
    print(f"  Restored -> 0x{val:X}")

k32.CloseHandle(h)
print("\n=== E2E TEST COMPLETE ===")
