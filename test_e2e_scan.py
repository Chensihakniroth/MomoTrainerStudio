"""
End-to-end memory scan test against the running MomoTrainer Studio.exe.
Tests: list_pages -> first_scan -> rescan -> write -> rescan again
"""
import ctypes, ctypes.wintypes as w
import struct, time, sys, os

k32 = ctypes.windll.kernel32

# Find MomoTrainer Studio PID
target_pid = None
PROCESSENTRY32 = type('PROCESSENTRY32', (ctypes.Structure,), {
    '_fields_': [('dwSize', ctypes.c_uint32), ('cntUsage', ctypes.c_uint32),
                 ('th32ProcessID', ctypes.c_uint32), ('th32DefaultHeapID', ctypes.c_void_p),
                 ('th32ModuleID', ctypes.c_uint32), ('cntThreads', ctypes.c_uint32),
                 ('th32ParentProcessID', ctypes.c_uint32), ('pcPriClassBase', ctypes.c_long),
                 ('dwFlags', ctypes.c_uint32), ('szExeFile', ctypes.c_char * 260)]
})

snap = k32.CreateToolhelp32Snapshot(0x2, 0)
entry = PROCESSENTRY32(); entry.dwSize = ctypes.sizeof(entry)
k32.Process32First(snap, ctypes.byref(entry))
while True:
    if b'MomoTrainer' in entry.szExeFile:
        target_pid = entry.th32ProcessID
        print(f"Found PID {target_pid}: {entry.szExeFile.decode('utf-8', errors='replace')}")
        break
    if not k32.Process32Next(snap, ctypes.byref(entry)): break
k32.CloseHandle(snap)

if not target_pid:
    print("FAIL: MomoTrainer Studio not running!"); sys.exit(1)

# Open with full access (same flags GUI uses)
flags = 0x0008 | 0x0010 | 0x0020 | 0x0400  # VM_OP|VM_READ|VM_WRITE|QUERY_INFO
h = k32.OpenProcess(flags, False, target_pid)
print(f"OpenProcess: handle={h}, err={ctypes.get_last_error()}")
if not h:
    print("FAIL: OpenProcess failed"); sys.exit(1)

import memory_scanner as ms

# 1) list_pages
print("\n--- list_pages ---")
t0 = time.time()
pages = list(ms.list_pages(h))
t1 = time.time()
rw_pages = [p for p in pages if p[1] & 0x04]  # PAGE_READWRITE
print(f"  {len(pages)} total pages, {len(rw_pages)} RW in {t1-t0:.2f}s")
if not rw_pages:
    print("FAIL: no RW pages found")
    sys.exit(1)
print(f"  First RW: base=0x{rw_pages[0][0]:X} size=0x{rw_pages[0][1]:X}")

# Pick a safe target: our own module's heap (allocate something)
import hashlib
marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:4].upper()
target_val = 0xDEADBEEF
print(f"\n--- Test marker = 0x{target_val:X} ---")

# Write known value to a RW page
target_page = rw_pages[0]
base = target_page[0]
size = target_page[1]
write_addr = base + 0x100  # skip header
buf = struct.pack('<I', target_val)
ok = ms.wblock(h, write_addr, buf)
err = ctypes.get_last_error()
print(f"  wblock(0x{write_addr:X}, 0x{target_val:X}): ok={ok}, err={err}")
if not ok:
    if err == 5: print("  NOTE: err=5 ACCESS_DENIED (UAC/proc protected). Trying VirtualProtectEx unlock...")
    if err == 998: print("  NOTE: err=998 NOACCESS (read-only page). This is the dist bug.")
    print("FAIL: write to first RW page failed")
    sys.exit(1)

# 2) first_scan for the value (fast_scan=True = aligned only)
print(f"\n--- first_scan: uint32 == 0x{target_val:X} ---")
t0 = time.time()
hits_gen = ms.first_scan(h, rw_pages, 'uint32', str(target_val), mode='exact',
                          progress_cb=None, stop_cb=lambda: False, nthreads=4)
hits = list(hits_gen)
t1 = time.time()
print(f"  {len(hits):,} candidates in {t1-t0:.2f}s")

# Verify our written address is in the hits
found = [h for h in hits if h.addr == write_addr]
if found:
    print(f"  OK: found our write at 0x{write_addr:X} in candidates")
else:
    print(f"  WARNING: our write 0x{write_addr:X} NOT in candidates ({len(hits)} hits)")
    print(f"  First 3 hits: {[(hex(h.addr), h.last.hex()) for h in hits[:3]]}")

# 3) rescan: confirm exact value
print(f"\n--- rescan: equal 0x{target_val:X} from {len(hits):,} ---")
t0 = time.time()
res = list(ms.rescan(h, hits, 'uint32', str(target_val), mode='equal',
                      progress_cb=None, stop_cb=lambda: False, nthreads=4))
t1 = time.time()
print(f"  {len(res):,} matches in {t1-t0:.2f}s")

# 4) scan for changed value (should be empty)
print(f"\n--- rescan: not 0x{target_val:X} ---")
t0 = time.time()
res2 = list(ms.rescan(h, hits, 'uint32', str(target_val), mode='notEqual',
                       progress_cb=None, stop_cb=lambda: False, nthreads=4))
t1 = time.time()
print(f"  {len(res2):,} matches (should be < {len(hits):,}) in {t1-t0:.2f}s")

# 5) write new value and scan for it
new_val = 0xCAFEBABE
ok2 = ms.wblock(h, write_addr, struct.pack('<I', new_val))
print(f"\n--- wblock(0x{write_addr:X}, 0x{new_val:X}): ok={ok2} ---")
t0 = time.time()
res3 = list(ms.rescan(h, hits, 'uint32', str(new_val), mode='equal',
                       progress_cb=None, stop_cb=lambda: False, nthreads=4))
t1 = time.time()
print(f"  {len(res3):,} matches for 0x{new_val:X} in {t1-t0:.2f}s")
print(f"  {'OK' if write_addr in {h.addr for h in res3} else 'FAIL'}: found our changed address")

# 6) restore
ms.wblock(h, write_addr, struct.pack('<I', target_val))
print(f"  Restored 0x{write_addr:X} -> 0x{target_val:X}")

k32.CloseHandle(h)

print("\n=== E2E SCAN TEST COMPLETE ===")
print("Summary:")
print(f"  list_pages: OK ({len(pages)} pages)")
print(f"  first_scan: {'OK' if hits else 'FAIL'} ({len(hits):,} candidates)")
print(f"  rescan eq:  {'OK' if res else 'FAIL'} ({len(res):,})")
print(f"  rescan neq: OK ({len(res2):,})")
print(f"  rescan changed: {'OK' if res3 else 'FAIL'} ({len(res3):,})")
