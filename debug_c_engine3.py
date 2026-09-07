"""
debug_c_engine3.py — Controlled test: write known value, then scan.
This eliminates the "memory changes" variable.
"""
import ctypes, struct, time, os
import ctypes.wintypes as w

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
k32.VirtualProtect.restype = ctypes.c_bool

mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x1F0FFF, False, mypid)  # PROCESS_ALL_ACCESS

# Write our test value to a known address
# Use a small allocation in this process
import ctypes.wintypes as w

# Allocate a test buffer we control
test_buf = (ctypes.c_uint32 * 10)()  # 10 uint32s
test_addr = ctypes.addressof(test_buf)

# Write 12345 at index 3, zeros elsewhere
for i in range(10):
    test_buf[i] = 0
test_buf[3] = 12345

print(f"Test buffer at 0x{test_addr:X}")
print(f"Value at index 3: {test_buf[3]} (expected 12345)")
print(f"First 10 values: {[test_buf[i] for i in range(10)]}")

# Read back via RPM to verify
verify_buf = (ctypes.c_uint8 * 40)()
rb = ctypes.c_size_t(0)
k32.ReadProcessMemory(h, ctypes.c_void_p(test_addr), verify_buf, 40, ctypes.byref(rb))
print(f"RPM read: {struct.unpack('<10I', verify_buf)}")

# Now scan using C engine
import scan_engine as se

# Create a page list with just our test buffer
test_page = [(test_addr, 40, 0x04)]  # base, size, READABLE

print(f"\nScanning 40 bytes at 0x{test_addr:X} for 12345...")
c_hits = se.fast_scan_uint32(h, 12345, page_list=test_page, nthreads=1, max_results=200_000)
print(f"C engine hits: {c_hits}")

# Also scan with numpy/memory_scanner
import memory_scanner as ms
orig_lp = ms.list_pages
ms.list_pages = lambda h: test_page
np_hits = list(ms.first_scan(h, 'uint32', 12345, mode='exact', nthreads=1, fast_scan=True))
ms.list_pages = orig_lp
print(f"numpy hits: {[(c.addr, c.value) for c in np_hits]}")

# Brute force
print(f"\nBrute force check:")
for i in range(10):
    addr = test_addr + i * 4
    val = struct.unpack('<I', verify_buf[i*4:(i+1)*4])[0]
    if val == 12345:
        print(f"  Found at index {i}, addr 0x{addr:X}, value {val}")

# Also test: scan WITHOUT our buffer — should find 0 hits
print(f"\nScanning garbage address (should be 0 hits):")
c_hits2 = se.fast_scan_uint32(h, 12345, page_list=[(0x1000, 0x1000, 0x04)],
                               nthreads=1, max_results=200_000)
print(f"C engine hits: {c_hits2}")

# And test: all-zeros page — should find 0 hits
import numpy as np
zero_page = np.zeros(4096, dtype='<u4')
zero_addr = zero_page.ctypes.data
zero_prot = ctypes.c_uint32(0)
k32.VirtualProtect(ctypes.c_void_p(zero_addr), 4096, 0x04, ctypes.byref(zero_prot))
print(f"\nScanning zero page at 0x{zero_addr:X}:")
c_hits3 = se.fast_scan_uint32(h, 0, page_list=[(zero_addr, 4096, 0x04)],
                               nthreads=1, max_results=200_000)
print(f"C engine hits: {c_hits3}")

# Hmm wait — zero_page is numpy array, its memory might not be readable by RPM
# Let's just scan the known buffer again
print(f"\nFull summary:")
print(f"  test_buf[3] = {test_buf[3]} (should be 12345)")
print(f"  C hits: {len(c_hits)}")
for hit_addr, hit_val in c_hits:
    print(f"    0x{hit_addr:X} = {hit_val}")
print(f"  numpy hits: {len(np_hits)}")

k32.CloseHandle(h)
