"""Debug: check what pages are readable"""
import ctypes, ctypes.wintypes as w, struct, os
import memory_scanner as ms

h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

print(f"Allocated: 0x{base1:X}, 0x{base2:X}, 0x{base3:X}")

# Now list all readable pages
pages = list(ms.list_pages(h))
print(f"Total readable pages: {len(pages)}")

# Check if our allocations are in the pages
found1 = any(p[0] <= base1 < p[0] + p[1] for p in pages)
found2 = any(p[0] <= base2 < p[0] + p[1] for p in pages)
found3 = any(p[0] <= base3 < p[0] + p[1] for p in pages)

print(f"base1 in pages: {found1}")
print(f"base2 in pages: {found2}")
print(f"base3 in pages: {found3}")

# Show some pages near our allocations
for p in pages:
    if base1 - 0x10000 <= p[0] <= base1 + 0x10000:
        print(f"  Page near base1: 0x{p[0]:X}-0x{p[0]+p[1]:X} (prot={p[2]})")
        break

ctypes.windll.kernel32.CloseHandle(h)
print("\nDebug done")