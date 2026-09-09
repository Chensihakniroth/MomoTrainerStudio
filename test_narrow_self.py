"""
test_narrow_self.py - Test the new narrow method using self-process memory.
No external process needed - uses our own process.
"""
import ctypes, ctypes.wintypes as w, struct, os, sys, time
import memory_scanner as ms


def main():
    h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return

    def rb(addr, n):
        buf = (ctypes.c_uint8 * n)()
        g = ctypes.c_size_t(0)
        if not ctypes.windll.kernel32.ReadProcessMemory(h, addr, buf, n, ctypes.byref(g)) or g.value != n:
            return None
        return bytes(buf)

    def wb(addr, data):
        buf = (ctypes.c_uint8 * len(data))(*data)
        g = ctypes.c_size_t(0)
        return ctypes.windll.kernel32.WriteProcessMemory(h, addr, buf, len(data), ctypes.byref(g))

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04

    base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

    print(f"Allocated: 0x{base1:X}, 0x{base2:X}, 0x{base3:X}")

    ptr1_addr = base1 + 0x100
    ptr2_addr = base2 + 0x200
    target_addr = base3 + 0x300

    # Create chain: base1[0x100] -> base2[0x200] -> base3[0x300] -> 0xDEADBEEF
    wb(ptr1_addr, struct.pack('<Q', ptr2_addr))
    wb(ptr2_addr, struct.pack('<Q', target_addr))
    wb(target_addr, struct.pack('<I', 0xDEADBEEF))

    print(f"Chain: 0x{base1:X}+0x100 -> 0x{ptr2_addr:X} -> 0x{ptr2_addr:X}+0x200 -> 0x{target_addr:X} -> 0x{target_addr:X}+0x300 = 0xDEADBEEF")

    # Run pointer scan for 0xDEADBEEF
    print("\n=== Running 3-level pointer scan for 0xDEADBEEF ===")
    ctrl = ms.PointerScanController(h, max_depth=3, max_offset=0x10000)

    results = ctrl.scan([0xDEADBEEF], depth=0)
    count = results.count()
    print(f"Initial scan found {count} pointers")

    if count > 0:
        print("First 3 results:")
        for i, (addr, blob) in enumerate(results.all_hits()[:3]):
            print(f"  {i+1}. 0x{addr:X} -> {blob.hex()}")

    # Simulate heap change - move target to new address
    print("\n=== Simulating heap change ===")
    new_target_addr = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    print(f"Moved target to: 0x{new_target_addr:X}")

    # Update chain to point to new target
    wb(ptr2_addr, struct.pack('<Q', new_target_addr))
    wb(new_target_addr + 0x300, struct.pack('<I', 0xCAFEBABE))

    print(f"Updated chain: ... -> 0x{new_target_addr:X}+0x300 = 0xCAFEBABE")

    # Now narrow
    print("\n=== Narrowing results to chains pointing to 0xCAFEBABE ===")
    narrowed = ctrl.narrow([0xCAFEBABE])
    narrowed_count = narrowed.count()
    print(f"After narrow: {narrowed_count} pointers still valid")

    if narrowed_count > 0:
        print("First 3 narrowed results:")
        for i, (addr, blob) in enumerate(narrowed.all_hits()[:3]):
            print(f"  {i+1}. 0x{addr:X} -> {blob.hex()}")

    ctrl.close()
    ctypes.windll.kernel32.CloseHandle(h)
    print("\nTest complete!")


if __name__ == '__main__':
    main()