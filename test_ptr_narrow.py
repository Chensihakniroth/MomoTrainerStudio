"""
test_ptr_narrow.py - End-to-end test for pointer scan + narrow.

Sets up a chain in our process's memory:
  STATIC_BASE -> +0x10 -> obj_addr -> +0x20 -> target_addr

Then runs a 2-level pointer scan and verifies the chain is found.
Then moves the target to a new address and verifies narrow() keeps the chain.
"""
import ctypes, ctypes.wintypes as w, struct, os, sys
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

    # Step 1: allocate three memory regions
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04

    base_static = ctypes.windll.kernel32.VirtualAlloc(
        None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    base_ptr1 = ctypes.windll.kernel32.VirtualAlloc(
        None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    base_obj = ctypes.windll.kernel32.VirtualAlloc(
        None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    base_target = ctypes.windll.kernel32.VirtualAlloc(
        None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )

    # Choose offsets
    OFF_STATIC_TO_PTR1 = 0x10
    OFF_PTR1_TO_OBJ = 0x20
    OFF_OBJ_TO_TARGET = 0x30

    # Layout: static[0x10] = ptr1; ptr1[0x20] = obj; obj[0x30] = target
    ptr1_addr = (base_ptr1 + 0x100) & 0xFFFFFFFFFFFFFFFF
    obj_addr = (base_obj + 0x100) & 0xFFFFFFFFFFFFFFFF
    target_addr = (base_target + 0x100) & 0xFFFFFFFFFFFFFFFF

    # Write pointers (this process is 64-bit; pointers are 8 bytes)
    wb(base_static + OFF_STATIC_TO_PTR1, struct.pack('<Q', ptr1_addr))
    wb(ptr1_addr + OFF_PTR1_TO_OBJ, struct.pack('<Q', obj_addr))
    wb(obj_addr + OFF_OBJ_TO_TARGET, struct.pack('<Q', target_addr))

    # Put a value at the target so we can verify
    wb(target_addr, struct.pack('<I', 0xDEADBEEF))
    # Add noise - random pointers that should NOT chain to target
    for i in range(50):
        noise_addr = base_static + 0x100 + i * 8
        wb(noise_addr, struct.pack('<Q', base_ptr1 + 0x500 + i * 32))

    print(f"Setup: target at {target_addr:#x}")
    print(f"  Chain: {base_static:#x} +{OFF_STATIC_TO_PTR1:X} -> {ptr1_addr:#x} +{OFF_PTR1_TO_OBJ:X} -> {obj_addr:#x} +{OFF_OBJ_TO_TARGET:X} -> {target_addr:#x}")

    # Step 2: run a 2-level pointer scan
    print("\n--- Running 2-level pointer scan ---")
    ctrl = ms.PointerScanController(h, max_depth=2, max_offset=0x100, no_loop=False)
    results = ctrl.scan(target_addrs=[target_addr], depth=0,
                        progress_cb=lambda w, s, h: None,
                        stop_cb=lambda: False)
    count = results.count()
    print(f"Scan found {count} pointer(s)")

    if count == 0:
        print("FAIL: no pointers found")
        return

    # Step 3: verify the chain
    print("\n--- Chains found ---")
    found_target_chain = False
    for row in results.all_hits():
        base, blob = row
        chain = ctrl._decode_chain(row)
        if not chain:
            continue
        b, offsets = chain
        if b == base_static:
            found_target_chain = True
            # Trace the chain
            cur = b
            for off in offsets:
                raw = rb(cur, 8)
                cur = struct.unpack('<Q', raw)[0] + off
            raw = rb(cur, 4)
            val = struct.unpack('<I', raw)[0]
            print(f"  Chain from {b:#x} + offsets {offsets} -> {cur:#x} = {val:#x}")
            if cur == target_addr and val == 0xDEADBEEF:
                print(f"  CHAIN MATCHES!")

    if not found_target_chain:
        print("  No chain starting at base_static found")
        print(f"  Base addrs in results: {[hex(r[0]) for r in results.all_hits()[:5]]}")

    # Step 4: move target to a new address (simulate heap change)
    new_target = ctypes.windll.kernel32.VirtualAlloc(
        None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    # Update obj[0x30] to point to new target
    wb(obj_addr + OFF_OBJ_TO_TARGET, struct.pack('<Q', new_target))
    wb(new_target, struct.pack('<I', 0xCAFEBABE))

    print(f"\n--- Target moved to {new_target:#x} ---")
    print("Running narrow()...")

    def narrow_progress(w, s, h):
        if s % 500 == 0:
            print(f"  narrow progress: checked={s}, hits={h}", end='\r')
    narrowed = ctrl.narrow([new_target], progress_cb=narrow_progress, stop_cb=lambda: False)
    print(f"\nNarrowed to {narrowed.count()} pointer(s)")

    if narrowed.count() == 0:
        print("FAIL: narrow returned 0 results")
        return

    # Verify the narrowed chain still works
    for row in narrowed.all_hits():
        chain = ctrl._decode_chain(row)
        if not chain:
            continue
        b, offsets = chain
        cur = b
        for off in offsets:
            raw = rb(cur, 8)
            cur = struct.unpack('<Q', raw)[0] + off
        raw = rb(cur, 4)
        val = struct.unpack('<I', raw)[0]
        print(f"  Chain: {b:#x} + {offsets} -> {cur:#x} = {val:#x}")
        if cur == new_target and val == 0xCAFEBABE:
            print(f"  NARROWED CHAIN MATCHES NEW TARGET!")

    ctrl.close()
    print("\n--- Test complete ---")


if __name__ == '__main__':
    main()