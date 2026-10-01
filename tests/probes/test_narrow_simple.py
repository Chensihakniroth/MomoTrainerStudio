"""
test_narrow_simple.py - Test the new narrow method with DummyGame
"""
import ctypes, ctypes.wintypes as w, struct, os, sys, time
import memory_scanner as ms


def main():
    # Open DummyGame if it's running, else start it
    proc_name = "DummyGame.exe"
    pid = None
    
    # Try to find existing process
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == proc_name:
            pid = proc.info['pid']
            break
    
    if pid is None:
        print("Starting DummyGame...")
        # Start DummyGame in background
        subprocess.Popen([sys.executable, "DummyGame.py"], 
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
        time.sleep(2)  # Give it time to start
        
        # Find the PID
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == proc_name:
                pid = proc.info['pid']
                break
    
    if pid is None:
        print("Could not find or start DummyGame")
        return
        
    print(f"Found DummyGame PID: {pid}")
    
    # Open process with read/write access
    h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return
        
    print("Opened process successfully")
    
    # Allocate some test memory to create a pointer chain
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04
    
    # Allocate three chunks
    base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    
    print(f"Allocated memory at: 0x{base1:X}, 0x{base2:X}, 0x{base3:X}")
    
    # Create a chain: base1[0x100] = base2, base2[0x200] = base3, base3[0x300] = 0xDEADBEEF
    ptr1_addr = base1 + 0x100
    ptr2_addr = base2 + 0x200
    target_addr = base3 + 0x300
    
    # Write the pointers
    wb = lambda addr, data: ctypes.windll.kernel32.WriteProcessMemory(h, addr, data, len(data), ctypes.byref(ctypes.c_size_t()))
    rb = lambda addr, n: (ctypes.c_uint8 * n)() if not ctypes.windll.kernel32.ReadProcessMemory(h, addr, (ctypes.c_uint8 * n)(), n, ctypes.byref(ctypes.c_size_t())) else (ctypes.c_uint8 * n)()
    
    wb(ptr1_addr, struct.pack('<Q', ptr2_addr))
    wb(ptr2_addr, struct.pack('<Q', target_addr))
    wb(target_addr, struct.pack('<I', 0xDEADBEEF))
    
    print(f"Created chain: 0x{base1:X}+0x100 -> 0x{ptr2_addr:X} -> 0x{ptr2_addr:X}+0x200 -> 0x{target_addr:X} -> 0x{target_addr:X}+0x300 = 0xDEADBEEF")
    
    # Now run a 3-level pointer scan for the target value 0xDEADBEEF
    print("\n=== Running 3-level pointer scan for value 0xDEADBEEF ===")
    ctrl = ms.PointerScanController(h, max_depth=3, max_offset=0x1000)
    
    results = ctrl.scan([0xDEADBEEF], depth=0)
    count = results.count()
    print(f"Initial scan found {count} pointers")
    
    if count == 0:
        print("No pointers found - trying again with different settings...")
        ctrl = ms.PointerScanController(h, max_depth=3, max_offset=0x10000)
        results = ctrl.scan([0xDEADBEEF], depth=0)
        count = results.count()
        print(f"Scan with larger offset found {count} pointers")
    
    # Show first few results
    if count > 0:
        print("\nFirst 5 results:")
        hits = results.all_hits()[:5]
        for i, (addr, blob) in enumerate(hits):
            print(f"  {i+1}. 0x{addr:X} -> {blob.hex()}")
    
    # Now simulate the target moving by changing the value at target_addr
    print("\n=== Simulating heap change (moving target) ===")
    new_target_addr = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    print(f"Moved target to: 0x{new_target_addr:X}")
    
    # Update the chain to point to new target
    wb(ptr2_addr, struct.pack('<Q', new_target_addr))
    wb(new_target_addr + 0x300, struct.pack('<I', 0xCAFEBABE))
    
    print(f"Updated chain: ... -> 0x{new_target_addr:X}+0x300 = 0xCAFEBABE")
    
    # Now narrow the results to find which chains still point to valid targets
    print("\n=== Narrowing results to chains pointing to 0xCAFEBABE ===")
    narrowed = ctrl.narrow([0xCAFEBABE])
    narrowed_count = narrowed.count()
    print(f"After narrow: {narrowed_count} pointers still valid")
    
    if narrowed_count > 0:
        print("\nFirst 3 narrowed results:")
        hits = narrowed.all_hits()[:3]
        for i, (addr, blob) in enumerate(hits):
            print(f"  {i+1}. 0x{addr:X} -> {blob.hex()}")
    
    # Cleanup
    ctrl.close()
    ctypes.windll.kernel32.CloseHandle(h)
    print("\nTest complete!")


if __name__ == '__main__':
    main()