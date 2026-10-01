"""
Simple narrow test - verifies the narrow method works
"""
import ctypes
import memory_scanner as ms
from memory_scanner import FoundList

def test_narrow_method():
    # Create a dummy FoundList with some results
    results = FoundList()
    
    # Add some test entries (slot_addr, blob)
    # Each blob should contain a chain that can be narrowed
    # For simplicity, let's create entries that represent pointers to target values
    
    # Create a test chain: [base, [offset1, offset2, ...]] -> target
    # We'll simulate this by creating entries that would narrow to a target
    
    # Create a test entry
    blob1 = struct.pack('<I', 1) + struct.pack('<I', 0x10) + struct.pack('<I', 0x20)  # 3-level chain
    results.add(0x1000, blob1)
    
    # Another entry that points directly to target
    blob2 = struct.pack('<I', 2) + struct.pack('<I', 0xDEADBEEF)  # Direct hit
    results.add(0x1004, blob2)
    
    print(f"Original results count: {results.count()}")
    
    # Now narrow to target 0xDEADBEEF
    print("Testing narrow method...")
    narrowed = results.narrow([0xDEADBEEF])
    narrowed_count = narrowed.count()
    print(f"Narrowed results count: {narrowed_count}")
    
    if narrowed_count > 0:
        print("SUCCESS: narrow method works!")
        print("Narrowed entries:")
        for i, (addr, blob) in enumerate(narrowed.all_hits()):
            print(f"  {i}: 0x{addr:X} -> {blob.hex()}")
    else:
        print("No results found after narrowing")

if __name__ == '__main__':
    test_narrow_method()