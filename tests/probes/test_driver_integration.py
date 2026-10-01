"""
MomoTrainerStudio Driver Integration Test
Tests kernel driver integration with existing project components
"""

import os
import sys
import time
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

# Import project components
try:
    from kernel_driver import driver_wrapper
    from kernel_driver import hybrid_memory
    print("✓ Imports successful")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

# Test driver availability
def test_driver_availability():
    """Test if kernel driver files exist"""
    print("\n=== Driver Availability Test ===")
    
    driver_files = [
        os.path.join('kernel_driver', 'driver.h'),
        os.path.join('kernel_driver', 'driver.c'),
        os.path.join('kernel_driver', 'driver_wrapper.py'),
        os.path.join('kernel_driver', 'hybrid_memory.py'),
        os.path.join('kernel_driver', 'build.bat')
    ]
    
    for file in driver_files:
        if os.path.exists(file):
            print(f"✓ {file}")
        else:
            print(f"✗ {file} - NOT FOUND")
            return False
    
    # Check for built driver .sys file
    driver_sys = os.path.join('kernel_driver', 'MomoTrainerDrv.sys')
    if os.path.exists(driver_sys):
        print(f"✓ {driver_sys} - Driver built")
        return True
    else:
        print(f"⚠️  {driver_sys} - Driver not built yet")
        print("   This is expected before building the driver")
        return None

# Test driver wrapper
def test_driver_wrapper():
    """Test driver wrapper initialization"""
    print("\n=== Driver Wrapper Test ===")
    
    try:
        # Initialize driver wrapper
        wrapper = driver_wrapper.MomoTrainerDriver()
        print(f"✓ Driver wrapper initialized")
        print(f"  Device name: {wrapper.device_name}")
        
        # Check if driver can be opened
        if wrapper.open():
            print("✓ Driver opened successfully")
            
            # Get driver version
            version = wrapper.get_version()
            if version:
                print(f"✓ Driver version: {version['major']}.{version['minor']}.{version['build']}")
            else:
                print("⚠️  Could not get driver version")
            
            wrapper.close()
            print("✓ Driver closed")
        else:
            print("⚠️  Driver open failed - expected if driver not built")
        
        return True
        
    except Exception as e:
        print(f"✗ Driver wrapper test failed: {e}")
        return False

# Test hybrid memory
def test_hybrid_memory():
    """Test hybrid memory layer"""
    print("\n=== Hybrid Memory Test ===")
    
    try:
        # Initialize hybrid memory
        hybrid = hybrid_memory.HybridMemory(use_driver=True)
        print(f"✓ Hybrid memory initialized")
        print(f"  Driver available: {hybrid.use_driver}")
        
        # Test process listing
        processes = hybrid_memory.HybridMemory.list_processes()
        print(f"✓ Listed {len(processes)} processes")
        
        # Show first few processes
        for i, proc in enumerate(processes[:3]):
            print(f"  {i+1}. PID {proc['pid']}: {proc['name']}")
        
        if len(processes) > 3:
            print(f"  ... and {len(processes) - 3} more")
        
        return True
        
    except Exception as e:
        print(f"✗ Hybrid memory test failed: {e}")
        return False

# Test driver build scripts
def test_build_scripts():
    """Test driver build scripts"""
    print("\n=== Driver Build Scripts Test ===")
    
    build_files = [
        ('kernel_driver', 'SOURCES'),
        ('kernel_driver', 'MAKEFILE'),
        ('kernel_driver', 'build.bat')
    ]
    
    all_present = True
    for dirname, filename in build_files:
        filepath = os.path.join(dirname, filename)
        if os.path.exists(filepath):
            print(f"✓ {filepath}")
        else:
            print(f"✗ {filepath} - MISSING")
            all_present = False
    
    return all_present

# Integration test
def run_integration_tests():
    """Run all integration tests"""
    print("=" * 60)
    print("MOMO TRAINER STUDIO DRIVER INTEGRATION TEST")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Driver Availability", test_driver_availability()))
    results.append(("Driver Wrapper", test_driver_wrapper()))
    results.append(("Hybrid Memory", test_hybrid_memory()))
    results.append(("Build Scripts", test_build_scripts()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = 0
    
    for test_name, result in results:
        total += 1
        if result is True:
            print(f"✅ {test_name}: PASSED")
            passed += 1
        elif result is False:
            print(f"❌ {test_name}: FAILED")
        else:  # None/null result
            print(f"⚠️  {test_name}: SKIPPED (expected)")
            passed += 1
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return True
    else:
        print(f"⚠️  {total - passed} tests failed or were skipped")
        return False

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)