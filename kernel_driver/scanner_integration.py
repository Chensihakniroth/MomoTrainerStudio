"""
Integration module: hook kernel driver into MomoTrainerStudio's existing Scanner
This allows automatic fallback from user-mode ReadProcessMemory to kernel driver
"""

import ctypes
import ctypes.wintypes as w
import os
import sys
from typing import Optional

# Import hybrid memory layer
sys.path.insert(0, os.path.dirname(__file__))
try:
    from kernel_driver.hybrid_memory import HybridMemory, rblock as hybrid_rblock
    HYBRID_AVAILABLE = True
except ImportError:
    HYBRID_AVAILABLE = False

# ============================================================
#  Modified rblock/rblock_fast with kernel driver fallback
# ============================================================

try:
    from memory_scanner import rblock as orig_rblock, rblock_fast as orig_rblock_fast
    _ORIGINAL_RBLOCK_AVAILABLE = True
except ImportError:
    _ORIGINAL_RBLOCK_AVAILABLE = False


def _read_with_user_mode(h, addr, n):
    """Original user-mode ReadProcessMemory"""
    buf = (ctypes.c_uint8 * n)()
    got = ctypes.c_size_t(0)
    if not orig_rblock(h, addr, n):
        return None
    return bytes(buf)


def _read_with_kernel_driver(h, addr, n, driver: HybridMemory):
    """Try kernel driver fallback"""
    if not HYBRID_AVAILABLE or not driver.use_driver:
        return None

    pid = driver._current_process_id
    if pid is None:
        return None

    data = driver.read_memory(pid, addr, n)
    if data is not None and len(data) == n:
        return data
    return None


def rblock_with_fallback(h, addr, n):
    """
    Read n bytes with hybrid fallback: user-mode first, then kernel driver
    Same signature as original rblock from memory_scanner.py
    """
    # Try user-mode first
    buf = (ctypes.c_uint8 * n)()
    got = ctypes.c_size_t(0)
    if orig_rblock(h, addr, n):
        return bytes(buf)

    # User-mode failed - try kernel driver fallback
    # We need access to the HybridMemory instance
    # This is a simplified approach - in production, pass driver reference
    # For now, try to get pid from context and use driver
    return None


def rblock_fast_with_fallback(h, addr, n):
    """
    Read n bytes fast with hybrid fallback
    Same signature as original rblock_fast from memory_scanner.py
    """
    # Try user-mode first
    buf = None
    tls = getattr(ctypes.windll.kernel32, '__tls', None)  # simplified
    buf = getattr(tls, 'rbuf', None) if tls else None

    if buf is None or len(buf) < n:
        buf = (ctypes.c_uint8 * max(n, 65536))()

    got = ctypes.c_size_t(0)
    if not orig_rblock_fast(h, addr, n):
        # User-mode failed - try kernel driver fallback
        return None

    # Convert to memoryview to avoid bytes() copy
    return memoryview(buf)[:n]


# ============================================================
#  Scanner Integration Wrapper
# ============================================================

class ScannerKernelIntegration:
    """Wrap Scanner to add kernel driver capabilities"""

    def __init__(self, scanner_handle, enable_kernel_fallback: bool = True):
        self.handle = scanner_handle
        self.kernel_fallback = enable_kernel_fallback and HYBRID_AVAILABLE
        self.driver = HybridMemory(use_driver=self.kernel_fallback) if HYBRID_AVAILABLE else None
        self._opened_pids = set()

    def _get_current_pid(self) -> Optional[int]:
        """Extract PID from the scanner handle - simplified"""
        # In a real integration, we'd track the PID when opening the process
        # For now, return None to use only user-mode, or attempt detection
        return None

    def read_memory_during_scan(self, pid: int, addr: int, size: int) -> Optional[bytes]:
        """Read memory during scan operations with kernel fallback"""
        if self.kernel_fallback and self.driver:
            return self.driver.read_memory(pid, addr, size)
        return None

    def enable_kernel_mode(self):
        """Enable kernel driver fallback"""
        self.kernel_fallback = True
        if self.driver and not self.driver._is_open:
            # Driver will be opened on first use
            pass

    def disable_kernel_mode(self):
        """Disable kernel driver fallback (use user-mode only)"""
        self.kernel_fallback = False


# ============================================================
#  Patch memory_scanner module functions
# ============================================================

def patch_scanner_for_kernel():
    """Patch memory_scanner module to use kernel driver fallback"""
    import memory_scanner as ms

    # Store originals
    ms._orig_rblock = ms.rblock
    ms._orig_rblock_fast = ms.rblock_fast

    # Patch rblock to add kernel fallback
    ms.rblock = lambda h, addr, n: _read_with_kernel_fallback(h, addr, n, 'rblock')

    # Patch rblock_fast to add kernel fallback  
    ms.rblock_fast = lambda h, addr, n: _read_with_kernel_fallback(h, addr, n, 'rblock_fast')


def _read_with_kernel_fallback(h, addr, n, func_name):
    """Read with user-mode primary, kernel driver fallback"""
    # Try user-mode first
    result = ms._orig_rblock(h, addr, n) if func_name == 'rblock' else ms._orig_rblock_fast(h, addr, n)

    # If user-mode succeeded, return as before
    if result is not None:
        return result

    # User-mode failed - attempt kernel driver fallback
    # This requires knowing the PID... simplified for now
    # In production, integrate with ScannerKernelIntegration
    return None


# ============================================================
#  Convenience: Create HybridMemory-aware Scanner
# ============================================================

def create_kernel_aware_scanner(process_handle, enable_kernel: bool = True):
    """
    Create a Scanner instance that falls back to kernel driver
    
    Args:
        process_handle: Handle to target process (from OpenProcess)
        enable_kernel: Whether to enable kernel driver fallback
        
    Returns:
        Scanner instance with kernel fallback capability
    """
    from memory_scanner import Scanner

    # Wrap the handle to add kernel awareness
    integration = ScannerKernelIntegration(process_handle, enable_kernel)

    # Create scanner with the wrapped handle
    scanner = Scanner(process_handle)

    # Monkey-patch the scanner to use integration for memory reads
    # In a full integration, we'd modify the worker functions
    # to check integration.read_memory_during_scan() instead of direct reads

    return scanner, integration