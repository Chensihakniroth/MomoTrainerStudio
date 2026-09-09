"""
debugger_unified.py - Unified Debugger Interface for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Auto-routes between:
  - Hardware breakpoints (debugger.py) for unprotected games
  - Stealth PAGE_GUARD (stealth_debugger.py) for anti-cheat protected games

Features:
  - Automatic anti-cheat detection
  - Seamless backend switching
  - Unified API surface
"""

import ctypes
import psutil
import threading
from typing import Optional, List, Dict, Callable

k32 = ctypes.windll.kernel32

# Known anti-cheat processes and drivers
KNOWN_ANTI_CHEAT = [
    'EasyAntiCheat', 'BattlEye', 'Vanguard', 'vgc.exe', 'vgk.sys',
    'FaceItClient', 'EQU8', 'Hyperion', 'Fortiche', 'RiotClient',
    'anticheat', 'ace-base.sys', 'bedaisy.sys'
]


class UnifiedDebugger:
    """
    Unified debugger that auto-selects the appropriate backend.
    
    Usage:
        udb = UnifiedDebugger(pid, target_address, mode='write')
        udb.start()
        # ... wait for hits ...
        hits = udb.get_hits()
        udb.stop()
    """
    
    def __init__(self, pid: int, address: int, mode: str = 'access',
                 size: int = 4, on_hit: Optional[Callable] = None,
                 on_status: Optional[Callable] = None,
                 force_stealth: bool = False):
        """
        pid: target process ID
        address: memory address to monitor
        mode: 'access' (read/write) or 'write' (write-only)
        size: monitored length in bytes (1, 2, 4, 8)
        on_hit: callback function(hit_dict) called when memory is accessed
        on_status: callback function(status_string)
        force_stealth: if True, always use stealth debugger
        """
        if int(pid) <= 0:
            raise ValueError("pid must be a positive integer")
        if int(address) < 0:
            raise ValueError("address must be non-negative")
        if mode not in ('access', 'write'):
            raise ValueError("mode must be 'access' or 'write'")
        if int(size) not in (1, 2, 4, 8):
            raise ValueError("size must be 1, 2, 4, or 8 bytes")
        self.pid = int(pid)
        self.address = int(address)
        self.mode = mode
        self.size = int(size)
        self.on_hit = on_hit
        self.on_status = on_status
        self.force_stealth = force_stealth
        
        self._backend = None
        self._backend_type = None  # 'hardware' or 'stealth'
        self._protection_detected = []
        self._is_scanned = False
        
    def scan_for_protection(self) -> List[str]:
        """
        Detect anti-cheat processes and drivers.
        Returns list of detected protection names.
        """
        detected = []
        seen = set()
        
        try:
            # Check running processes
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    name = proc.info['name']
                    if name:
                        name_lower = name.lower()
                        for ac in KNOWN_ANTI_CHEAT:
                            if ac.lower() in name_lower:
                                item = f"{ac} (process: {name})"
                                if item not in seen:
                                    detected.append(item)
                                    seen.add(item)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            # Check loaded modules in target process (requires admin)
            # This is a simplified check - could be expanded with EnumProcessModules
            try:
                h = k32.OpenProcess(0x0410, False, self.pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                if h:
                    # Could enumerate modules here with EnumProcessModulesEx
                    # For now, we just check process name
                    k32.CloseHandle(h)
            except:
                pass
                
        except Exception as exc:
            if self.on_status:
                self.on_status(f"[Unified] Protection scan unavailable: {exc}")
            
        self._protection_detected = detected
        self._is_scanned = True
        return detected
        
    def should_use_stealth(self) -> bool:
        """Determine if stealth debugger should be used."""
        if self.force_stealth:
            return True
            
        if not self._is_scanned:
            self.scan_for_protection()
            
        return len(self._protection_detected) > 0
        
    def start(self):
        """
        Start debugging with auto-selected backend.
        """
        use_stealth = self.should_use_stealth()
        
        if use_stealth:
            from stealth_debugger import StealthDebugger
            self._backend = StealthDebugger(
                self.pid, self.address, self.mode,
                self.size, self.on_hit, self.on_status
            )
            self._backend_type = 'stealth'
            if self.on_status:
                self.on_status(f"[Unified] Using STEALTH debugger (protection detected: {len(self._protection_detected)})")
        else:
            from debugger import HardwareDebugger
            self._backend = HardwareDebugger(
                self.pid, self.address, self.mode,
                self.size, self.on_hit, self.on_status
            )
            self._backend_type = 'hardware'
            if self.on_status:
                self.on_status("[Unified] Using HARDWARE debugger (no protection detected)")
                
        self._backend.start()
        
    def stop(self):
        """Stop debugging session."""
        if self._backend:
            self._backend.stop()
            
    def is_running(self) -> bool:
        """Check if debugger is active."""
        if self._backend:
            return self._backend.is_running()
        return False
        
    def get_hits(self) -> Dict:
        """
        Get all captured hits.
        Returns dict: {rip: {count, rip, insn, regs, bytes}}
        """
        if self._backend and hasattr(self._backend, 'hit_cache'):
            return dict(self._backend.hit_cache)
        return {}
        
    def get_unique_hit_count(self) -> int:
        """Get count of unique instruction addresses."""
        return len(self.get_hits())
        
    def get_total_hit_count(self) -> int:
        """Get total hit count across all addresses."""
        hits = self.get_hits()
        return sum(h.get('count', 0) for h in hits.values())
        
    def get_backend_type(self) -> str:
        """Get current backend type: 'hardware' or 'stealth'."""
        return self._backend_type or 'none'
        
    def get_protection_info(self) -> List[str]:
        """Get list of detected anti-cheat protections."""
        if not self._is_scanned:
            self.scan_for_protection()
        return self._protection_detected
        
    def replace_with_nops(self, address: int, size: int = 5) -> bool:
        """
        Replace instruction at address with NOPs.
        Uses backend's replace_with_nops if available.
        """
        if self._backend and hasattr(self._backend, 'replace_with_nops'):
            return self._backend.replace_with_nops(address, size)
        return False
        
    def clear_hits(self):
        """Clear all captured hits."""
        if self._backend and hasattr(self._backend, 'hit_cache'):
            self._backend.hit_cache.clear()
            
    # Context manager support
    def __enter__(self):
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class MultiBreakpointManager:
    """
    Manages multiple unified debugger instances for multi-address monitoring.
    
    Usage:
        mgr = MultiBreakpointManager(pid)
        mgr.add_breakpoint(addr1, mode='write')
        mgr.add_breakpoint(addr2, mode='access')
        mgr.start_all()
        hits = mgr.get_all_hits()
        mgr.stop_all()
    """
    
    def __init__(self, pid: int, on_hit: Optional[Callable] = None,
                 on_status: Optional[Callable] = None):
        self.pid = pid
        self.on_hit = on_hit
        self.on_status = on_status
        self._debuggers = {}  # address -> UnifiedDebugger
        
    def add_breakpoint(self, address: int, mode: str = 'access',
                       size: int = 4, force_stealth: bool = False):
        """Add a breakpoint address."""
        if address in self._debuggers:
            return False
            
        udb = UnifiedDebugger(
            self.pid, address, mode, size,
            self.on_hit, self.on_status, force_stealth
        )
        self._debuggers[address] = udb
        return True
        
    def remove_breakpoint(self, address: int):
        """Remove a breakpoint."""
        if address in self._debuggers:
            udb = self._debuggers[address]
            if udb.is_running():
                udb.stop()
            del self._debuggers[address]
            
    def start_all(self):
        """Start all breakpoints."""
        for udb in self._debuggers.values():
            if not udb.is_running():
                udb.start()
                
    def stop_all(self):
        """Stop all breakpoints."""
        for udb in self._debuggers.values():
            if udb.is_running():
                udb.stop()
                
    def get_all_hits(self) -> Dict[int, Dict]:
        """Get hits from all breakpoints."""
        all_hits = {}
        for addr, udb in self._debuggers.items():
            all_hits[addr] = udb.get_hits()
        return all_hits
        
    def get_breakpoint_count(self) -> int:
        """Get number of active breakpoints."""
        return len(self._debuggers)
        
    def list_breakpoints(self) -> List[int]:
        """List all breakpoint addresses."""
        return list(self._debuggers.keys())


# Convenience function
def create_debugger(pid: int, address: int, mode: str = 'access',
                    auto_stealth: bool = True, force_stealth: bool = False) -> UnifiedDebugger:
    """
    Convenience function to create a unified debugger.
    
    auto_stealth: if True, auto-detect protection and use stealth if needed
    """
    # ``auto_stealth=False`` means do not force stealth; callers that need a
    # deterministic backend can use the explicit force_stealth flag.
    return UnifiedDebugger(pid, address, mode, force_stealth=force_stealth)
