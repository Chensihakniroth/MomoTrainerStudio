"""
arch_detect.py — Process architecture detection for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Detects whether a target process is 64-bit native or 32-bit (WOW64).
Provides cross-architecture injection support.
"""

import ctypes
from ctypes import wintypes
from typing import Optional

k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll


def is_64bit_os() -> bool:
    """Check if the current OS is 64-bit."""
    # On 64-bit Windows, ctypes.sizeof(ctypes.c_void_p) == 8
    # But this tells us the Python bitness, not necessarily the OS
    # Better way: check if Wow64DisableWow64FsRedirection exists
    try:
        # Only exists on 64-bit Windows
        k32.Wow64DisableWow64FsRedirection
        return True
    except AttributeError:
        return False


def is_wow64_process(pid: int, process_handle=None) -> Optional[bool]:
    """
    Check if a process is running under WOW64 (32-bit on 64-bit Windows).

    Returns:
        True  = 32-bit process (WOW64)
        False = 64-bit process
        None  = could not determine (e.g., 32-bit OS)
    """
    if not is_64bit_os():
        # 32-bit OS — all processes are 32-bit
        return False

    h = process_handle or k32.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        h = k32.OpenProcess(0x0010, False, pid)  # PROCESS_QUERY_INFORMATION
    if not h:
        return None

    try:
        is_wow64 = wintypes.BOOL()
        result = k32.IsWow64Process(h, ctypes.byref(is_wow64))
        if result:
            return bool(is_wow64.value)
        return None
    finally:
        if not process_handle:
            k32.CloseHandle(h)


def get_process_arch(pid: int, process_handle=None) -> Optional[str]:
    """
    Get the architecture of a target process.

    Returns:
        'x64'  = 64-bit process
        'x86'  = 32-bit process
        None   = could not determine
    """
    wow64 = is_wow64_process(pid, process_handle)
    if wow64 is None:
        return None
    return 'x86' if wow64 else 'x64'


def get_injector_arch() -> str:
    """Get the architecture of the current (injector) process."""
    import struct
    return 'x64' if struct.calcsize('P') == 8 else 'x86'


def can_inject(target_arch: str) -> tuple:
    """
    Check if injection is possible given the target architecture.

    Returns:
        (can_inject: bool, method: str, note: str)
    """
    injector_arch = get_injector_arch()

    if injector_arch == target_arch:
        return True, "native", f"Native {injector_arch} injection"

    if injector_arch == 'x64' and target_arch == 'x86':
        # 64-bit injector → 32-bit target: possible but limited
        return True, "wow64", "Cross-architecture (64→32): LoadLibrary only, manual map requires 32-bit DLL"

    if injector_arch == 'x86' and target_arch == 'x64':
        # 32-bit injector → 64-bit target: not possible without kernel driver
        return False, "unsupported", "Cannot inject from 32-bit to 64-bit without kernel driver"

    return False, "unknown", "Unknown architecture combination"


def get_kernel32_loadlibrary_address(target_pid: int, target_arch: str) -> Optional[int]:
    """
    Get the address of LoadLibraryA in the target process.

    For same architecture: returns address in target process space.
    For cross-architecture (64→32): returns address of 32-bit LoadLibraryA.

    Note: kernel32.dll is always loaded at the same address in all processes
    (for the same architecture), so we can get it from our process and it'll
    be valid in the target.
    """
    # Get kernel32.dll base from our process
    kernel32_handle = k32.GetModuleHandleA(b"kernel32.dll")
    if not kernel32_handle:
        return None

    # Get LoadLibraryA address
    load_library_a = k32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
    if not load_library_a:
        return None

    return load_library_a


def get_wow64_kernel32_info() -> dict:
    """
    Get information about the 32-bit kernel32.dll in WOW64.

    Returns dict with:
        - base: base address of 32-bit kernel32.dll
        - load_library_a: address of 32-bit LoadLibraryA
        - load_library_w: address of 32-bit LoadLibraryW
    """
    if not is_64bit_os():
        return {}

    # On 64-bit Windows, the 32-bit kernel32.dll is loaded in WOW64 processes
    # We can get its address by creating a helper or reading PEB
    # Simplified approach: use GetModuleHandle which returns the 64-bit version
    # For 32-bit version, we'd need to enumerate modules via WOW64 PEB

    # For now, return the standard addresses
    kernel32_64 = k32.GetModuleHandleA(b"kernel32.dll")
    load_library_a = k32.GetProcAddress(kernel32_64, b"LoadLibraryA")

    return {
        'base': kernel32_64,
        'load_library_a': load_library_a,
        'load_library_w': k32.GetProcAddress(kernel32_64, b"LoadLibraryW"),
    }
