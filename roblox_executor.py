"""
roblox_executor.py — Roblox Lua script executor for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Full Roblox Lua execution pipeline:
  1. Auto-detect or attach to Roblox process
  2. Inject our own executor DLL (manual mapping for stealth)
  3. Auto-compile our executor DLL if not present
  4. Connect to Named Pipe: uoQhySKXSUxxJNpVQyatpHQwYoGfhcbh_{PID}
  5. Send Lua scripts via pipe (Base64 encoded)
  6. Receive and display responses

Usage:
    executor = RobloxExecutor(studio_app)
    executor.launch()  # One-click: attach + inject + connect + show UI
"""

import ctypes
import ctypes.wintypes as wintypes
import base64
import os
import sys
import time
from pathlib import Path
from typing import Optional, List

# Win32
k32 = ctypes.windll.kernel32

# Internal imports
from velocity_connector import PipeConnection, PipeManager
from manual_mapper import ManualMapper
from roblox_executor_dll import ExecutorDLLCompiler


# ============================================================
# Executor DLL management
# ============================================================

#_executor_compiler = ExecutorDLLCompiler()
#_download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')


def _find_download_dir() -> str:
    """
    Find the downloads directory.

    When running from a compiled exe, __file__ won't point to the right place.
    Try multiple strategies:
    1. Relative to the executable (sys.executable)
    2. Relative to the source file (frozen=False)
    3. Current working directory
    """
    # Strategy 1: Relative to the running executable
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    candidate1 = os.path.join(exe_dir, 'downloads')
    if os.path.exists(candidate1):
        return candidate1

    # Strategy 2: Relative to source file (when running from source)
    try:
        src_dir = os.path.dirname(os.path.abspath(__file__))
        candidate2 = os.path.join(src_dir, 'downloads')
        if os.path.exists(candidate2):
            return candidate2
    except NameError:
        pass

    # Strategy 3: The exe's parent directory (MoStudio - beta.exe sits in dist/)
    # The downloads folder is in the project root, not dist/
    if hasattr(sys, 'frozen') and sys.frozen:
        # Running from compiled exe — look in project root
        # The exe is in dist/, downloads is in project root (same level as dist/)
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        project_root = os.path.dirname(exe_dir)  # Go up from dist/ to project root
        candidate3 = os.path.join(project_root, 'downloads')
        if os.path.exists(candidate3):
            return candidate3

    # Strategy 4: Fallback to current working directory
    candidate4 = os.path.join(os.getcwd(), 'downloads')
    return candidate4


def get_executor_dll_path() -> Optional[str]:
    """
    Find the best executor DLL for the target architecture.
    Prefers 64-bit CRT-free DLL for 64-bit targets (Roblox).
    """
    download_dir = _find_download_dir()
    os.makedirs(download_dir, exist_ok=True)

    # Prefer 64-bit CRT-free DLL (works in 64-bit processes)
    for f in os.listdir(download_dir):
        if f == 'RobloxExecutorCRT.dll':
            return os.path.join(download_dir, f)

    # Fall back to any 64-bit DLL
    import struct
    for f in os.listdir(download_dir):
        if f.startswith('RobloxExecutor') and f.endswith('.dll'):
            path = os.path.join(download_dir, f)
            try:
                with open(path, 'rb') as fh:
                    data = fh.read(2)
                    if data != b'MZ':
                        continue
                    fh.seek(0x3C)
                    e_lfanew = struct.unpack('<I', fh.read(4))[0]
                    fh.seek(e_lfanew + 4)
                    machine = struct.unpack('<H', fh.read(2))[0]
                    if machine == 0x8664:  # 64-bit
                        return path
            except Exception:
                continue

    # Fall back to any DLL
    for f in os.listdir(download_dir):
        if f.startswith('RobloxExecutor') and f.endswith('.dll'):
            return os.path.join(download_dir, f)

    return None


def get_executor_dll_path_for_arch(is_64bit: bool) -> Optional[str]:
    """
    Get the executor DLL for the target architecture.
    Prefers the CRT-free DLL for 64-bit targets.

    Args:
        is_64bit: True for 64-bit target, False for 32-bit target.

    Returns path to the compiled DLL, or None if not available.
    """
    download_dir = _find_download_dir()
    os.makedirs(download_dir, exist_ok=True)

    # Prefer CRT-free DLL for 64-bit targets
    if is_64bit:
        crt_free = os.path.join(download_dir, 'RobloxExecutorCRT.dll')
        if os.path.exists(crt_free):
            return crt_free

    # Look for architecture-specific DLL
    suffix = "64" if is_64bit else "32"
    for f in os.listdir(download_dir):
        if f.startswith('RobloxExecutor') and f.endswith('.dll'):
            # Check if this DLL matches the target architecture
            dll_path = os.path.join(download_dir, f)
            if _is_dll_64bit(dll_path) == is_64bit:
                return dll_path

    return None


def _is_dll_64bit(dll_path: str) -> bool:
    """Check if a DLL is 64-bit."""
    import struct
    with open(dll_path, 'rb') as f:
        data = f.read(2)
        if data != b'MZ':
            return False
        f.seek(0x3C)
        e_lfanew = struct.unpack('<I', f.read(4))[0]
        # Machine type is at e_lfanew + 2 (after "PE\0\0" signature)
        f.seek(e_lfanew + 4)
        machine = struct.unpack('<H', f.read(2))[0]
        return machine == 0x8664
# ============================================================
# Roblox Executor Class
# ============================================================

class RobloxExecutor:
    """
    Full Roblox Lua execution pipeline.

    Handles the entire flow from process detection to script execution.
    Uses our own executor DLL (not Velocity).
    """

    def __init__(self, studio_app=None, log_callback=None):
        self.studio_app = studio_app
        self.pid = None
        self.h_process = None
        self.pipe_conn = None
        self.pipe_manager = None
        self.dll_path = None
        self.connected = False
        self.latest_scripts: List[str] = []
        self._log_callback = log_callback

    def _log(self, msg: str):
        """Log a message to console and/or callback."""
        # Ensure ASCII-safe output - replace any non-ASCII characters
        safe_msg = msg.encode('ascii', errors='replace').decode('ascii')
        # Replace any remaining replacement characters
        safe_msg = safe_msg.replace('\ufffd', '?')
        print(safe_msg)
        if self._log_callback:
            self._log_callback(safe_msg)

    def find_roblox(self) -> Optional[int]:
        """Find the Roblox process PID."""
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name']
                if 'roblox' in name.lower() and 'player' in name.lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return None

    def attach(self, pid: int = None) -> bool:
        """Attach to Roblox process. Auto-detect if no PID given."""
        if pid:
            self.pid = pid
        else:
            self.pid = self.find_roblox()

        if not self.pid:
            return False

        self.h_process = k32.OpenProcess(0x1F0FFF, False, self.pid)
        if not self.h_process:
            return False

        return True

    def inject_owlhelper(self, dll_path: str = None) -> bool:
        """
        Inject using OWHelperLoader method — much simpler than manual mapping.

        How it works:
        1. Copy Loader.dll + executor DLL to Roblox's working directory
        2. CreateRemoteThread(LoadLibraryA, "Loader.dll") in target process
        3. Windows loader calls Loader.dll's DllMain automatically
        4. Loader.dll's DllMain calls LoadLibraryW("RobloxExecutorCRT.dll")
        5. Windows handles ALL PE parsing, CRT init, relocations, imports

        No manual PE parsing, IAT patching, or relocation fixing needed.
        The Windows loader does everything for us.
        """
        import shutil

        if not self.pid:
            if not self.attach():
                return False

        if not dll_path:
            dll_path = get_executor_dll_path()
            if not dll_path or not os.path.exists(dll_path):
                return False

        self.dll_path = dll_path

        # Get Roblox working directory
        try:
            import psutil
            proc = psutil.Process(self.pid)
            roblox_dir = proc.cwd()
        except Exception:
            # Fallback: get directory from exe path
            try:
                proc = psutil.Process(self.pid)
                roblox_dir = os.path.dirname(proc.exe())
            except Exception:
                return False

        # Copy DLLs to Roblox directory so LoadLibrary can find them
        loader_src = os.path.join(os.path.dirname(dll_path), 'Loader.dll')
        executor_dst = os.path.join(roblox_dir, 'RobloxExecutorCRT.dll')
        loader_dst = os.path.join(roblox_dir, 'Loader.dll')

        # Create Loader.dll if it doesn't exist
        if not os.path.exists(loader_src):
            self._create_loader_dll(loader_src)

        shutil.copy2(dll_path, executor_dst)
        if os.path.exists(loader_src):
            shutil.copy2(loader_src, loader_dst)

        # Inject Loader.dll using simple CreateRemoteThread + LoadLibraryA
        k32 = ctypes.windll.kernel32
        k32.LoadLibraryA.restype = ctypes.c_void_p
        k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
        k32.CreateRemoteThread.restype = ctypes.c_void_p

        # Write loader path to remote process memory
        loader_path = loader_dst.encode('ascii')
        name_addr = k32.VirtualAllocEx(
            self.h_process, None, len(loader_path) + 1,
            ctypes.c_ulong(0x00001000 | 0x00002000),  # MEM_COMMIT | MEM_RESERVE
            ctypes.c_ulong(0x04)  # PAGE_READWRITE
        )
        if not name_addr:
            return False

        k32.WriteProcessMemory(self.h_process, ctypes.c_void_p(name_addr),
            loader_path, ctypes.c_size_t(len(loader_path) + 1),
            ctypes.byref(ctypes.c_size_t(0)))

        # Get LoadLibraryA address
        kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
        load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

        # Create remote thread to load Loader.dll
        h_thread = k32.CreateRemoteThread(
            self.h_process, None, 0,
            ctypes.c_void_p(load_library_a),
            ctypes.c_void_p(name_addr),
            0, ctypes.byref(ctypes.c_ulong(0))
        )

        if not h_thread:
            return False

        k32.WaitForSingleObject(h_thread, 10000)
        k32.CloseHandle(h_thread)

        # Wait for the loader to load our executor DLL
        time.sleep(2)
        return True

    def _create_loader_dll(self, path: str) -> None:
        """Create the OWHelperLoader DLL source and compile it."""
        src_path = path.replace('.dll', '.cpp')
        cpp_code = '''// OWHelperLoader.dll — Loads the real DLL via Windows loader
#include <windows.h>
#include <shlwapi.h>

BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        // Get the directory where this DLL is loaded from
        WCHAR dir[MAX_PATH];
        GetModuleFileNameW(hDll, dir, MAX_PATH);
        PathRemoveFileSpecW(dir);
        // Build path to executor DLL
        WCHAR exePath[MAX_PATH];
        PathCombineW(exePath, dir, L"RobloxExecutorCRT.dll");
        // Load the real DLL — Windows handles everything
        LoadLibraryW(exePath);
    }
    return TRUE;
}
'''
        with open(src_path, 'w') as f:
            f.write(cpp_code)

        import subprocess
        subprocess.run([
            'x86_64-w64-mingw32-g++', '-shared', '-o', path, src_path,
            '-lkernel32', '-lshlwapi', '-std=c++17'
        ], check=True, capture_output=True)

    def inject(self, dll_path: str = None, method: str = 'owlhelper') -> bool:
        """
        Inject our executor DLL into Roblox.

        Args:
            dll_path: Path to the executor DLL. If None, auto-detects.
            method: 'owlhelper' (simple, uses Windows loader) or 'manual' (manual mapping).

        Returns:
            True if injection succeeded.
        """
        if method == 'owlhelper':
            return self.inject_owlhelper(dll_path)
        else:
            return self.inject_manual(dll_path)

    def inject_manual(self, dll_path: str = None) -> bool:
        """Original manual mapping injection method."""
        if not self.pid:
            if not self.attach():
                return False

        if not dll_path:
            from arch_detect import get_process_arch
            target_arch = get_process_arch(self.pid)
            is_64bit = (target_arch == 'x64')
            dll_path = get_executor_dll_path_for_arch(is_64bit)
            if not dll_path or not os.path.exists(dll_path):
                dll_path = get_executor_dll_path()
            if not dll_path or not os.path.exists(dll_path):
                return False

        self.dll_path = dll_path

        injector = ManualMapper(self.pid, self.h_process)
        ok = injector.map(dll_path)
        return ok

    def connect_pipe(self) -> bool:
        """Connect to the Named Pipe after injection."""
        time.sleep(2)
        self.pipe_manager = PipeManager()
        self.pipe_conn = self.pipe_manager.connect(self.pid)

        if self.pipe_conn and self.pipe_conn.is_connected:
            self.connected = True
            return True
        return False

    def execute_script(self, script: str) -> Optional[str]:
        """Execute a Lua script via the pipe. Returns response or None."""
        if not self.connected or not self.pipe_conn:
            return None

        ok = self.pipe_conn.send_lua(script)
        if not ok:
            return None

        response = self.pipe_conn.recv_lua(timeout=5000)
        if response:
            self.latest_scripts.append(script)
        return response

    def run_full_pipeline(self) -> bool:
        """
        Run the complete pipeline: attach → inject → connect → ready.

        Returns True if injection succeeded (pipe may need retry).
        """
        self._log("Roblox Executor: Starting pipeline...")

        # Step 1: Attach
        self._log("  Step 1: Attaching to Roblox...")
        if not self.attach():
            self._log("  Failed: Roblox not found or cannot attach")
            return False
        self._log(f"  Attached to PID {self.pid}")

        # Step 2: Get our executor DLL
        self._log("  Step 2: Getting executor DLL...")
        if not self.dll_path:
            self.dll_path = get_executor_dll_path()
        if not self.dll_path or not os.path.exists(self.dll_path):
            self._log(f"  Failed: No executor DLL at {self.dll_path}")
            return False
        self._log(f"  DLL: {self.dll_path}")

        # Step 3: Inject using OWHelperLoader (simpler, Windows handles everything)
        self._log("  Step 3: Injecting DLL via OWHelperLoader...")
        ok = self.inject(method='owlhelper')
        if not ok:
            self._log("  Failed: Injection failed")
            return False
        self._log("  Injected!")

        # Step 4: Wait for DLL to initialize, then connect to pipe
        self._log("  Step 4: Waiting for DLL to initialize...")
        time.sleep(3)  # Give the DLL time to set up the pipe

        self._log("  Step 5: Connecting to Named Pipe...")
        self.pipe_manager = PipeManager()
        self.pipe_conn = self.pipe_manager.connect(self.pid)

        if self.pipe_conn and self.pipe_conn.is_connected:
            self.connected = True
            self._log("  Connected!")
            return True
        else:
            self._log("  Warning: Injection OK but pipe not available")
            self.connected = False
            return True  # Still return True — injection worked

    def cleanup(self):
        """Clean up resources."""
        if self.pipe_conn:
            self.pipe_conn.disconnect()
        if self.h_process:
            k32.CloseHandle(self.h_process)
        self.connected = False
        self.pid = None
        self.h_process = None
