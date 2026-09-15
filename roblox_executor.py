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

_executor_compiler = ExecutorDLLCompiler()
_download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')


def get_executor_dll_path() -> Optional[str]:
    """
    Find or compile our own Roblox executor DLL.

    Returns path to the compiled DLL, or None if not available.
    """
    os.makedirs(_download_dir, exist_ok=True)

    # Check if already compiled
    for f in os.listdir(_download_dir):
        if f.startswith('RobloxExecutor') and f.endswith('.dll'):
            return os.path.join(_download_dir, f)

    # Compile it
    output_path = os.path.join(_download_dir, "RobloxExecutor.dll")
    result = _executor_compiler.generate_executor(output_path)
    if result and result.endswith('.dll'):
        return result

    # Return source path for manual compilation
    source_path = os.path.join(_download_dir, "RobloxExecutor.cpp")
    if os.path.exists(source_path):
        return source_path

    return None


# ============================================================
# Roblox Executor Class
# ============================================================

class RobloxExecutor:
    """
    Full Roblox Lua execution pipeline.

    Handles the entire flow from process detection to script execution.
    Uses our own executor DLL (not Velocity).
    """

    def __init__(self, studio_app=None):
        self.studio_app = studio_app
        self.pid = None
        self.h_process = None
        self.pipe_conn = None
        self.pipe_manager = None
        self.dll_path = None
        self.connected = False
        self.latest_scripts: List[str] = []

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

    def inject(self, dll_path: str = None) -> bool:
        """
        Inject our executor DLL into Roblox.

        Uses manual mapping by default (stealth).
        If no path given, uses our auto-compiled executor DLL.
        """
        if not self.pid:
            if not self.attach():
                return False

        if not dll_path:
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
        print("Roblox Executor: Starting pipeline...")

        # Step 1: Attach
        print("  Step 1: Attaching to Roblox...")
        if not self.attach():
            print("  Failed: Roblox not found or cannot attach")
            return False
        print(f"  Attached to PID {self.pid}")

        # Step 2: Get our executor DLL
        print("  Step 2: Getting executor DLL...")
        if not self.dll_path:
            self.dll_path = get_executor_dll_path()
        if not self.dll_path or not os.path.exists(self.dll_path):
            print(f"  Failed: No executor DLL at {self.dll_path}")
            return False
        print(f"  DLL: {self.dll_path}")

        # Step 3: Inject
        print("  Step 3: Injecting DLL...")
        injector = ManualMapper(self.pid, self.h_process)
        ok = injector.map(self.dll_path)
        if not ok:
            print("  Failed: Injection failed")
            return False
        print("  Injected!")

        # Step 4: Wait for DLL to initialize
        print("  Step 4: Waiting for DLL to initialize...")
        time.sleep(3)

        # Step 5: Connect to pipe
        print("  Step 5: Connecting to Named Pipe...")
        self.pipe_manager = PipeManager()
        self.pipe_conn = self.pipe_manager.connect(self.pid)

        if self.pipe_conn and self.pipe_conn.is_connected:
            self.connected = True
            print("  Connected!")
            return True
        else:
            print("  Warning: Injection OK but pipe not available")
            self.connected = False
            return True

    def cleanup(self):
        """Clean up resources."""
        if self.pipe_conn:
            self.pipe_conn.disconnect()
        if self.h_process:
            k32.CloseHandle(self.h_process)
        self.connected = False
        self.pid = None
        self.h_process = None
