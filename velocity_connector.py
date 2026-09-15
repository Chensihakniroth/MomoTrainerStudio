"""
velocity_connector.py — Named Pipe communication for VelocityAPI-style execution
made by Momo aka Steav Beoung Salang

Implements the Named Pipe communication layer that VelocityAPI uses to talk
to injected DLLs in target processes (e.g. Roblox).

Pipe name format: uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{PID}

Features:
  - Connect to named pipe
  - Send Base64-encoded Lua scripts
  - Receive responses
  - Auto-reconnect on disconnect
  - Thread-safe send/receive
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import base64
import threading
import time
from typing import Optional, Tuple

# Win32 constants
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_WRITE_THROUGH = 0x80000000
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF
SECURITY_SGD_READ = 0x00001000

# Win32 APIs
k32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# CreateFileW for pipe access
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000


# ============================================================
# Named Pipe Client
# ============================================================

class PipeConnection:
    """
    Manages a named pipe connection to an injected DLL.

    Used for communicating with VelocityAPI-style injected code
    in target processes (e.g. Roblox with Velocity DLL).
    """

    PIPE_PREFIX = "\\\\.\\pipe\\"

    def __init__(self, pid: int, pipe_suffix: str = None):
        self.pid = pid
        self.pipe_name = self._build_pipe_name(pid, pipe_suffix)
        self._handle = None
        self._connected = False
        self._lock = threading.Lock()
        self._recv_thread = None
        self._running = False
        self._pending_queue = []
        self._recv_queue = []
        self._recv_lock = threading.Lock()

    def _build_pipe_name(self, pid: int, suffix: str = None) -> str:
        """Build the full pipe name."""
        if suffix:
            return f"{self.PIPE_PREFIX}{suffix}"
        # Velocity pipe format: uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{PID}
        return f"{self.PIPE_PREFIX}uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{pid}"

    def connect(self, timeout: int = 5000) -> bool:
        """Connect to the named pipe."""
        with self._lock:
            # CreateFile on the pipe
            self._handle = k32.CreateFileW(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,  # no sharing
                None,
                3,  # OPEN_EXISTING
                FILE_FLAG_WRITE_THROUGH,
                None
            )
            if self._handle and self._handle != wintypes.HANDLE(-1).value:
                self._connected = True
                self._running = True
                self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                self._recv_thread.start()
                return True
            return False

    def disconnect(self):
        """Disconnect and clean up."""
        with self._lock:
            self._running = False
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)
        if self._handle:
            k32.CloseHandle(self._handle)
            self._handle = None
        self._connected = False

    def send(self, data: bytes) -> bool:
        """Send raw bytes to the pipe."""
        if not self._connected:
            return False
        with self._lock:
            if not self._handle:
                return False
            written = wintypes.DWORD(0)
            result = k32.WriteFile(
                self._handle,
                data,
                len(data),
                ctypes.byref(written),
                None
            )
            return result and written.value == len(data)

    def send_lua(self, script: str) -> bool:
        """
        Send a Lua script encoded as Base64.

        Velocity API uses Base64 encoding for Lua scripts sent over the pipe.
        """
        encoded = base64.b64encode(script.encode('utf-8'))
        return self.send(encoded)

    def recv(self, timeout: int = 5000) -> Optional[bytes]:
        """Receive data from the pipe with timeout."""
        start = time.monotonic()
        while time.monotonic() - start < timeout / 1000.0:
            with self._recv_lock:
                if self._recv_queue:
                    return self._recv_queue.pop(0)
            time.sleep(0.01)
        return None

    def recv_lua(self, timeout: int = 5000) -> Optional[str]:
        """Receive a Lua response and decode from Base64."""
        data = self.recv(timeout)
        if data:
            try:
                return base64.b64decode(data).decode('utf-8')
            except Exception:
                return data.decode('utf-8', errors='replace')
        return None

    def _recv_loop(self):
        """Background thread that reads from the pipe."""
        while self._running:
            try:
                # Read in chunks
                buf = ctypes.create_string_buffer(4096)
                bytes_read = wintypes.DWORD(0)
                result = k32.ReadFile(
                    self._handle,
                    buf,
                    4096,
                    ctypes.byref(bytes_read),
                    None
                )
                if result and bytes_read.value > 0:
                    data = buf.raw[:bytes_read.value]
                    with self._recv_lock:
                        self._recv_queue.append(data)
                else:
                    # Pipe closed or error — wait a bit
                    time.sleep(0.1)
            except Exception:
                time.sleep(0.1)

    @property
    def is_connected(self) -> bool:
        return self._connected


# ============================================================
# Pipe Manager — handles multiple connections
# ============================================================

class PipeManager:
    """
    Manages named pipe connections to multiple processes.
    """

    def __init__(self):
        self._connections: Dict[int, PipeConnection] = {}
        self._lock = threading.Lock()

    def get_connection(self, pid: int) -> Optional[PipeConnection]:
        """Get or create a pipe connection for a PID."""
        with self._lock:
            if pid in self._connections:
                conn = self._connections[pid]
                if conn.is_connected:
                    return conn
                # Reconnect
                conn.disconnect()
                self._connections[pid] = PipeConnection(pid)
                return self._connections[pid]
            conn = PipeConnection(pid)
            self._connections[pid] = conn
            return conn

    def connect(self, pid: int) -> Optional[PipeConnection]:
        """Connect to a process's pipe."""
        conn = self.get_connection(pid)
        if conn.connect():
            return conn
        return None

    def send_lua(self, pid: int, script: str) -> bool:
        """Send a Lua script to a specific process."""
        conn = self.get_connection(pid)
        if conn and conn.is_connected:
            return conn.send_lua(script)
        return False

    def recv_lua(self, pid: int, timeout: int = 5000) -> Optional[str]:
        """Receive a Lua response from a specific process."""
        conn = self.get_connection(pid)
        if conn:
            return conn.recv_lua(timeout)
        return None

    def disconnect_all(self):
        """Disconnect all connections."""
        with self._lock:
            for conn in self._connections.values():
                conn.disconnect()
            self._connections.clear()

    def list_connections(self) -> list:
        """List all active connections."""
        with self._lock:
            return [
                {'pid': pid, 'connected': conn.is_connected}
                for pid, conn in self._connections.items()
            ]
