"""
MomoTrainerStudio Kernel Driver Wrapper
Provides Python ctypes interface to communicate with the MomoTrainer kernel driver
"""

import ctypes
import ctypes.wintypes as w
import os
import sys
from ctypes import WinDLL, wintypes

# ============================================================
#  Constants and IOCTL Codes (must match driver.h)
# ============================================================

# Device type from driver.h
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

def CTL_CODE(DeviceType, Function, Method, Access):
    return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)

# IOCTL codes (must match driver.h)
IOCTL_MOMO_READ_MEMORY    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_WRITE_MEMORY   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_QUERY_MEMORY   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_OPEN_PROCESS   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_CLOSE_PROCESS  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_GET_VERSION    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MOMO_DISABLE_PROTECTION = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x07, METHOD_BUFFERED, FILE_ANY_ACCESS)

# ============================================================
#  Data Structures (must match driver.h pack alignment)
# ============================================================

class MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ProcessId", w.HANDLE),
        ("Address",   ctypes.c_void_p),
        ("Size",      w.ULONG),
    ]

class QUERY_MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ProcessId", w.HANDLE),
        ("Address",   ctypes.c_void_p),
        ("Size",      w.ULONG),
    ]

class OPEN_PROCESS_REQUEST(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ProcessId",   w.HANDLE),
        ("ProcessHandle", w.HANDLE),
    ]

class DRIVER_VERSION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Major",   w.ULONG),
        ("Minor",   w.ULONG),
        ("Build",   w.ULONG),
        ("Reserved", w.BYTE * 256),
    ]

# ============================================================
#  Kernel32 Function Prototypes
# ============================================================

kernel32 = WinDLL('kernel32', use_last_error=True)

# CreateFile
CreateFile = kernel32.CreateFileW
CreateFile.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
CreateFile.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.LPVOID,
]
DeviceIoControl.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = wintypes.DWORD

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# ============================================================
#  MomoTrainerDriver Class
# ============================================================

class MomoTrainerDriver:
    """Wrapper for communicating with MomoTrainer kernel driver"""

    def __init__(self, device_name=r"\\.\MomoTrainer"):
        self.device_name = device_name
        self.handle = None
        self._is_open = False

    def open(self):
        """Open connection to the driver"""
        if self._is_open:
            return True

        self.handle = CreateFile(
            self.device_name,
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0,           # No sharing
            None,        # Default security
            3,           # OPEN_EXISTING
            0,           # No flags
            None
        )

        if self.handle == INVALID_HANDLE_VALUE or self.handle is None:
            self.handle = None
            self._is_open = False
            return False

        self._is_open = True
        return True

    def close(self):
        """Close connection to the driver"""
        if self._is_open and self.handle:
            CloseHandle(self.handle)
            self.handle = None
            self._is_open = False

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _ioctl(self, ioctl_code, in_buffer=None, in_size=0, out_buffer_size=0):
        """Perform DeviceIoControl call"""
        if not self._is_open:
            if not self.open():
                return False, 0, None

        # Prepare output buffer
        out_buffer = (ctypes.c_byte * out_buffer_size)() if out_buffer_size > 0 else None
        bytes_returned = wintypes.DWORD(0)

        # Prepare in_buffer pointer
        if in_buffer is None:
            in_ptr = None
        elif isinstance(in_buffer, (bytes, bytearray)):
            in_ptr = (ctypes.c_byte * len(in_buffer)).from_buffer_copy(in_buffer)
            in_size = len(in_ptr)
        else:
            in_ptr = ctypes.byref(in_buffer)
            in_size = ctypes.sizeof(in_buffer)

        result = DeviceIoControl(
            self.handle, ioctl_code,
            in_ptr, in_size,
            out_buffer, out_buffer_size,
            ctypes.byref(bytes_returned), None
        )

        if not result:
            return False, bytes_returned.value, None

        output = bytes(out_buffer[:bytes_returned.value]) if out_buffer and bytes_returned.value > 0 else None
        return True, bytes_returned.value, output

    def read_memory(self, process_id, address, size):
        """Read memory from target process via kernel driver"""
        header_size = ctypes.sizeof(MEMORY_REQUEST)
        total_size = header_size + size

        # Allocate buffer: header + space for read data
        buffer = (ctypes.c_byte * total_size)()
        header = ctypes.cast(buffer, ctypes.POINTER(MEMORY_REQUEST)).contents
        header.ProcessId = wintypes.HANDLE(process_id)
        header.Address   = ctypes.c_void_p(address)
        header.Size      = wintypes.ULONG(size)

        # Driver fills data into the buffer after header
        success, bytes_returned, _ = self._ioctl(
            IOCTL_MOMO_READ_MEMORY,
            in_buffer=buffer,
            in_size=total_size,
            out_buffer_size=ctypes.sizeof(wintypes.ULONG)
        )

        if not success:
            return None

        # Extract data from the buffer (after header)
        return bytes(buffer[header_size:header_size + size])

    def write_memory(self, process_id, address, data):
        """Write memory to target process via kernel driver"""
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)

        size = len(data)
        header_size = ctypes.sizeof(MEMORY_REQUEST)
        total_size = header_size + size

        buffer = (ctypes.c_byte * total_size)()
        header = ctypes.cast(buffer, ctypes.POINTER(MEMORY_REQUEST)).contents
        header.ProcessId = wintypes.HANDLE(process_id)
        header.Address   = ctypes.c_void_p(address)
        header.Size      = wintypes.ULONG(size)

        ctypes.memmove(
            ctypes.addressof(buffer) + header_size,
            data,
            size
        )

        success, bytes_returned, _ = self._ioctl(
            IOCTL_MOMO_WRITE_MEMORY,
            in_buffer=buffer,
            in_size=total_size,
            out_buffer_size=ctypes.sizeof(wintypes.ULONG)
        )

        if not success:
            return False

        return bytes_returned >= ctypes.sizeof(wintypes.ULONG)

    def query_memory(self, process_id, address):
        """Query memory information"""
        request = QUERY_MEMORY_REQUEST()
        request.ProcessId = wintypes.HANDLE(process_id)
        request.Address   = ctypes.c_void_p(address)
        request.Size      = wintypes.ULONG(0x1000)  # One page

        success, bytes_returned, output = self._ioctl(
            IOCTL_MOMO_QUERY_MEMORY,
            in_buffer=request,
            in_size=ctypes.sizeof(QUERY_MEMORY_REQUEST),
            out_buffer_size=ctypes.sizeof(wintypes.MEMORY_BASIC_INFORMATION)
        )

        if not success or not output or len(output) < ctypes.sizeof(wintypes.MEMORY_BASIC_INFORMATION):
            return None

        mbi = wintypes.MEMORY_BASIC_INFORMATION()
        ctypes.memmove(ctypes.byref(mbi), output, ctypes.sizeof(mbi))
        return mbi

    def get_version(self):
        """Get driver version"""
        success, bytes_returned, output = self._ioctl(
            IOCTL_MOMO_GET_VERSION,
            in_buffer=None, in_size=0,
            out_buffer_size=ctypes.sizeof(DRIVER_VERSION)
        )

        if not success or not output or len(output) < ctypes.sizeof(DRIVER_VERSION):
            return None

        version = ctypes.cast(output, ctypes.POINTER(DRIVER_VERSION)).contents
        return {
            'major': version.Major,
            'minor': version.Minor,
            'build': version.Build
        }

    def disable_protection(self):
        """Attempt to disable anti-debug protections"""
        success, bytes_returned, output = self._ioctl(
            IOCTL_MOMO_DISABLE_PROTECTION,
            in_buffer=None, in_size=0,
            out_buffer_size=ctypes.sizeof(wintypes.ULONG)
        )

        if not success or not output:
            return False

        return ctypes.cast(output, ctypes.POINTER(wintypes.ULONG)).contents.value != 0


# ============================================================
#  Convenience Functions
# ============================================================

def test_driver():
    """Test if the driver is accessible and responsive"""
    driver = MomoTrainerDriver()
    if not driver.open():
        return False, "Failed to open driver"
    try:
        version = driver.get_version()
        if version:
            return True, f"v{version['major']}.{version['minor']}.{version['build']}"
        return False, "Could not get version"
    finally:
        driver.close()


if __name__ == "__main__":
    success, msg = test_driver()
    print(f"{'✓' if success else '✗'} {msg}")
    sys.exit(0 if success else 1)