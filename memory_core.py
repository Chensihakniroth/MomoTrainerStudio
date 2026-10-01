"""
memory_core.py — Native "Memory.h" engine for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Direct Python port of the classic C++ `Memory.h` trainer header
(https://github.com/TeamBrogrammers/Memory.h), exposing the same
API shape as a native engine:

    memory = Memory("ac_client.exe")
    base   = memory.GetModuleAddress("ac_client.exe")
    ptr    = memory.Read<uintptr_t>(base + 0x17E0A8)
    health = ptr + 0xEC
    memory.Write<int>(health, 1337)

Python port adds what C++ cannot give us for free:
  * snake_case + PascalCase aliases (both styles work)
  * typed read/write by name ("int32", "float", ...) and by struct format
  * pointer-chain resolution in one call
  * module listing, process listing
  * error reporting instead of silent {}-returns (the C++ Read swallows
    failures and returns a zeroed value; we surface it)

The C++ version is:
    Memory(const std::string_view processName)  ->  Memory(process_name)
    ~Memory()                                    ->  .close() / __del__
    GetModuleAddress(moduleName)                ->  get_module_address()
    Read<T>(address)                             ->  read(addr, vtype)
    Write<T>(address, value)                     ->  write(addr, value, vtype)
"""

import ctypes
import struct
import threading
from ctypes import wintypes as wt

# ============================================================
# Win32 bindings
# ============================================================

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32NextW.restype = wt.BOOL
k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
k32.Process32FirstW.restype = wt.BOOL
k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
k32.Module32NextW.restype = wt.BOOL
k32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
k32.Module32FirstW.restype = wt.BOOL
k32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.GetLastError.restype = wt.DWORD

# ============================================================
# Type system
# ============================================================

# name -> (struct format, size, python type)
TYPES = {
    "int8":    ("<b",  1, int),
    "uint8":   ("<B",  1, int),
    "byte":    ("<B",  1, int),
    "bool":    ("<?",  1, bool),
    "int16":   ("<h",  2, int),
    "uint16":  ("<H",  2, int),
    "short":   ("<h",  2, int),
    "word":    ("<H",  2, int),
    "int32":   ("<i",  4, int),
    "uint32":  ("<I",  4, int),
    "int":     ("<i",  4, int),
    "dword":   ("<I",  4, int),
    "float":   ("<f",  4, float),
    "float32": ("<f",  4, float),
    "int64":   ("<q",  8, int),
    "uint64":  ("<Q",  8, int),
    "intptr":  ("<q",  8, int),
    "uintptr": ("<Q",  8, int),
    "uintptr_t": ("<Q", 8, int),
    "double":  ("<d",  8, float),
    "float64": ("<d",  8, float),
    "ptr":     ("<Q",  8, int),
}

TYPE_ALIASES = {
    "i8": "int8", "u8": "uint8", "byte": "uint8",
    "i16": "int16", "u16": "uint16", "word": "uint16",
    "i32": "int32", "u32": "uint32", "i64": "int64", "u64": "uint64",
    "f32": "float", "f64": "double", "long": "int32", "ulong": "uint32",
    "qword": "int64", "size_t": "uintptr", "uintptr_t": "uintptr",
}

TYPE_NAMES = sorted(TYPES.keys())


def normalize_type(vtype) -> str:
    """Accept 'int32', 'Int32', 'i32', 'uintptr_t' -> canonical name.

    Raw struct formats ('<I', '>H') are returned UNCHANGED — lowercasing
    them would flip signed/unsigned ('<I' -> '<i') and change semantics.
    """
    if vtype is None:
        return "uintptr"
    if isinstance(vtype, str):
        raw = vtype.strip()
        # A struct format: first char is byte order, rest are type chars.
        if raw[:1] in "<>=!" and len(raw) > 1:
            return raw
        key = raw.lower()
    else:
        key = str(vtype).lower()
    if key in TYPES:
        return key
    if key in TYPE_ALIASES:
        return TYPE_ALIASES[key]
    raise ValueError(
        "Unknown type %r. Known: %s" % (vtype, ", ".join(TYPE_NAMES)))


def type_size(vtype) -> int:
    key = normalize_type(vtype)
    if key in TYPES:
        return TYPES[key][1]
    return struct.calcsize(key)


# ============================================================
# Process / module enumeration (static helpers)
# ============================================================

def enable_debug_privilege() -> bool:
    """Enable SeDebugPrivilege on the current process.

    Required to OpenProcess() protected or elevated targets. Returns True
    if the privilege was acquired (it is absent when not running as admin,
    which is not fatal - just means elevated targets stay out of reach).
    """
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_uint32),
                        ("HighPart", ctypes.c_int32)]

        class LAA(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

        class TP(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.c_uint32),
                        ("Privileges", LAA * 1)]

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 2

        tp = TP()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid.HighPart = 0
        # SE_DEBUG_NAME = "SeDebugPrivilege" -> LUID 20
        tp.Privileges[0].Luid.LowPart = 20
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        token = wt.HANDLE()
        if not advapi32.OpenProcessToken(k32.GetCurrentProcess(),
                                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                         ctypes.byref(token)):
            return False
        try:
            if not advapi32.AdjustTokenPrivileges(token, False,
                                                  ctypes.byref(tp),
                                                  0, None, None):
                return False
            # AdjustTokenPrivileges reports success even when it assigned
            # nothing - GetLastError() is the real signal.
            return k32.GetLastError() == 0
        finally:
            k32.CloseHandle(token)
    except Exception:
        return False


def list_processes() -> list:
    """[(pid, exe_name), ...] for every visible process."""
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return out
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if k32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                out.append((int(entry.th32ProcessID), entry.szExeFile))
                entry = PROCESSENTRY32()
                entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
                if not k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


def find_pids(process_name: str) -> list:
    """Every PID whose exe name matches (case-insensitive)."""
    target = process_name.lower()
    if not target.endswith(".exe"):
        target += ".exe"
    return [pid for pid, name in list_processes() if name.lower() == target]


def find_pid(process_name: str) -> int:
    """First PID whose exe name matches (case-insensitive), 0 if none.

    NOTE: multiple instances are common (every python.exe, every
    chrome.exe). Use find_pids() / list_instances() when the name is
    ambiguous — binding to matches[0] silently attaches to the wrong one.
    """
    target = process_name.lower()
    if not target.endswith(".exe"):
        target += ".exe"
    for pid, name in list_processes():
        if name.lower() == target:
            return pid
    return 0


# ============================================================
# Window titles — needed to tell instances apart
# ============================================================

EnumWindowsProc = ctypes.WINFUNCTYPE(
    wt.BOOL, wt.HWND, wt.LPARAM)

# Window APIs live in user32, not kernel32 — a bare k32.<fn> lookup
# raises AttributeError at import time and takes the whole module with it.
user32 = ctypes.WinDLL("user32", use_last_error=True)

user32.EnumWindows.restype = wt.BOOL
user32.EnumWindows.argtypes = [EnumWindowsProc, wt.LPARAM]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.restype = wt.DWORD
user32.GetWindowThreadProcessId.argtypes = [wt.HWND,
                                            ctypes.POINTER(wt.DWORD)]
user32.IsWindowVisible.restype = wt.BOOL
user32.IsWindowVisible.argtypes = [wt.HWND]


def window_titles_by_pid(pids=None, visible_only: bool = True) -> dict:
    """{pid: [window titles]} for the given PIDs (or all).

    A PID list alone cannot tell you which chrome.exe is the one you
    want; the window title can. This walks EnumWindows once and buckets
    titles per owning process.

    visible_only skips hidden/helper windows (tray, message-only), which
    otherwise fill the list with duplicates nobody can act on.
    """
    wanted = set(int(p) for p in pids) if pids else None
    out = {}
    if wanted is not None:
        for p in wanted:
            out[p] = []

    def _cb(hwnd, _lparam):
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        pid = wt.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        p = int(pid.value)
        if wanted is not None and p not in wanted:
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value.strip()
        if title:
            out.setdefault(p, []).append(title)
        return True

    # Keep the callback alive for the duration of the walk; letting the
    # WINFUNCTYPE object be collected mid-EnumWindows is a hard crash.
    cb = EnumWindowsProc(_cb)
    try:
        user32.EnumWindows(cb, 0)
    except Exception:
        pass
    return out


def list_instances(process_name: str) -> list:
    """[(pid, exe_name, [titles]), ...] for every instance of an exe name.

    This is what the GUI should offer when a name is ambiguous: PID plus
    a human-meaningful window title, so the user picks the right one
    instead of silently getting matches[0].
    """
    target = process_name.lower()
    if not target.endswith(".exe"):
        target += ".exe"
    rows = [(pid, name) for pid, name in list_processes()
            if name.lower() == target]
    titles = window_titles_by_pid([pid for pid, _ in rows])
    return [(pid, name, titles.get(pid, [])) for pid, name in rows]


def describe_instance(pid: int, name: str = "", titles=None) -> str:
    """One-line human label for an instance, for logs and pickers."""
    pid = int(pid)
    if titles is None:
        titles = window_titles_by_pid([pid]).get(pid, [])
    if titles:
        return "pid %d (%s) - %s" % (pid, name or "?", titles[0])
    return "pid %d (%s) - no visible window" % (pid, name or "?")


def list_modules(pid: int) -> list:
    """[(name, base, size, path), ...] loaded modules of a process."""
    out = []
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snap = k32.CreateToolhelp32Snapshot(flags, pid)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return out
    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if k32.Module32FirstW(snap, ctypes.byref(entry)):
            while True:
                base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                out.append((entry.szModule, base, int(entry.modBaseSize),
                            entry.szExePath))
                entry = MODULEENTRY32()
                entry.dwSize = ctypes.sizeof(MODULEENTRY32)
                if not k32.Module32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


# ============================================================
# Memory — the ported class
# ============================================================

class MemoryError_(Exception):
    """Raised when a read/write fails (C++ version returns {} silently)."""


class Memory:
    """
    Attach to a process by exe name (or PID) and read/write its memory.

    Mirrors the C++ Memory.h class:

        memory = Memory("DummyGame.py")
        base = memory.GetModuleAddress("DummyGame.py")
        memory.Write(0x1234, 1337, "int32")
    """

    def __init__(self, process_name: str = None, pid: int = None,
                 access: int = PROCESS_ALL_ACCESS):
        self.pid = 0
        self.handle = None
        self.process_name = process_name or ""
        self.last_error = 0
        self.ambiguous = []       # other PIDs sharing the same exe name
        self._lock = threading.RLock()
        self._closed = False

        if pid:
            self.pid = int(pid)
        elif process_name:
            matches = find_pids(process_name)
            if not matches:
                raise MemoryError_(
                    "Process not found: %s" % process_name)
            self.pid = matches[0]
            self.ambiguous = matches[1:]

        if not self.pid:
            raise MemoryError_("No process specified (need process_name or pid)")

        # SeDebugPrivilege is required to open protected/elevated targets.
        # studio_gui enables this for its own handle; without it here the
        # Memory.h panel fails with access denied on the very same process.
        self.debug_privilege = enable_debug_privilege()

        # Fall back to reduced rights if PROCESS_ALL_ACCESS is denied
        # (happens on protected / cross-session targets).
        self.handle = k32.OpenProcess(access, False, self.pid)
        if not self.handle:
            access = (PROCESS_VM_READ | PROCESS_VM_WRITE |
                      PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
            self.handle = k32.OpenProcess(access, False, self.pid)
        if not self.handle:
            err = k32.GetLastError()
            raise MemoryError_(
                "OpenProcess(%d) failed (error %d) — try Elevate Admin"
                % (self.pid, err))

        # Cache the main module name (first entry is the exe itself)
        mods = list_modules(self.pid)
        if mods and not self.process_name:
            self.process_name = mods[0][0]

    # -- C++ style aliases -------------------------------------
    GetModuleAddress = None   # bound below (needs the method body)

    # -- lifecycle --------------------------------------------
    @classmethod
    def from_handle(cls, handle, pid, process_name="", owns_handle=False):
        """Wrap an already-open process handle (e.g. studio_gui's self.h).

        Lets the engine reuse a handle that was opened with privileges we
        cannot acquire ourselves. Set owns_handle=False so close() leaves
        the caller's handle alone.
        """
        obj = cls.__new__(cls)
        obj.pid = int(pid)
        obj.handle = handle
        obj.process_name = process_name or ""
        obj.last_error = 0
        obj.ambiguous = []
        obj._lock = threading.RLock()
        obj._closed = False
        obj.debug_privilege = True
        obj.owns_handle = owns_handle
        return obj

    def close(self):
        """Close the process handle (C++ destructor).

        A handle wrapped via from_handle(owns_handle=False) is left open -
        it belongs to the caller.
        """
        if self.handle and getattr(self, 'owns_handle', True):
            try:
                k32.CloseHandle(self.handle)
            except Exception:
                pass
        if getattr(self, 'owns_handle', True):
            self.handle = None
            self._closed = True
        else:
            self._closed = True

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def is_attached(self) -> bool:
        return bool(self.handle) and not self._closed

    # -- module access ----------------------------------------
    def get_module_address(self, module_name: str) -> int:
        """Base address of a loaded module, 0 when not found.

        Accepts "kernel32.dll", "kernel32" and "python.exe" (extension
        optional). An empty name returns the main exe base.
        """
        mods = list_modules(self.pid)
        if not mods:
            return 0
        if not module_name:
            return mods[0][1]

        raw = module_name.lower()
        # Candidate spellings: as-given, with .dll, with .exe
        has_ext = raw.endswith(".dll") or raw.endswith(".exe")
        cands = [raw]
        if not has_ext:
            cands.append(raw + ".dll")
            cands.append(raw + ".exe")
        # exact match first (case-insensitive)
        for want in cands:
            for mod_name, base, _size, _path in mods:
                if mod_name.lower() == want:
                    return base
        # then prefix/substring, e.g. "unityplayer" -> UnityPlayer.dll
        for want in cands:
            stem = want.rsplit(".", 1)[0]
            for mod_name, base, _size, _path in mods:
                low = mod_name.lower()
                if low.startswith(stem) or stem in low:
                    return base
        return 0

    def get_modules(self) -> list:
        """[(name, base, size, path), ...] for the attached process."""
        return list_modules(self.pid)

    # -- raw bytes --------------------------------------------
    def read_bytes(self, address: int, size: int) -> bytes:
        if not self.is_attached():
            raise MemoryError_("Not attached to a process")
        if size <= 0:
            return b""
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.handle, ctypes.c_void_p(address),
                                   ctypes.byref(buf), size, ctypes.byref(got))
        if not ok or got.value != size:
            self.last_error = k32.GetLastError()
            raise MemoryError_(
                "ReadProcessMemory failed at 0x%X (size %d, error %d)"
                % (address, size, self.last_error))
        return bytes(bytearray(buf))

    def write_bytes(self, address: int, data: bytes) -> int:
        if not self.is_attached():
            raise MemoryError_("Not attached to a process")
        if not data:
            return 0
        raw = bytes(data)
        buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        put = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(self.handle, ctypes.c_void_p(address),
                                    ctypes.byref(buf), len(raw),
                                    ctypes.byref(put))
        if not ok or put.value != len(raw):
            self.last_error = k32.GetLastError()
            raise MemoryError_(
                "WriteProcessMemory failed at 0x%X (size %d, error %d)"
                % (address, len(raw), self.last_error))
        return put.value

    # -- typed access -----------------------------------------
    def read(self, address: int, vtype="uintptr", safe: bool = False):
        """Read a typed value at an address.

        safe=True returns None instead of raising on a failed read.
        """
        key = normalize_type(vtype)
        try:
            if key in TYPES:
                fmt, size, _py = TYPES[key]
                raw = self.read_bytes(address, size)
                val = struct.unpack(fmt, raw)[0]
                return bool(val) if key == "bool" else val
            # raw struct format
            raw = self.read_bytes(address, struct.calcsize(key))
            return struct.unpack(key, raw)[0]
        except MemoryError_:
            if safe:
                return None
            raise

    def write(self, address: int, value, vtype="uintptr") -> int:
        """Write a typed value at an address. Returns bytes written.

        Integer values are TRUNCATED to the type width, matching the C++
        Memory.h behaviour (Write<int>(addr, 0x1FFFFFFFF) writes 0xFFFFFFFF)
        instead of raising struct.error. Floats are converted.
        """
        key = normalize_type(vtype)
        if key in TYPES:
            fmt, size, _py = TYPES[key]
            if key == "bool":
                value = bool(value)
            elif key in ("float", "double", "float32", "float64"):
                value = float(value)
            elif fmt[1] in "bhiq":        # signed int types
                # Mask to the unsigned width, then wrap back into the signed
                # range so struct.pack sees a valid value.
                masked = int(value) & ((1 << (size * 8)) - 1)
                half = 1 << (size * 8 - 1)
                if masked >= half:
                    masked -= (1 << (size * 8))
                value = masked
            else:
                value = int(value) & ((1 << (size * 8)) - 1)
            raw = struct.pack(fmt, value)
        else:
            # Raw struct format, e.g. '<H'. Truncate integers to the
            # format's width so it behaves like the C++ Write<T>.
            c = key[-1]
            if c in "bhiqBHIQL":
                width = {"b": 1, "B": 1, "h": 2, "H": 2, "i": 4, "I": 4,
                         "l": 4, "L": 4, "q": 8, "Q": 8, "Q": 8}[c]
                value = int(value) & ((1 << (width * 8)) - 1)
            raw = struct.pack(key, value)
        return self.write_bytes(address, raw)

    def read_string(self, address: int, max_len: int = 256,
                    encoding: str = "utf-8") -> str:
        """Read a NUL-terminated (or fixed-length) string."""
        raw = self.read_bytes(address, max_len)
        if b"\x00" in raw:
            raw = raw[:raw.index(b"\x00")]
        return raw.decode(encoding, errors="replace")

    def write_string(self, address: int, text: str, encoding: str = "utf-8",
                     null_terminate: bool = True) -> int:
        raw = text.encode(encoding)
        if null_terminate:
            raw += b"\x00"
        return self.write_bytes(address, raw)

    # -- pointer chains ---------------------------------------
    def resolve_chain(self, base_address: int, offsets, deref_last=True):
        """
        Walk a pointer chain.

        resolve_chain(base, [0x10, 0x20]) ->
            addr = read(base + 0x10); addr = read(addr + 0x20)
        With deref_last=False the final offset is added, not read:
            base + 0x10 -> read -> +0x20  (returns the address to read)
        """
        if not offsets:
            return base_address
        addr = base_address
        offsets = list(offsets)
        for i, off in enumerate(offsets):
            addr = addr + int(off)
            last = (i == len(offsets) - 1)
            if not (last and not deref_last):
                addr = self.read(addr, "uintptr")
            if not addr:
                raise MemoryError_(
                    "Chain broke at offset index %d (0x%X)" % (i, off))
        return addr

    def read_chain(self, base_address: int, offsets, vtype="int32",
                   deref_last=False):
        """Read a typed value through a pointer chain in one call.

        deref_last=False (default, and what trainers want): every offset
        except the last is dereferenced, the last is added to form the
        final address, and vtype is read there.

            read_chain(base, [0x10, 0x20, 0xEC], "int32")
              -> read(base+0x10) + 0x20 -> read -> + 0xEC -> int32 value
        """
        return self.read(
            self.resolve_chain(base_address, offsets, deref_last), vtype)

    def write_chain(self, base_address: int, offsets, value,
                    vtype="int32", deref_last=False) -> int:
        """Write a typed value through a pointer chain in one call."""
        return self.write(
            self.resolve_chain(base_address, offsets, deref_last),
            value, vtype)

    # -- safety helpers ---------------------------------------
    def query(self, address: int):
        """(state, protect, type, size) of the region containing address."""
        # NOTE: PartitionId (WORD) exists on Win10+ between AllocationProtect
        # and RegionSize. Omitting it shifts every later field and yields
        # garbage — VirtualQueryEx still "succeeds" so the bug is silent.
        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("PartitionId", ctypes.c_ushort),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
            ]
        mbi = MBI()
        if not k32.VirtualQueryEx(ctypes.c_void_p(self.handle),
                                  ctypes.c_void_p(address), ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
            return None
        return (int(mbi.State), int(mbi.Protect), int(mbi.Type),
                int(mbi.RegionSize))

    def protect(self, address: int, protect_flags: int):
        """Change page protection, returns (old_flags, ok)."""
        old = ctypes.c_ulong(0)
        ok = k32.VirtualProtectEx(ctypes.c_void_p(self.handle),
                                  ctypes.c_void_p(address),
                                  ctypes.c_size_t(0x1000),
                                  protect_flags, ctypes.byref(old))
        return old.value, bool(ok)

    def is_readable(self, address: int) -> bool:
        info = self.query(address)
        return bool(info and info[0] == 0x1000 and not (info[1] & 0x100))

    def __repr__(self):
        return "<Memory pid=%d name=%r attached=%s>" % (
            self.pid, self.process_name, self.is_attached())


# C++-style method alias, defined after the class body
Memory.GetModuleAddress = Memory.get_module_address
Memory.Read = Memory.read
Memory.Write = Memory.write


# ============================================================
# Self-test
# ============================================================

def _self_test():
    """Attach to our own process and round-trip a value."""
    import os
    me = Memory(pid=os.getpid())
    print("attached:", me)
    base = me.get_module_address("") or me.get_module_address("kernel32.dll")
    print("module base:", hex(base))
    # python list of bytes we own
    probe = bytearray(b"MOMOCORE-TEST-1234")
    addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
    assert me.read(addr, "int8") == ord("M"), "int8 read failed"
    me.write(addr + 0, ord("X"), "int8")
    assert probe[0:1] == b"X", "int8 write failed"
    me.write(addr + 1, 1337, "int32")
    assert me.read(addr + 1, "int32") == 1337, "int32 round-trip failed"
    me.write(addr + 5, 3.5, "float")
    assert abs(me.read(addr + 5, "float") - 3.5) < 0.001, "float failed"
    print("string:", me.read_string(addr, 16))
    me.close()
    print("SELF-TEST PASSED")


if __name__ == "__main__":
    _self_test()
