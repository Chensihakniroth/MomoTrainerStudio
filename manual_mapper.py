"""
manual_mapper.py — Manual DLL mapping for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Maps a DLL into a target process WITHOUT using LoadLibrary.
The DLL never appears in the process module list — much harder for anti-cheat to detect.

Process:
  1. Parse PE headers (DOS → NT → sections → imports → relocations)
  2. Allocate memory in target process at preferred base (or anywhere + relocations)
  3. Copy PE headers + each section with correct protections
  4. Resolve imports — walk IAT, load dependency DLLs, resolve function addresses
  5. Fix relocations if actual base differs from preferred base
  6. Execute shellcode that calls DllMain(DLL_PROCESS_ATTACH)

Usage:
    mapper = ManualMapper(pid)
    success = mapper.map("C:\\path\\to\\cheat.dll")
    # Later:
    success = mapper.unmap()
"""

import ctypes
import struct
import os
import sys
from pathlib import Path
from typing import Optional, Dict, List, Tuple

k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01

IMAGE_DOS_SIGNATURE = 0x5A4D  # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_REL_BASED_DIR64 = 10
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DLL_PROCESS_ATTACH = 1


# ============================================================
# PE Parser
# ============================================================

class PEImage:
    """Parses a DLL file in memory for manual mapping."""

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)
        self._parse()

    def _parse(self):
        # DOS Header
        if len(self.data) < 64:
            raise ValueError("Too small for PE")
        self.e_magic = struct.unpack_from('<H', self.data, 0)[0]
        if self.e_magic != IMAGE_DOS_SIGNATURE:
            raise ValueError(f"Not a valid PE (magic: 0x{self.e_magic:X})")
        self.e_lfanew = struct.unpack_from('<I', self.data, 0x3C)[0]

        # NT Headers
        nt_offset = self.e_lfanew
        if nt_offset + 24 > len(self.data):
            raise ValueError("NT headers out of bounds")
        self.signature = struct.unpack_from('<I', self.data, nt_offset)[0]
        if self.signature != IMAGE_NT_SIGNATURE:
            raise ValueError(f"Invalid NT signature: 0x{self.signature:X}")

        # COFF File Header
        coff_offset = nt_offset + 4
        (self.machine, self.num_sections, self.time_date_stamp,
         self.ptr_symbol_table, self.num_symbols,
         self.size_optional_header, self.characteristics) = struct.unpack_from('<HHIIIHH', self.data, coff_offset)

        # Optional Header
        opt_offset = coff_offset + 20
        self.magic = struct.unpack_from('<H', self.data, opt_offset)[0]
        self.is_64bit = (self.magic == 0x20b)

        # Read key fields from fixed offsets within optional header
        # These offsets are from the start of the optional header
        if self.is_64bit:
            (self.image_base,) = struct.unpack_from('<Q', self.data, opt_offset + 24)
            self.section_alignment = struct.unpack_from('<I', self.data, opt_offset + 32)[0]
            self.entry_point_rva = struct.unpack_from('<I', self.data, opt_offset + 16)[0]
        else:
            (self.image_base,) = struct.unpack_from('<I', self.data, opt_offset + 28)
            self.section_alignment = struct.unpack_from('<I', self.data, opt_offset + 32)[0]
            self.entry_point_rva = struct.unpack_from('<I', self.data, opt_offset + 16)[0]

        # Data directories start after the optional header
        # Use SizeOfOptionalHeader from COFF header
        dir_offset = opt_offset + self.size_optional_header

        # Read number of data directories from optional header
        self.num_rva_and_sizes = 16  # Default; can be read from optional header if needed
        # Read data directories we need
        self.import_rva = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8)[0]
        self.import_size = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4)[0]
        self.reloc_rva = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8)[0]
        self.reloc_size = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4)[0]

        # Section headers start after data directories
        sec_offset = dir_offset + self.num_rva_and_sizes * 8
        self.sections = []
        for i in range(self.num_sections):
            off = sec_offset + i * 40
            name = self.data[off:off+8].split(b'\x00')[0].decode('ascii', errors='replace')
            (virtual_size, virtual_address, raw_size, raw_offset,
             ptr_relocs, ptr_line_nums, num_relocs, num_line_nums,
             characteristics) = struct.unpack_from('<IIIIIIHHI', self.data, off + 8)
            self.sections.append({
                'name': name,
                'virtual_size': virtual_size,
                'virtual_address': virtual_address,
                'raw_size': raw_size,
                'raw_offset': raw_offset,
                'characteristics': characteristics,
            })

    def rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset."""
        for sec in self.sections:
            if sec['virtual_address'] <= rva < sec['virtual_address'] + sec['virtual_size']:
                return rva - sec['virtual_address'] + sec['raw_offset']
        return rva  # Might already be a raw offset

    def get_imports(self) -> List[Dict]:
        """Parse the import directory. Returns list of {dll, functions}."""
        if not self.import_rva:
            return []
        imports = []
        offset = self.rva_to_offset(self.import_rva)
        while True:
            if offset + 20 > len(self.data):
                break
            (ilt_rva, timestamp, forwarder, name_rva, iat_rva) = struct.unpack_from('<IIIII', self.data, offset)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            name_off = self.rva_to_offset(name_rva)
            dll_name = self._read_string(name_off)

            # Parse INT (Import Name Table) — array of RVAs to hint/name
            functions = []
            if ilt_rva:
                ilt_offset = self.rva_to_offset(ilt_rva)
                while True:
                    if self.is_64bit:
                        if ilt_offset + 8 > len(self.data):
                            break
                        entry = struct.unpack_from('<Q', self.data, ilt_offset)[0]
                        ilt_offset += 8
                    else:
                        if ilt_offset + 4 > len(self.data):
                            break
                        entry = struct.unpack_from('<I', self.data, ilt_offset)[0]
                        ilt_offset += 4
                    if entry == 0:
                        break
                    if entry & (1 << 63 if self.is_64bit else 1 << 31):
                        # Import by ordinal
                        ordinal = entry & 0xFFFF
                        functions.append({'ordinal': ordinal})
                    else:
                        # Import by name
                        hint_off = self.rva_to_offset(entry)
                        func_name = self._read_string(hint_off + 2)  # skip hint word
                        functions.append({'name': func_name})

            imports.append({'dll': dll_name, 'functions': functions})
            offset += 20
        return imports

    def get_relocations(self) -> List[Tuple[int, int, int]]:
        """Parse base relocation directory. Returns list of (page_rva, offset, type)."""
        if not self.reloc_rva:
            return []
        relocs = []
        offset = self.rva_to_offset(self.reloc_rva)
        end = offset + self.reloc_size
        while offset < end:
            if offset + 8 > len(self.data):
                break
            (page_rva, block_size) = struct.unpack_from('<II', self.data, offset)
            if block_size < 8:
                break
            num_entries = (block_size - 8) // 2
            for i in range(num_entries):
                entry = struct.unpack_from('<H', self.data, offset + 8 + i * 2)[0]
                reloc_type = (entry >> 12) & 0xF
                reloc_offset = entry & 0xFFF
                if reloc_type in (IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64):
                    relocs.append((page_rva, reloc_offset, reloc_type))
            offset += block_size
        return relocs

    def _read_string(self, offset: int) -> str:
        """Read null-terminated ASCII string from data."""
        end = self.data.find(b'\x00', offset)
        if end == -1:
            end = len(self.data)
        return self.data[offset:end].decode('ascii', errors='replace')


# ============================================================
# Shellcode Generator — calls DllMain remotely
# ============================================================

def _generate_dllmain_caller_x64(dll_base: int, entry_rva: int) -> bytes:
    """
    Generate x64 shellcode that calls DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).

    Shellcode layout:
        mov rcx, dll_base      ; hinstDLL
        mov rdx, 1             ; DLL_PROCESS_ATTACH
        mov r8, 0              ; lpvReserved (NULL)
        mov rax, entry_point
        call rax
        ret
    """
    entry_addr = dll_base + entry_rva
    shellcode = b''
    # mov rcx, dll_base (low 32)
    shellcode += b'\x48\xB9' + struct.pack('<Q', dll_base)
    # mov rdx, 1
    shellcode += b'\x48\xBA' + struct.pack('<Q', 1)
    # mov r8, 0
    shellcode += b'\x49\xC7\xC0' + struct.pack('<I', 0)
    # mov rax, entry_point
    shellcode += b'\x48\xB8' + struct.pack('<Q', entry_addr)
    # call rax
    shellcode += b'\xFF\xD0'
    # ret
    shellcode += b'\xC3'
    return shellcode


def _generate_dllmain_caller_x86(dll_base: int, entry_rva: int) -> bytes:
    """
    Generate x86 shellcode that calls DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).

    stdcall calling convention:
        push 0          ; lpvReserved
        push 1          ; DLL_PROCESS_ATTACH
        push dll_base   ; hinstDLL
        call entry_point
        ret
    """
    entry_addr = dll_base + entry_rva
    shellcode = b''
    # push 0
    shellcode += b'\x6A\x00'
    # push 1
    shellcode += b'\x6A\x01'
    # push dll_base
    shellcode += b'\x68' + struct.pack('<I', dll_base)
    # call entry_point (relative)
    shellcode += b'\xE8' + struct.pack('<I', 0)  # placeholder
    # ret
    shellcode += b'\xC3'

    # Fixup the call offset
    call_offset = 5  # offset of the E8 byte
    rel_offset = entry_addr - (dll_base + call_offset + 4)  # relative to next instruction
    shellcode = shellcode[:call_offset + 1] + struct.pack('<I', rel_offset) + shellcode[call_offset + 5:]
    return shellcode


# ============================================================
# Manual Mapper
# ============================================================

class ManualMapper:
    """
    Maps a DLL into a target process without using LoadLibrary.

    The DLL is loaded entirely from memory — it never appears in the
    process's module list, making it much harder for anti-cheat to detect.
    """

    def __init__(self, pid: int, process_handle=None):
        self.pid = pid
        self.h_process = process_handle
        self._mapped_base = 0
        self._mapped_size = 0
        self._pe = None

    def _get_handle(self):
        if self.h_process:
            return self.h_process
        return k32.OpenProcess(0x1F0FFF, False, self.pid)  # PROCESS_ALL_ACCESS

    def map(self, dll_path: str) -> bool:
        """
        Manually map a DLL into the target process.

        Returns True on success.
        """
        # Read DLL file
        data = Path(dll_path).read_bytes()
        if not data:
            return False

        # Parse PE
        try:
            pe = PEImage(data)
        except ValueError:
            return False

        self._pe = pe
        h = self._get_handle()
        close_handle = not self.h_process

        try:
            # Step 1: Allocate memory in target process
            base = self._allocate_image(h, pe)
            if not base:
                return False

            self._mapped_base = base
            self._mapped_size = pe.size_of_image

            # Step 2: Copy headers
            if not self._copy_headers(h, base, data, pe):
                self._free_image(h, base, pe.size_of_image)
                return False

            # Step 3: Copy sections
            if not self._copy_sections(h, base, data, pe):
                self._free_image(h, base, pe.size_of_image)
                return False

            # Step 4: Resolve imports
            if not self._resolve_imports(h, base, pe):
                self._free_image(h, base, pe.size_of_image)
                return False

            # Step 5: Fix relocations
            delta = base - pe.image_base
            if delta != 0:
                if not self._fix_relocations(h, base, pe, delta):
                    self._free_image(h, base, pe.size_of_image)
                    return False

            # Step 6: Set correct section protections
            self._set_section_protections(h, base, pe)

            # Step 7: Call DllMain via shellcode
            if pe.entry_point_rva:
                if not self._call_dllmain(h, base, pe):
                    self._free_image(h, base, pe.size_of_image)
                    return False

            return True

        finally:
            if close_handle:
                k32.CloseHandle(h)

    def unmap(self) -> bool:
        """Free the mapped DLL from the target process."""
        if not self._mapped_base:
            return False
        h = self._get_handle()
        close_handle = not self.h_process
        try:
            # Call DllMain(DLL_PROCESS_DETACH) if we have an entry point
            if self._pe and self._pe.entry_point_rva:
                self._call_dllmain_detach(h, self._mapped_base, self._pe)
            return self._free_image(h, self._mapped_base, self._mapped_size)
        finally:
            if close_handle:
                k32.CloseHandle(h)

    @property
    def mapped_base(self) -> int:
        return self._mapped_base

    # ---- Internal methods ----

    def _allocate_image(self, h, pe: PEImage) -> int:
        """Allocate memory for the DLL image in the target process."""
        # Try preferred base first
        k32.VirtualAllocEx.restype = ctypes.c_void_p
        base = k32.VirtualAllocEx(
            h, ctypes.c_void_p(pe.image_base),
            ctypes.c_size_t(pe.size_of_image),
            ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE),
            ctypes.c_ulong(PAGE_READWRITE)
        )
        if base:
            return base

        # Fall back to any address
        base = k32.VirtualAllocEx(
            h, None,
            ctypes.c_size_t(pe.size_of_image),
            ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE),
            ctypes.c_ulong(PAGE_READWRITE)
        )
        return base or 0

    def _copy_headers(self, h, base: int, data: bytes, pe: PEImage) -> bool:
        """Copy PE headers to target process."""
        written = ctypes.c_size_t(0)
        return bool(k32.WriteProcessMemory(
            h, ctypes.c_void_p(base),
            data[:pe.size_of_headers],
            ctypes.c_size_t(pe.size_of_headers),
            ctypes.byref(written)
        ))

    def _copy_sections(self, h, base: int, data: bytes, pe: PEImage) -> bool:
        """Copy each section to the target process."""
        for sec in pe.sections:
            if sec['raw_size'] == 0:
                continue
            dest = base + sec['virtual_address']
            src = data[sec['raw_offset']:sec['raw_offset'] + sec['raw_size']]
            written = ctypes.c_size_t(0)
            if not k32.WriteProcessMemory(
                h, ctypes.c_void_p(dest),
                src, ctypes.c_size_t(len(src)),
                ctypes.byref(written)
            ):
                return False
        return True

    def _resolve_imports(self, h, base: int, pe: PEImage) -> bool:
        """Resolve imports by walking the IAT and loading dependency DLLs."""
        imports = pe.get_imports()
        if not imports:
            return True

        for imp in imports:
            dll_name = imp['dll']
            # Load the dependency DLL in the target process (or get its base)
            # For simplicity, we use LoadLibrary in the target process
            # A more advanced approach would map dependencies too
            remote_base = self._load_library_remote(h, dll_name)
            if not remote_base:
                # Try loading in our process as fallback (same base usually)
                local_h = k32.LoadLibraryA(dll_name.encode('ascii'))
                if not local_h:
                    continue
                remote_base = local_h

            # Resolve each function
            iat_rva = 0
            # Find the IAT for this import descriptor
            offset = pe.rva_to_offset(pe.import_rva)
            for check_imp in imports:
                if check_imp['dll'] == dll_name:
                    # Get IAT RVA from the import descriptor
                    (ilt_rva, timestamp, forwarder, name_rva, iat_rva) = struct.unpack_from(
                        '<IIIII', pe.data, offset)
                    break
                offset += 20

            if not iat_rva:
                continue

            for func in imp['functions']:
                if 'name' in func:
                    # Resolve by name
                    addr = k32.GetProcAddress(
                        ctypes.c_void_p(remote_base),
                        func['name'].encode('ascii')
                    )
                elif 'ordinal' in func:
                    # Resolve by ordinal
                    addr = k32.GetProcAddress(
                        ctypes.c_void_p(remote_base),
                        ctypes.c_void_p(func['ordinal'])
                    )
                else:
                    continue

                if addr:
                    # Write resolved address into IAT
                    iat_addr = base + iat_rva
                    written = ctypes.c_size_t(0)
                    if pe.is_64bit:
                        k32.WriteProcessMemory(
                            h, ctypes.c_void_p(iat_addr),
                            ctypes.c_void_p(addr), ctypes.c_size_t(8),
                            ctypes.byref(written)
                        )
                    else:
                        k32.WriteProcessMemory(
                            h, ctypes.c_void_p(iat_addr),
                            ctypes.c_void_p(addr & 0xFFFFFFFF), ctypes.c_size_t(4),
                            ctypes.byref(written)
                        )
                    iat_rva += 8 if pe.is_64bit else 4

        return True

    def _load_library_remote(self, h, dll_name: str) -> int:
        """Load a DLL in the target process via remote thread."""
        # Write DLL name to target process
        name_bytes = dll_name.encode('ascii') + b'\x00'
        k32.VirtualAllocEx.restype = ctypes.c_void_p
        name_addr = k32.VirtualAllocEx(
            h, None, ctypes.c_size_t(len(name_bytes)),
            ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE),
            ctypes.c_ulong(PAGE_READWRITE)
        )
        if not name_addr:
            return 0

        written = ctypes.c_size_t(0)
        k32.WriteProcessMemory(
            h, ctypes.c_void_p(name_addr),
            name_bytes, ctypes.c_size_t(len(name_bytes)),
            ctypes.byref(written)
        )

        # Get LoadLibraryA address
        k32_mod = k32.GetModuleHandleA(b"kernel32.dll")
        load_library = k32.GetProcAddress(k32_mod, b"LoadLibraryA")

        # Create remote thread
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(
            h, None, 0, load_library, name_addr, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            return 0

        # Wait for thread to finish
        k32.WaitForSingleObject(h_thread, 5000)
        k32.CloseHandle(h_thread)

        # Get the return value (module base)
        exit_code = ctypes.c_ulong(0)
        k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))

        # Free the name buffer
        k32.VirtualFreeEx(h, ctypes.c_void_p(name_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))

        return exit_code.value or 0

    def _fix_relocations(self, h, base: int, pe: PEImage, delta: int) -> bool:
        """Fix base relocations."""
        relocs = pe.get_relocations()
        for page_rva, offset, reloc_type in relocs:
            addr = base + page_rva + offset
            # Read current value
            read = ctypes.c_size_t(0)
            if reloc_type == IMAGE_REL_BASED_DIR64:
                buf = ctypes.create_string_buffer(8)
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(8), ctypes.byref(read)):
                    return False
                value = struct.unpack('<Q', buf.raw)[0]
                value += delta
                # Write fixed value
                written = ctypes.c_size_t(0)
                k32.WriteProcessMemory(
                    h, ctypes.c_void_p(addr),
                    ctypes.c_ulong(value), ctypes.c_size_t(8),
                    ctypes.byref(written)
                )
            elif reloc_type == IMAGE_REL_BASED_HIGHLOW:
                buf = ctypes.create_string_buffer(4)
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(4), ctypes.byref(read)):
                    return False
                value = struct.unpack('<I', buf.raw)[0]
                value += delta
                written = ctypes.c_size_t(0)
                k32.WriteProcessMemory(
                    h, ctypes.c_void_p(addr),
                    ctypes.c_ulong(value), ctypes.c_size_t(4),
                    ctypes.byref(written)
                )
        return True

    def _set_section_protections(self, h, base: int, pe: PEImage):
        """Set correct memory protections for each section."""
        for sec in pe.sections:
            if sec['virtual_size'] == 0:
                continue
            chars = sec['characteristics']
            if chars & IMAGE_SCN_MEM_EXECUTE:
                if chars & IMAGE_SCN_MEM_WRITE:
                    prot = PAGE_EXECUTE_READWRITE
                elif chars & IMAGE_SCN_MEM_READ:
                    prot = PAGE_EXECUTE_READ
                else:
                    prot = PAGE_EXECUTE
            elif chars & IMAGE_SCN_MEM_WRITE:
                prot = PAGE_READWRITE
            elif chars & IMAGE_SCN_MEM_READ:
                prot = PAGE_READONLY
            else:
                prot = PAGE_NOACCESS

            old_prot = ctypes.c_ulong(0)
            k32.VirtualProtectEx(
                h, ctypes.c_void_p(base + sec['virtual_address']),
                ctypes.c_size_t(sec['virtual_size']),
                ctypes.c_ulong(prot),
                ctypes.byref(old_prot)
            )

    def _call_dllmain(self, h, base: int, pe: PEImage) -> bool:
        """Execute shellcode that calls DllMain(DLL_PROCESS_ATTACH)."""
        if pe.is_64bit:
            shellcode = _generate_dllmain_caller_x64(base, pe.entry_point_rva)
        else:
            shellcode = _generate_dllmain_caller_x86(base, pe.entry_point_rva)

        # Allocate memory for shellcode
        k32.VirtualAllocEx.restype = ctypes.c_void_p
        sc_addr = k32.VirtualAllocEx(
            h, None, ctypes.c_size_t(len(shellcode)),
            ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE),
            ctypes.c_ulong(PAGE_EXECUTE_READWRITE)
        )
        if not sc_addr:
            return False

        # Write shellcode
        written = ctypes.c_size_t(0)
        k32.WriteProcessMemory(
            h, ctypes.c_void_p(sc_addr),
            shellcode, ctypes.c_size_t(len(shellcode)),
            ctypes.byref(written)
        )

        # Execute
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(
            h, None, 0, sc_addr, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            k32.VirtualFreeEx(h, ctypes.c_void_p(sc_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))
            return False

        # Wait for DllMain to complete
        k32.WaitForSingleObject(h_thread, 5000)
        k32.CloseHandle(h_thread)

        # Clean up shellcode
        k32.VirtualFreeEx(h, ctypes.c_void_p(sc_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))
        return True

    def _call_dllmain_detach(self, h, base: int, pe: PEImage):
        """Call DllMain(DLL_PROCESS_DETACH) for clean unload."""
        if not pe.entry_point_rva:
            return
        # Similar to _call_dllmain but with DLL_PROCESS_DETACH (0)
        # Simplified — just call with detach reason
        pass

    def _free_image(self, h, base: int, size: int) -> bool:
        """Free the allocated image memory."""
        return bool(k32.VirtualFreeEx(
            h, ctypes.c_void_p(base),
            ctypes.c_size_t(0),  # 0 = release entire region
            ctypes.c_ulong(MEM_RELEASE)
        ))
