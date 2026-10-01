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

# CRITICAL: Set all restype/argtypes for 64-bit pointer compatibility.
# Without this, ctypes defaults to c_int (32-bit signed) which silently
# truncates 64-bit addresses on x64 Windows, producing garbage in the IAT.
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
k32.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
k32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

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
            # PE32+ optional header offsets:
            # SizeOfImage at offset 56, SizeOfHeaders at offset 60
            self.size_of_image = struct.unpack_from('<I', self.data, opt_offset + 56)[0]
            self.size_of_headers = struct.unpack_from('<I', self.data, opt_offset + 60)[0]
        else:
            (self.image_base,) = struct.unpack_from('<I', self.data, opt_offset + 28)
            self.section_alignment = struct.unpack_from('<I', self.data, opt_offset + 32)[0]
            self.entry_point_rva = struct.unpack_from('<I', self.data, opt_offset + 16)[0]
            # PE32 optional header offsets:
            # SizeOfImage at offset 56, SizeOfHeaders at offset 60
            self.size_of_image = struct.unpack_from('<I', self.data, opt_offset + 56)[0]
            self.size_of_headers = struct.unpack_from('<I', self.data, opt_offset + 60)[0]

        # Read number of data directories from optional header (always 16 for PE)
        self.num_rva_and_sizes = 16

        # Data directories start at the END of the optional header (last 128 bytes)
        dir_offset = opt_offset + self.size_optional_header - (self.num_rva_and_sizes * 8)
        print(f"[PE DEBUG] opt_offset=0x{opt_offset:X}, size_opt={self.size_optional_header}, dir_offset=0x{dir_offset:X}")
        print(f"[PE DEBUG] import_rva raw @ 0x{dir_offset + 8:X} = 0x{struct.unpack_from('<I', self.data, dir_offset + 8)[0]:X}")

        # Read data directories we need
        self.import_rva = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8)[0]
        self.import_size = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4)[0]
        self.reloc_rva = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8)[0]
        self.reloc_size = struct.unpack_from('<I', self.data, dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4)[0]
        print(f"[PE DEBUG] import_rva=0x{self.import_rva:X}, reloc_rva=0x{self.reloc_rva:X}")

        # Section headers start after optional header (standard PE layout)
        # Number of sections comes from COFF header
        coff_offset = self.e_lfanew + 4  # After PE signature (4 bytes)
        # COFF header: Machine(2) + NumberOfSections(2) + ...
        num_sections = struct.unpack_from('<H', self.data, coff_offset + 2)[0]
        size_opt_header = struct.unpack_from('<H', self.data, coff_offset + 16)[0]
        sec_offset = coff_offset + 20 + size_opt_header  # COFF header is 20 bytes
        self.sections = []
        for i in range(num_sections):
            off = sec_offset + i * 40
            if off + 40 > len(self.data):
                break
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
            print(f"[SECTION DEBUG] Section {i}: {name}, VA=0x{virtual_address:X}, VS={virtual_size}, RS={raw_size}, RO=0x{raw_offset:X}")

    def rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset."""
        for sec in self.sections:
            if sec['virtual_address'] <= rva < sec['virtual_address'] + sec['virtual_size']:
                return rva - sec['virtual_address'] + sec['raw_offset']
        return rva  # Might already be a raw offset

    def get_imports(self) -> List[Dict]:
        """Parse the import directory. Returns list of {dll, functions}."""
        if self.import_rva:
            offset = self.rva_to_offset(self.import_rva)
            print(f"[IMPORT DEBUG] Using import directory: RVA=0x{self.import_rva:X}, offset=0x{offset:X}")
        else:
            # Fallback: find .idata section directly
            idata_offset = self._find_idata_section()
            if idata_offset is None:
                print(f"[IMPORT DEBUG] No import_rva and no .idata section found")
                return []
            offset = idata_offset
            print(f"[IMPORT DEBUG] Using .idata section directly: offset=0x{offset:X}")

        imports = []
        while True:
            if offset + 20 > len(self.data):
                break
            (ilt_rva, timestamp, forwarder, name_rva, iat_rva) = struct.unpack_from('<IIIII', self.data, offset)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            name_off = self.rva_to_offset(name_rva)
            dll_name = self._read_string(name_off)
            print(f"[IMPORT DEBUG] Found DLL: {dll_name}, ILT=0x{ilt_rva:X}, IAT=0x{iat_rva:X}")

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
                        ordinal = entry & 0xFFFF
                        functions.append({'ordinal': ordinal})
                    else:
                        hint_off = self.rva_to_offset(entry)
                        func_name = self._read_string(hint_off + 2)
                        functions.append({'name': func_name})

            imports.append({'dll': dll_name, 'functions': functions})
            offset += 20
        print(f"[IMPORT DEBUG] Total imports: {len(imports)}")
        return imports

    def _find_idata_section(self):
        """Find the .idata section file offset by scanning section headers."""
        coff_offset = self.e_lfanew + 4
        size_opt = struct.unpack_from('<H', self.data, coff_offset + 16)[0]
        opt_offset = coff_offset + 20
        section_offset = opt_offset + size_opt
        num_sections = struct.unpack_from('<H', self.data, coff_offset + 2)[0]
        for i in range(num_sections):
            name = self.data[section_offset:section_offset+8]
            if name[:6] == b'.idata':
                raddr = struct.unpack_from('<I', self.data, section_offset + 20)[0]
                return raddr
            section_offset += 40
        return None

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
        # Use errors='ignore' to drop non-ASCII bytes instead of producing \ufffd
        return self.data[offset:end].decode('ascii', errors='ignore')


# ============================================================
# Shellcode Generator — calls DllMain remotely
# ============================================================

def _generate_dllmain_caller_x64(dll_base: int, entry_rva: int) -> bytes:
    """
    Generate x64 shellcode that calls DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).

    x64 ABI requires:
     - 16-byte stack alignment at the CALL instruction
     - 32 bytes of shadow space above the return address
    Shellcode layout:
        sub rsp, 0x28      ; shadow space (32) + alignment (8) = 40
        mov rcx, dll_base   ; hinstDLL
        mov rdx, 1          ; DLL_PROCESS_ATTACH
        xor r8, r8          ; lpvReserved (NULL)
        mov rax, entry_point
        call rax
        add rsp, 0x28
        ret
    """
    entry_addr = dll_base + entry_rva
    shellcode = b''
    # sub rsp, 0x28  (allocate shadow space + alignment)
    shellcode += b'\x48\x83\xEC\x28'
    # mov rcx, dll_base
    shellcode += b'\x48\xB9' + struct.pack('<Q', dll_base)
    # mov rdx, 1
    shellcode += b'\x48\xBA' + struct.pack('<Q', 1)
    # xor r8, r8  (NULL — 3 bytes vs 7 for mov r8, 0)
    shellcode += b'\x4D\x31\xC0'
    # mov rax, entry_point
    shellcode += b'\x48\xB8' + struct.pack('<Q', entry_addr)
    # call rax
    shellcode += b'\xFF\xD0'
    # add rsp, 0x28
    shellcode += b'\x48\x83\xC4\x28'
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
        self._target_arch = None
        self._handle_opened_locally = False

    def _get_handle(self):
        if self.h_process:
            self._handle_opened_locally = False
            return self.h_process
        self._handle_opened_locally = True
        return k32.OpenProcess(0x1F0FFF, False, self.pid)  # PROCESS_ALL_ACCESS

    def map(self, dll_path: str) -> bool:
        """
        Manually map a DLL into the target process.

        Returns True on success.
        """
        # Detect target architecture
        from arch_detect import get_process_arch, get_injector_arch, can_inject
        self._target_arch = get_process_arch(self.pid, self.h_process)

        # Read DLL file
        data = Path(dll_path).read_bytes()
        if not data:
            return False

        # Parse PE
        try:
            pe = PEImage(data)
        except ValueError:
            return False

        # Check architecture compatibility
        dll_arch = 'x64' if pe.is_64bit else 'x86'
        if self._target_arch:
            can, method, note = can_inject(self._target_arch)
            if not can:
                return False
            # Verify DLL matches target
            if dll_arch != self._target_arch:
                return False

        self._pe = pe
        h = self._get_handle()
        close_handle = self._handle_opened_locally

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
        close_handle = self._handle_opened_locally
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
        print(f"[RESOLVE DEBUG] Found {len(imports)} import descriptors")
        if not imports:
            print("[RESOLVE DEBUG] No imports found, returning True")
            return True

        for imp in imports:
            dll_name = imp['dll']
            print(f"[RESOLVE DEBUG] Resolving {dll_name} ({len(imp['functions'])} functions)")
            # Load the dependency DLL in the target process (or get its base)
            # For simplicity, we use LoadLibrary in the target process
            # A more advanced approach would map dependencies too
            remote_base = self._load_library_remote(h, dll_name)
            if not remote_base:
                print(f"[RESOLVE DEBUG] _load_library_remote failed for {dll_name}")
                # Try loading in our process as fallback (same base usually)
                try:
                    local_h = k32.LoadLibraryA(dll_name.encode('ascii'))
                except Exception as e:
                    print(f"[RESOLVE DEBUG] LoadLibraryA failed: {e}")
                    local_h = None
                if not local_h:
                    print(f"[RESOLVE DEBUG] Skipping {dll_name}")
                    continue
                remote_base = local_h
                print(f"[RESOLVE DEBUG] Using local handle for {dll_name}: 0x{remote_base:X}")

            print(f"[RESOLVE DEBUG] {dll_name} base: 0x{remote_base:X}")

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
                    # Resolve by name from the remote DLL base.
                    # For forwarded exports (like CreateNamedPipeW -> kernelbase.dll),
                    # GetProcAddress returns a stub address that is NOT the actual function.
                    # We need to check if the returned address is a forwarder and resolve it.
                    addr = k32.GetProcAddress(
                        ctypes.c_void_p(remote_base),
                        func['name'].encode('ascii')
                    )
                    if not addr:
                        addr = self._resolve_forwarded_function(dll_name, func['name'], h)
                    else:
                        # Check if this is a forwarded export by examining if the address
                        # points to a jmp instruction (FF 25 = jmp qword ptr [rip+disp32])
                        # at the start of the function
                        try:
                            instr_buf = ctypes.create_string_buffer(6)
                            bytes_read = ctypes.c_size_t(0)
                            if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), instr_buf, 6, ctypes.byref(bytes_read)):
                                if instr_buf.raw[0:2] == b'\xff\x25':
                                    # This is a forwarder (jmp [rip+disp32])
                                    addr = self._resolve_forwarded_function(dll_name, func['name'], h)
                        except Exception:
                            pass
                elif 'ordinal' in func:
                    # Resolve by ordinal
                    addr = k32.GetProcAddress(
                        ctypes.c_void_p(remote_base),
                        ctypes.c_void_p(func['ordinal'])
                    )
                    if not addr:
                        addr = self._resolve_forwarded_function(dll_name, func['name'], h)
                else:
                    continue

                if addr:
                    # Write resolved address into IAT.
                    # WriteProcessMemory needs a pointer to a buffer in OUR process memory.
                    # Create a ctypes object holding the address, then pass byref().
                    iat_addr = base + iat_rva
                    written = ctypes.c_size_t(0)
                    if pe.is_64bit:
                        buf = ctypes.c_ulonglong(addr)
                        if not k32.WriteProcessMemory(
                            h, ctypes.c_void_p(iat_addr),
                            ctypes.byref(buf), ctypes.c_size_t(8),
                            ctypes.byref(written)
                        ):
                            print(f"[IAT DEBUG] WriteProcessMemory 64-bit failed for {func['name']} @ 0x{iat_addr:X}: {k32.GetLastError()}")
                            return False
                    else:
                        buf = ctypes.c_ulong(addr & 0xFFFFFFFF)
                        if not k32.WriteProcessMemory(
                            h, ctypes.c_void_p(iat_addr),
                            ctypes.byref(buf), ctypes.c_size_t(4),
                            ctypes.byref(written)
                        ):
                            print(f"[IAT DEBUG] WriteProcessMemory 32-bit failed for {func['name']} @ 0x{iat_addr:X}: {k32.GetLastError()}")
                            return False
                    iat_rva += 8 if pe.is_64bit else 4
                    # Debug: verify write (use 64-bit type to read full address)
                    if pe.is_64bit:
                        verify = ctypes.c_ulonglong(0)
                        verify_buf = ctypes.byref(verify)
                    else:
                        verify = ctypes.c_ulong(0)
                        verify_buf = ctypes.byref(verify)
                    k32.ReadProcessMemory(h, ctypes.c_void_p(iat_addr), verify_buf, ctypes.c_size_t(8 if pe.is_64bit else 4), ctypes.byref(ctypes.c_size_t(0)))
                    print(f"[IAT DEBUG] {dll_name}!{func['name']} @ 0x{iat_addr:X} = 0x{verify.value:X} (expected 0x{addr:X}) {'OK' if verify.value == addr else 'MISMATCH'}")

        return True
    def _load_library_remote(self, h, dll_name: str) -> int:
        """Get base address of a system DLL in the target process.

        For system DLLs (kernel32, msvcrt, user32, ntdll), we use local GetProcAddress
        since these DLLs are loaded at the same base address in all processes on the
        same Windows session, so their function addresses are valid everywhere.
        This avoids the chicken-and-egg problem of needing LoadLibraryA to resolve
        imports that haven't been patched yet.
        """
        # restype/argtypes are set at module level — no need to set here

        # Get the DLL module name in uppercase for comparison
        dll_upper = dll_name.upper()


        system_dlls = [
            'KERNEL32.DLL', 'NTDLL.DLL', 'USER32.DLL', 'MSVCRT.DLL',
            'KERNELBASE.DLL', 'ADVAPI32.DLL', 'GDI32.DLL', 'SHELL32.DLL',
            'COMCTL32.DLL', 'COMDLG32.DLL', 'WS2_32.DLL', 'RPCRT4.DLL',
            'OLE32.DLL', 'OLEAUT32.DLL', 'CRYPT32.DLL', 'BCRYPY.DLL',
            'VERSION.DLL', 'WINMM.DLL', 'DBGHELP.DLL', 'SHLWAPI.DLL',
        ]

        if dll_upper not in system_dlls:
            # For non-system DLLs, try loading in target process
            target_kernel32 = self._get_remote_kernel32_base(h)
            if target_kernel32:
                local_kernel32 = k32.LoadLibraryA(b"kernel32.dll")
                if local_kernel32:
                    load_library_offset = k32.GetProcAddress(local_kernel32, b"LoadLibraryA") - local_kernel32
                    target_load_library = target_kernel32 + load_library_offset
                    # Write DLL name to target process
                    try:
                        name_bytes = dll_name.encode('ascii') + b'\x00'
                    except Exception:
                        return 0
                    k32.VirtualAllocEx.restype = ctypes.c_void_p
                    name_addr = k32.VirtualAllocEx(h, None, ctypes.c_size_t(len(name_bytes)),
                        ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE), ctypes.c_ulong(PAGE_READWRITE))
                    if not name_addr:
                        return 0
                    k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), name_bytes,
                        ctypes.c_size_t(len(name_bytes)), ctypes.byref(ctypes.c_size_t(0)))
                    param = ctypes.c_void_p(name_addr)
                    h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(target_load_library),
                        param, 0, ctypes.byref(ctypes.c_ulong(0)))
                    if not h_thread:
                        k32.VirtualFreeEx(h, ctypes.c_void_p(name_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))
                        return 0
                    k32.WaitForSingleObject(h_thread, 10000)
                    k32.CloseHandle(h_thread)
                    k32.VirtualFreeEx(h, ctypes.c_void_p(name_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))

            # Fallback: use local handle
            local_h = k32.LoadLibraryA(dll_name.encode('ascii'))
            return local_h if local_h else 0

        # For system DLLs: use local GetProcAddress
        # kernel32.dll and other system DLLs are always loaded at the same base address
        # in all processes on the same Windows session, so their function addresses
        # are valid in the target process too
        local_h = k32.LoadLibraryA(dll_name.encode('ascii'))
        if local_h:
            return local_h

        # Try GetModuleHandleA as fallback (DLL may already be loaded)
        local_h = k32.GetModuleHandleA(dll_name.encode('ascii'))
        if local_h:
            return local_h

        return 0

    def _resolve_forwarded_function(self, dll_name: str, func_name: str, h: int) -> int:
        """Resolve a forwarded export (e.g., CreateNamedPipeW -> kernelbase.dll).

        When a function is forwarded, GetProcAddress returns a stub address.
        We calculate the real address in the target process by adding the
        function's offset (relative to the source DLL base) to the target
        DLL base address.
        """
        # restype/argtypes are set at module level

        # Get kernel32.dll base address in the target process
        target_kernel32_base = self._get_remote_kernel32_base(h)
        if not target_kernel32_base:
            print(f"[FORWARD DEBUG] Cannot get kernel32 base in target")
            return 0
        print(f"[FORWARD DEBUG] kernel32 base in target: 0x{target_kernel32_base:X}")

        # Get the local function address
        local_kernel32 = k32.LoadLibraryA(b"kernel32.dll")
        if not local_kernel32:
            print(f"[FORWARD DEBUG] Cannot load local kernel32")
            return 0
        local_func_addr = k32.GetProcAddress(local_kernel32, func_name.encode('ascii'))
        if not local_func_addr:
            print(f"[FORWARD DEBUG] GetProcAddress({func_name}) returned NULL")
            return 0
        print(f"[FORWARD DEBUG] Local {func_name} addr: 0x{local_func_addr:X}")

        # Check if the function is forwarded by examining if the address
        # contains a jmp instruction (FF 25 = jmp qword ptr [rip+disp32])
        try:
            instr_buf = ctypes.create_string_buffer(6)
            bytes_read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(local_func_addr), instr_buf, 6, ctypes.byref(bytes_read)):
                if instr_buf.raw[0:2] == b'\xff\x25':
                    # This is a forwarder - read the forwarder string
                    disp = struct.unpack_from('<i', instr_buf.raw, 2)[0]
                    forwarder_addr = local_func_addr + 6 + disp
                    fwd_buf = ctypes.create_string_buffer(256)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(forwarder_addr), fwd_buf, 256, ctypes.byref(bytes_read)):
                        forwarder_str = fwd_buf.raw.split(b'\x00')[0].decode('ascii', errors='ignore')
                        print(f"[FORWARD DEBUG] {func_name} forwarded to: {forwarder_str}")
                        # Parse "DLLName.FunctionName" or "DLLName.#Ordinal"
                        if '.' not in forwarder_str:
                            print(f"[FORWARD DEBUG] Invalid forwarder string: {forwarder_str}")
                            return 0
                        target_dll, target_func_name = forwarder_str.split('.', 1)
                        if not target_dll.endswith('.dll'):
                            target_dll += '.dll'

                        # Get the target DLL base in the target process
                        target_dll_base = self._get_remote_dll_base(h, target_dll)
                        if not target_dll_base:
                            print(f"[FORWARD DEBUG] Cannot get {target_dll} base")
                            return 0
                        print(f"[FORWARD DEBUG] {target_dll} base: 0x{target_dll_base:X}")

                        # Get the function address in the target DLL
                        # NOTE: The process handle might not have correct access rights
                        local_target_dll = k32.LoadLibraryA(target_dll.encode('ascii'))
                        if local_target_dll:
                            # Calculate function offset in local DLL and apply to remote base
                            local_target_func_addr = k32.GetProcAddress(local_target_dll, target_func_name.encode('ascii'))
                            if local_target_func_addr:
                                func_offset = local_target_func_addr - local_target_dll
                                target_func_addr = target_dll_base + func_offset
                                print(f"[FORWARD DEBUG] Resolved {func_name} -> {target_dll}!{target_func_name} at 0x{target_func_addr:X}")
                                return target_func_addr
                        print(f"[FORWARD DEBUG] Could not resolve forwarded function: {target_dll}!{target_func_name}")
                        return 0
        except Exception as e:
            print(f"[FORWARD DEBUG] Exception during forwarder check: {e}")
            pass

        # Not a forwarder - calculate address using offset
        func_offset = local_func_addr - local_kernel32
        target_func_addr = target_kernel32_base + func_offset
        print(f"[FORWARD DEBUG] Direct offset: {func_name} offset=0x{func_offset:X}, target_addr=0x{target_func_addr:X}")
        return target_func_addr

    def _get_remote_dll_base(self, h, dll_name: str) -> int:
        """Get the base address of a DLL in the target process."""

        # Use EnumProcessModules to find the DLL
        hMods = (ctypes.c_void_p * 1024)()
        cbNeeded = ctypes.c_ulong(0)

        psapi = ctypes.windll.psapi
        psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        psapi.EnumProcessModules.restype = ctypes.c_bool
        psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
        psapi.GetModuleBaseNameW.restype = ctypes.c_ulong

        if not psapi.EnumProcessModules(h, ctypes.cast(hMods, ctypes.c_void_p), ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
            return 0

        nMods = cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)
        dll_name_lower = dll_name.lower()
        for i in range(nMods):
            modName = (ctypes.c_wchar * 260)()
            hMod = ctypes.c_void_p(hMods[i])
            if psapi.GetModuleBaseNameW(h, hMod, modName, 260):
                if modName.value.lower() == dll_name_lower:
                    return hMods[i]

        return 0

    def _get_kernel32_via_remote_thread(self, h) -> int:
        """Fallback: get kernel32.dll base via GetModuleHandleW in target process."""

        # Get GetModuleHandleW address in target process
        local_kernel32 = k32.GetModuleHandleA(b"kernel32.dll")
        gmh_offset = k32.GetProcAddress(local_kernel32, b"GetModuleHandleW") - local_kernel32

        # We need kernel32.dll base in target process to calculate the address...
        # This is a chicken-and-egg problem. Use a different approach:
        # Read the PEB to find kernel32.dll base

        # Get PEB address
        pbi = ctypes.c_ulonglong(0)
        return 0  # TODO: implement PEB reading

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
                # Write fixed value - pass as buffer, not value
                written = ctypes.c_size_t(0)
                val_bytes = struct.pack('<Q', value)
                if not k32.WriteProcessMemory(
                    h, ctypes.c_void_p(addr),
                    val_bytes, ctypes.c_size_t(8),
                    ctypes.byref(written)
                ):
                    return False
            elif reloc_type == IMAGE_REL_BASED_HIGHLOW:
                buf = ctypes.create_string_buffer(4)
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(4), ctypes.byref(read)):
                    return False
                value = struct.unpack('<I', buf.raw)[0]
                value += delta
                written = ctypes.c_size_t(0)
                val_bytes = struct.pack('<I', value)
                if not k32.WriteProcessMemory(
                    h, ctypes.c_void_p(addr),
                    val_bytes, ctypes.c_size_t(4),
                    ctypes.byref(written)
                ):
                    return False
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
        print(f"[DLLMAIN] _call_dllmain called: base=0x{base:X}, ep_rva=0x{pe.entry_point_rva:X}, is_64bit={pe.is_64bit}")

        if pe.is_64bit:
            shellcode = _generate_dllmain_caller_x64(base, pe.entry_point_rva)
        else:
            shellcode = _generate_dllmain_caller_x86(base, pe.entry_point_rva)

        print(f"[DLLMAIN] Shellcode length: {len(shellcode)} bytes")

        # Allocate memory for shellcode
        sc_addr = k32.VirtualAllocEx(
            h, None, ctypes.c_size_t(len(shellcode)),
            ctypes.c_ulong(MEM_COMMIT | MEM_RESERVE),
            ctypes.c_ulong(PAGE_EXECUTE_READWRITE)
        )
        if not sc_addr:
            print(f"[DLLMAIN] VirtualAllocEx failed: {k32.GetLastError()}")
            return False
        print(f"[DLLMAIN] Shellcode allocated at 0x{sc_addr:X}")

        # Write shellcode
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(
            h, ctypes.c_void_p(sc_addr),
            shellcode, ctypes.c_size_t(len(shellcode)),
            ctypes.byref(written)
        ):
            err = k32.GetLastError()
            print(f"[DLLMAIN] WriteProcessMemory failed: GetLastError={err}")
            return False
        print(f"[DLLMAIN] Shellcode written: {written.value}/{len(shellcode)} bytes")

        # Flush instruction cache
        k32.FlushInstructionCache(h, ctypes.c_void_p(sc_addr), ctypes.c_size_t(len(shellcode)))

        # Cast to c_void_p for 64-bit compatibility
        sc_param = ctypes.c_void_p(sc_addr)

        # Execute
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(
            h, None, 0, sc_param, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            err = k32.GetLastError()
            k32.VirtualFreeEx(h, ctypes.c_void_p(sc_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))
            print(f"[DLLMAIN DEBUG] CreateRemoteThread failed: GetLastError={err}")
            return False
        print(f"[DLLMAIN DEBUG] Thread created: handle={h_thread}, tid={thread_id.value}")

        # Wait for DllMain to complete
        wait_result = k32.WaitForSingleObject(h_thread, 10000)
        print(f"[DLLMAIN DEBUG] WaitForSingleObject result: {wait_result} (0=success, 0x102=timeout)")
        k32.CloseHandle(h_thread)

        # Clean up shellcode
        k32.VirtualFreeEx(h, ctypes.c_void_p(sc_addr), ctypes.c_size_t(0), ctypes.c_ulong(MEM_RELEASE))
        print(f"[DLLMAIN DEBUG] DllMain execution completed")
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
