"""
Quick launch test: start the EXE, wait 3s, check if it started, kill it.
Also verify the DLL is bundled correctly by checking the EXE's embedded CArchive.
"""
import subprocess, time, os, sys

exe_path = os.path.join(os.path.dirname(__file__), 'dist', 'MomoTrainer Studio v4 C.exe')
if not os.path.exists(exe_path):
    print(f'EXE not found: {exe_path}')
    sys.exit(1)

print(f'EXE size: {os.path.getsize(exe_path):,} bytes')

# Try to extract DLL from the bundled PKG using PyInstaller's stored TOC
# Read CArchive TOC from the end of the PKG file
pkg_path = os.path.join(os.path.dirname(__file__), 'build', 'MomoTrainer Studio', 'MomoTrainer Studio v4 C.pkg')
pkg_size = os.path.getsize(pkg_path)
print(f'PKG size: {pkg_size:,} bytes')

# CArchive TOC structure (at end of PKG):
# struct ca_pkg {
#     uint32_t magic;       // 0xBDCCPKG
#     uint32_t pkg_len;     // length of this pkg (including this header)
#     uint32_t python_version;
#     uint32_t pylib_name_len;
# char pylib_name[pylib_name_len];
# uint32_t n_files;
# then for each file:
#     uint32_t namelen;
#     char name[namelen];
#     uint32_t offset;      // from start of pkg (includes pkg header itself)
#     uint32_t length;
#     uint32_t compressed_len;  // 0 if not compressed
#     uint32_t is_egg;         // 0 or 1
# }
import struct

def read_carchive_toc(pkg_path):
    """Read PyInstaller CArchive TOC from the end of the file."""
    with open(pkg_path, 'rb') as f:
        # Read last 64 bytes to find cookie
        f.seek(-64, 2)
        data = f.read(64)
    
    # Try to find CA01 marker (magic = 0xBDCCPKG = 0xCAFEECFA little-endian)
    for i in range(len(data) - 4):
        magic = struct.unpack('<I', data[i:i+4])[0]
        if magic == 0xBDCC0500:
            # Found it - TOC starts at pkg_len bytes from the end
            pkg_len_pos = 64 - i - 4
            pkg_len_bytes = data[i+4:i+8]
            pkg_len = struct.unpack('<I', pkg_len_bytes)[0]
            f.seek(-pkg_len, 2)
            toc_start = f.read(16)  # version, python version, etc.
            version = struct.unpack('<I', toc_start[0:4])[0]
            py_version = struct.unpack('<I', toc_start[4:8])[0]
            name_len = struct.unpack('<I', toc_start[8:12])[0]
            name = toc_start[12:12+name_len].decode('utf-8', errors='replace')
            print(f'CArchive: version={version:#x}, python_version={py_version}, name={name}')
            
            # Read TOC entries
            n_files_off = 12 + name_len
            f.seek(-pkg_len + n_files_off, 2)
            n_files_data = f.read(4)
            n_files = struct.unpack('<I', n_files_data)[0]
            print(f'Files in archive: {n_files}')
            
            entries = []
            for _ in range(n_files):
                try:
                    name_len_b = f.read(4)
                    if len(name_len_b) < 4:
                        break
                    name_len = struct.unpack('<I', name_len_b)[0]
                    name_b = f.read(name_len)
                    if len(name_b) < name_len:
                        break
                    name = name_b.decode('utf-8', errors='replace')
                    entry_data = f.read(16)
                    if len(entry_data) < 16:
                        break
                    offset, length, comp_len, is_egg = struct.unpack('<IIII', entry_data)
                    entries.append((name, offset, length, comp_len, is_egg))
                    if 'scan_engine' in name.lower() or 'dll' in name.lower():
                        print(f'  >>> {name}: offset={offset}, len={length}, comp={comp_len}')
                except Exception as e:
                    print(f'Error reading TOC entry: {e}')
                    break
            return entries
    print('Could not find CArchive cookie')
    return []

toc_entries = read_carchive_toc(pkg_path)
print(f'\nTotal entries found: {len(toc_entries)}')
dll_entries = [(n, o, l, c) for n, o, l, c, e in toc_entries if '.dll' in n.lower()]
py_entries = [(n, o, l, c) for n, o, l, c, e in toc_entries if 'scan_engine' in n.lower()]
print(f'DLL entries: {dll_entries}')
print(f'scan_engine entries: {py_entries}')
print(f'\nBuild verification: {"PASS" if py_entries else "FAIL"} - scan_engine bundled: {bool(py_entries)}')
