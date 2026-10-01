"""Verify the built exe really contains a working Memory.h engine."""
import ctypes
import os
import sys

from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

# dist/ lives at the repo root, not next to this script.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
exe = os.environ.get("MOMOSTUDIO_EXE") or os.path.join(
    ROOT, "dist", "MoStudio - beta.exe")
print("exe:", exe, "(%.1f MB)" % (os.path.getsize(exe) / 1024 / 1024))

c = CArchiveReader(exe)
names = list(c.toc)
print("archive entries:", len(names))

pyz_names = [n for n in names if n.endswith('.pyz') or n == 'PYZ.pyz']
print("pyz entries:", pyz_names)
if not pyz_names:
    print("no PYZ found")
    sys.exit(1)

data = c.extract(pyz_names[0])
if isinstance(data, tuple):
    data = data[1]
with open('_embedded.pyz', 'wb') as fh:
    fh.write(data)

z = ZlibArchiveReader('_embedded.pyz')
mods = list(z.toc)
ok = True
for want in ('memory_core', 'memory_core_panel', 'memory_scanner',
             'scan_engine'):
    present = want in mods
    ok = ok and present
    print("  %-20s %s" % (want, "IN BUILT EXE" if present else "MISSING"))
# NOTE: the ZlibArchiveReader mmaps this file, so it must stay on disk
# until every extract() call below is done.

if not ok:
    sys.exit(1)

# Exec memory_core straight out of the archive against this process.
# ZlibArchiveReader.extract() returns a compiled code object, not source.
code = z.extract('memory_core')
ns = {'__name__': 'memory_core_embedded'}
exec(code, ns)
Mem = ns['Memory']

me = Mem(pid=os.getpid())
probe = bytearray(b"BUILDOK")
addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
assert me.read(addr, 'int8') == ord('B'), "embedded read failed"
me.write(addr + 0, 0x5A, 'int8')
assert probe[0:1] == b'Z', "embedded write failed"
me.write(addr + 1, 4242, 'int32')
assert me.read(addr + 1, 'int32') == 4242
me.write(addr + 5, 1.5, 'float')
assert abs(me.read(addr + 5, 'float') - 1.5) < 1e-6
print("\nembedded engine self-test: PASS")
print("  module base:", hex(me.get_module_address('')))
print("  types available:", len(ns['TYPES']))
me.close()
os.remove('_embedded.pyz')
print("\nBUILD VERIFIED")
