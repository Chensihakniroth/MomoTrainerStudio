"""Locate C_EconItemView inside C_AttributeContainer by measuring, not nesting.

## The mistake this corrects

The schema says:

    C_EconEntity::m_AttributeManager  = 0x1290   (C_AttributeContainer)
    C_AttributeContainer::m_Item       = 0x50     (C_EconItemView, by value)

so m_Item should sit at weapon + 0x1290 + 0x50 = weapon + 0x12E0. Reading
there returned 0x-727735E8, which is not a pointer - so one of the two
assumptions is wrong even though the dump and the running game are the same
build (both 14188).

Two plausible reasons, and the fix differs:

  1. `m_AttributeManager` at 0x1290 is itself a POINTER, not embedded. The
     earlier probe read 0x7FF88D88CBB8 there, which is inside client.dll -
     static storage, i.e. a global rather than the entity's own container.
  2. The container is embedded but `m_Item` is not at +0x50 on this build.

Rather than choose, this locates the item view by CONTENT. A C_EconItemView
holds the item's own identity, so the most reliable fingerprint available
without the string table is the entity's designer-name string index and a
cluster of plausible small ints. It also just walks the chain both ways and
prints what is actually there, so the layout is read off the process instead
of assumed from a header.

Read-only.
"""
import ctypes as C
import struct
import sys

sys.path.insert(0, r"D:\game\MomoTrainerStudio\tools")
src = open(r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py", encoding="utf-8").read()
ns = {"__file__": r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py"}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
MODULE_LO = 0x7FF8 << 40


def is_addr(v):
    return 0x10000 < v < (1 << 47)


def is_heap(v):
    return is_addr(v) and not (MODULE_LO <= v < MODULE_LO + (1 << 32))


pid = ns["find_pid"]("cs2.exe")
if not pid:
    print("cs2.exe not running")
    raise SystemExit(2)
h = k32.OpenProcess(0x0410, False, pid)
base = ns["module_base"](pid, "client.dll")


def raw(va, n):
    b = C.create_string_buffer(n)
    g = C.c_size_t(0)
    if (not k32.ReadProcessMemory(h, C.c_void_p(va), b, n, C.byref(g))
            or g.value != n):
        return None
    return b.raw


def q(va):
    r = raw(va, 8)
    return struct.unpack("<Q", r)[0] if r else 0


def i32(va):
    r = raw(va, 4)
    return struct.unpack_from("<i", r)[0] if r else 0


el = q(base + ns["ENTITY_LIST"])
page = q(el + ns["PAGE_OFFSET"])
lp = q(base + ns["LOCAL_PAWN"])
ws = q(lp + 0x12F0)
wsh = i32(ws + 0x60)
wpn = q(page + ns["SLOT_STRIDE"] * (wsh & ns["HANDLE_MASK"]))
print(f"local weapon 0x{wpn:X}   (client.dll 0x{base:X})\n")

print("=== is m_AttributeManager a pointer or embedded? ===")
at1290 = q(wpn + 0x1290)
print(f"  *(weapon+0x1290) = 0x{at1290:X}")
if MODULE_LO <= at1290 < MODULE_LO + (1 << 32):
    print("    -> inside client.dll: a GLOBAL, not the entity's container")
    print("    -> so the container is EMBEDDED at 0x1290, and m_Item")
    print("       should be at 0x1290+0x50 = 0x12E0")
else:
    print("    -> looks like a heap pointer")

print("\n=== raw bytes of the container region 0x1290..0x1340 ===")
blob = raw(wpn + 0x1290, 0xB0)
if not blob:
    print("  cannot read")
    raise SystemExit(1)
for off in range(0, 0xB0, 16):
    row = blob[off:off + 16]
    hexs = " ".join(f"{b:02X}" for b in row)
    ints = [struct.unpack_from("<i", row, k)[0] for k in (0, 4, 8, 12)]
    print(f"  +0x{0x1290 + off:04X}: {hexs}   "
          + " ".join(f"{v:>12}" for v in ints))

print("\n=== hunting the attribute vector across weapon+0x1200..0x1A00 ===")
big = raw(wpn + 0x1200, 0x800)
if not big:
    print("  cannot read")
    raise SystemExit(1)
for off in range(0, len(big) - 16, 4):
    ptr = struct.unpack_from("<Q", big, off)[0]
    if not is_heap(ptr):
        continue
    cnt = struct.unpack_from("<i", big, off + 8)[0]
    cap = struct.unpack_from("<i", big, off + 12)[0]
    if 1 <= cnt <= 64 and cnt <= cap <= 4096:
        print(f"  weapon+0x{0x1200 + off:04X}  data=0x{ptr:X} count={cnt} cap={cap}")
        eb = raw(ptr, 0x48 * cnt)
        if eb:
            for k in range(cnt):
                e = k * 0x48
                idx = struct.unpack_from("<H", eb, e + 0x30)[0]
                val = struct.unpack_from("<f", eb, e + 0x34)[0]
                ini = struct.unpack_from("<f", eb, e + 0x38)[0]
                print(f"      [{k}] defIndex={idx:<6} value={val:<14} initial={ini}")

print("\n=== designer-name index: CEntityIdentity is at weapon+0 ===")
for off in (0x8, 0xC, 0x10, 0x14, 0x18, 0x1C):
    print(f"  weapon+0x{off:02X} = {i32(wpn + off)} (u16 "
          f"{struct.unpack_from('<H', raw(wpn + off, 2))[0]})")