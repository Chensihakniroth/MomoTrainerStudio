"""Verify the C_EconItemView -> attribute list chain before building on it.

## Why this gate exists

`m_nFallbackPaintKit = 0x18A8` was written successfully and read back
correctly (466), but the viewmodel did not repaint. That field is the
*fallback* skin - used when the item has no attribute-set skin. The real skin
lives in the attribute list:

    weapon + 0x1290   C_AttributeContainer   (embedded, not a pointer)
      + 0x50          m_Item -> C_EconItemView
        + 0x08        CAttributeList::m_Attributes  (vector)
                      entry +0x30 m_iAttributeDefinitionIndex (uint16)
                            +0x34 m_flValue                (float32)
    defIndex 2001 = paint kit

Building an applier on that chain means writing 4 bytes inside a
game-allocated vector. Before doing that, each link is confirmed live. A
step that reads back a non-address is where the work stops - guessing past a
broken link is exactly how this project lost a day to the PAGE_READWRITE bug.

Read-only. Writes nothing.
"""
import ctypes as C
import struct
import sys

sys.path.insert(0, r"D:\game\MomoTrainerStudio\tools")
src = open(r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py", encoding="utf-8").read()
ns = {"__file__": r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py"}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
MODULE_LO = 0x7FF8 << 40           # inside client.dll: static, not heap


def is_heap(v):
    return 0x100000 < v < (1 << 47) and not (MODULE_LO <= v < MODULE_LO + (1 << 32))


def is_addr(v):
    return 0x10000 < v < (1 << 47)


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
    return struct.unpack("<i", r)[0] if r else None


def f32(va):
    r = raw(va, 4)
    return struct.unpack("<f", r)[0] if r else None


# ---- resolve the LOCAL weapon, freshly, every call ----
def local_weapon():
    el = q(base + ns["ENTITY_LIST"])
    if not is_addr(el):
        return 0, 0, "dwEntityList is not a pointer (no match running?)"
    page = q(el + ns["PAGE_OFFSET"])
    if not is_addr(page):
        return 0, 0, f"no entity page (0x{page:X}) - start a match"
    lp = q(base + ns["LOCAL_PAWN"])
    if not is_addr(lp):
        return 0, 0, f"local pawn is 0x{lp:X} - you are dead or spectating"
    ws = q(lp + 0x12F0)
    if not is_addr(ws):
        return 0, 0, f"no weapon services (0x{ws:X})"
    wsh = i32(ws + 0x60)
    if not wsh:
        return 0, 0, "m_hActiveWeapon is 0 - hold a gun, not a knife"
    wpn = q(page + ns["SLOT_STRIDE"] * (wsh & ns["HANDLE_MASK"]))
    if not is_addr(wpn):
        return 0, 0, f"weapon entity did not resolve (0x{wpn:X})"
    return wpn, page, ""


print("=== link 1: C_AttributeContainer is EMBEDDED at weapon+0x1290 ===")
wpn, page, err = local_weapon()
if not wpn:
    print(f"  FAIL: {err}")
    raise SystemExit(1)
print(f"  local weapon 0x{wpn:X}")
print(f"  container+0x50 (m_Item)     = 0x{i32(wpn + 0x12E0):X}")
print(f"  container+0x600 (token)     = {i32(wpn + 0x1890)}")
print(f"  container+0x608 (itemID)    = {q(wpn + 0x1898)}")
print(f"  m_nFallbackPaintKit+0x18A8  = {i32(wpn + 0x18A8)}")

print("\n=== link 2: find the attribute vector inside C_EconItemView ===")
item = wpn + 0x12E0
blob = raw(item, 0x600)
if not blob:
    print("  FAIL: cannot read 0x600 bytes of the item view")
    raise SystemExit(1)
print(f"  read 0x600 bytes of C_EconItemView at 0x{item:X}")

# A UtlVector is (data ptr, count int32, capacity int32). Search for the
# triple anywhere in the item view, keeping only heap data pointers with a
# plausible small count.
found = []
for off in range(0, len(blob) - 16, 4):
    ptr = struct.unpack_from("<Q", blob, off)[0]
    if not is_heap(ptr):
        continue
    cnt = struct.unpack_from("<i", blob, off + 8)[0]
    cap = struct.unpack_from("<i", blob, off + 12)[0]
    if 1 <= cnt <= 64 and cap >= cnt and cap <= 4096:
        found.append((off, ptr, cnt, cap))
print(f"  {len(found)} (ptr,count,cap) candidates in the item view")
for off, ptr, cnt, cap in found[:12]:
    print(f"    item+0x{off:04X}  data=0x{ptr:X} count={cnt} cap={cap}")

if not found:
    print("\n  No attribute vector found in C_EconItemView.")
    print("  Possible causes, in the order worth checking:")
    print("   1. m_Item is NOT at container+0x50 on this build - the schema")
    print("      dump is from a different CS2 build. Verify by locating the")
    print("      weapon's designer name string.")
    print("   2. The vector lives outside the item view, reached through a")
    print("      pointer at an offset not covered by the 0x600 byte read.")
    print("   3. The item has genuinely zero attributes (count 0), which the")
    print("      filter above rejects because it requires count >= 1.")
    raise SystemExit(2)

print("\n=== link 3: read the attribute entries ===")
for off, ptr, cnt, cap in found[:4]:
    eb = raw(ptr, 0x48 * cnt)
    if not eb:
        continue
    print(f"\n  item+0x{off:04X} count={cnt}:")
    for k in range(cnt):
        e = k * 0x48
        idx = struct.unpack_from("<H", eb, e + 0x30)[0]
        val = struct.unpack_from("<f", eb, e + 0x34)[0]
        ini = struct.unpack_from("<f", eb, e + 0x38)[0]
        print(f"    [{k}] defIndex={idx:<6} value={val:<14} initial={ini}")
    hits = [k for k in range(cnt)
            if struct.unpack_from("<H", eb, k * 0x48 + 0x30)[0] == 2001]
    if hits:
        print(f"    *** defIndex 2001 (paint kit) at entry {hits} ***")
print("\nAll links readable.")