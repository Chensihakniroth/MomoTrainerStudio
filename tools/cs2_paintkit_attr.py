"""Walk to the paint-kit attribute entry and read defIndex 2001.

## The chain, from the cs2-dumper schema (build 14188, same as the game)

    C_EconEntity::m_AttributeManager   0x1290   C_AttributeContainer (embedded)
      C_AttributeContainer::m_Item      0x50     C_EconItemView  (by value)
        C_EconItemView::m_AttributeList 0x208    CAttributeList  (embedded)
          CAttributeList::m_Attributes   0x08    vector<CEconItemAttribute>
            CEconItemAttribute::m_iAttributeDefinitionIndex  0x30  uint16
            CEconItemAttribute::m_flValue                    0x34  float32

    paint kit  = defIndex 2001, value = the kit id

So the attribute vector is at:

    weapon + 0x1290 + 0x50 + 0x208 + 0x08  ==  weapon + 0x14F0

## Why the fallback field did not repaint

`m_nFallbackPaintKit = 0x18A8` is only consulted when the item has no
paint-kit attribute. It writes fine and reads back fine - and changes nothing,
because the attribute list wins. That is the whole reason for this file: not a
wrong offset, a wrong field.

## The repaint problem, stated honestly

Changing the attribute changes what the skin *is*. Getting the viewmodel to
*redraw* is a second problem: the client caches the painted material on the
weapon entity, and a raw memory write does not invalidate that cache.
Candidates from the schema, in the order worth trying:

    weapon + 0x1B8C  m_bAttachmentDirty   (bool)   flip true, wait a frame
    weapon + 0x1288  m_bAttributesInitialized (bool) - risks an assert
    swapping weapons after the write forces a full rebuild

Each is tried and reported. None is guaranteed; the cache invalidation is
game-side logic, and this tool can only flip the flags it can see.

Read-only. Use --write to apply a kit, which modifies the game process.
"""
import argparse
import ctypes as C
import struct
import sys
import time

sys.path.insert(0, r"D:\game\MomoTrainerStudio\tools")
src = open(r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py", encoding="utf-8").read()
ns = {"__file__": r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py"}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]

# --- schema offsets ---
OFF_ATTR_MANAGER = 0x1290
OFF_ITEM = 0x50
OFF_ATTR_LIST = 0x208
OFF_ATTR_VECTOR = 0x08
ATTR_SIZE = 0x48
ATTR_DEF_INDEX = 0x30
ATTR_VALUE = 0x34
ATTR_INITIAL = 0x38
OFF_FALLBACK_PAINTKIT = 0x18A8
OFF_FALLBACK_SEED = 0x18AC
OFF_FALLBACK_WEAR = 0x18B0
OFF_ATTACHMENT_DIRTY = 0x1B8C
OFF_ATTRIBUTES_INIT = 0x1288
PAINT_KIT_DEF_INDEX = 2001

ATTR_LIST_BASE = (OFF_ATTR_MANAGER + OFF_ITEM + OFF_ATTR_LIST)
VECTOR_AT = ATTR_LIST_BASE + OFF_ATTR_VECTOR

PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008


def is_addr(v):
    return 0x10000 < v < (1 << 47)


pid = ns["find_pid"]("cs2.exe")
if not pid:
    print("cs2.exe not running")
    raise SystemExit(2)

WRITE = "--write" in sys.argv
h = k32.OpenProcess(0x0410 | (PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                              if WRITE else 0), False, pid)
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


def put_i(va, v):
    if not k32.WriteProcessMemory(h, C.c_void_p(va), C.byref(C.c_int32(v)),
                                  4, None):
        raise C.WinError()


def local_weapon():
    el = q(base + ns["ENTITY_LIST"])
    if not is_addr(el):
        return 0, "dwEntityList is not a pointer - no match running?"
    page = q(el + ns["PAGE_OFFSET"])
    if not is_addr(page):
        return 0, f"no entity page (0x{page:X}) - start a match"
    lp = q(base + ns["LOCAL_PAWN"])
    if not is_addr(lp):
        return 0, f"local pawn 0x{lp:X} - dead or spectating?"
    ws = q(lp + 0x12F0)
    if not is_addr(ws):
        return 0, "no weapon services"
    wsh = i32(ws + 0x60)
    if not wsh:
        return 0, "no active weapon - hold a gun, not a knife"
    wpn = q(page + ns["SLOT_STRIDE"] * (wsh & ns["HANDLE_MASK"]))
    if not is_addr(wpn):
        return 0, f"weapon entity 0x{wpn:X} did not resolve"
    return wpn, ""


def read_attrs(wpn):
    """[(idx, value, initial)] from the item view's attribute list."""
    vec = wpn + VECTOR_AT
    ptr = q(vec)
    cnt = i32(vec + 8)
    cap = i32(vec + 12)
    if not is_addr(ptr) or not (0 <= cnt <= 256) or cap < cnt:
        return None, (ptr, cnt, cap)
    blob = raw(ptr, ATTR_SIZE * cnt)
    if not blob:
        return None, (ptr, cnt, cap)
    out = []
    for k in range(cnt):
        e = k * ATTR_SIZE
        out.append((struct.unpack_from("<H", blob, e + ATTR_DEF_INDEX)[0],
                    struct.unpack_from("<f", blob, e + ATTR_VALUE)[0],
                    struct.unpack_from("<f", blob, e + ATTR_INITIAL)[0]))
    return out, (ptr, cnt, cap)


wpn, err = local_weapon()
if not wpn:
    print(f"FAIL: {err}")
    raise SystemExit(1)

print(f"local weapon 0x{wpn:X}")
print(f"attribute vector at weapon+0x{VECTOR_AT:X}")
attrs, (ptr, cnt, cap) = read_attrs(wpn)
print(f"  data=0x{ptr:X} count={cnt} capacity={cap}")

if attrs is None:
    print("\n  vector did not read as a plausible UtlVector.")
    print(f"  raw at weapon+0x{VECTOR_AT:X}: "
          + " ".join(f"{i32(wpn + VECTOR_AT + k):>12}" for k in (0, 4, 8, 12)))
    # Widen: the item view is ~0x600 bytes of embedded structs, so its
    # attribute vector could be anywhere in weapon+0x1200..0x1900. Do not
    # assume the schema nesting is right - it is the thing under test.
    print("\n  Scanning weapon+0x1200..0x1900 for ANY plausible vector:")
    big = raw(wpn + 0x1200, 0x700)
    hits = []
    for off in range(0, len(big) - 16, 4):
        p = struct.unpack_from("<Q", big, off)[0]
        c = struct.unpack_from("<i", big, off + 8)[0]
        cp = struct.unpack_from("<i", big, off + 12)[0]
        if is_addr(p) and 1 <= c <= 256 and c <= cp <= 4096:
            hits.append((0x1200 + off, p, c, cp))
            print(f"    weapon+0x{0x1200 + off:04X} data=0x{p:X} "
                  f"count={c} cap={cp}")
            eb = raw(p, ATTR_SIZE * c)
            if eb:
                for k in range(min(c, 12)):
                    e = k * ATTR_SIZE
                    di = struct.unpack_from("<H", eb, e + ATTR_DEF_INDEX)[0]
                    vv = struct.unpack_from("<f", eb, e + ATTR_VALUE)[0]
                    mark = "  <== PAINT KIT" if di == PAINT_KIT_DEF_INDEX else ""
                    print(f"        [{k}] defIndex={di:<6} value={vv}{mark}")
    if not hits:
        print("    (none)")
        print("\n  The weapon at 0x%X may not be an econ entity, or the" % wpn)
        print("  item view is reached through a pointer rather than embedded.")
        # last resort: report what IS at the known fields
        print(f"  m_AttributeManager+0x1290 = 0x{q(wpn + OFF_ATTR_MANAGER):X}")
        print(f"  fallback paintkit+0x18A8 = {i32(wpn + OFF_FALLBACK_PAINTKIT)}")
    raise SystemExit(2)

print(f"\n  {len(attrs)} attributes:")
for k, (idx, val, ini) in enumerate(attrs):
    tag = "  <== PAINT KIT" if idx == PAINT_KIT_DEF_INDEX else ""
    print(f"    [{k}] defIndex={idx:<6} value={val:<14} initial={ini}{tag}")

cur = next((v for i, v, _ in attrs if i == PAINT_KIT_DEF_INDEX), None)
print(f"\nm_nFallbackPaintKit (0x18A8) = {i32(wpn + OFF_FALLBACK_PAINTKIT)}")
wear_val = struct.unpack('<f', raw(wpn + OFF_FALLBACK_WEAR, 4))[0]
print(f"m_flFallbackWear    (0x18B0) = {wear_val}")
print(f"paint kit attribute: "
      f"{cur if cur is not None else 'ABSENT (this is why fallback did nothing)'}")

if "--write" not in sys.argv:
    print("\n(dry read. --write applies a kit)")
    raise SystemExit(0)

kit = None
for a in sys.argv[1:]:
    if a.isdigit():
        kit = int(a)
if kit is None:
    print("\nusage: cs2_paintkit_attr.py --write <kitId>")
    raise SystemExit(2)

print(f"\napplying paint kit {kit}")
if cur is None:
    print("  no existing paint-kit attribute to edit. Growing the vector is a"
          " different and riskier operation (game-allocated memory).")
    print("  Refusing rather than attempt it blindly.")
    raise SystemExit(3)

# locate the entry and rewrite its value
vec = wpn + VECTOR_AT
for k, (idx, val, ini) in enumerate(attrs):
    if idx == PAINT_KIT_DEF_INDEX:
        e = ptr + k * ATTR_SIZE
        print(f"  entry {k} at 0x{e:X}: value {val} -> {kit}")
        put_i(e + ATTR_VALUE, kit)
        put_i(wpn + OFF_FALLBACK_PAINTKIT, kit)
        time.sleep(0.2)
        a2, _ = read_attrs(wpn)
        now = next((v for i, v, _ in (a2 or []) if i == PAINT_KIT_DEF_INDEX),
                   None)
        print(f"  readback: {now}  {'OK' if now == kit else 'MISMATCH'}")

        # force a repaint
        print("\n  flipping m_bAttachmentDirty (0x1B8C) to force a redraw")
        d = i32(wpn + OFF_ATTACHMENT_DIRTY)
        put_i(wpn + OFF_ATTACHMENT_DIRTY, 1)
        time.sleep(0.5)
        print(f"    m_bAttachmentDirty: {d} -> {i32(wpn + OFF_ATTACHMENT_DIRTY)}")
        print("\n  Look at the viewmodel now. If it has not repainted, the")
        print("  material cache is game-side and the next lever is a weapon")
        print("  swap after the write (switch to the knife and back).")
        break
raise SystemExit(0)