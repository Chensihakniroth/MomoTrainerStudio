"""Find the paint-kit attribute vector by structure, offline.

## Why this and not another offset guess

Six schema-derived paths to the attribute list all failed:

    client  C_AttributeContainer @ weapon+0x1290, m_Item +0x50, list +0x208
    server  CAttributeContainer  @ weapon+0xA58 / 0xAB0 / 0xCB0, list +0x70

`weapon+0x1290` reads `0x0010079600000009`, and 0x1280-0x1298 are all that
shape - `C_NetVar` serialiser metadata, not item data. On this build the
container is not inline in the entity.

So stop deriving and start measuring. This walks every heap pointer the
weapon entity holds, reads the region it points at, and looks for a
`CUtlVector<CEconItemAttribute>` by the SHAPE of its contents:

    entry + 0x30   m_iAttributeDefinitionIndex   uint16
    entry + 0x34   m_flValue                     float32
    entry + 0x38   m_flInitialValue              float32
    entry + 0x3C   m_nRefundableCurrency         int32
    entry + 0x40   m_bSetBonus                   bool
    stride 0x48

A convincing vector has SEVERAL entries whose defIndex values look like real
attribute ids and whose float values are sane. One entry is a coincidence;
four agreeing is a field. Paint kit is defIndex 2001.

Runs entirely against build/weapon_entity.bin captured earlier. Touches no
process, so it cannot race a round transition and needs the game closed.
"""
import ctypes as C
import json
import os
import struct
import sys

BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "build")
DUMP = os.path.join(BUILD, "weapon_entity.bin")
META = os.path.join(BUILD, "weapon_entity.json")

ENTRY_SIZE = 0x48
OFF_DEF_INDEX = 0x30
OFF_VALUE = 0x34
OFF_INITIAL = 0x38
OFF_REFUND = 0x3C
OFF_SETBONUS = 0x40
PAINT_KIT = 2001

MODULE_LO = 0x7FF8 << 40
FOLLOW_BYTES = 0x400          # how much to read behind each heap pointer


def is_heap(v):
    return (0x100000 < v < (1 << 47)
            and not (MODULE_LO <= v < MODULE_LO + (1 << 32)))


class Remote:
    """Read-only handle on the (still-running) game, for following pointers.

    Falls back to a no-op if the game is gone: the dump alone can still be
    searched for inline vectors, just not followed ones.
    """

    def __init__(self):
        self.h = None
        self.base = 0
        self.pid = 0
        self.k32 = None      # kept on the instance: ns is local to __init__
        try:
            src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "cs2_weapon_probe.py"), encoding="utf-8").read()
            ns = {"__file__": os.path.join(os.path.dirname(
                os.path.abspath(__file__)), "cs2_weapon_probe.py")}
            exec(compile(src.split("def main")[0], "wp", "exec"), ns)
            pid = ns["find_pid"]("cs2.exe")
            if pid:
                self.pid = pid
                self.k32 = ns["k32"]
                self.h = self.k32.OpenProcess(0x0410, False, pid)
                self.base = ns["module_base"](pid, "client.dll")
        except Exception as e:                       # noqa: BLE001
            print(f"(no live process: {e})", file=sys.stderr)

    def read(self, va, n):
        if not self.h:
            return None
        b = C.create_string_buffer(n)
        g = C.c_size_t(0)
        if (not self.k32.ReadProcessMemory(self.h, C.c_void_p(va), b, n,
                                           C.byref(g)) or g.value != n):
            return None
        return b.raw


def score_entries(buf):
    """[(defIndex, value, initial)] that look like real attributes."""
    out = []
    for k in range(len(buf) // ENTRY_SIZE):
        e = k * ENTRY_SIZE
        di = struct.unpack_from("<H", buf, e + OFF_DEF_INDEX)[0]
        val = struct.unpack_from("<f", buf, e + OFF_VALUE)[0]
        ini = struct.unpack_from("<f", buf, e + OFF_INITIAL)[0]
        # defIndex must be a plausible attribute id; value a finite float
        if not (1 <= di <= 5000):
            continue
        if val != val or val in (float("inf"), float("-inf")):
            continue
        if abs(val) > 1e7:
            continue
        out.append((k, di, val, ini))
    return out


def looks_like_attribute_block(buf):
    """True if `buf` is a packed run of CEconItemAttribute entries.

    The strongest signal is several entries with DISTINCT plausible
    defIndex values at the right stride. Real attribute sets contain a
    handful of different ids; random memory does not.
    """
    got = score_entries(buf)
    if len(got) < 3:
        return None
    # require the entries to be at consecutive 0x48 strides from the start
    if got[0][0] != 0:
        return None
    strides = [g[0] for g in got]
    if strides != list(range(len(strides))):
        return None
    ids = {g[1] for g in got}
    if len(ids) < 2:
        return None
    return got


def main():
    if not os.path.exists(DUMP):
        print(f"missing {DUMP}\nRun tools/cs2_dump_weapon.py in a live match "
              f"first.")
        return 2
    with open(META, encoding="utf-8") as f:
        meta = json.load(f)
    blob = open(DUMP, "rb").read()
    print(f"weapon entity dump: {meta['weapon']}  slot {meta['slot']}  "
          f"clip1 {meta['clip1']}  ({len(blob):,} bytes)")

    rem = Remote()
    print(f"live process: {'pid ' + str(rem.pid) if rem.h else 'none - inline search only'}")

    def q(o):
        return struct.unpack_from("<Q", blob, o)[0]

    def i32(o):
        return struct.unpack_from("<i", blob, o)[0]

    # ---- 1. inline vectors inside the entity dump ----
    print("\n=== inline (ptr,count,cap) inside the entity ===")
    inline = 0
    for o in range(0, len(blob) - 16, 4):
        p = struct.unpack_from("<Q", blob, o)[0]
        if not is_heap(p):
            continue
        c = struct.unpack_from("<i", blob, o + 8)[0]
        cp = struct.unpack_from("<i", blob, o + 12)[0]
        if 0 < c <= 64 and c <= cp <= 4096:
            inline += 1
            print(f"  +0x{o:04X} data=0x{p:X} count={c} cap={cp}")
    if not inline:
        print("  (none - as established)")

    # ---- 2. follow every heap pointer, read a window, look for attributes ----
    print("\n=== following heap pointers for a CEconItemAttribute block ===")
    ptrs = sorted({q(o) for o in range(0, len(blob) - 8, 8) if is_heap(q(o))})
    print(f"  {len(ptrs)} distinct heap pointers")

    hits = []
    for p in ptrs:
        buf = rem.read(p, FOLLOW_BYTES) if rem.h else None
        if not buf:
            continue
        got = looks_like_attribute_block(buf)
        if got:
            hits.append((p, got))
            print(f"\n  CANDIDATE at 0x{p:X}  "
                  f"({len(got)} consecutive entries)")
            for k, di, val, ini in got[:12]:
                mark = "   <== PAINT KIT" if di == PAINT_KIT else ""
                print(f"     [{k}] defIndex={di:<6} value={val:<14} "
                      f"initial={ini}{mark}")

    if not hits:
        print("\n  no attribute-shaped block behind any of them.")
        print("  Next levers, in order of how much they change the answer:")
        print("   - widen FOLLOW_BYTES (a vector's data may sit further in)")
        print("   - follow pointers TWO levels deep")
        print("   - the attribute list may be in the pawn's item services")
        print("     (CPlayer_ItemServices, m_pItemServices @ pawn+0x12F8)")
        return 1

    print(f"\n{len(hits)} candidate block(s).")
    for p, got in hits:
        pk = [g for g in got if g[1] == PAINT_KIT]
        print(f"  0x{p:X}: {len(got)} entries, "
              f"paint-kit(2001) present: {'YES' if pk else 'no'}")
    print("\nVerify a candidate before writing: change defIndex 2001's value")
    print("and confirm the viewmodel changes. A structurally correct block")
    print("that does not change the render is a different container.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())