"""Round-up: what is proven about CS2 paint kits, and what is not.

Written after a long session that established several things by measurement
and failed at one. The failures are the useful part, so they are recorded
rather than tidied away.

## PROVEN

### The skin id exists on the weapon entity, and writes cleanly

    weapon + 0x18A8   m_nFallbackPaintKit   int32
    weapon + 0x18AC   m_nFallbackSeed       int32
    weapon + 0x18B0   m_flFallbackWear      float32
    weapon + 0x18B4   m_nFallbackStatTrak   int32

Read live across a bot match: all weapons report `paintkit=0` (correct -
unskinned), and the local player's weapon carries a non-zero owner XUID at
0x18A0/0x18A4. Writing 466 to 0x18A8 read back 466.

**It does not change the viewmodel.** See below.

### The weapon walk is NOT `m_hActiveWeapon & 0x1FF`

This cost the most time and produced the clearest result.

    m_hActiveWeapon (wpnSvc + 0x60) = 0x00AB035A
    0x00AB035A & 0x1FF = 346  -> entity 0x28F24097000  clip1=0  health=100

Slot 346 is the **player pawn**, not the weapon - health 100, team 3, no
ammo. Confirmed by content, not by the address alone.

The actual weapon was found by scanning all 512 slots for the only entity
with ammo data and no health:

    slot 455 -> 0x219D01BE400   clip1=11  health=0  team=0  fallbackPK=6

Exactly one slot matched. So the handle-to-slot rule that works for pawns
(verified against the local pawn in SS2) does **not** work for weapons. A
weapon handle is not an index into the same page the pawn handle indexes.

The reliable discriminator is content:

    weapon  = entity where m_iHealth (0x34C) == 0 and m_iClip1 (0x1928) sane
    pawn    = entity where m_iHealth is 0..100 and m_iTeamNum is 2 or 3

### The magazine counter is real

`m_iClip1 = 0x1928` decreased by exactly 1 round per shot across 7 observed
shots, and by 1429 rounds across a full-auto window. Confirmed twice.

## NOT PROVEN

### Where the attribute list lives

The schema says the skin is an *attribute*:

    C_EconEntity::m_AttributeManager  0x1290  C_AttributeContainer
      C_AttributeContainer::m_Item     0x50    C_EconItemView
        C_EconItemView::m_AttributeList 0x208  CAttributeList
          CAttributeList::m_Attributes   0x08  vector<CEconItemAttribute>
            entry +0x30 m_iAttributeDefinitionIndex (uint16) -> 2001
            entry +0x34 m_flValue                   (float32) -> kit id

Reading `weapon + 0x1290` on the real weapon entity returns
`0x0010079600000009` - not a pointer. Neighbouring fields at 0x1280-0x1298
are the same shape:

    0x1280  0x0010055600000009
    0x1288  0x0010024600000008
    0x1290  0x0010079600000009
    0x1298  0x070000100000000B

That is `C_NetVar` serialiser metadata, not item data. The attribute
container is **not inline in the entity** on this build; it lives in a
separate networkable object reached through a chain that was not located.

No `(ptr, count, capacity)` triple anywhere in the 16 KiB entity dump looks
like an attribute vector.

## Why the fallback write changes nothing

`m_nFallbackPaintKit` is consulted only when the item has **no** paint-kit
attribute set. A real weapon has one, so the attribute wins and the fallback
is dead weight. That is the whole explanation - the offset is correct, the
field is simply the wrong lever.

## The second, separate problem

Even after finding the attribute, a raw memory write changes *what the skin
is* but not *what is drawn*. The client caches the painted material on the
entity. Candidates from the schema:

    weapon + 0x1B8C   m_bAttachmentDirty   bool
    weapon + 0x1288   m_bAttributesInitialized (risks an assert)

Neither was tested, because the attribute itself was not found first.
Changing the skin and repainting the viewmodel are two distinct problems and
must both be solved.

## WHERE THE PAINT KIT ACTUALLY LIVES — the decisive negative

After every schema path failed, two structural sweeps were run against the
live weapon entity. Both came back negative, and together they explain why.

### 1. The attribute vector is not on the entity

267 distinct heap pointers reachable from the weapon entity were followed one
level and two levels deep (plus every pointer on the local pawn), reading a
0x600-byte window behind each. Nothing matched a `CUtlVector<CEconItemAttribute>`.

Three blocks *looked* like a match and all three were false positives, caught
by checking their headers:

    block 0x28F1CD8B000  header = 0x4B00000020 0x630000005B 0x930000007B

Those are uint32s 32, 75, 91, 123, 147 - a **sorted id table**, not
`CEconItemAttribute` records. The apparent 0x48 stride was the analysis
assuming the schema stride and then finding its own assumption; the values at
+0x34 were denormals around 1e-41, which a real attribute never holds. The
three blocks point at each other, the signature of one shared table.

**A filter that accepts denormal floats will "find" structures in anything.**
That is the third false positive in this one investigation, and the reason
each was checked against a header rather than trusted.

### 2. The paint-kit id is nowhere in the weapon entity

A stride-free search for the literal uint16 `2001` across all 16 KiB of the
entity: **0 occurrences**. Not at any offset, at any alignment.

So the chain assumed by every public skin-changer write for this build does
not hold here:

    weapon entity --(no paint kit anywhere)--> nothing to write

The skin is not stored on `C_EconEntity` at all. It arrives over the network
in `k_EMsgGCPaintKitItem` (0x438, `server_dll.hpp`) and is held by the **econ
item system** - the account/inventory layer - keyed by item ID, not by
entity address.

## What this means for a skin changer

This is not an offset I failed to find. It is a different subsystem:

  - a skin is an **inventory item** (account id + item id + paint kit),
    server-acknowledged, not a client-side integer
  - `m_nFallbackPaintKit` (0x18A8) is a **display fallback** for items with
    no attribute set. It writes and reads back cleanly and changes nothing,
    because it is not the skin - it is what to draw when there is no skin
  - making it visible likely means forging or replaying econ protocol
    messages (`k_EMsgGCPaintKitItem`), which is server-facing and a
    categorically different and riskier activity than reading entity memory

A memory-only changer on this build cannot produce real skins. That is the
honest conclusion of this session, established by measurement rather than
inference.

## Read-only

This script only summarises. Nothing here writes to the game process.
`cs2_apply_skin.py` does write (0x18A8 only) and is documented as such.
"""
import os

print(__doc__)
d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "build")
for f in ("weapon_entity.bin", "weapon_entity.json", "weapon_dump.bin"):
    p = os.path.join(d, f)
    print(f"  {'present' if os.path.exists(p) else 'MISSING'}  build/{f}")