"""
DummyGame.py — A simple game to test MomoTrainerStudio memory scanning & writing.

Usage:
  python DummyGame.py

What it does:
  - Health: starts at 100, decreases by 1 every second. Write to address to stop decay.
  - Ammo:   starts at 30, decreases by 1 every second. Write to address to stop decay.
  - Gold:   starts at 5000, static (doesn't change). Write to change it.
  - Health, Ammo, Gold values are stored in ALLOCATED MEMORY (not globals) so
    they appear in a memory scan.

Keyboard controls:
  D = take 10 damage (health -= 10)
  H = heal 20 (health += 20)
  S = shoot (ammo -= 1)
  R = reload (ammo = 30)
  G = add 100 gold
  Q = quit
"""
import ctypes, time, os, sys

# ── Allocate memory and store values there ──────────────────────────────────────
# We use VirtualAlloc so the addresses are stable and in a committed page
# (not part of the Python interpreter's heap — easier to find in a scan)
PAGE_RW = 0x04

# ── Game state storage (in a heap-allocated ctypes object) ────────────────────
# We allocate a 4096-byte RW buffer via ctypes (which uses malloc under the hood).
# This goes into the Python heap (which IS writable, unlike the static data pages).
# The values 100, 30, 5000 are written to it, and the memory scanner will find
# them in a RW page.

# Create a 4096-byte ctypes buffer
_state = (ctypes.c_uint8 * 4096)()

# Typed views into the buffer
pHealth = ctypes.addressof(_state)          # offset 0
pAmmo   = pHealth + 4                       # offset 4
pGold   = pHealth + 8                       # offset 8
pName   = pHealth + 12                      # offset 12
GAME_ADDR = pHealth

def write32(addr, value):
    """Write a 32-bit int to `addr` (c_void_p — 64-bit safe)."""
    ctypes.memmove(ctypes.c_void_p(addr), ctypes.byref(ctypes.c_int32(int(value))), 4)

def read32(addr):
    """Read a 32-bit int from `addr` (c_void_p — 64-bit safe)."""
    buf = ctypes.c_int32(0)
    ctypes.memmove(ctypes.byref(buf), ctypes.c_void_p(addr), 4)
    return buf.value

# Initialise values in the heap buffer
write32(pHealth, 100)
write32(pAmmo, 30)
write32(pGold, 5000)
ctypes.memmove(ctypes.c_void_p(pName), b"PLAYER_01\x00\x00\x00\x00", 16)

print(f"[DummyGame] Game state allocated at 0x{GAME_ADDR:016X} (heap, 4096 bytes)")
print(f"[DummyGame]   Health: 0x{pHealth:016X}")
print(f"[DummyGame]   Ammo:   0x{pAmmo:016X}")
print(f"[DummyGame]   Gold:   0x{pGold:016X}")
print(f"[DummyGame] Use these addresses in MomoTrainerStudio to test!")

# ── Game state ──────────────────────────────────────────────────────────────────
health = read32(pHealth)
ammo   = read32(pAmmo)
gold   = read32(pGold)

def update_from_memory():
    """Sync Python vars from the allocated memory block."""
    global health, ammo, gold
    health = read32(pHealth)
    ammo   = read32(pAmmo)
    gold   = read32(pGold)

def sync_to_memory():
    """Write Python vars back to the allocated memory block."""
    write32(pHealth, health)
    write32(pAmmo,   ammo)
    write32(pGold,   gold)

def draw():
    """Render the game state. Uses ASCII (not Unicode) so it works
    in any console encoding (UTF-8, cp1252, etc.)."""
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        print('\n' * 40)
    bar = lambda v, m=100: '#' * (v * 20 // m) + '-' * (20 - v * 20 // m)
    print("+--------------------------------------+")
    print("|       DUMMY GAME  (MomoTrainer)     |")
    print("+--------------------------------------+")
    print(f"|  Health: {health:>4} / 100  [{bar(min(health,100))}]  0x{pHealth:08X} |")
    print(f"|  Ammo:   {ammo:>4} /  30  [{bar(min(ammo,30),30)}]  0x{pAmmo:08X}   |")
    print(f"|  Gold:   {gold:>6}                        0x{pGold:08X}   |")
    print("+--------------------------------------+")
    print("|  D = take 10 damage    H = heal +20  |")
    print("|  S = shoot (-1 ammo)  R = reload    |")
    print("|  G = +100 gold         Q = quit      |")
    print("+--------------------------------------+")
    print(f"|  All values are at 0x{GAME_ADDR:08X}    |")
    print("|  Scan these addresses in MomoStudio! |")
    print("+--------------------------------------+")

# ── Main loop ──────────────────────────────────────────────────────────────────
print("DummyGame starting...")
print(f"Allocated memory at 0x{GAME_ADDR:08X}")
time.sleep(1)

last_tick = time.time()
running = True

while running:
    now = time.time()
    # Auto-decay: health -1/s, ammo -1/s  (every 1 second)
    if now - last_tick >= 1.0:
        last_tick = now
        update_from_memory()
        health = max(0, health - 1)
        ammo   = max(0, ammo - 1)
        sync_to_memory()

    update_from_memory()
    draw()
    print(f"\nType command then press Enter: ", end='', flush=True)
    try:
        key = input().strip().upper()
    except (EOFError, KeyboardInterrupt):
        key = 'Q'

    update_from_memory()

    if key == 'D':
        health = max(0, health - 10)
        print(f"  Took 10 damage!  health now {health}")
    elif key == 'H':
        health = min(999, health + 20)
        print(f"  Healed 20!       health now {health}")
    elif key == 'S':
        if ammo > 0:
            ammo -= 1
            print(f"  Shot!             ammo now {ammo}")
        else:
            print("  No ammo! Press R to reload.")
    elif key == 'R':
        ammo = 30
        print(f"  Reloaded!         ammo now {ammo}")
    elif key == 'G':
        gold += 100
        print(f"  +100 gold!        gold now {gold}")
    elif key == 'Q':
        print("Quitting...")
        running = False
    else:
        print(f"  Unknown command: '{key}'")

    sync_to_memory()
    time.sleep(0.1)

# Cleanup
try:
    ctypes.windll.kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    ctypes.windll.kernel32.VirtualFree(pHealth, 0, 0x8000)  # MEM_RELEASE
except Exception:
    pass
print("Done!")
