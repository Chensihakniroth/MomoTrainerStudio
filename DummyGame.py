#!/usr/bin/env python3
"""
DummyGame.py - Enhanced writable heap memory test target with pointer chains.

Run this in a separate terminal while studio_gui.py connects to it.
Has automated test scenario that creates pointer chains and can be used to test narrow/rescan.
"""

import ctypes
import struct
import time
import os
import sys
from ctypes import wintypes as w

# ============================================================
# Win32 Bindings
# ============================================================
k32 = ctypes.WinDLL("kernel32", use_last_error=True)

VirtualAlloc = k32.VirtualAlloc
VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
VirtualAlloc.restype = ctypes.c_void_p

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# ============================================================
# Player Struct
# ============================================================
class PlayerStruct:
    SIZE = 16
    
    def __init__(self, hp, mana, level, xp):
        self.hp = hp
        self.mana = mana
        self.level = level
        self.xp = xp
        
    def pack(self):
        return struct.pack('<HHB7xI', self.hp, self.mana, self.level, self.xp)
    
    @staticmethod
    def unpack(data):
        if len(data) < PlayerStruct.SIZE:
            return None
        hp, mana, level, xp = struct.unpack('<HHB7xI', data[:PlayerStruct.SIZE])
        return PlayerStruct(hp, mana, level, xp)
    
    def __repr__(self):
        return f"Player(HP={self.hp}, Mana={self.mana}, Lvl={self.level}, XP={self.xp})"


# ============================================================
# Game World
# ============================================================
class DummyGameWorld:
    def __init__(self):
        self.players = []
        self.enemies = []
        self.allocations = []
        
    def allocate(self, size):
        addr = VirtualAlloc(None, size, MEM_COMMIT, PAGE_READWRITE)
        if not addr:
            raise RuntimeError(f"VirtualAlloc failed: {ctypes.get_last_error()}")
        self.allocations.append((addr, size))
        return addr
    
    def write_struct_at(self, addr, data):
        memmove = ctypes.memmove
        memmove(addr, data, len(data))
    
    def read_struct_at(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, addr, size)
        return buf.raw
    
    def spawn_player(self, hp, mana, level, xp):
        addr = self.allocate(PlayerStruct.SIZE)
        player = PlayerStruct(hp, mana, level, xp)
        self.write_struct_at(addr, player.pack())
        self.players.append((addr, player))
        print(f"[SPAWN] Player @ 0x{addr:X}: {player}")
        return addr
    
    def spawn_enemy(self, health, damage, enemy_id):
        addr = self.allocate(12)
        # Health (uint32) | Damage (uint32) | Enemy ID (uint16) | Padding (2)
        enemy = struct.pack('<IIH2x', health, damage, enemy_id)
        self.write_struct_at(addr, enemy)
        self.enemies.append((addr, enemy))
        print(f"[SPAWN] Enemy @ 0x{addr:X}: health={health}, dmg={damage}, id={enemy_id}")
        return addr
    
    def spawn_pointer_chain(self, base_addr, hp_target=0xDEADBEEF):
        """Create a pointer chain: base_addr -> p1 -> p2 -> target_with_hp
        
        Chain layout:
        base_addr[0x10] = addr_of_p1
        p1[0x200] = addr_of_p2
        p2[0x300] = addr_of_target
        target[0x300] = hp_target value
        """
        try:
            # Allocate intermediate addresses
            p1 = self.allocate(0x400)
            p2 = self.allocate(0x400)
            target = self.allocate(0x400)
            
            # Write the pointer chain
            # base_addr + 0x100 -> p1
            ctypes.windll.kernel32.WriteProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                base_addr + 0x100,
                struct.pack('<Q', p1),
                8, ctypes.byref(ctypes.c_size_t())
            )
            # p1 + 0x200 -> p2
            ctypes.windll.kernel32.WriteProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                p1 + 0x200,
                struct.pack('<Q', p2),
                8, ctypes.byref(ctypes.c_size_t())
            )
            # p2 + 0x300 -> target
            ctypes.windll.kernel32.WriteProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                p2 + 0x300,
                struct.pack('<Q', target),
                8, ctypes.byref(ctypes.c_size_t())
            )
            # target + 0x300 = HP value
            ctypes.windll.kernel32.WriteProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                target + 0x300,
                struct.pack('<I', hp_target),
                4, ctypes.byref(ctypes.c_size_t())
            )
            
            print(f"[CHAIN] Created pointer chain at {base_addr:X} -> p1@p1+0x100 -> p2@p2+0x200 -> target@target+0x300 -> hp=0x{hp_target:X}")
            return target
        except Exception as e:
            print(f"[CHAIN ERROR] {e}")
            return None


def main():
    print(f"[START] PID: {os.getpid()}")
    world = DummyGameWorld()
    
    # Scenario 1: Basic player
    print("\n=== Scenario 1: Basic player ===")
    player1 = world.spawn_player(100, 50, 5, 10000)
    player2 = world.spawn_player(200, 100, 10, 25000)
    
    # Scenario 2: Pointer chain with HP
    print("\n=== Scenario 2: Pointer chain with HP ===")
    # Allocate a base that will be the starting pointer
    base = world.allocate(0x1000)
    world.spawn_pointer_chain(base, hp_target=0xDEADBEEF)
    
    # Scenario 3: Multiple identical players
    print("\n=== Scenario 3: Multiple identical players ===")
    for i in range(3):
        world.spawn_player(100 + i*10, 50 + i*5, 5 + i, 10000 + i*1000)
    
    # Keep running - press Ctrl+C to exit
    print("\n[READY] DummyGame running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EXIT] DummyGame stopped.")


if __name__ == '__main__':
    main()