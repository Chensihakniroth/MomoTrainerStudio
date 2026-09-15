"""
pro_gui.py — Advanced GUI windows for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Windows:
  - AutoAssemblerWindow    — inject custom ASM/code from a text editor
  - StructureVisualizer    — struct tree with expandable pointer chains
  - CTFileImporter         — import Cheat Engine .CT table files
  - SignatureDatabaseGUI   — store/manage AOB patterns per game
  - MemoryRegionMapWindow  — visual memory map with protection flags
  - SpeedhackWindow        — speed slider with real-time control
  - ScriptRecorderWindow   — record actions → export script
  - SessionDialogs         — save/load session dialogs
  - GroupScanDialog        — scan for multiple values at once
  - MultiProcessWatchWindow — watch addresses across multiple processes
"""

import json
import os
import struct
import threading
import time
import ctypes
import tkinter as tk
from collections import OrderedDict
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Optional, Tuple

import advanced_features as af
import debugger_toolkit as dbk
import memory_scanner as ms
import pro_tools as pt


# ============================================================
# Auto-Assembler GUI
# ============================================================

class AutoAssemblerWindow(tk.Toplevel):
    """
    Inject custom code into the target process.
    Supports raw hex bytes or simple ASM-like syntax.
    """

    def __init__(self, parent, pid: int, process_handle=None):
        super().__init__(parent)
        self.title("⚡ Auto-Assembler")
        self.geometry("600x480")
        self.configure(bg="#1e1e1e")
        self.pid = pid
        self.h_process = process_handle
        self.asm = af.AutoAssembler(pid, process_handle)

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "font": ("Segoe UI", 9), "relief": "flat", "padx": 8, "pady": 2}

        tk.Button(toolbar, text="💉 Inject", bg="#238636", fg="#ffffff", **btn, command=self._inject).pack(side='left', padx=2)
        tk.Button(toolbar, text="▶ Execute", bg="#1f6feb", fg="#ffffff", **btn, command=self._execute).pack(side='left', padx=2)
        tk.Button(toolbar, text="🗑 Free All", **btn, command=self._free_all).pack(side='left', padx=2)
        tk.Button(toolbar, text="📋 Presets", **btn, command=self._show_presets).pack(side='left', padx=2)

        self.status = tk.Label(toolbar, text="", bg="#262626", fg="#909090", font=("Segoe UI", 9))
        self.status.pack(side='right', padx=8)

        # Code editor
        tk.Label(self, text="Code / Hex Bytes:", bg="#1e1e1e", fg="#8b949e",
                 font=("Segoe UI", 9)).pack(anchor='w', padx=10, pady=(4, 0))

        self.editor = tk.Text(self, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10),
                               insertbackground="#58a6ff", relief="flat", height=15,
                               selectbackground="#1f6feb", wrap="none")
        self.editor.pack(fill='both', expand=True, padx=10, pady=4)

        # Info
        info = tk.Label(self, text="Enter hex bytes (e.g. 90 90 90) or use presets",
                          bg="#1e1e1e", fg="#8b949e", font=("Consolas", 8))
        info.pack(anchor='w', padx=10, pady=(0, 4))

    def _parse_input(self) -> Optional[bytes]:
        """Parse editor content into bytes."""
        text = self.editor.get('1.0', 'end').strip()
        if not text:
            return None

        # Remove comments
        lines = []
        for line in text.split('\n'):
            # Remove // comments
            idx = line.find('//')
            if idx >= 0:
                line = line[:idx]
            lines.append(line.strip())
        text = ' '.join(lines)

        # Try hex parse
        parts = text.split()
        try:
            return bytes(int(p, 16) for p in parts)
        except ValueError:
            messagebox.showerror("Parse Error", "Invalid hex bytes. Use format: 90 90 90 or // comment")
            return None

    def _inject(self):
        data = self._parse_input()
        if not data:
            return
        addr = self.asm.inject_bytes(data)
        if addr:
            self.status.config(text=f"Injected {len(data)}B @ 0x{addr:X}", fg="#3fb950")
        else:
            self.status.config(text="Injection failed", fg="#f85149")

    def _execute(self):
        """Execute the last injected address."""
        if not self._allocations:
            messagebox.showinfo("Execute", "No allocations. Inject code first.")
            return
        last_addr = self._allocations[-1]
        result = self.asm.create_thread(last_addr)
        self.status.config(text=f"Thread {'started' if result else 'failed'} @ 0x{last_addr:X}",
                            fg="#3fb950" if result else "#f85149")

    def _free_all(self):
        self.asm.cleanup()
        self.status.config(text="All allocations freed", fg="#d29922")

    @property
    def _allocations(self):
        return [a for a, _ in self.asm._allocations]

    def _show_presets(self):
        menu = tk.Menu(self, tearoff=0)
        presets = [
            ("NOP Sled (16)", b'\x90' * 16),
            ("RET", b'\xC3'),
            ("INT3 (Breakpoint)", b'\xCC'),
            ("NOP (1)", b'\x90'),
            ("Infinite Loop", b'\xEB\xFE'),
        ]
        for name, data in presets:
            def make_cb(d):
                return lambda: self._load_preset(d, name)
            menu.add_command(label=name, command=make_cb(data))
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _load_preset(self, data: bytes, name: str):
        self.editor.delete('1.0', 'end')
        hex_str = ' '.join(f'{b:02X}' for b in data)
        self.editor.insert('1.0', f"// {name}\n{hex_str}")


# ============================================================
# Structure Dissect Visualizer
# ============================================================

class StructureVisualizer(tk.Toplevel):
    """Visual struct tree with expandable pointer chains."""

    def __init__(self, parent, pid: int, process_handle=None, initial_addr=None):
        super().__init__(parent)
        self.title("🔬 Structure Visualizer")
        self.geometry("550x500")
        self.configure(bg="#1e1e1e")
        self.pid = pid
        self.h_process = process_handle
        self.dissect = af.StructureDissect(pid, process_handle)

        # Address bar
        addr_bar = tk.Frame(self, bg="#262626")
        addr_bar.pack(fill='x', padx=5, pady=4)

        tk.Label(addr_bar, text="Address:", bg="#262626", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left')
        self.addr_var = tk.StringVar(value=f"0x{initial_addr:X}" if initial_addr else "")
        tk.Entry(addr_bar, textvariable=self.addr_var, width=18, bg="#0d1117",
                 fg="#58a6ff", insertbackground="#58a6ff",
                 font=("Consolas", 10)).pack(side='left', padx=4)
        tk.Button(addr_bar, text="Analyze", bg="#238636", fg="#ffffff", relief='flat',
                  padx=12, command=self._analyze).pack(side='left', padx=4)

        # Tree
        self.tree = ttk.Treeview(self, columns=('offset', 'type', 'value'), show='headings')
        self.tree.heading('offset', text='Offset')
        self.tree.heading('type', text='Type')
        self.tree.heading('value', text='Value')
        self.tree.column('offset', width=70)
        self.tree.column('type', width=80)
        self.tree.column('value', width=300)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)

        self.tree.tag_configure('pointer', foreground="#58a6ff")
        self.tree.tag_configure('string', foreground="#3fb950")
        self.tree.tag_configure('float', foreground="#d29922")

        if initial_addr:
            self._analyze()

    def _analyze(self):
        try:
            addr = int(self.addr_var.get().replace("0x", ""), 16)
        except ValueError:
            return

        self.tree.delete(*self.tree.get_children())
        result = self.dissect.detect_struct(addr)

        if not result:
            self.tree.insert('', 'end', values=('', 'No struct detected', ''))
            return

        self.tree.insert('', 'end', values=('', 'STRUCT',
                                             f'0x{result.base_address:X} (confidence: {result.confidence:.0%})'),
                          tags=('struct',))

        for field in result.fields:
            tag = ''
            if field.vtype == 'pointer':
                tag = 'pointer'
            elif field.vtype == 'string':
                tag = 'string'
            elif field.vtype == 'float':
                tag = 'float'

            self.tree.insert('', 'end', values=(
                f"+0x{field.offset:X}",
                field.vtype,
                str(field.value)[:80],
            ), tags=(tag,))


# ============================================================
# Cheat Engine CT File Importer
# ============================================================

class CTFileImporter:
    """Import Cheat Engine .CT table files."""

    @staticmethod
    def parse_ct_file(path: str) -> List[Dict]:
        """Parse a CT file and extract cheat entries."""
        entries = []
        try:
            content = Path(path).read_text(encoding='utf-8', errors='replace')
        except Exception:
            return entries

        # CT files have a specific XML-like structure
        # Parse <CheatEntry> blocks
        import re
        entry_pattern = re.compile(
            r'<CheatEntry>.*?<Address>(.*?)</Address>.*?<Description>"(.*?)"</Description>'
            r'.*?<Type>(\d+)</Type>.*?<Address>(.*?)</Address>.*?</CheatEntry>',
            re.DOTALL
        )

        # Simplified parser — look for address + description pairs
        lines = content.split('\n')
        current_entry = {}

        for line in lines:
            line = line.strip()
            if '<CheatEntry>' in line:
                current_entry = {}
            elif '<Address>' in line and '</Address>' in line:
                addr_str = line.split('<Address>')[1].split('</Address>')[0].strip()
                if addr_str and not addr_str.startswith('CT'):
                    current_entry['address'] = addr_str
            elif '<Description>' in line and '</Description>' in line:
                desc = line.split('<Description>')[1].split('</Description>')[0].strip().strip('"')
                current_entry['description'] = desc
            elif '<Type>' in line and '</Type>' in line:
                vtype = line.split('<Type>')[1].split('</Type>')[0].strip()
                type_map = {'0': 'byte', '1': '2_bytes', '2': '4_bytes',
                            '3': 'float', '4': 'string', '5': 'array'}
                current_entry['vtype'] = type_map.get(vtype, '4_bytes')
            elif '<VariableType>' in line and '</VariableType>' in line:
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}

        if current_entry:
            entries.append(current_entry)

        return entries

    @staticmethod
    def show_import_dialog(parent, studio_app) -> bool:
        """Show file picker and import selected CT file."""
        path = filedialog.askopenfilename(
            title="Import Cheat Engine Table",
            filetypes=[("Cheat Engine Tables", "*.ct"), ("All Files", "*.*")]
        )
        if not path:
            return False

        entries = CTFileImporter.parse_ct_file(path)
        if not entries:
            messagebox.showinfo("Import", "No entries found in CT file.")
            return False

        # Add entries to cheat table
        for entry in entries:
            addr_str = entry.get('address', '')
            desc = entry.get('description', 'Imported')
            vtype = entry.get('vtype', '4_bytes')

            # Parse address
            try:
                if addr_str.startswith('?'):
                    # Pointer notation: base+offset
                    addr = int(addr_str.split('+')[0].replace('0x', ''), 16)
                else:
                    addr = int(addr_str, 16)
            except (ValueError, IndexError):
                continue

            if studio_app and hasattr(studio_app, 'addresses'):
                studio_app.addresses.append({
                    'addr': addr,
                    'vtype': vtype.replace('_bytes', ''),
                    'description': desc,
                    'frozen': False,
                    'current': None,
                    'previous': None,
                })

        messagebox.showinfo("Import", f"Imported {len(entries)} entries from CT file.")
        return True


# ============================================================
# Signature Database GUI
# ============================================================

class SignatureDatabase:
    """Store and manage AOB signatures per game."""

    def __init__(self, db_path: str = "signatures.json"):
        self.db_path = Path(db_path)
        self._db: Dict[str, List[Dict]] = {}
        self._load()

    def _load(self):
        if self.db_path.exists():
            try:
                self._db = json.loads(self.db_path.read_text(encoding='utf-8'))
            except (json.JSONDecodeError, OSError):
                self._db = {}

    def _save(self):
        self.db_path.write_text(json.dumps(self._db, indent=2), encoding='utf-8')

    def add_signature(self, game: str, name: str, pattern: str, offset: int = 0, description: str = ""):
        """Add an AOB signature for a game."""
        if game not in self._db:
            self._db[game] = []
        self._db[game].append({
            "name": name,
            "pattern": pattern,
            "offset": offset,
            "description": description,
            "added": time.strftime('%Y-%m-%d'),
        })
        self._save()

    def get_signatures(self, game: str) -> List[Dict]:
        return self._db.get(game, [])

    def get_games(self) -> List[str]:
        return sorted(self._db.keys())

    def search(self, query: str) -> Dict[str, List[Dict]]:
        """Search across all games."""
        results = {}
        for game, sigs in self._db.items():
            matches = [s for s in sigs if query.lower() in s.get('name', '').lower()
                        or query.lower() in s.get('description', '').lower()]
            if matches:
                results[game] = matches
        return results

    def delete_signature(self, game: str, index: int):
        if game in self._db and 0 <= index < len(self._db[game]):
            self._db[game].pop(index)
            if not self._db[game]:
                del self._db[game]
            self._save()


class SignatureDatabaseGUI(tk.Toplevel):
    """GUI for managing signature database."""

    def __init__(self, parent, pid: Optional[int] = None):
        super().__init__(parent)
        self.title("📚 Signature Database")
        self.geometry("650x450")
        self.configure(bg="#1e1e1e")
        self.db = SignatureDatabase()
        self.pid = pid

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "font": ("Segoe UI", 9), "relief": "flat", "padx": 8, "pady": 2}

        tk.Button(toolbar, text="➕ Add", bg="#238636", fg="#ffffff", **btn, command=self._add_sig).pack(side='left', padx=2)
        tk.Button(toolbar, text="🔍 Search", **btn, command=self._search).pack(side='left', padx=2)
        tk.Button(toolbar, text="🗑 Delete", **btn, command=self._delete).pack(side='left', padx=2)
        tk.Button(toolbar, text="📤 Export", **btn, command=self._export).pack(side='left', padx=2)

        # Game selector
        tk.Label(toolbar, text="  Game:", bg="#262626", fg="#909090", font=("Segoe UI", 9)).pack(side='left', padx=(10, 2))
        self.game_var = tk.StringVar()
        games = ["All"] + self.db.get_games()
        game_combo = ttk.Combobox(toolbar, textvariable=self.game_var, values=games, width=20, state='readonly')
        game_combo.pack(side='left', padx=2)
        if games:
            game_combo.set(games[0])
        game_combo.bind('<<ComboboxSelected>>', lambda _: self._refresh())

        # Signature list
        self.tree = ttk.Treeview(self, columns=('name', 'pattern', 'offset', 'desc'), show='headings')
        self.tree.heading('name', text='Name')
        self.tree.heading('pattern', text='AOB Pattern')
        self.tree.heading('offset', text='Offset')
        self.tree.heading('desc', text='Description')
        self.tree.column('name', width=120)
        self.tree.column('pattern', width=250)
        self.tree.column('offset', width=50)
        self.tree.column('desc', width=150)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)

        self._refresh()

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        game = self.game_var.get()
        if game == "All" or not game:
            for g, sigs in self.db._db.items():
                for sig in sigs:
                    self.tree.insert('', 'end', values=(
                        f"[{g}] {sig.get('name', '')}",
                        sig.get('pattern', ''),
                        f"+{sig.get('offset', 0)}",
                        sig.get('description', ''),
                    ))
        else:
            for sig in self.db.get_signatures(game):
                self.tree.insert('', 'end', values=(
                    sig.get('name', ''),
                    sig.get('pattern', ''),
                    f"+{sig.get('offset', 0)}",
                    sig.get('description', ''),
                ))

    def _add_sig(self):
        dialog = _AddSignatureDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self.db.add_signature(**dialog.result)
            self._refresh()

    def _search(self):
        query = simpledialog.askstring("Search", "Search signatures:", parent=self)
        if not query:
            return
        results = self.db.search(query)
        self.tree.delete(*self.tree.get_children())
        for game, sigs in results.items():
            for sig in sigs:
                self.tree.insert('', 'end', values=(
                    f"[{game}] {sig.get('name', '')}",
                    sig.get('pattern', ''),
                    f"+{sig.get('offset', 0)}",
                    sig.get('description', ''),
                ))

    def _delete(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        game = self.game_var.get()
        if game and game != "All":
            self.db.delete_signature(game, idx)
            self._refresh()

    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            import shutil
            shutil.copy(self.db.db_path, path)


class _AddSignatureDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add Signature")
        self.geometry("400x250")
        self.configure(bg="#1e1e1e")
        self.transient(parent)
        self.result = None

        pad = {"padx": 12, "pady": 4}
        fields = [
            ("Game:", "game"),
            ("Name:", "name"),
            ("AOB Pattern:", "pattern"),
            ("Offset:", "offset"),
            ("Description:", "desc"),
        ]

        self.vars = {}
        for label, key in fields:
            tk.Label(self, text=label, bg="#1e1e1e", fg="#e8e8e8",
                     font=("Segoe UI", 9)).pack(anchor='w', **pad)
            var = tk.StringVar(value="0" if key == "offset" else "")
            tk.Entry(self, textvariable=var, bg="#0d1117", fg="#c9d1d9",
                     insertbackground="#c9d1d9", font=("Consolas", 10)).pack(fill='x', padx=12)
            self.vars[key] = var

        btn_frame = tk.Frame(self, bg="#1e1e1e")
        btn_frame.pack(pady=12)
        tk.Button(btn_frame, text="Add", bg="#238636", fg="#ffffff", relief='flat',
                  padx=16, command=self._ok).pack(side='left', padx=4)
        tk.Button(btn_frame, text="Cancel", bg="#3a3a3a", fg="#e8e8e8", relief='flat',
                  padx=16, command=self.destroy).pack(side='left', padx=4)

    def _ok(self):
        try:
            offset = int(self.vars['offset'].get() or "0")
        except ValueError:
            offset = 0
        self.result = {
            "game": self.vars['game'].get(),
            "name": self.vars['name'].get(),
            "pattern": self.vars['pattern'].get(),
            "offset": offset,
            "description": self.vars['desc'].get(),
        }
        self.destroy()


# ============================================================
# Memory Region Map
# ============================================================

class MemoryRegionMapWindow(tk.Toplevel):
    """Visual memory map with protection flags."""

    def __init__(self, parent, pid: int, process_handle=None):
        super().__init__(parent)
        self.title("🗺 Memory Region Map")
        self.geometry("720x480")
        self.configure(bg="#1e1e1e")
        self.pid = pid
        self.h_process = process_handle

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "font": ("Segoe UI", 9), "relief": "flat", "padx": 8, "pady": 2}

        tk.Button(toolbar, text="🔄 Refresh", **btn, command=self._refresh).pack(side='left', padx=2)
        tk.Button(toolbar, text="📤 Export", **btn, command=self._export).pack(side='left', padx=2)

        self.status = tk.Label(toolbar, text="", bg="#262626", fg="#909090", font=("Segoe UI", 9))
        self.status.pack(side='right', padx=8)

        # Region list
        self.tree = ttk.Treeview(self, columns=('base', 'size', 'protect', 'state', 'type'),
                                  show='headings')
        self.tree.heading('base', text='Base Address')
        self.tree.heading('size', text='Size')
        self.tree.heading('protect', text='Protection')
        self.tree.heading('state', text='State')
        self.tree.heading('type', text='Type')
        self.tree.column('base', width=130)
        self.tree.column('size', width=80, anchor='e')
        self.tree.column('protect', width=100)
        self.tree.column('state', width=60)
        self.tree.column('type', width=60)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)

        # Tags
        self.tree.tag_configure('readable', foreground="#3fb950")
        self.tree.tag_configure('writable', foreground="#d29922")
        self.tree.tag_configure('executable', foreground="#f85149")

        self._refresh()

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        h = self.h_process or k32.OpenProcess(0x1010, False, self.pid)

        try:
            regions = self._enumerate_regions(h)
            for r in regions:
                tag = ''
                prot = r['protect']
                if 'EXECUTE' in prot:
                    tag = 'executable'
                elif 'WRITE' in prot:
                    tag = 'writable'
                else:
                    tag = 'readable'

                self.tree.insert('', 'end', values=(
                    f"0x{r['base']:X}",
                    self._format_size(r['size']),
                    prot,
                    r['state'],
                    r['type'],
                ), tags=(tag,))

            self.status.config(text=f"{len(regions)} regions", fg="#909090")
        finally:
            if not self.h_process:
                k32.CloseHandle(h)

    def _enumerate_regions(self, h) -> List[Dict]:
        regions = []

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        protect_map = {0x01: 'NOACCESS', 0x02: 'READONLY', 0x04: 'READWRITE',
                       0x08: 'WRITECOPY', 0x10: 'EXECUTE', 0x20: 'EXECUTE_READ',
                       0x40: 'EXECUTE_READWRITE', 0x80: 'EXECUTE_WRITECOPY'}
        state_map = {0x1000: 'COMMIT', 0x2000: 'RESERVE', 0x1000000: 'FREE'}
        type_map = {0x20000: 'IMAGE', 0x40000: 'MAPPED', 0x100000: 'PRIVATE'}

        while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) != 0:
            regions.append({
                'base': mbi.BaseAddress,
                'size': mbi.RegionSize,
                'protect': protect_map.get(mbi.Protect, f'0x{mbi.Protect:X}'),
                'state': state_map.get(mbi.State, f'0x{mbi.State:X}'),
                'type': type_map.get(mbi.Type, f'0x{mbi.Type:X}'),
            })
            addr += mbi.RegionSize
            if addr > 0x7FFFFFFFFFFF:
                break

        return regions

    @staticmethod
    def _format_size(size):
        if size >= 1024 * 1024:
            return f"{size // (1024*1024)} MB"
        if size >= 1024:
            return f"{size // 1024} KB"
        return f"{size} B"

    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        import csv
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Base', 'Size', 'Protection', 'State', 'Type'])
            for item in self.tree.get_children():
                writer.writerow(self.tree.item(item)['values'])


# ============================================================
# Speedhack Window
# ============================================================

class SpeedhackWindow(tk.Toplevel):
    """Speed control with slider."""

    def __init__(self, parent, pid: int, process_handle=None):
        super().__init__(parent)
        self.title("⏱ Speedhack")
        self.geometry("380x200")
        self.configure(bg="#1e1e1e")
        self.pid = pid
        self.speedhack = af.Speedhack(pid, process_handle)

        # Speed slider
        tk.Label(self, text="Speed Multiplier", bg="#1e1e1e", fg="#e8e8e8",
                 font=("Segoe UI", 12, "bold")).pack(pady=(20, 5))

        self.speed_var = tk.DoubleVar(value=1.0)
        self.slider = tk.Scale(self, from_=0.1, to=5.0, resolution=0.1,
                                orient='horizontal', variable=self.speed_var,
                                bg="#1e1e1e", fg="#58a6ff", font=("Segoe UI", 10),
                                troughcolor="#262626", highlightthickness=0, length=280,
                                command=self._on_slider)
        self.slider.pack(padx=20)

        self.status_label = tk.Label(self, text="Speedhack OFF", bg="#1e1e1e",
                                      fg="#909090", font=("Segoe UI", 10))
        self.status_label.pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(self, bg="#1e1e1e")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Enable", bg="#238636", fg="#ffffff", relief='flat',
                  padx=16, command=self._toggle).pack(side='left', padx=4)
        tk.Button(btn_frame, text="Reset", bg="#3a3a3a", fg="#e8e8e8", relief='flat',
                  padx=16, command=self._reset).pack(side='left', padx=4)

    def _on_slider(self, val):
        speed = float(val)
        self.speedhack.set_speed(speed)
        if self.speedhack.active:
            self.status_label.config(text=f"Speedhack ON — {speed:.1f}x", fg="#3fb950")

    def _toggle(self):
        self.speedhack.toggle()
        if self.speedhack.active:
            self.status_label.config(text=f"Speedhack ON — {self.speedhack.speed:.1f}x", fg="#3fb950")
        else:
            self.status_label.config(text="Speedhack OFF", fg="#909090")

    def _reset(self):
        self.speed_var.set(1.0)
        self.speedhack.set_speed(1.0)
        self.speedhack.disable()
        self.status_label.config(text="Speedhack OFF", fg="#909090")


# ============================================================
# Script Recorder Window
# ============================================================

class ScriptRecorderWindow(tk.Toplevel):
    """Record user actions into a script."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("⏺ Script Recorder")
        self.geometry("500x400")
        self.configure(bg="#1e1e1e")
        self.recorder = af.ScriptRecorder()

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "font": ("Segoe UI", 9), "relief": "flat", "padx": 8, "pady": 2}

        self.btn_record = tk.Button(toolbar, text="⏺ Record", bg="#da3633", fg="#ffffff", **btn, command=self._toggle_record)
        self.btn_record.pack(side='left', padx=2)
        tk.Button(toolbar, text="💾 Export", **btn, command=self._export).pack(side='left', padx=2)
        tk.Button(toolbar, text="🗑 Clear", **btn, command=self._clear).pack(side='left', padx=2)

        self.status = tk.Label(toolbar, text="Idle", bg="#262626", fg="#909090", font=("Segoe UI", 9))
        self.status.pack(side='right', padx=8)

        # Recorded actions
        self.text = tk.Text(self, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10),
                             insertbackground="#58a6ff", relief="flat", state='disabled')
        self.text.pack(fill='both', expand=True, padx=5, pady=5)

    def _toggle_record(self):
        if self.recorder.is_recording:
            self.recorder.stop()
            self.btn_record.config(text="⏺ Record", bg="#da3633")
            self.status.config(text="Stopped", fg="#909090")
            self._update_view()
        else:
            self.recorder.start()
            self.btn_record.config(text="⏹ Stop", bg="#212626")
            self.status.config(text="● Recording", fg="#da3633")

    def _update_view(self):
        self.text.config(state='normal')
        self.text.delete('1.0', 'end')
        self.text.insert('1.0', self.recorder.get_script())
        self.text.config(state='disabled')

    def _clear(self):
        self.recorder = af.ScriptRecorder()
        self._update_view()

    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python", "*.py")])
        if path:
            self.recorder.export(path)


# ============================================================
# Session Dialogs
# ============================================================

class SessionDialogs:
    """Save/Load session dialogs."""

    @staticmethod
    def save_session(parent, studio_app):
        if not studio_app:
            return
        path = filedialog.asksaveasfilename(defaultextension=".mots",
                                              filetypes=[("MomoTrainer Session", "*.mots"), ("JSON", "*.json")],
                                              title="Save Session")
        if not path:
            return
        session = af.ScanSession(studio_app)
        session.save(path)
        if hasattr(studio_app, '_status'):
            studio_app._status(f"Session saved: {os.path.basename(path)}", toast="success")

    @staticmethod
    def load_session(parent, studio_app):
        if not studio_app:
            return
        path = filedialog.askopenfilename(title="Load Session",
                                            filetypes=[("MomoTrainer Session", "*.mots"), ("JSON", "*.json")])
        if not path:
            return
        session = af.ScanSession(studio_app)
        try:
            data = session.load(path)
            count = len(data.get('candidates', [])) + len(data.get('addresses', []))
            if hasattr(studio_app, '_status'):
                studio_app._status(f"Session loaded: {count} entries", toast="success")
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load session: {e}")


# ============================================================
# Group/Fuzzy Scanner Dialog
# ============================================================

class GroupScanDialog(tk.Toplevel):
    """Scan for multiple values at once."""

    def __init__(self, parent, pid: int, process_handle=None):
        super().__init__(parent)
        self.title("🔍 Group Scanner")
        self.geometry("450x400")
        self.configure(bg="#1e1e1e")
        self.pid = pid
        self.h_process = process_handle

        # Input
        tk.Label(self, text="Values (one per line, hex or decimal):", bg="#1e1e1e",
                 fg="#e8e8e8", font=("Segoe UI", 9)).pack(anchor='w', padx=10, pady=(10, 2))

        self.text = tk.Text(self, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10),
                             insertbackground="#58a6ff", relief="flat", height=8)
        self.text.pack(fill='x', padx=10, pady=4)
        self.text.insert('1.0', "100\n200\n50\n1000")

        # Options
        opt_frame = tk.Frame(self, bg="#1e1e1e")
        opt_frame.pack(fill='x', padx=10, pady=4)

        tk.Label(opt_frame, text="Type:", bg="#1e1e1e", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left')
        self.type_var = tk.StringVar(value="int32")
        ttk.Combobox(opt_frame, textvariable=self.type_var,
                      values=['int8', 'int16', 'int32', 'int64', 'float', 'double'],
                      width=10, state='readonly').pack(side='left', padx=4)

        # Results
        self.results_label = tk.Label(self, text="", bg="#1e1e1e", fg="#909090",
                                       font=("Segoe UI", 9))
        self.results_label.pack(anchor='w', padx=10)

        self.tree = ttk.Treeview(self, columns=('value', 'count'), show='headings', height=6)
        self.tree.heading('value', text='Value')
        self.tree.heading('count', text='Hits')
        self.tree.column('value', width=150)
        self.tree.column('count', width=100, anchor='e')
        self.tree.pack(fill='both', expand=True, padx=10, pady=5)

        # Button
        tk.Button(self, text="🔍 Scan All", bg="#238636", fg="#ffffff", relief='flat',
                  padx=20, pady=5, command=self._scan).pack(pady=8)

    def _parse_values(self) -> List[int]:
        text = self.text.get('1.0', 'end').strip()
        values = []
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            try:
                if line.startswith('0x'):
                    values.append(int(line, 16))
                else:
                    values.append(int(line))
            except ValueError:
                pass
        return values

    def _scan(self):
        values = self._parse_values()
        if not values:
            return

        vtype = self.type_var.get()
        self.tree.delete(*self.tree.get_children())

        for value in values:
            try:
                cands = ms.first_scan(self._get_handle(), vtype, value, mode='exact', nthreads=2)
                self.tree.insert('', 'end', values=(str(value), len(cands)))
            except Exception as e:
                self.tree.insert('', 'end', values=(str(value), f"Error: {e}"))

    def _get_handle(self):
        if self.h_process:
            return self.h_process
        return k32.OpenProcess(0x1010, False, self.pid)


# ============================================================
# Multi-Process Watch Window
# ============================================================

class MultiProcessWatchWindow(tk.Toplevel):
    """Watch addresses across multiple processes."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("👁 Multi-Process Watch")
        self.geometry("600x350")
        self.configure(bg="#1e1e1e")

        # Process list
        columns = ('pid', 'name', 'addr', 'value', 'status')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        self.tree.heading('pid', text='PID')
        self.tree.heading('name', text='Process')
        self.tree.heading('addr', text='Address')
        self.tree.heading('value', text='Value')
        self.tree.heading('status', text='Status')
        self.tree.column('pid', width=70)
        self.tree.column('name', width=120)
        self.tree.column('addr', width=120)
        self.tree.column('value', width=120)
        self.tree.column('status', width=80)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)

        self.watches: List[Dict] = []
        self._running = False

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "font": ("Segoe UI", 9), "relief": "flat", "padx": 8, "pady": 2}

        tk.Button(toolbar, text="➕ Add", bg="#238636", fg="#ffffff", **btn, command=self._add).pack(side='left', padx=2)
        tk.Button(toolbar, text="⏵ Start", **btn, command=self._start).pack(side='left', padx=2)
        tk.Button(toolbar, text="⏹ Stop", **btn, command=self._stop).pack(side='left', padx=2)

    def _add(self):
        pid_str = simpledialog.askstring("Add Process", "PID (decimal):", parent=self)
        if not pid_str:
            return
        try:
            pid = int(pid_str)
        except ValueError:
            return

        addr_str = simpledialog.askstring("Add Address", "Address (hex):", parent=self)
        if not addr_str:
            return
        try:
            addr = int(addr_str.replace("0x", ""), 16)
        except ValueError:
            return

        self.watches.append({
            'pid': pid,
            'addr': addr,
            'name': f'PID {pid}',
            'value': '?',
            'status': 'idle',
        })
        self.tree.insert('', 'end', values=(pid, f'PID {pid}', f'0x{addr:X}', '?', 'idle'))

    def _start(self):
        self._running = True
        self._refresh()

    def _stop(self):
        self._running = False

    def _refresh(self):
        if not self._running:
            return

        for i, watch in enumerate(self.watches):
            h = k32.OpenProcess(0x0010, False, watch['pid'])
            if not h:
                watch['status'] = 'dead'
                continue
            try:
                buf = ctypes.create_string_buffer(4)
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(watch['addr']), buf, ctypes.c_size_t(4), ctypes.byref(read)):
                    watch['value'] = str(struct.unpack('<I', buf.raw)[0])
                    watch['status'] = 'ok'
            except Exception:
                watch['status'] = 'error'
            finally:
                k32.CloseHandle(h)

        # Update tree
        self.tree.delete(*self.tree.get_children())
        for w in self.watches:
            self.tree.insert('', 'end', values=(w['pid'], w['name'], f"0x{w['addr']:X}",
                                               w['value'], w['status']))

        self.after(500, self._refresh)


k32 = ctypes.windll.kernel32
