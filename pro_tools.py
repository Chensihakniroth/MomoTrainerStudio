"""
pro_tools.py — Enhanced Memory Watch & Hex Viewer for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Memory Watch Pro:
  - Type auto-detect (int8/16/32/64, float, double, string per entry)
  - Format presets (hex, decimal, binary, float, scientific)
  - CSV export with timestamps
  - Find-writer wizard (uses debugger_toolkit breakpoints)
  - Value change log + sparkline per address

Hex Viewer Pro:
  - AOB/pattern search highlighting
  - Diff view (compare snapshots side-by-side)
  - Copy as: C array, Python bytes, Go []byte, Rust [u8], Lua table
  - Bookmarks bar for saved offsets
  - Jump history (back/forward)
"""

import csv
import ctypes
import struct
import time
import tkinter as tk
from collections import OrderedDict, deque
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Deque, Dict, List, Optional, Tuple

# Type constants
TYPE_FORMATS = [
    ("auto", "Auto-Detect"),
    ("int8", "Int8 (1B)"),
    ("int16", "Int16 (2B)"),
    ("int32", "Int32 (4B)"),
    ("int64", "Int64 (8B)"),
    ("uint8", "UInt8 (1B)"),
    ("uint16", "UInt16 (2B)"),
    ("uint32", "UInt32 (4B)"),
    ("uint64", "UInt64 (8B)"),
    ("float", "Float (4B)"),
    ("double", "Double (8B)"),
    ("string", "String (UTF-8)"),
]

DISPLAY_FORMATS = ["Hex", "Decimal", "Binary", "Float", "Scientific"]

k32 = ctypes.windll.kernel32


# ============================================================
# Memory Watch Pro
# ============================================================

class WatchEntryPro:
    """Enhanced watch entry with type + format tracking."""

    def __init__(self, address: int, size: int = 4, vtype: str = "auto",
                 display_format: str = "Hex", frozen: bool = False,
                 description: str = ""):
        self.address = address
        self.size = size
        self.vtype = vtype
        self.display_format = display_format
        self.frozen = frozen
        self.description = description
        self.current_raw: Optional[bytes] = None
        self.previous_raw: Optional[bytes] = None
        self.change_history: List[Tuple[float, bytes]] = []  # (timestamp, raw)
        self.max_history = 100
        self.detected_type = vtype  # updated when auto-detect finds a match

    def update_value(self, raw: bytes):
        """Store new value, keep history."""
        self.previous_raw = self.current_raw
        self.current_raw = raw
        ts = time.time()
        self.change_history.append((ts, raw))
        if len(self.change_history) > self.max_history:
            self.change_history.pop(0)

    @property
    def has_changed(self) -> bool:
        return (self.current_raw is not None
                and self.previous_raw is not None
                and self.current_raw != self.previous_raw)

    @property
    def change_count(self) -> int:
        """Number of value changes recorded."""
        return len(self.change_history) - 1 if self.change_history else 0


def format_value(raw: bytes, vtype: str, display_fmt: str) -> str:
    """Format raw bytes according to type and display format."""
    if not raw:
        return "?"

    try:
        # String type
        if vtype == "string":
            s = raw.split(b'\x00')[0].decode('utf-8', errors='replace')
            return s[:64] if s else "(empty)"

        # Numeric types
        if vtype in ("int8",) and len(raw) >= 1:
            val = struct.unpack('<b', raw[:1])[0]
        elif vtype in ("uint8",) and len(raw) >= 1:
            val = struct.unpack('<B', raw[:1])[0]
        elif vtype in ("int16",) and len(raw) >= 2:
            val = struct.unpack('<h', raw[:2])[0]
        elif vtype in ("uint16",) and len(raw) >= 2:
            val = struct.unpack('<H', raw[:2])[0]
        elif vtype in ("int32",) and len(raw) >= 4:
            val = struct.unpack('<i', raw[:4])[0]
        elif vtype in ("uint32",) and len(raw) >= 4:
            val = struct.unpack('<I', raw[:4])[0]
        elif vtype in ("int64",) and len(raw) >= 8:
            val = struct.unpack('<q', raw[:8])[0]
        elif vtype in ("uint64",) and len(raw) >= 8:
            val = struct.unpack('<Q', raw[:8])[0]
        elif vtype in ("float",) and len(raw) >= 4:
            val = struct.unpack('<f', raw[:4])[0]
        elif vtype in ("double",) and len(raw) >= 8:
            val = struct.unpack('<d', raw[:8])[0]
        else:
            return raw.hex().upper()

        # Apply display format
        if display_fmt == "Hex":
            if isinstance(val, int):
                return f"0x{val:X}"
            return f"0x{raw.hex().upper()}"
        elif display_fmt == "Decimal":
            return str(val)
        elif display_fmt == "Binary":
            if isinstance(val, int):
                return bin(val)
            return raw.hex().upper()
        elif display_fmt == "Float":
            if vtype in ("float", "double"):
                return f"{val:g}"
            return f"{struct.unpack('<f', (val & 0xFFFFFFFF).to_bytes(4, 'little'))[0]:g}" if isinstance(val, int) else str(val)
        elif display_fmt == "Scientific":
            if isinstance(val, float):
                return f"{val:.6e}"
            return f"{val:.6e}" if isinstance(val, (int, float)) else str(val)

        return str(val)

    except (struct.error, ValueError):
        return raw.hex().upper()


def auto_detect_type(raw: bytes) -> str:
    """Heuristic type detection from raw bytes."""
    if not raw or len(raw) < 4:
        return "int32"

    # Try float — if it's a reasonable float, likely a float
    f_val = struct.unpack('<f', raw[:4])[0]
    if not (f_val != f_val) and abs(f_val) < 1e15 and abs(f_val) > 1e-15:
        # Check if it looks like a "clean" float (fractional part exists)
        if f_val != int(f_val):
            return "float"

    # Try int32
    i_val = struct.unpack('<i', raw[:4])[0]
    if 0 < abs(i_val) < 1000000:
        return "int32"

    # Check if it looks like a string (printable ASCII)
    try:
        s = raw[:16].split(b'\x00')[0].decode('ascii')
        if all(c.isprintable() or c in ' \t\n\r' for c in s) and len(s) > 2:
            return "string"
    except (UnicodeDecodeError, ValueError):
        pass

    return "uint32"


class MemoryWatchProWindow(tk.Toplevel):
    """
    Enhanced memory watch with type auto-detect, format presets, export,
    and find-writer integration.
    """

    def __init__(self, parent, pid: int, process_handle=None,
                 on_freeze_toggle=None, on_find_writer=None):
        super().__init__(parent)
        self.title("🔍 Memory Watch Pro")
        self.geometry("950x500")
        self.configure(bg="#1e1e1e")

        self.pid = pid
        self.process_handle = process_handle
        self.on_freeze_toggle = on_freeze_toggle
        self.on_find_writer = on_find_writer

        self._watches: OrderedDict[int, WatchEntryPro] = OrderedDict()
        self._refresh_job = None
        self.refresh_interval = 100  # ms
        self._is_refreshing = False

        self._setup_ui()

    def _setup_ui(self):
        """Build the UI."""
        # Header
        header = tk.Frame(self, bg="#262626")
        header.pack(fill='x', padx=5, pady=5)
        tk.Label(header, text="🔍 Memory Watch Pro", bg="#262626", fg="#e8e8e8",
                 font=("Segoe UI", 12, "bold")).pack(side='left')
        self.status_label = tk.Label(header, text="0 addresses", bg="#262626",
                                       fg="#909090", font=("Segoe UI", 9))
        self.status_label.pack(side='right')

        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=2)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "activeforeground": "#e8e8e8", "font": ("Segoe UI", 9),
               "relief": "flat", "padx": 8, "pady": 2}

        tk.Button(toolbar, text="➕ Add", **btn, command=self._on_add).pack(side='left', padx=2)
        tk.Button(toolbar, text="✏️ Edit", **btn, command=self._on_edit).pack(side='left', padx=2)
        tk.Button(toolbar, text="❄️ Freeze", **btn, command=self._on_freeze).pack(side='left', padx=2)
        tk.Button(toolbar, text="🔍 Find Writer", **btn, command=self._on_find_writer).pack(side='left', padx=2)
        tk.Button(toolbar, text="📋 Copy", **btn, command=self._on_copy).pack(side='left', padx=2)
        tk.Button(toolbar, text="🗑️ Remove", **btn, command=self._on_remove).pack(side='left', padx=2)
        tk.Button(toolbar, text="📄 Export CSV", **btn, command=self._on_export_csv).pack(side='left', padx=2)

        ttk.Separator(toolbar, orient='vertical').pack(side='left', fill='y', padx=8)

        # Global display format
        tk.Label(toolbar, text="Format:", bg="#262626", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left')
        self.fmt_var = tk.StringVar(value="Hex")
        fmt_combo = ttk.Combobox(toolbar, textvariable=self.fmt_var, values=DISPLAY_FORMATS,
                                  width=10, state='readonly')
        fmt_combo.pack(side='left', padx=4)
        fmt_combo.bind('<<ComboboxSelected>>', lambda _: self._refresh_display())

        # Refresh rate
        tk.Label(toolbar, text="Rate:", bg="#262626", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left', padx=(10, 0))
        self.rate_var = tk.StringVar(value="100ms")
        rate_combo = ttk.Combobox(toolbar, textvariable=self.rate_var,
                                   values=['10ms', '50ms', '100ms', '250ms', '500ms', '1000ms'],
                                   width=7, state='readonly')
        rate_combo.pack(side='left', padx=4)
        rate_combo.bind('<<ComboboxSelected>>', self._on_rate_change)

        # Treeview
        tree_frame = tk.Frame(self, bg="#1e1e1e")
        tree_frame.pack(fill='both', expand=True, padx=5, pady=(2, 5))

        columns = ('addr', 'type', 'value', 'prev', 'changes', 'frozen', 'desc')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        self.tree.heading('addr', text='Address')
        self.tree.heading('type', text='Type')
        self.tree.heading('value', text='Value')
        self.tree.heading('prev', text='Previous')
        self.tree.heading('changes', text='Changes')
        self.tree.heading('frozen', text='❄')
        self.tree.heading('desc', text='Description')
        self.tree.column('addr', width=120, anchor='w')
        self.tree.column('type', width=90, anchor='center')
        self.tree.column('value', width=140, anchor='e')
        self.tree.column('prev', width=140, anchor='e')
        self.tree.column('changes', width=60, anchor='center')
        self.tree.column('frozen', width=30, anchor='center')
        self.tree.column('desc', width=180, anchor='w')
        self.tree.pack(side='left', fill='both', expand=True)

        scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        scroll.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scroll.set)

        # Tags for change highlighting
        self.tree.tag_configure('changed', background='#1a3a1a', foreground='#7ee787')
        self.tree.tag_configure('frozen', background='#3d2805', foreground='#f0b72f')

        # Auto-refresh
        self.auto_var = tk.BooleanVar(value=True)
        self._start_auto_refresh()

    def _on_add(self):
        """Add a new address to watch."""
        addr_str = tk.simpledialog.askstring("Add Watch", "Address (hex):",
                                               parent=self) if hasattr(tk, 'simpledialog') else None
        if not addr_str:
            # Fallback
            addr_str = self._ask_string("Add Watch", "Address (hex):")
        if not addr_str:
            return
        try:
            addr = int(addr_str.replace("0x", ""), 16)
        except ValueError:
            messagebox.showerror("Error", f"Invalid address: {addr_str}")
            return

        entry = WatchEntryPro(address=addr, vtype="auto")
        self._watches[addr] = entry
        iid = str(id(entry))
        self.tree.insert('', 'end', iid=iid, values=(
            f"0x{addr:X}", "auto", "?", "?", "0", "", ""
        ))

    def _ask_string(self, title, prompt):
        """Simple string input dialog."""
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.geometry("300x100")
        dlg.configure(bg="#1e1e1e")
        dlg.transient(self)
        dlg.grab_set()
        tk.Label(dlg, text=prompt, bg="#1e1e1e", fg="#e8e8e8",
                 font=("Segoe UI", 10)).pack(pady=(10, 5))
        entry = tk.Entry(dlg, bg="#0d1117", fg="#e8e8e8", insertbackground="#e8e8e8",
                          font=("Consolas", 11))
        entry.pack(fill='x', padx=20)
        entry.focus_set()
        result = [None]

        def ok():
            result[0] = entry.get()
            dlg.destroy()

        def cancel():
            dlg.destroy()

        entry.bind('<Return>', lambda _: ok())
        entry.bind('<Escape>', lambda _: cancel())
        btn_frame = tk.Frame(dlg, bg="#1e1e1e")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="OK", command=ok, bg="#238636", fg="#ffffff",
                  relief='flat', padx=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Cancel", command=cancel, bg="#3a3a3a", fg="#e8e8e8",
                  relief='flat', padx=15).pack(side='left', padx=5)
        self.wait_window(dlg)
        return result[0]

    def _on_edit(self):
        """Edit selected entry's type/description."""
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        entry = self._find_entry_by_iid(iid)
        if not entry:
            return

        dlg = tk.Toplevel(self)
        dlg.title("Edit Watch Entry")
        dlg.geometry("350x200")
        dlg.configure(bg="#1e1e1e")
        dlg.transient(self)
        dlg.grab_set()

        tk.Label(dlg, text="Type:", bg="#1e1e1e", fg="#e8e8e8").pack(anchor='w', padx=20, pady=(15, 2))
        type_var = tk.StringVar(value=entry.vtype)
        type_combo = ttk.Combobox(dlg, textvariable=type_var,
                                   values=[t[0] for t in TYPE_FORMATS], width=15, state='readonly')
        type_combo.pack(anchor='w', padx=20)

        tk.Label(dlg, text="Description:", bg="#1e1e1e", fg="#e8e8e8").pack(anchor='w', padx=20, pady=(10, 2))
        desc_entry = tk.Entry(dlg, bg="#0d1117", fg="#e8e8e8", insertbackground="#e8e8e8",
                               font=("Segoe UI", 10), width=30)
        desc_entry.pack(anchor='w', padx=20)
        desc_entry.insert(0, entry.description)

        def save():
            entry.vtype = type_var.get()
            entry.description = desc_entry.get()
            dlg.destroy()

        tk.Button(dlg, text="Save", command=save, bg="#238636", fg="#ffffff",
                  relief='flat', padx=20).pack(pady=15)

    def _on_freeze(self):
        """Toggle freeze on selected."""
        sel = self.tree.selection()
        for iid in sel:
            entry = self._find_entry_by_iid(iid)
            if entry:
                entry.frozen = not entry.frozen
                if self.on_freeze_toggle:
                    self.on_freeze_toggle(entry.address, entry.frozen)

    def _on_find_writer(self):
        """Find what writes to selected address."""
        sel = self.tree.selection()
        if not sel:
            return
        entry = self._find_entry_by_iid(sel[0])
        if not entry:
            return
        if self.on_find_writer:
            self.on_find_writer(entry.address)
        else:
            messagebox.showinfo("Find Writer",
                                f"Set a write breakpoint on 0x{entry.address:X}\n"
                                f"Use the Debugger → Breakpoint Manager to monitor writes.")

    def _on_copy(self):
        """Copy selected entry's address + value."""
        sel = self.tree.selection()
        if not sel:
            return
        entry = self._find_entry_by_iid(sel[0])
        if not entry or not entry.current_raw:
            return
        val_str = format_value(entry.current_raw, entry.vtype, self.fmt_var.get())
        self.clipboard_clear()
        self.clipboard_append(f"0x{entry.address:X} = {val_str}")

    def _on_remove(self):
        """Remove selected entries."""
        sel = self.tree.selection()
        for iid in sel:
            entry = self._find_entry_by_iid(iid)
            if entry and entry.address in self._watches:
                del self._watches[entry.address]
            self.tree.delete(iid)

    def _on_clear(self):
        """Clear all watches."""
        self._watches.clear()
        self.tree.delete(*self.tree.get_children())

    def _on_rate_change(self, event=None):
        rate_str = self.rate_var.get().replace("ms", "")
        try:
            self.refresh_interval = int(rate_str)
        except ValueError:
            pass

    def _on_export_csv(self):
        """Export change history to CSV."""
        if not self._watches:
            messagebox.showinfo("Export", "No watches to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                              filetypes=[("CSV", "*.csv")],
                                              title="Export Watch History")
        if not path:
            return

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Address', 'Type', 'Timestamp', 'Value', 'Raw Hex'])
            for entry in self._watches.values():
                for ts, raw in entry.change_history:
                    val = format_value(raw, entry.vtype, "Hex")
                    writer.writerow([
                        f"0x{entry.address:X}",
                        entry.vtype,
                        time.strftime('%H:%M:%S', time.localtime(ts)),
                        val,
                        raw.hex().upper(),
                    ])

        messagebox.showinfo("Export", f"Saved to {path}")

    def _find_entry_by_iid(self, iid: str) -> Optional[WatchEntryPro]:
        for entry in self._watches.values():
            if str(id(entry)) == iid:
                return entry
        return None

    def _start_auto_refresh(self):
        self._is_refreshing = True
        self._refresh_values()

    def _stop_auto_refresh(self):
        self._is_refreshing = False
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None

    def _refresh_values(self):
        if not self._is_refreshing:
            return

        changed_entries = []
        for addr, entry in self._watches.items():
            if entry.frozen and entry.current_raw:
                raw = entry.current_raw  # keep frozen value
            else:
                raw = self._read_memory(addr, max(entry.size, 8))

            if raw is None:
                continue

            # Auto-detect type
            if entry.vtype == "auto":
                entry.detected_type = auto_detect_type(raw)
                display_type = entry.detected_type
            else:
                display_type = entry.vtype

            # Track changes
            had_previous = entry.current_raw is not None
            entry.update_value(raw)

            if had_previous and entry.has_changed:
                changed_entries.append((entry, display_type))

        # Update display
        self._refresh_display()
        self.status_label.config(text=f"{len(self._watches)} addresses | {self.refresh_interval}ms")

        # Highlight changed rows
        for entry, _ in changed_entries:
            iid = str(id(entry))
            if self.tree.exists(iid):
                self.tree.item(iid, tags=('changed',))
            # Auto-clear highlight after 1.5s
            self.after(1500, lambda i=iid: self._clear_highlight(i))

        self._refresh_job = self.after(self.refresh_interval, self._refresh_values)

    def _clear_highlight(self, iid):
        if self.tree.exists(iid):
            entry = self._find_entry_by_iid(iid)
            if entry and entry.frozen:
                self.tree.item(iid, tags=('frozen',))
            else:
                self.tree.item(iid, tags=())

    def _refresh_display(self):
        """Update treeview values."""
        fmt = self.fmt_var.get()
        for addr, entry in self._watches.items():
            iid = str(id(entry))
            if not self.tree.exists(iid):
                continue

            display_type = entry.detected_type if entry.vtype == "auto" else entry.vtype
            val_str = format_value(entry.current_raw, display_type, fmt) if entry.current_raw else "?"
            prev_str = format_value(entry.previous_raw, display_type, fmt) if entry.previous_raw else "?"

            tags = ()
            if entry.frozen:
                tags = ('frozen',)
            elif entry.has_changed:
                tags = ('changed',)

            self.tree.item(iid, tags=tags, values=(
                f"0x{addr:X}",
                display_type,
                val_str,
                prev_str,
                entry.change_count,
                "❄" if entry.frozen else "",
                entry.description,
            ))

    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        if self.process_handle:
            return self._read_with_handle(self.process_handle, address, size)
        elif self.pid:
            h = k32.OpenProcess(0x0010, False, self.pid)
            if not h:
                return None
            try:
                return self._read_with_handle(h, address, size)
            finally:
                k32.CloseHandle(h)
        return None

    def _read_with_handle(self, h, address: int, size: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, ctypes.c_size_t(size), ctypes.byref(read)):
            return buf.raw[:read.value]
        return None

    def add_watch(self, address: int, size: int = 4, vtype: str = "auto",
                  description: str = ""):
        """Programmatically add a watch."""
        entry = WatchEntryPro(address=address, size=size, vtype=vtype, description=description)
        self._watches[address] = entry
        iid = str(id(entry))
        self.tree.insert('', 'end', iid=iid, values=(
            f"0x{address:X}", vtype, "?", "?", "0", "", description
        ))

    def close(self):
        self._stop_auto_refresh()
        self.destroy()


# ============================================================
# Hex Viewer Pro
# ============================================================

class HexViewerProWindow(tk.Toplevel):
    """
    Enhanced hex viewer with AOB search, diff view, format export, bookmarks.
    """

    def __init__(self, parent, process_handle, address: int = 0,
                 size: int = 4096, pid: Optional[int] = None):
        super().__init__(parent)
        self.title("📝 Hex Viewer Pro")
        self.geometry("820x560")
        self.configure(bg="#1e1e1e")

        self.h_process = process_handle
        self.pid = pid
        self.current_address = address
        self.view_size = size
        self.bytes_per_row = 16

        # Bookmarks: offset -> label
        self.bookmarks: Dict[int, str] = {}
        # Jump history
        self._jump_history: Deque[int] = deque(maxlen=50)
        self._jump_forward: Deque[int] = deque(maxlen=50)
        # Snapshot for diff
        self._snapshot: Optional[bytes] = None

        self._setup_ui()

    def _setup_ui(self):
        # Toolbar
        toolbar = tk.Frame(self, bg="#262626")
        toolbar.pack(fill='x', padx=5, pady=4)

        btn = {"bg": "#262626", "fg": "#e8e8e8", "activebackground": "#1e1e1e",
               "activeforeground": "#e8e8e8", "font": ("Segoe UI", 9),
               "relief": "flat", "padx": 6, "pady": 2}

        tk.Button(toolbar, text="◀ Back", **btn, command=self._jump_back).pack(side='left', padx=2)
        tk.Button(toolbar, text="▶ Fwd", **btn, command=self._jump_forward).pack(side='left', padx=2)

        tk.Label(toolbar, text="  Goto:", bg="#262626", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left', padx=(10, 2))
        self.goto_var = tk.StringVar()
        goto_entry = tk.Entry(toolbar, textvariable=self.goto_var, width=14,
                               bg="#0d1117", fg="#58a6ff", insertbackground="#58a6ff",
                               font=("Consolas", 9))
        goto_entry.pack(side='left', padx=2)
        goto_entry.bind('<Return>', lambda _: self._go_to())

        tk.Button(toolbar, text="Go", bg="#1f6feb", fg="#ffffff", relief='flat',
                  padx=8, command=self._go_to).pack(side='left', padx=4)

        # AOB search
        tk.Label(toolbar, text="  AOB:", bg="#262626", fg="#909090",
                 font=("Segoe UI", 9)).pack(side='left', padx=(10, 2))
        self.aob_var = tk.StringVar()
        aob_entry = tk.Entry(toolbar, textvariable=self.aob_var, width=24,
                              bg="#0d1117", fg="#d29922", insertbackground="#d29922",
                              font=("Consolas", 9))
        aob_entry.pack(side='left', padx=2)
        aob_entry.bind('<Return>', lambda _: self._search_aob())

        tk.Button(toolbar, text="Find", bg="#9e6a03", fg="#ffffff", relief='flat',
                  padx=8, command=self._search_aob).pack(side='left', padx=4)

        # Right-side buttons
        right_bar = tk.Frame(toolbar, bg="#262626")
        right_bar.pack(side='right', padx=4)

        tk.Button(right_bar, text="📸 Snap", **btn, command=self._take_snapshot).pack(side='left', padx=2)
        tk.Button(right_bar, text="⚖ Diff", **btn, command=self._show_diff).pack(side='left', padx=2)
        tk.Button(right_bar, text="🔖 BM", **btn, command=self._toggle_bookmark).pack(side='left', padx=2)
        tk.Button(right_bar, text="📤 Copy As", **btn, command=self._copy_as_menu).pack(side='left', padx=2)

        # Hex display
        self.text = tk.Text(self, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10),
                             insertbackground="#58a6ff", relief="flat", wrap="none",
                             selectbackground="#1f6feb", selectforeground="#ffffff",
                             padx=10, pady=8)
        self.text.pack(fill='both', expand=True, padx=5, pady=(0, 4))

        # Configure tags
        self.text.tag_configure("address", foreground="#8b949e")
        self.text.tag_configure("hex", foreground="#c9d1d9")
        self.text.tag_configure("ascii", foreground="#8b949e")
        self.text.tag_configure("highlight", background="#1f6feb", foreground="#ffffff")
        self.text.tag_configure("bookmark", background="#3d2805", foreground="#f0b72f")
        self.text.tag_configure("diff", background="#3d0505", foreground="#ff7b72")
        self.text.tag_configure("header", foreground="#58a6ff")

        # Status bar
        self.status = tk.Label(self, text="", bg="#161b22", fg="#8b949e",
                                font=("Consolas", 9), anchor='w', padx=8, pady=3)
        self.status.pack(fill='x', side='bottom')

        # Bookmarks sidebar (hidden initially)
        self._bm_frame = None

        # Initial render
        self._render()

    def _render(self):
        """Render hex dump."""
        data = self._read_memory(self.current_address, self.view_size)
        if data is None:
            data = b'\x00' * self.view_size

        self._current_data = data
        self.text.config(state='normal')
        self.text.delete('1.0', 'end')

        # Header
        hex_headers = ' '.join(f'{i:02X}' for i in range(self.bytes_per_row))
        self.text.insert('end', f"  Offset    {hex_headers}  {'ASCII':16}\n", 'header')
        self.text.insert('end', f"  {'─' * 72}\n", 'header')

        # Bookmarked offsets for highlighting
        bm_offsets = set(self.bookmarks.keys())

        for row_start in range(0, len(data), self.bytes_per_row):
            row_data = data[row_start:row_start + self.bytes_per_row]
            abs_addr = self.current_address + row_start

            # Address column
            line = f"  0x{abs_addr:08X}  "
            self.text.insert('end', line, 'address')

            # Hex column
            hex_str = []
            for i, b in enumerate(row_data):
                tag = None
                offset = abs_addr + i
                if offset in bm_offsets:
                    tag = 'bookmark'
                hex_str.append(f'{b:02X}')

            for i, hb in enumerate(hex_str):
                offset = abs_addr + i
                t = 'bookmark' if offset in bm_offsets else 'hex'
                self.text.insert('end', hb, t)
                if i < len(hex_str) - 1:
                    self.text.insert('end', ' ', '')

            # Padding for incomplete rows
            if len(row_data) < self.bytes_per_row:
                pad = '   ' * (self.bytes_per_row - len(row_data))
                self.text.insert('end', pad, '')

            # ASCII column
            ascii_str = ''
            for b in row_data:
                if 32 <= b <= 126:
                    ascii_str += chr(b)
                else:
                    ascii_str += '.'

            self.text.insert('end', f'  {ascii_str}\n', 'ascii')

        self.text.config(state='disabled')

        # Update status
        bookmarks_here = sum(1 for bm in bm_offsets
                             if self.current_address <= bm < self.current_address + self.view_size)
        self.status.config(
            text=f"  0x{self.current_address:X} ({len(data)} bytes) | "
                 f"Bookmarks: {bookmarks_here} | "
                 f"History: {len(self._jump_history)} back"
        )

    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        if self.h_process:
            return self._read_with_handle(self.h_process, address, size)
        elif self.pid:
            h = k32.OpenProcess(0x0010, False, self.pid)
            if not h:
                return None
            try:
                return self._read_with_handle(h, address, size)
            finally:
                k32.CloseHandle(h)
        return None

    def _read_with_handle(self, h, address: int, size: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, ctypes.c_size_t(size), ctypes.byref(read)):
            return buf.raw[:read.value]
        return None

    def _go_to(self):
        addr_str = self.goto_var.get().strip()
        if not addr_str:
            return
        try:
            addr = int(addr_str.replace("0x", "").replace("0X", ""), 16)
        except ValueError:
            return
        self._jump_history.append(self.current_address)
        self._jump_forward.clear()
        self.current_address = addr
        self._render()

    def _jump_back(self):
        if self._jump_history:
            self._jump_forward.append(self.current_address)
            self.current_address = self._jump_history.pop()
            self._render()

    def _jump_forward(self):
        if self._jump_forward:
            self._jump_history.append(self.current_address)
            self.current_address = self._jump_forward.pop()
            self._render()

    def _search_aob(self):
        pattern_str = self.aob_var.get().strip()
        if not pattern_str:
            return
        # Parse AOB pattern (e.g. "48 8B ?? ?? 05")
        parts = pattern_str.split()
        pattern = []
        mask = []
        for p in parts:
            if p in ('?', '??'):
                pattern.append(0)
                mask.append(0)
            else:
                pattern.append(int(p, 16))
                mask.append(0xFF)
        if not pattern:
            return

        # Search in current view
        data = self._read_memory(self.current_address, self.view_size)
        if not data:
            return

        self.text.config(state='normal')
        self.text.tag_remove('highlight', '1.0', 'end')

        found = False
        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if mask[j] and (data[i + j] & mask[j]) != (pattern[j] & mask[j]):
                    match = False
                    break
            if match:
                found = True
                abs_offset = i
                # Calculate text position
                line_num = (abs_offset // self.bytes_per_row) + 2  # +2 for header lines
                hex_start_col = 12 + (abs_offset % self.bytes_per_row) * 3
                hex_end_col = hex_start_col + len(pattern) * 3 - 1

                start = f"{line_num}.{hex_start_col}"
                end = f"{line_num}.{hex_end_col}"
                self.text.tag_add('highlight', start, end)

        self.text.config(state='disabled')

        if found:
            self.status.config(text=f"  Found pattern '{pattern_str}' — highlighted in blue")
        else:
            self.status.config(text=f"  Pattern '{pattern_str}' not found in 0x{self.current_address:X}+0x{self.view_size:X}")

    def _take_snapshot(self):
        """Take a snapshot for diff comparison."""
        data = self._read_memory(self.current_address, self.view_size)
        if data:
            self._snapshot = data
            self.status.config(text=f"  📸 Snapshot taken at 0x{self.current_address:X} ({len(data)} bytes)")

    def _show_diff(self):
        """Compare current view with snapshot."""
        if self._snapshot is None:
            messagebox.showinfo("Diff", "No snapshot taken. Click 📸 Snap first.")
            return

        current = self._read_memory(self.current_address, self.view_size)
        if not current:
            return

        # Find differences
        diffs = []
        min_len = min(len(self._snapshot), len(current))
        for i in range(min_len):
            if self._snapshot[i] != current[i]:
                diffs.append((i, self._snapshot[i], current[i]))

        # Highlight diffs
        self.text.config(state='normal')
        self.text.tag_remove('diff', '1.0', 'end')

        for offset, old_byte, new_byte in diffs[:200]:
            line_num = (offset // self.bytes_per_row) + 2
            hex_col = 12 + (offset % self.bytes_per_row) * 3
            self.text.tag_add('diff', f"{line_num}.{hex_col}", f"{line_num}.{hex_col + 2}")

        self.text.config(state='disabled')
        self.status.config(text=f"  ⚖ Diff: {len(diffs)} byte(s) changed from snapshot")

    def _toggle_bookmark(self):
        """Bookmark the current start address."""
        if self.current_address in self.bookmarks:
            del self.bookmarks[self.current_address]
            self.status.config(text=f"  🔖 Bookmark removed at 0x{self.current_address:X}")
        else:
            label = f"Bookmark {len(self.bookmarks) + 1}"
            self.bookmarks[self.current_address] = label
            self.status.config(text=f"  🔖 Bookmark added at 0x{self.current_address:X}")
        self._render()

    def _copy_as_menu(self):
        """Show copy-as format menu."""
        data = self._read_memory(self.current_address, self.view_size)
        if not data:
            return

        menu = tk.Menu(self, tearoff=0)
        formats = [
            ("C Array", self._format_c_array),
            ("Python Bytes", self._format_python),
            ("Go []byte", self._format_go),
            ("Rust [u8]", self._format_rust),
            ("Lua Table", self._format_lua),
        ]

        for label, fmt_fn in formats:
            def make_callback(fn):
                return lambda: self._copy_formatted(fn(data))
            menu.add_command(label=label, command=make_callback(fmt_fn))

        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _copy_formatted(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    @staticmethod
    def _format_c_array(data: bytes) -> str:
        lines = ["unsigned char bytes[] = {"]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            hex_vals = ', '.join(f'0x{b:02X}' for b in row)
            lines.append(f"    {hex_vals},")
        lines.append("};")
        return '\n'.join(lines)

    @staticmethod
    def _format_python(data: bytes) -> str:
        lines = ["data = ("]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            row_str = ''.join(f'\\x{b:02X}' for b in row)
            lines.append(f"    b'{row_str}',")
        lines.append(")")
        return '\n'.join(lines)

    @staticmethod
    def _format_go(data: bytes) -> str:
        lines = ["data := []byte{"]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            hex_vals = ', '.join(f'0x{b:02X}' for b in row)
            lines.append(f"    {hex_vals},")
        lines.append("}")
        return '\n'.join(lines)

    @staticmethod
    def _format_rust(data: bytes) -> str:
        lines = ["let data: [u8; {}] = [".format(len(data))]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            hex_vals = ', '.join(f'0x{b:02X}' for b in row)
            lines.append(f"    {hex_vals},")
        lines.append("];")
        return '\n'.join(lines)

    @staticmethod
    def _format_lua(data: bytes) -> str:
        lines = ["local data = {"]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            hex_vals = ', '.join(f'0x{b:02X}' for b in row)
            lines.append(f"    {hex_vals},")
        lines.append("}")
        return '\n'.join(lines)

    def close(self):
        self.destroy()
