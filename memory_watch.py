"""
memory_watch.py - Live Memory Watch Window for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Auto-refreshing values at configurable intervals
  - Change highlighting (green/red/yellow)
  - Multiple format display (hex, int, float, string)
  - Freeze/unfreeze toggle
  - Byte diff view
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import ctypes
import struct
import time
from typing import Optional, Dict, List, Tuple
from collections import OrderedDict

k32 = ctypes.windll.kernel32

# Theme colors
THEME = {
    'bg': '#0a0e27',
    'fg': '#00d4ff',
    'accent': '#ff6b9d',
    'success': '#00ff88',
    'warning': '#ffaa00',
    'error': '#ff4444',
    'panel_bg': '#151a30',
    'tree_bg': '#1a1f35',
    'tree_fg': '#e0e0e0',
    'changed_inc': '#00ff88',
    'changed_dec': '#ff4444',
    'changed': '#ffaa00'
}


class WatchEntry:
    """Data class for a watched address."""
    
    def __init__(self, address: int, size: int = 16, frozen: bool = False,
                 freeze_value: Optional[bytes] = None):
        self.address = address
        self.size = size
        self.frozen = frozen
        self.freeze_value = freeze_value
        self.last_value = None
        self.change_count = 0
        
    def to_tuple(self):
        """Convert to tuple for Treeview display."""
        return (
            f'0x{self.address:016X}',
            self.size,
            '',  # hex (filled at runtime)
            '',  # int
            '',  # float
            '',  # string
            '',  # changed
            '❄️' if self.frozen else ''
        )


class MemoryWatchWindow(tk.Toplevel):
    """
    Live memory watch window.
    
    Usage:
        win = MemoryWatchWindow(root, pid)
        win.add_watch(0x140001000)
        win.start_auto_refresh()
    """
    
    def __init__(self, parent, pid: int, process_handle=None,
                 on_freeze_toggle=None):
        """
        parent: tkinter parent window
        pid: target process ID
        process_handle: optional open process handle
        on_freeze_toggle: callback(address, frozen) when freeze toggled
        """
        super().__init__(parent)
        
        self.title("🔍 Memory Watch")
        self.geometry("800x400")
        self.configure(bg=THEME['bg'])
        
        self.pid = pid
        self.process_handle = process_handle
        self.on_freeze_toggle = on_freeze_toggle
        
        self._watches: Dict[int, WatchEntry] = OrderedDict()
        self._prev_values: Dict[int, bytes] = {}
        self._change_state: Dict[int, Tuple[str, str]] = {}
        self._refresh_job = None
        self.refresh_interval = 100  # ms
        self._is_refreshing = False
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup UI components."""
        # Header
        header_frame = tk.Frame(self, bg=THEME['panel_bg'])
        header_frame.pack(fill='x', padx=5, pady=5)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Memory Watch",
            bg=THEME['panel_bg'],
            fg=THEME['fg'],
            font=('Segoe UI', 12, 'bold')
        )
        title_label.pack(side='left')
        
        self.status_label = tk.Label(
            header_frame,
            text="0 addresses | Refresh: 100ms",
            bg=THEME['panel_bg'],
            fg=THEME['tree_fg'],
            font=('Segoe UI', 9)
        )
        self.status_label.pack(side='right')
        
        # Toolbar
        toolbar = tk.Frame(self, bg=THEME['panel_bg'])
        toolbar.pack(fill='x', padx=5, pady=2)
        
        btn_style = {'bg': THEME['panel_bg'], 'fg': THEME['fg'],
                     'activebackground': THEME['bg'], 'activeforeground': THEME['fg'],
                     'font': ('Segoe UI', 9), 'relief': 'flat', 'padx': 8, 'pady': 2}
        
        self.btn_add = tk.Button(toolbar, text="➕ Add Address", **btn_style,
                                  command=self._on_add_click)
        self.btn_add.pack(side='left', padx=2)
        
        self.btn_remove = tk.Button(toolbar, text="🗑️ Remove", **btn_style,
                                     command=self._on_remove_click)
        self.btn_remove.pack(side='left', padx=2)
        
        self.btn_freeze = tk.Button(toolbar, text="❄️ Freeze", **btn_style,
                                     command=self._on_freeze_click)
        self.btn_freeze.pack(side='left', padx=2)
        
        self.btn_clear = tk.Button(toolbar, text="🧹 Clear All", **btn_style,
                                    command=self._on_clear_click)
        self.btn_clear.pack(side='left', padx=2)
        
        # Separator
        ttk.Separator(toolbar, orient='vertical').pack(side='left', fill='y', padx=10)
        
        # Refresh rate
        tk.Label(toolbar, text="Refresh:", bg=THEME['panel_bg'],
                 fg=THEME['tree_fg'], font=('Segoe UI', 9)).pack(side='left')
        
        self.refresh_var = tk.StringVar(value='100ms')
        refresh_combo = ttk.Combobox(toolbar, textvariable=self.refresh_var,
                                      values=['10ms', '50ms', '100ms', '250ms', '500ms', '1000ms'],
                                      width=8, state='readonly')
        refresh_combo.pack(side='left', padx=5)
        refresh_combo.bind('<<ComboboxSelected>>', self._on_refresh_rate_change)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.btn_auto = tk.Checkbutton(
            toolbar, text="Auto", variable=self.auto_refresh_var,
            bg=THEME['panel_bg'], fg=THEME['fg'],
            selectcolor=THEME['bg'], activebackground=THEME['panel_bg'],
            command=self._toggle_auto_refresh
        )
        self.btn_auto.pack(side='left', padx=5)
        
        self.btn_refresh_now = tk.Button(toolbar, text="🔄 Refresh", **btn_style,
                                          command=self._refresh_values)
        self.btn_refresh_now.pack(side='left', padx=2)
        
        # Treeview
        tree_frame = tk.Frame(self, bg=THEME['tree_bg'])
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('address', 'size', 'hex', 'int', 'float', 'string', 'changed', 'freeze')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('address', text='Address', anchor='w')
        self.tree.heading('size', text='Size', anchor='w')
        self.tree.heading('hex', text='Hex', anchor='w')
        self.tree.heading('int', text='Int32', anchor='w')
        self.tree.heading('float', text='Float', anchor='w')
        self.tree.heading('string', text='String', anchor='w')
        self.tree.heading('changed', text='Δ', anchor='center')
        self.tree.heading('freeze', text='❄️', anchor='center')
        
        self.tree.column('address', width=140, minwidth=120)
        self.tree.column('size', width=50, minwidth=40)
        self.tree.column('hex', width=200, minwidth=150)
        self.tree.column('int', width=80, minwidth=60)
        self.tree.column('float', width=80, minwidth=60)
        self.tree.column('string', width=100, minwidth=80)
        self.tree.column('changed', width=30, minwidth=30, anchor='center')
        self.tree.column('freeze', width=30, minwidth=30, anchor='center')
        
        # Scrollbars
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        xscroll = ttk.Scrollbar(tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Configure treeview tags
        self.tree.tag_configure('changed_inc', foreground=THEME['changed_inc'])
        self.tree.tag_configure('changed_dec', foreground=THEME['changed_dec'])
        self.tree.tag_configure('changed', foreground=THEME['changed'])
        self.tree.tag_configure('frozen', foreground=THEME['accent'])
        
        # Context menu
        self.menu = tk.Menu(self, tearoff=0, bg=THEME['panel_bg'], fg=THEME['tree_fg'])
        self.menu.add_command(label="Edit Value", command=self._on_edit_value)
        self.menu.add_command(label="Freeze/Unfreeze", command=self._on_freeze_click)
        self.menu.add_separator()
        self.menu.add_command(label="Copy Address", command=self._copy_address)
        self.menu.add_command(label="Copy Value", command=self._copy_value)
        self.menu.add_separator()
        self.menu.add_command(label="Remove", command=self._on_remove_click)
        
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Double-1>', self._on_double_click)
        
        # Start auto-refresh
        self._start_auto_refresh()
        
    def _on_add_click(self):
        """Add address dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("Add Watch Address")
        dialog.geometry("300x150")
        dialog.configure(bg=THEME['panel_bg'])
        dialog.transient(self)
        dialog.grab_set()
        
        tk.Label(dialog, text="Address (hex):", bg=THEME['panel_bg'],
                 fg=THEME['fg']).pack(pady=5)
        
        addr_entry = tk.Entry(dialog, bg=THEME['tree_bg'], fg=THEME['tree_fg'],
                               font=('Consolas', 10), width=30)
        addr_entry.pack(padx=10, fill='x')
        addr_entry.insert(0, "0x")
        
        tk.Label(dialog, text="Size (bytes):", bg=THEME['panel_bg'],
                 fg=THEME['fg']).pack(pady=5)
        
        size_var = tk.StringVar(value='16')
        size_spin = tk.Spinbox(dialog, from_=1, to=256, textvariable=size_var,
                               bg=THEME['tree_bg'], fg=THEME['tree_fg'], width=10)
        size_spin.pack()
        
        def on_ok():
            try:
                addr_str = addr_entry.get().strip()
                if addr_str.startswith('0x') or addr_str.startswith('0X'):
                    addr = int(addr_str, 16)
                else:
                    addr = int(addr_str, 16)
                    
                size = int(size_var.get())
                
                self.add_watch(addr, size)
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid address or size")
                
        btn_frame = tk.Frame(dialog, bg=THEME['panel_bg'])
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Add", command=on_ok, bg=THEME['panel_bg'],
                  fg=THEME['success'], font=('Segoe UI', 9, 'bold')).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg=THEME['panel_bg'],
                  fg=THEME['tree_fg']).pack(side='left', padx=5)
        
    def _on_remove_click(self):
        """Remove selected watch."""
        selection = self.tree.selection()
        if not selection:
            return
            
        for item in selection:
            values = self.tree.item(item, 'values')
            if values:
                addr_str = values[0]
                addr = int(addr_str, 16)
                self.remove_watch(addr)
                
    def _on_freeze_click(self):
        """Toggle freeze on selected."""
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.tree.item(item, 'values')
        if values:
            addr_str = values[0]
            addr = int(addr_str, 16)
            
            if addr in self._watches:
                entry = self._watches[addr]
                entry.frozen = not entry.frozen
                
                if entry.frozen and entry.last_value:
                    entry.freeze_value = entry.last_value
                else:
                    entry.freeze_value = None
                    
                if self.on_freeze_toggle:
                    self.on_freeze_toggle(addr, entry.frozen)
                    
                self._refresh_values()
                
    def _on_clear_click(self):
        """Clear all watches."""
        if self._watches and messagebox.askyesno("Confirm Clear",
                                                   f"Remove all {len(self._watches)} watches?"):
            self._watches.clear()
            self._prev_values.clear()
            self._change_state.clear()
            self._refresh_display()
            
    def _on_refresh_rate_change(self, event):
        """Handle refresh rate change."""
        rate_str = self.refresh_var.get()
        try:
            self.refresh_interval = max(10, min(5000, int(rate_str.replace('ms', ''))))
        except (TypeError, ValueError):
            self.refresh_interval = 100
            self.refresh_var.set('100ms')
        self.status_label.config(text=f"{len(self._watches)} addresses | Refresh: {rate_str}")
        
    def _toggle_auto_refresh(self):
        """Toggle auto-refresh."""
        if self.auto_refresh_var.get():
            self._start_auto_refresh()
        else:
            self._stop_auto_refresh()
            
    def _start_auto_refresh(self):
        """Start auto-refresh cycle."""
        self._stop_auto_refresh()
        self._refresh_values()
        self._refresh_job = self.after(self.refresh_interval, self._start_auto_refresh)
        
    def _stop_auto_refresh(self):
        """Stop auto-refresh."""
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
            
    def _refresh_values(self):
        """Read and update all watched addresses."""
        if self._is_refreshing:
            return
            
        self._is_refreshing = True
        
        try:
            for addr, entry in self._watches.items():
                # Read current value
                data = self._read_memory(addr, entry.size)
                
                if data:
                    entry.last_value = data
                    
                    # Check for changes before replacing the previous value.
                    prev = self._prev_values.get(addr)
                    changed = ''
                    tag = ''
                    
                    if prev and prev != data:
                        # Determine change type
                        if len(prev) >= 4 and len(data) >= 4:
                            old_int = struct.unpack('<i', prev[:4])[0]
                            new_int = struct.unpack('<i', data[:4])[0]
                            
                            if new_int > old_int:
                                changed = '▲'
                                tag = 'changed_inc'
                            elif new_int < old_int:
                                changed = '▼'
                                tag = 'changed_dec'
                            else:
                                changed = '●'
                                tag = 'changed'
                        else:
                            changed = '●'
                            tag = 'changed'
                            
                        entry.change_count += 1
                        self._change_state[addr] = (changed, tag)
                    elif prev is None:
                        self._change_state.pop(addr, None)
                        
                    # Handle freeze
                    if entry.frozen and entry.freeze_value is not None:
                        self._write_memory(addr, entry.freeze_value)
                        
                    self._prev_values[addr] = data
                        
        finally:
            self._is_refreshing = False
            
        self._refresh_display()
        
    def _refresh_display(self):
        """Refresh treeview display."""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Populate
        for addr, entry in self._watches.items():
            if entry.last_value:
                data = entry.last_value
                changed, tag = self._change_state.get(addr, ('', ''))
                        
                # Format values
                hex_str = data.hex()
                int_val = struct.unpack('<i', data[:4])[0] if len(data) >= 4 else 0
                float_val = struct.unpack('<f', data[:4])[0] if len(data) >= 4 else 0.0
                str_val = data.decode('utf-8', errors='replace')[:16]
                
                values = (
                    f'0x{addr:016X}',
                    entry.size,
                    hex_str,
                    int_val,
                    f'{float_val:.2f}',
                    str_val,
                    changed,
                    '❄️' if entry.frozen else ''
                )
                
                tags = (tag,) if tag else ('frozen' if entry.frozen else '')
                self.tree.insert('', 'end', values=values, tags=tags)
            else:
                # No data yet
                values = entry.to_tuple()
                self.tree.insert('', 'end', values=values)
                
        # Update status
        rate_str = self.refresh_var.get()
        self.status_label.config(text=f"{len(self._watches)} addresses | Refresh: {rate_str}")
        
    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from target process."""
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
        """Read memory with given handle."""
        if address < 0 or size < 1 or size > 16 * 1024 * 1024:
            return None
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        
        if k32.ReadProcessMemory(h, address, buffer, size, ctypes.byref(read)):
            return buffer.raw[:read.value]
        return None
        
    def _write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to target process."""
        if self.process_handle:
            return self._write_with_handle(self.process_handle, address, data)
        elif self.pid:
            h = k32.OpenProcess(0x0020 | 0x0008, False, self.pid)  # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
            if not h:
                return False
            try:
                return self._write_with_handle(h, address, data)
            finally:
                k32.CloseHandle(h)
        return False
        
    def _write_with_handle(self, h, address: int, data: bytes) -> bool:
        """Write memory with given handle."""
        if address < 0 or not isinstance(data, (bytes, bytearray)) or not data:
            return False
        written = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(h, address, data, len(data), ctypes.byref(written)) != 0
        return bool(ok and written.value == len(data))
        
    def _show_context_menu(self, event):
        """Show context menu."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.menu.post(event.x_root, event.y_root)
            
    def _on_double_click(self, event):
        """Handle double-click."""
        self._on_edit_value()
        
    def _on_edit_value(self):
        """Edit value at selected address."""
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.tree.item(item, 'values')
        if values:
            addr_str = values[0]
            addr = int(addr_str, 16)
            
            if addr in self._watches:
                entry = self._watches[addr]
                
                # Show edit dialog
                new_value = simpledialog.askstring(
                    "Edit Value",
                    f"New value for 0x{addr:X} (hex):",
                    initialvalue=entry.last_value.hex() if entry.last_value else ''
                )
                
                if new_value:
                    try:
                        data = bytes.fromhex(new_value.replace(' ', ''))
                        self._write_memory(addr, data)
                        self._refresh_values()
                    except ValueError:
                        messagebox.showerror("Error", "Invalid hex string")
                        
    def _copy_address(self):
        """Copy address to clipboard."""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0], 'values')
            if values:
                self.clipboard_clear()
                self.clipboard_append(values[0])
                
    def _copy_value(self):
        """Copy value to clipboard."""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0], 'values')
            if values:
                self.clipboard_clear()
                self.clipboard_append(values[2])  # hex column
                
    def add_watch(self, address: int, size: int = 16):
        """Add an address to watch."""
        try:
            address = int(address)
            size = int(size)
        except (TypeError, ValueError) as exc:
            raise ValueError("address and size must be integers") from exc
        if address < 0 or size < 1 or size > 4096:
            raise ValueError("address must be non-negative and size must be 1-4096 bytes")
        if address not in self._watches:
            self._watches[address] = WatchEntry(address, size)
            self._refresh_values()
            
    def remove_watch(self, address: int):
        """Remove a watched address."""
        if address in self._watches:
            del self._watches[address]
            if address in self._prev_values:
                del self._prev_values[address]
            self._change_state.pop(address, None)
            self._refresh_display()
            
    def get_watched_addresses(self) -> List[int]:
        """Get list of watched addresses."""
        return list(self._watches.keys())
        
    def close(self):
        """Clean close."""
        self._stop_auto_refresh()
        self.destroy()


# Standalone test
if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    win = MemoryWatchWindow(root, pid=0)  # PID 0 for test
    win.add_watch(0x140001000, 16)
    
    root.mainloop()
