"""
breakpoint_manager.py - Visual Breakpoint Manager for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Unified list of all breakpoints (hardware + stealth)
  - Enable/disable individual breakpoints
  - Hit counter and last value tracking
  - Conditional breakpoint support
  - Quick actions: Replace with NOPs, Copy address, Remove
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional, Dict, List, Callable
from collections import OrderedDict

# Theme colors (matching studio_gui.py Hick's Law design)
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
    'tree_selected': '#00d4ff'
}


class BreakpointInfo:
    """Data class for breakpoint information."""
    
    def __init__(self, address: int, mode: str = 'access', size: int = 4,
                 enabled: bool = True, condition: Optional[str] = None):
        self.address = address
        self.mode = mode  # 'access' or 'write'
        self.size = size
        self.enabled = enabled
        self.condition = condition  # e.g., "value == 100"
        self.hit_count = 0
        self.last_value = None
        self.debugger = None  # Reference to UnifiedDebugger instance
        
    def to_tuple(self):
        """Convert to tuple for Treeview display."""
        return (
            f'0x{self.address:016X}',
            self.mode.upper(),
            self.size,
            self.hit_count,
            self.condition or '-',
            '✓' if self.enabled else '✗'
        )


class BreakpointManager(ttk.Frame):
    """
    Visual breakpoint manager panel.
    
    Usage:
        mgr = BreakpointManager(parent, on_toggle, on_remove, on_nop)
        mgr.add_breakpoint(0x140001000, mode='write')
        mgr.refresh()
    """
    
    def __init__(self, parent, on_toggle: Optional[Callable] = None,
                 on_remove: Optional[Callable] = None,
                 on_nop: Optional[Callable] = None,
                 on_condition: Optional[Callable] = None):
        """
        parent: tkinter parent widget
        on_toggle: callback(address, enabled) when toggle clicked
        on_remove: callback(address) when remove clicked
        on_nop: callback(address) when NOP clicked
        on_condition: callback(address, condition) when condition set
        """
        super().__init__(parent)
        
        self.on_toggle = on_toggle
        self.on_remove = on_remove
        self.on_nop = on_nop
        self.on_condition = on_condition
        
        self._breakpoints: Dict[int, BreakpointInfo] = OrderedDict()
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup UI components."""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container
        self.configure(style='Dark.TFrame')
        style.configure('Dark.TFrame', background=THEME['panel_bg'])
        
        # Header
        header_frame = tk.Frame(self, bg=THEME['panel_bg'])
        header_frame.pack(fill='x', padx=5, pady=5)
        
        title_label = tk.Label(
            header_frame,
            text="⚡ Breakpoint Manager",
            bg=THEME['panel_bg'],
            fg=THEME['fg'],
            font=('Segoe UI', 11, 'bold')
        )
        title_label.pack(side='left')
        
        # Stats label
        self.stats_label = tk.Label(
            header_frame,
            text="0 breakpoints | 0 total hits",
            bg=THEME['panel_bg'],
            fg=THEME['tree_fg'],
            font=('Segoe UI', 9)
        )
        self.stats_label.pack(side='right')
        
        # Toolbar
        toolbar = tk.Frame(self, bg=THEME['panel_bg'])
        toolbar.pack(fill='x', padx=5, pady=2)
        
        btn_style = {'bg': THEME['panel_bg'], 'fg': THEME['fg'],
                     'activebackground': THEME['bg'], 'activeforeground': THEME['fg'],
                     'font': ('Segoe UI', 9), 'relief': 'flat', 'padx': 8, 'pady': 2}
        
        self.btn_add = tk.Button(toolbar, text="➕ Add", **btn_style, command=self._on_add_click)
        self.btn_add.pack(side='left', padx=2)
        
        self.btn_toggle = tk.Button(toolbar, text="🔘 Toggle", **btn_style, command=self._on_toggle_click)
        self.btn_toggle.pack(side='left', padx=2)
        
        self.btn_condition = tk.Button(toolbar, text="📝 Condition", **btn_style, command=self._on_condition_click)
        self.btn_condition.pack(side='left', padx=2)
        
        self.btn_nop = tk.Button(toolbar, text="🚫 NOP", **btn_style, command=self._on_nop_click)
        self.btn_nop.pack(side='left', padx=2)
        
        self.btn_remove = tk.Button(toolbar, text="🗑️ Remove", **btn_style,
                                     fg=THEME['error'], command=self._on_remove_click)
        self.btn_remove.pack(side='left', padx=2)
        
        self.btn_clear = tk.Button(toolbar, text="🧹 Clear All", **btn_style,
                                    fg=THEME['warning'], command=self._on_clear_click)
        self.btn_clear.pack(side='right', padx=2)
        
        # Treeview for breakpoints
        tree_frame = tk.Frame(self, bg=THEME['tree_bg'])
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('address', 'type', 'size', 'hits', 'condition', 'enabled')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                  height=8, style='Dark.Treeview')
        
        # Configure columns
        self.tree.heading('address', text='Address', anchor='w')
        self.tree.heading('type', text='Type', anchor='w')
        self.tree.heading('size', text='Size', anchor='w')
        self.tree.heading('hits', text='Hits', anchor='w')
        self.tree.heading('condition', text='Condition', anchor='w')
        self.tree.heading('enabled', text='Enabled', anchor='w')
        
        self.tree.column('address', width=160, minwidth=120)
        self.tree.column('type', width=60, minwidth=50)
        self.tree.column('size', width=50, minwidth=40)
        self.tree.column('hits', width=60, minwidth=50)
        self.tree.column('condition', width=100, minwidth=80)
        self.tree.column('enabled', width=60, minwidth=50)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Configure treeview style
        style.configure('Dark.Treeview',
                        background=THEME['tree_bg'],
                        foreground=THEME['tree_fg'],
                        fieldbackground=THEME['tree_bg'],
                        borderwidth=0)
        style.map('Dark.Treeview',
                  background=[('selected', THEME['tree_selected'])],
                  foreground=[('selected', THEME['bg'])])
        
        # Context menu (right-click)
        self.menu = tk.Menu(self, tearoff=0, bg=THEME['panel_bg'], fg=THEME['tree_fg'])
        self.menu.add_command(label="Toggle Enable/Disable", command=self._on_toggle_click)
        self.menu.add_command(label="Set Condition", command=self._on_condition_click)
        self.menu.add_separator()
        self.menu.add_command(label="Replace with NOPs", command=self._on_nop_click)
        self.menu.add_command(label="Copy Address", command=self._copy_address)
        self.menu.add_separator()
        self.menu.add_command(label="Remove Breakpoint", command=self._on_remove_click)
        
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Double-1>', self._on_double_click)
        
    def _show_context_menu(self, event):
        """Show context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.menu.post(event.x_root, event.y_root)
            
    def _on_double_click(self, event):
        """Handle double-click to toggle breakpoint."""
        self._on_toggle_click()
        
    def _get_selected_address(self) -> Optional[int]:
        """Get the address of selected item."""
        selection = self.tree.selection()
        if not selection:
            return None
        item = selection[0]
        values = self.tree.item(item, 'values')
        if values:
            addr_str = values[0]
            try:
                return int(addr_str, 16)
            except (TypeError, ValueError):
                return None
        return None
        
    def _on_add_click(self):
        """Handle add button click."""
        # Simple dialog for address input
        dialog = tk.Toplevel(self)
        dialog.title("Add Breakpoint")
        dialog.configure(bg=THEME['panel_bg'])
        dialog.geometry("320x180")
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry(f"+{self.winfo_rootx() + 50}+{self.winfo_rooty() + 50}")
        
        # Address input
        tk.Label(dialog, text="Address (hex):", bg=THEME['panel_bg'], fg=THEME['fg']).pack(pady=5)
        addr_entry = tk.Entry(dialog, bg=THEME['tree_bg'], fg=THEME['tree_fg'],
                               insertbackground=THEME['fg'], font=('Consolas', 10))
        addr_entry.pack(padx=10, fill='x')
        addr_entry.insert(0, "0x")
        
        # Mode selection
        tk.Label(dialog, text="Mode:", bg=THEME['panel_bg'], fg=THEME['fg']).pack(pady=5)
        mode_var = tk.StringVar(value='write')
        mode_frame = tk.Frame(dialog, bg=THEME['panel_bg'])
        mode_frame.pack()
        tk.Radiobutton(mode_frame, text="Write Only", variable=mode_var, value='write',
                       bg=THEME['panel_bg'], fg=THEME['fg'],
                       selectcolor=THEME['bg']).pack(side='left', padx=5)
        tk.Radiobutton(mode_frame, text="Read/Write", variable=mode_var, value='access',
                       bg=THEME['panel_bg'], fg=THEME['fg'],
                       selectcolor=THEME['bg']).pack(side='left', padx=5)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=THEME['panel_bg'])
        btn_frame.pack(pady=10)
        
        def on_ok():
            try:
                addr_str = addr_entry.get().strip()
                if addr_str.startswith('0x') or addr_str.startswith('0X'):
                    addr = int(addr_str, 16)
                else:
                    addr = int(addr_str, 16)
                mode = mode_var.get()
                self.add_breakpoint(addr, mode=mode)
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid address format")
                
        tk.Button(btn_frame, text="Add", command=on_ok, bg=THEME['panel_bg'],
                  fg=THEME['success'], font=('Segoe UI', 9, 'bold')).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg=THEME['panel_bg'],
                  fg=THEME['tree_fg'], font=('Segoe UI', 9)).pack(side='left', padx=5)
        
    def _on_toggle_click(self):
        """Toggle enabled state of selected breakpoint."""
        addr = self._get_selected_address()
        if addr is None:
            return
            
        if addr in self._breakpoints:
            bp = self._breakpoints[addr]
            bp.enabled = not bp.enabled
            
            if self.on_toggle:
                self.on_toggle(addr, bp.enabled)
                
            self.refresh()
            
    def _on_condition_click(self):
        """Set condition for selected breakpoint."""
        addr = self._get_selected_address()
        if addr is None:
            return
            
        if addr in self._breakpoints:
            bp = self._breakpoints[addr]
            condition = simpledialog.askstring(
                "Set Condition",
                f"Enter condition for 0x{addr:X}\n(e.g., 'value == 100', 'value > 50')",
                initialvalue=bp.condition or ''
            )
            
            if condition is not None:
                bp.condition = condition.strip() if condition.strip() else None
                
                if self.on_condition:
                    self.on_condition(addr, bp.condition)
                    
                self.refresh()
                
    def _on_nop_click(self):
        """Replace selected instruction with NOPs."""
        addr = self._get_selected_address()
        if addr is None:
            return
            
        if messagebox.askyesno("Confirm NOP",
                               f"Replace instruction at 0x{addr:X} with NOPs?"):
            if self.on_nop:
                self.on_nop(addr)
                
    def _on_remove_click(self):
        """Remove selected breakpoint."""
        addr = self._get_selected_address()
        if addr is None:
            return
            
        if self.on_remove:
            self.on_remove(addr)
            
        self.remove_breakpoint(addr)
        
    def _on_clear_click(self):
        """Clear all breakpoints."""
        if not self._breakpoints:
            return
            
        if messagebox.askyesno("Confirm Clear",
                               f"Remove all {len(self._breakpoints)} breakpoints?"):
            for addr in list(self._breakpoints.keys()):
                if self.on_remove:
                    self.on_remove(addr)
            self._breakpoints.clear()
            self.refresh()
            
    def _copy_address(self):
        """Copy selected address to clipboard."""
        addr = self._get_selected_address()
        if addr is not None:
            self.clipboard_clear()
            self.clipboard_append(f'0x{addr:016X}')
            
    def add_breakpoint(self, address: int, mode: str = 'access',
                       size: int = 4, condition: Optional[str] = None):
        """Add a breakpoint to the manager."""
        try:
            address = int(address)
            size = int(size)
        except (TypeError, ValueError) as exc:
            raise ValueError("address and size must be integers") from exc
        if address < 0:
            raise ValueError("address must be non-negative")
        if mode not in ('access', 'write'):
            raise ValueError("mode must be 'access' or 'write'")
        if size not in (1, 2, 4, 8):
            raise ValueError("size must be 1, 2, 4, or 8 bytes")
        if address not in self._breakpoints:
            bp = BreakpointInfo(address, mode, size, enabled=True, condition=condition)
            self._breakpoints[address] = bp
            self.refresh()
            
    def remove_breakpoint(self, address: int):
        """Remove a breakpoint from the manager."""
        if address in self._breakpoints:
            del self._breakpoints[address]
            self.refresh()
            
    def update_hit_count(self, address: int, hit_count: int, last_value: Optional[int] = None):
        """Update hit count and last value for a breakpoint."""
        if address in self._breakpoints:
            bp = self._breakpoints[address]
            bp.hit_count = hit_count
            bp.last_value = last_value
            self.refresh()
            
    def get_breakpoint(self, address: int) -> Optional[BreakpointInfo]:
        """Get breakpoint info for an address."""
        return self._breakpoints.get(address)
        
    def get_all_breakpoints(self) -> Dict[int, BreakpointInfo]:
        """Get all breakpoints."""
        return dict(self._breakpoints)
        
    def get_enabled_breakpoints(self) -> List[int]:
        """Get list of enabled breakpoint addresses."""
        return [addr for addr, bp in self._breakpoints.items() if bp.enabled]
        
    def refresh(self):
        """Refresh the display."""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Populate tree
        for addr, bp in self._breakpoints.items():
            self.tree.insert('', 'end', values=bp.to_tuple())
            
        # Update stats
        total_hits = sum(bp.hit_count for bp in self._breakpoints.values())
        enabled_count = sum(1 for bp in self._breakpoints.values() if bp.enabled)
        self.stats_label.config(
            text=f"{len(self._breakpoints)} breakpoints ({enabled_count} enabled) | {total_hits} total hits"
        )


# Standalone test
if __name__ == '__main__':
    root = tk.Tk()
    root.title("Breakpoint Manager Test")
    root.configure(bg=THEME['bg'])
    root.geometry("600x400")
    
    mgr = BreakpointManager(root)
    mgr.pack(fill='both', expand=True)
    
    # Add test breakpoints
    mgr.add_breakpoint(0x140001000, mode='write')
    mgr.add_breakpoint(0x140002000, mode='access')
    mgr.update_hit_count(0x140001000, 42)
    
    root.mainloop()
