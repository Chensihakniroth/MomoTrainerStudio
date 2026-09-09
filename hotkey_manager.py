"""
hotkey_manager.py - Global Hotkey System for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Configurable hotkeys for common debugging operations
  - F2: Toggle breakpoint
  - F5: Run/Continue
  - F9: Toggle freeze
  - Ctrl+N: Replace with NOPs
  - Ctrl+G: Go to address
  - Ctrl+B: Add to cheat table
"""

import tkinter as tk
from tkinter import simpledialog, messagebox
from typing import Optional, Callable, Dict
from collections import OrderedDict


class HotkeyManager:
    """
    Global hotkey manager for debugging operations.
    
    Usage:
        hk = HotkeyManager(root, debugger, scanner, gui)
        hk.register('<F2>', lambda: print('F2 pressed'))
        hk.unregister('<F2>')
    """
    
    def __init__(self, root: tk.Tk, debugger=None, scanner=None, gui=None):
        """
        root: tkinter root window
        debugger: UnifiedDebugger instance
        scanner: memory scanner instance
        gui: main GUI instance (for accessing UI elements)
        """
        self.root = root
        self.debugger = debugger
        self.scanner = scanner
        self.gui = gui
        
        self._hotkeys: Dict[str, Callable] = OrderedDict()
        self._enabled = True
        
        self._register_defaults()
        
    def _register_defaults(self):
        """Register default hotkeys."""
        # F2: Toggle breakpoint at selected address
        self.register('<F2>', self._toggle_breakpoint)
        
        # F5: Run/Continue execution
        self.register('<F5>', self._continue_execution)
        
        # F9: Toggle freeze on selected address
        self.register('<F9>', self._toggle_freeze)
        
        # F10: Step over (if supported)
        self.register('<F10>', self._step_over)
        
        # F11: Step into (if supported)
        self.register('<F11>', self._step_into)
        
        # Ctrl+B: Add to cheat table
        self.register('<Control-b>', self._add_to_cheat_table)
        
        # Ctrl+N: Replace with NOPs
        self.register('<Control-n>', self._nop_instruction)
        
        # Ctrl+G: Go to address
        self.register('<Control-g>', self._goto_address)
        
        # Ctrl+C: Copy address (when address field focused)
        self.register('<Control-c>', self._copy_address)
        
        # Delete: Remove selected item
        self.register('<Delete>', self._delete_selected)
        
        # Escape: Cancel current operation
        self.register('<Escape>', self._cancel_operation)
        
    def register(self, key_sequence: str, callback: Callable):
        """
        Register a hotkey.
        
        key_sequence: tkinter key sequence (e.g., '<F2>', '<Control-n>')
        callback: function to call when hotkey pressed
        """
        self._hotkeys[key_sequence] = callback
        self.root.bind(key_sequence, lambda e: self._execute_callback(callback))
        
    def unregister(self, key_sequence: str):
        """Unregister a hotkey."""
        if key_sequence in self._hotkeys:
            del self._hotkeys[key_sequence]
            self.root.unbind(key_sequence)
            
    def _execute_callback(self, callback: Callable):
        """Execute callback with error handling."""
        if not self._enabled:
            return
            
        try:
            callback()
        except Exception as e:
            print(f"[HotkeyManager] Error executing callback: {e}")
            
    def enable(self):
        """Enable hotkey processing."""
        self._enabled = True
        
    def disable(self):
        """Disable hotkey processing."""
        self._enabled = False
        
    def is_enabled(self) -> bool:
        """Check if hotkeys are enabled."""
        return self._enabled
        
    def get_registered_hotkeys(self) -> Dict[str, str]:
        """Get all registered hotkeys with descriptions."""
        return {
            '<F2>': 'Toggle breakpoint',
            '<F5>': 'Run/Continue',
            '<F9>': 'Toggle freeze',
            '<F10>': 'Step over',
            '<F11>': 'Step into',
            '<Control-b>': 'Add to cheat table',
            '<Control-n>': 'Replace with NOPs',
            '<Control-g>': 'Go to address',
            '<Delete>': 'Remove selected',
            '<Escape>': 'Cancel operation'
        }
        
    # ========== Default Hotkey Handlers ==========
    
    def _toggle_breakpoint(self):
        """Toggle breakpoint at selected address."""
        if not self.gui:
            return
            
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showinfo("Info", "Select an address first")
            return
            
        if self.debugger:
            # Check if breakpoint exists
            if hasattr(self.debugger, '_breakpoints'):
                if addr in self.debugger._breakpoints:
                    # Remove breakpoint
                    self.debugger.remove_breakpoint(addr)
                    self._show_status(f"Breakpoint removed: 0x{addr:X}")
                else:
                    # Add breakpoint
                    self.debugger.add_breakpoint(addr, mode='write')
                    self._show_status(f"Breakpoint added: 0x{addr:X}")
            else:
                # Single debugger instance
                if self.debugger.is_running():
                    self.debugger.stop()
                    self._show_status(f"Breakpoint disabled: 0x{addr:X}")
                else:
                    self.debugger.address = addr
                    self.debugger.start()
                    self._show_status(f"Breakpoint enabled: 0x{addr:X}")
                    
    def _continue_execution(self):
        """Continue execution (run)."""
        if not self.debugger:
            return
            
        if hasattr(self.debugger, 'is_running'):
            if self.debugger.is_running():
                self._show_status("Debugger already running")
            else:
                self.debugger.start()
                self._show_status("Debugger started")
                
    def _toggle_freeze(self):
        """Toggle freeze on selected address."""
        if not self.gui:
            return
            
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showinfo("Info", "Select an address first")
            return
            
        # This would integrate with the cheat table's freeze functionality
        if hasattr(self.gui, 'toggle_freeze'):
            self.gui.toggle_freeze(addr)
            self._show_status(f"Freeze toggled: 0x{addr:X}")
        else:
            self._show_status("Freeze toggle not implemented")
            
    def _step_over(self):
        """Step over current instruction."""
        self._show_status("Step over not yet implemented")
        
    def _step_into(self):
        """Step into current instruction."""
        self._show_status("Step into not yet implemented")
        
    def _add_to_cheat_table(self):
        """Add selected address to cheat table."""
        if not self.gui:
            return
            
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showinfo("Info", "Select an address first")
            return
            
        # Ask for description
        description = simpledialog.askstring(
            "Add to Cheat Table",
            f"Description for 0x{addr:X}:",
            initialvalue=f"Address_{addr:X}"
        )
        
        if description and hasattr(self.gui, 'add_to_cheat_table'):
            self.gui.add_to_cheat_table(addr, description)
            self._show_status(f"Added to cheat table: {description}")
            
    def _nop_instruction(self):
        """Replace current instruction with NOPs."""
        if not self.gui:
            return
            
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showinfo("Info", "Select an address first")
            return
            
        if messagebox.askyesno("Confirm NOP",
                               f"Replace instruction at 0x{addr:X} with NOPs?"):
            if self.debugger and hasattr(self.debugger, 'replace_with_nops'):
                if self.debugger.replace_with_nops(addr):
                    self._show_status(f"NOPed: 0x{addr:X}")
                else:
                    messagebox.showerror("Error", "Failed to write NOPs")
                    
    def _goto_address(self):
        """Go to address dialog."""
        addr_str = simpledialog.askstring(
            "Go to Address",
            "Enter address (hex):",
            initialvalue="0x"
        )
        
        if addr_str:
            try:
                if addr_str.startswith('0x') or addr_str.startswith('0X'):
                    addr = int(addr_str, 16)
                else:
                    addr = int(addr_str, 16)
                    
                if self.gui and hasattr(self.gui, 'goto_address'):
                    self.gui.goto_address(addr)
                    
                self._show_status(f"Jumped to: 0x{addr:X}")
            except ValueError:
                messagebox.showerror("Error", "Invalid address format")
                
    def _copy_address(self):
        """Copy selected address to clipboard."""
        addr = self._get_selected_address()
        if addr is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append(f'0x{addr:016X}')
            self._show_status(f"Copied: 0x{addr:X}")
            
    def _delete_selected(self):
        """Delete selected item."""
        if self.gui and hasattr(self.gui, 'delete_selected'):
            self.gui.delete_selected()
            self._show_status("Item deleted")
            
    def _cancel_operation(self):
        """Cancel current operation."""
        if self.debugger and hasattr(self.debugger, 'is_running'):
            if self.debugger.is_running():
                self.debugger.stop()
                self._show_status("Debugger stopped")
                
    def _get_selected_address(self) -> Optional[int]:
        """Get selected address from GUI."""
        if self.gui and hasattr(self.gui, 'get_selected_address'):
            return self.gui.get_selected_address()
        return None
        
    def _show_status(self, message: str):
        """Show status message in GUI."""
        if self.gui and hasattr(self.gui, 'show_status'):
            self.gui.show_status(message)
        else:
            print(f"[HotkeyManager] {message}")


class HotkeyConfigDialog(tk.Toplevel):
    """
    Dialog for configuring hotkeys.
    """
    
    def __init__(self, parent, hotkey_manager: HotkeyManager):
        super().__init__(parent)
        self.title("Configure Hotkeys")
        self.geometry("400x350")
        self.configure(bg='#0a0e27')
        self.transient(parent)
        self.grab_set()
        
        self.hkm = hotkey_manager
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup dialog UI."""
        # Title
        tk.Label(self, text="⌨️ Hotkey Configuration",
                 bg='#0a0e27', fg='#00d4ff',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Listbox for hotkeys
        list_frame = tk.Frame(self, bg='#1a1f35')
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.listbox = tk.Listbox(
            list_frame,
            bg='#1a1f35',
            fg='#e0e0e0',
            selectbackground='#00d4ff',
            selectforeground='#0a0e27',
            font=('Consolas', 10),
            yscrollcommand=scrollbar.set
        )
        self.listbox.pack(fill='both', expand=True)
        scrollbar.config(command=self.listbox.yview)
        
        # Populate listbox
        hotkeys = self.hkm.get_registered_hotkeys()
        for key, desc in hotkeys.items():
            self.listbox.insert('end', f"{key:15} - {desc}")
            
        # Buttons
        btn_frame = tk.Frame(self, bg='#0a0e27')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Close", command=self.destroy,
                  bg='#0a0e27', fg='#00d4ff',
                  font=('Segoe UI', 10)).pack()


# Standalone test
if __name__ == '__main__':
    root = tk.Tk()
    root.title("Hotkey Manager Test")
    root.geometry("400x300")
    
    hkm = HotkeyManager(root)
    
    # Show registered hotkeys
    tk.Label(root, text="Press F2, F5, F9, Ctrl+N, Ctrl+G",
             bg='#0a0e27', fg='#00d4ff').pack(pady=20)
    
    hotkeys = hkm.get_registered_hotkeys()
    for key, desc in hotkeys.items():
        tk.Label(root, text=f"{key}: {desc}",
                 bg='#0a0e27', fg='#e0e0e0').pack(anchor='w', padx=20)
    
    root.configure(bg='#0a0e27')
    root.mainloop()
