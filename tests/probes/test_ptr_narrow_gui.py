"""
Add rescan button and handler to studio_gui.py PointerScanDialog
"""
import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
import ctypes.wintypes as w
import struct
import os
import json
import time
import threading
import queue as _q
import memory_scanner as ms
import trainer_compiler as tc
import themes as th
import debugger as dbg
import stealth_debugger as sdbg

_DEBUG_LOG = os.path.join(os.path.expandvars('%TEMP%'), 'momotrainer_debug.log')
def _dbg(msg):
    try:
        with open(_DEBUG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass

# --- PointerScanDialog ---
class PointerScanDialog:
    """Pointer Scan Results + Rescan / Narrow button"""
    def __init__(self, parent, ctrl, target_addrs=None):
        self.parent = parent
        self.ctrl = ctrl
        self.target_addrs = target_addrs or []
        self.rescan_count = 0
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Pointer Scan Results")
        self.dialog.geometry("600x400")
        
        # Info
        info_frame = ttk.Frame(self.dialog, padding="10")
        info_frame.pack(fill=tk.X)
        
        ttk.Label(info_frame, text="Pointer Scan Results", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        count = self.ctrl.results.count()
        self.count_label = ttk.Label(info_frame, text=f"Results: {count} pointers found")
        self.count_label.pack(anchor=tk.W)
        
        # Buttons
        btn_frame = ttk.Frame(self.dialog, padding="10")
        btn_frame.pack(fill=tk.X)
        
        self.rescan_btn = ttk.Button(
            btn_frame,
            text="Narrow Results",
            command=self._on_narrow,
            state=tk.DISABLED if count == 0 else tk.NORMAL
        )
        self.rescan_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Close", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Results list
        list_frame = ttk.Frame(self.dialog, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Consolas", 10))
        self.results_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.results_listbox.yview)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.dialog, textvariable=self.status_var).pack(anchor=tk.W)
        
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Populate results
        self._populate_results()
    
    def _populate_results(self):
        self.results_listbox.delete(0, tk.END)
        for i, (addr, blob) in enumerate(self.ctrl.results.all_hits()):
            try:
                step = ctypes.sizeof(ctypes.c_void_p)
                ptr_pack = '<I' if step == 4 else '<Q'
                ptr_val = struct.unpack(ptr_pack, blob[:step])[0]
                self.results_listbox.insert(tk.END, f"[{i:4}] Slot: 0x{addr:X} -> Ptr: 0x{ptr_val:X}")
            except Exception:
                self.results_listbox.insert(tk.END, f"[{i:4}] Slot: 0x{addr:X} -> {blob.hex()}")
    
    def _on_narrow(self):
        """Handle narrow button click"""
        if self.ctrl.results.count() == 0:
            messagebox.showinfo("Info", "No results to narrow")
            return
        
        # Ask user for new target address
        new_target = simpledialog.askinteger("Narrow", "Enter new target address (hex or decimal):", parent=self.dialog)
        if new_target is None:
            return
        
        self.status_var.set(f"Narrowing to 0x{new_target:X}...")
        self.rescan_btn.config(state=tk.DISABLED)
        
        def narrow_thread():
            try:
                narrowed = self.ctrl.narrow([new_target])
                self.dialog.after(0, lambda: self._update_results(narrowed))
            except Exception as e:
                self.dialog.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.dialog.after(0, lambda: self.status_var.set("Error during narrow"))
        
        threading.Thread(target=narrow_thread, daemon=True).start()
    
    def _update_results(self, narrowed_results):
        self.ctrl.results = narrowed_results
        count = narrowed_results.count()
        self.count_label.config(text=f"Results: {count} pointers found")
        self.results_listbox.delete(0, tk.END)
        for i, (addr, blob) in enumerate(narrowed_results.all_hits()):
            try:
                step = ctypes.sizeof(ctypes.c_void_p)
                ptr_pack = '<I' if step == 4 else '<Q'
                ptr_val = struct.unpack(ptr_pack, blob[:step])[0]
                self.results_listbox.insert(tk.END, f"[{i:4}] Slot: 0x{addr:X} -> Ptr: 0x{ptr_val:X}")
            except Exception:
                self.results_listbox.insert(tk.END, f"[{i:4}] Slot: 0x{addr:X} -> {blob.hex()}")
        
        self.rescan_btn.config(state=tk.NORMAL if count > 0 else tk.DISABLED)
        self.status_var.set(f"Narrow complete - {count} results")


# Test function
def test_pointer_scan_narrow():
    """Test the PointerScanDialog with actual scan results"""
    root = tk.Tk()
    root.withdraw()
    
    h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())
    
    if h:
        ctrl = ms.PointerScanController(h, max_depth=1, max_offset=0x1000)
        results = ctrl.scan([0x1234], depth=0)
        
        if results.count() > 0:
            dialog = PointerScanDialog(root, ctrl, target_addrs=[0x1234])
            dialog.dialog.wait_window()
        
        ctrl.close()
        ctypes.windll.kernel32.CloseHandle(h)
    
    root.destroy()


if __name__ == '__main__':
    test_pointer_scan_narrow()