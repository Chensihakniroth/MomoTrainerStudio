#!/usr/bin/env python3
"""
Patch studio_gui.py to add narrow button and handler for pointer scan results.

This script modifies studio_gui.py in-place to add:
1. simpledialog import
2. Narrow Results button in _show_ptrscan_results
3. _on_narrow_results handler method
"""

import re

with open('studio_gui.py', 'r') as f:
    content = f.read()

# 1. Add simpledialog import
content = content.replace(
    'from tkinter import ttk, filedialog, messagebox, scrolledtext',
    'from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog'
)

# 2. Add narrow button before "Add to Trainer Spec" button
old_add_line = 'ttk.Button(btns, text="Add to Trainer Spec",'
new_add_line = '''# Narrow button (CE: Pointer Scan -> New Scan)
        ttk.Button(btns, text="Narrow Results",
            command=lambda: self._on_narrow_results(results, target_addr)).pack(side='left', padx=4)
        
        ttk.Button(btns, text="Add to Trainer Spec",'''

content = content.replace(old_add_line, new_add_line)

# 3. Add _on_narrow_results method before _show_ptrscan_results
old_method_start = '    def _show_ptrscan_results(self, results, max_depth, target_addr=0):'

narrow_method = '''    def _on_narrow_results(self, results, target_addr):
        """Handle narrow button click for pointer scan results."""
        if results.count() == 0:
            messagebox.showinfo("Info", "No results to narrow")
            return
        
        new_target = simpledialog.askinteger(
            "Narrow Results",
            f"Enter new target address (current: 0x{target_addr:X}):",
            parent=self.root
        )
        if new_target is None:
            return
        
        self.status_var.set(f"Narrowing to 0x{new_target:X}...")
        
        def narrow_thread():
            try:
                narrowed = results.narrow([new_target])
                count = narrowed.count()
                self.root.after(0, messagebox.showinfo(
                    "Narrow Complete",
                    f"{count:,} pointer chains still resolve to 0x{new_target:X}"
                ))
                self.status_var.set(f"Narrow complete - {count} results")
            except Exception as e:
                msg = str(e)
                self.root.after(0, messagebox.showerror("Error", msg))
                self.root.after(0, lambda: self.status_var.set("Error during narrow"))
        
        import threading
        threading.Thread(target=narrow_thread, daemon=True).start()

    def _show_ptrscan_results(self, results, max_depth, target_addr=0):'''

content = content.replace(old_method_start, narrow_method)

with open('studio_gui.py', 'w') as f:
    f.write(content)

print('Successfully patched studio_gui.py')
print('- Added simpledialog import')
print('- Added Narrow Results button')
print('- Added _on_narrow_results handler')