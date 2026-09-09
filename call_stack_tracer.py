"""
call_stack_tracer.py - Call Stack Capture for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Capture call stack at breakpoint
  - Walk x64 stack chain using RBP/RSP
  - Resolve module names for return addresses
  - Show function arguments (if readable)
  - Export to IDA script format
"""

import ctypes
import struct
from typing import Optional, List, Dict, Tuple
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
    'text_bg': '#1a1f35',
    'text_fg': '#e0e0e0'
}


class StackFrame:
    """Represents a single stack frame."""
    
    def __init__(self, address: int, return_addr: Optional[int] = None,
                 module_name: Optional[str] = None, offset: Optional[int] = None,
                 function_name: Optional[str] = None):
        self.address = address  # Instruction pointer for this frame
        self.return_addr = return_addr  # Return address (caller)
        self.module_name = module_name
        self.offset = offset  # Offset from module base
        self.function_name = function_name
        self.args = []  # Function arguments (if captured)
        
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'address': self.address,
            'return_addr': self.return_addr,
            'module_name': self.module_name,
            'offset': self.offset,
            'function_name': self.function_name,
            'args': self.args
        }
        
    def __str__(self) -> str:
        """String representation."""
        parts = [f'0x{self.address:016X}']
        
        if self.module_name:
            parts.append(f'[{self.module_name}')
            if self.offset is not None:
                parts.append(f'+0x{self.offset:X}')
            parts.append(']')
            
        if self.function_name:
            parts.append(f'({self.function_name})')
            
        return ' '.join(parts)


class CallStackTracer:
    """
    Capture call stack from target process.
    
    Usage:
        tracer = CallStackTracer(pid, process_handle)
        stack = tracer.capture_stack(context)
        for frame in stack:
            print(frame)
    """
    
    def __init__(self, pid: int, process_handle=None):
        """
        pid: target process ID
        process_handle: optional open process handle
        """
        self.pid = pid
        self.process_handle = process_handle
        
        # Module map (populated lazily)
        self._module_map: Dict[int, Tuple[str, int]] = {}  # base -> (name, size)
        self._module_list_loaded = False
        
    def capture_stack(self, context: dict, max_frames: int = 20) -> List[StackFrame]:
        """
        Capture call stack from CPU context.
        
        context: dict with 'RIP', 'RBP', 'RSP' keys (from debugger)
        max_frames: maximum frames to walk
        
        Returns list of StackFrame objects.
        """
        if not isinstance(context, dict):
            raise ValueError("context must be a mapping of register names to values")
        try:
            max_frames = max(1, min(int(max_frames), 256))
        except (TypeError, ValueError) as exc:
            raise ValueError("max_frames must be a positive integer") from exc
        stack = []
        
        rip = int(context.get('RIP', 0) or 0)
        rbp = int(context.get('RBP', 0) or 0)
        rsp = int(context.get('RSP', 0) or 0)
        
        # Current frame (where we are now)
        current_frame = StackFrame(rip)
        current_frame.module_name = self._resolve_module(rip)
        current_frame.offset = self._get_module_offset(rip)
        stack.append(current_frame)
        
        # Walk the stack
        frame_count = 0
        current_rbp = rbp
        
        visited = set()
        while current_rbp and frame_count < max_frames:
            if current_rbp in visited or current_rbp < 0x1000:
                break
            visited.add(current_rbp)
            # Read saved RBP and return address
            # Stack layout: [saved RBP] [return address] [args...]
            
            saved_rbp = self._read_pointer(current_rbp)
            return_addr = self._read_pointer(current_rbp + 8)
            
            if not saved_rbp or not return_addr:
                break
                
            # Create frame for return address
            frame = StackFrame(return_addr, return_addr)
            frame.module_name = self._resolve_module(return_addr)
            frame.offset = self._get_module_offset(return_addr)
            
            # Try to read first 4 arguments (Windows x64 calling convention)
            # Args are at RBP+0x10, RBP+0x18, RBP+0x20, RBP+0x28
            args_base = current_rbp + 0x10
            for i in range(4):
                arg = self._read_pointer(args_base + i * 8)
                if arg:
                    frame.args.append(arg)
                    
            stack.append(frame)
            
            # A valid frame chain moves upward.  Reject corrupt/self-cycling
            # chains so a bad context cannot hang the UI.
            if saved_rbp <= current_rbp:
                break
            current_rbp = saved_rbp
            frame_count += 1
            
        return stack
        
    def capture_stack_from_context_struct(self, context_struct, max_frames: int = 20) -> List[StackFrame]:
        """
        Capture call stack from CONTEXT struct.
        
        context_struct: ctypes CONTEXT64 or similar structure
        """
        # Extract values from context struct
        context = {
            'RIP': getattr(context_struct, 'Rip', 0),
            'RBP': getattr(context_struct, 'Rbp', 0),
            'RSP': getattr(context_struct, 'Rsp', 0),
            'RAX': getattr(context_struct, 'Rax', 0),
            'RBX': getattr(context_struct, 'Rbx', 0),
            'RCX': getattr(context_struct, 'Rcx', 0),
            'RDX': getattr(context_struct, 'Rdx', 0),
            'RSI': getattr(context_struct, 'Rsi', 0),
            'RDI': getattr(context_struct, 'Rdi', 0),
            'R8': getattr(context_struct, 'R8', 0),
            'R9': getattr(context_struct, 'R9', 0),
        }
        
        return self.capture_stack(context, max_frames)
        
    def _read_pointer(self, address: int) -> int:
        """Read a pointer (8 bytes) from target process."""
        if self.process_handle:
            return self._read_pointer_with_handle(self.process_handle, address)
        elif self.pid:
            h = k32.OpenProcess(0x0010, False, self.pid)
            if not h:
                return 0
            try:
                return self._read_pointer_with_handle(h, address)
            finally:
                k32.CloseHandle(h)
        return 0
        
    def _read_pointer_with_handle(self, h, address: int) -> int:
        """Read pointer with given handle."""
        buffer = ctypes.c_uint64(0)
        read = ctypes.c_size_t(0)
        
        if k32.ReadProcessMemory(h, address, ctypes.byref(buffer), 8, ctypes.byref(read)):
            return buffer.value
        return 0
        
    def _resolve_module(self, address: int) -> Optional[str]:
        """Resolve module name for an address."""
        # Load modules if not done yet
        if not self._module_list_loaded:
            self._load_module_list()
            
        # Find which module contains this address
        for base, (name, size) in self._module_map.items():
            if base <= address < base + size:
                return name
                
        return None
        
    def _get_module_offset(self, address: int) -> Optional[int]:
        """Get offset from module base."""
        if not self._module_list_loaded:
            self._load_module_list()
            
        for base, (name, size) in self._module_map.items():
            if base <= address < base + size:
                return address - base
                
        return None
        
    def _load_module_list(self):
        """Load list of modules in target process."""
        # This would use EnumProcessModulesEx
        # Simplified version - just mark as loaded
        self._module_list_loaded = True
        
        # Could populate with actual module list:
        # for module in psutil.Process(self.pid).memory_maps():
        #     base = int(module.addr.split('-')[0], 16)
        #     self._module_map[base] = (module.path.split('\\')[-1], module.size)
        
    def export_to_ida_script(self, stack: List[StackFrame], output_path: str):
        """
        Export call stack to IDA Python script.
        
        stack: list of StackFrame objects
        output_path: output file path
        """
        lines = [
            "# IDA Python script - Call stack addresses",
            "# Generated by MomoTrainer Studio",
            "",
            "import idaapi",
            "import idc",
            "",
        ]
        
        for i, frame in enumerate(stack):
            addr = frame.address
            comment = f"Frame {i}"
            if frame.module_name:
                comment += f" [{frame.module_name}"
                if frame.offset is not None:
                    comment += f"+0x{frame.offset:X}"
                comment += "]"
                
            lines.append(f"# {comment}")
            lines.append(f"idc.create_insn(0x{addr:X})")
            lines.append(f"idc.set_cmt(0x{addr:X}, \"{comment}\", 0)")
            lines.append("")
            
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
            
    def export_to_text(self, stack: List[StackFrame], output_path: str):
        """Export call stack to plain text."""
        lines = [
            "Call Stack:",
            "=" * 80,
            ""
        ]
        
        for i, frame in enumerate(stack):
            line = f"#{i:2d} {frame}"
            lines.append(line)
            
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))


import tkinter as tk
from tkinter import ttk


class CallStackView(ttk.Frame):
    """
    Visual call stack display widget.
    """
    
    def __init__(self, parent, on_address_click=None):
        """
        parent: tkinter parent widget
        on_address_click: callback(address) when address is clicked
        """
        super().__init__(parent)
        
        self.on_address_click = on_address_click
        self._stack: List[StackFrame] = []
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup UI."""
        # Header
        header = tk.Frame(self, bg=THEME['panel_bg'])
        header.pack(fill='x', padx=5, pady=5)
        
        tk.Label(
            header, text="📚 Call Stack",
            bg=THEME['panel_bg'], fg=THEME['fg'],
            font=('Segoe UI', 11, 'bold')
        ).pack(side='left')
        
        self.depth_label = tk.Label(
            header, text="0 frames",
            bg=THEME['panel_bg'], fg=THEME['text_fg'],
            font=('Segoe UI', 9)
        )
        self.depth_label.pack(side='right')
        
        # Toolbar
        toolbar = tk.Frame(self, bg=THEME['panel_bg'])
        toolbar.pack(fill='x', padx=5, pady=2)
        
        btn_style = {'bg': THEME['panel_bg'], 'fg': THEME['fg'],
                     'font': ('Segoe UI', 9), 'relief': 'flat', 'padx': 8, 'pady': 2}
        
        tk.Button(toolbar, text="📋 Copy", command=self._copy_stack, **btn_style).pack(side='left', padx=2)
        tk.Button(toolbar, text="💾 Export IDA", command=self._export_ida, **btn_style).pack(side='left', padx=2)
        
        # Treeview
        tree_frame = tk.Frame(self, bg=THEME['text_bg'])
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('frame', 'address', 'module', 'offset')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=8)
        
        self.tree.heading('frame', text='#', anchor='w')
        self.tree.heading('address', text='Address', anchor='w')
        self.tree.heading('module', text='Module', anchor='w')
        self.tree.heading('offset', text='Offset', anchor='w')
        
        self.tree.column('frame', width=40, minwidth=30)
        self.tree.column('address', width=140, minwidth=120)
        self.tree.column('module', width=150, minwidth=100)
        self.tree.column('offset', width=100, minwidth=80)
        
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        yscroll.pack(side='right', fill='y')
        
        # Bind click
        self.tree.bind('<Double-1>', self._on_double_click)
        
    def set_stack(self, stack: List[StackFrame]):
        """Set call stack to display."""
        self._stack = stack
        self._refresh()
        
    def clear(self):
        """Clear display."""
        self._stack = []
        self._refresh()
        
    def _refresh(self):
        """Refresh display."""
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for i, frame in enumerate(self._stack):
            self.tree.insert('', 'end', values=(
                f'#{i}',
                f'0x{frame.address:016X}',
                frame.module_name or '-',
                f'0x{frame.offset:X}' if frame.offset is not None else '-'
            ))
            
        self.depth_label.config(text=f"{len(self._stack)} frames")
        
    def _on_double_click(self, event):
        """Handle double-click."""
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.tree.item(item, 'values')
        if values and len(values) > 1:
            addr_str = values[1]
            if addr_str.startswith('0x'):
                addr = int(addr_str, 16)
                if self.on_address_click:
                    self.on_address_click(addr)
                    
    def _copy_stack(self):
        """Copy stack to clipboard."""
        lines = [str(frame) for frame in self._stack]
        self.clipboard_clear()
        self.clipboard_append('\n'.join(lines))
        
    def _export_ida(self):
        """Export to IDA script."""
        from tkinter import filedialog
        
        path = filedialog.asksaveasfilename(
            defaultextension='.py',
            filetypes=[('Python files', '*.py'), ('All files', '*.*')],
            title='Export IDA Script'
        )
        
        if path:
            tracer = CallStackTracer(0)  # PID not needed for export
            tracer.export_to_ida_script(self._stack, path)
            
            from tkinter import messagebox
            messagebox.showinfo("Exported", f"IDA script saved to:\n{path}")


# Standalone test
if __name__ == '__main__':
    root = tk.Tk()
    root.title("Call Stack View Test")
    root.geometry("500x400")
    root.configure(bg=THEME['bg'])
    
    view = CallStackView(root)
    view.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Test data
    test_stack = [
        StackFrame(0x140001000, module_name='game.exe', offset=0x1000),
        StackFrame(0x140002000, module_name='game.exe', offset=0x2000),
        StackFrame(0x7FF800001000, module_name='unityplayer.dll', offset=0x1000),
    ]
    view.set_stack(test_stack)
    
    root.mainloop()
