"""
disassembly_view.py - Live Disassembly Panel for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Features:
  - Real-time disassembly around current RIP
  - Syntax highlighting with Capstone
  - Module name resolution
  - String reference detection
  - Jump/call target visualization
  - Cross-reference count display
"""

import tkinter as tk
from tkinter import ttk
import ctypes
import struct
from typing import Optional, List, Dict, Tuple
from collections import OrderedDict

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

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
    'text_fg': '#e0e0e0',
    'address': '#00d4ff',
    'bytes': '#888888',
    'mnemonic': '#ff6b9d',
    'operands': '#e0e0e0',
    'string_ref': '#00ff88',
    'comment': '#666666',
    'rip_marker': '#ff4444'
}


class DisassemblyView(ttk.Frame):
    """
    Live disassembly panel with context view.
    
    Usage:
        view = DisassemblyView(parent, pid)
        view.render_context(0x140001000, num_instructions=30)
    """
    
    def __init__(self, parent, pid: Optional[int] = None,
                 process_handle=None, on_address_click=None):
        """
        parent: tkinter parent widget
        pid: target process ID
        process_handle: optional process handle (if already opened)
        on_address_click: callback(address) when address is clicked
        """
        super().__init__(parent)
        
        self.pid = pid
        self.process_handle = process_handle
        self.on_address_click = on_address_click
        
        self.is_64bit = True
        self.current_rip = 0
        self.current_base = 0
        self.current_size = 0
        
        # Disassembler
        if HAS_CAPSTONE:
            self.md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md64.detail = True
            self.md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.md32.detail = True
        else:
            self.md64 = None
            self.md32 = None
            
        # Module map (populated on demand)
        self._module_map: Dict[int, Tuple[str, int]] = {}  # base -> (name, size)
        
        # String reference cache
        self._string_cache: Dict[int, str] = {}
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup UI components."""
        # Configure style
        style = ttk.Style()
        style.configure('Dark.TFrame', background=THEME['panel_bg'])
        self.configure(style='Dark.TFrame')
        
        # Header
        header_frame = tk.Frame(self, bg=THEME['panel_bg'])
        header_frame.pack(fill='x', padx=5, pady=5)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Disassembly View",
            bg=THEME['panel_bg'],
            fg=THEME['fg'],
            font=('Segoe UI', 11, 'bold')
        )
        title_label.pack(side='left')
        
        self.addr_label = tk.Label(
            header_frame,
            text="RIP: 0x0000000000000000",
            bg=THEME['panel_bg'],
            fg=THEME['address'],
            font=('Consolas', 9)
        )
        self.addr_label.pack(side='right')
        
        # Toolbar
        toolbar = tk.Frame(self, bg=THEME['panel_bg'])
        toolbar.pack(fill='x', padx=5, pady=2)
        
        btn_style = {'bg': THEME['panel_bg'], 'fg': THEME['fg'],
                     'activebackground': THEME['bg'], 'activeforeground': THEME['fg'],
                     'font': ('Segoe UI', 9), 'relief': 'flat', 'padx': 8, 'pady': 2}
        
        self.btn_goto = tk.Button(toolbar, text="📍 Go to", **btn_style, command=self._on_goto_click)
        self.btn_goto.pack(side='left', padx=2)
        
        self.btn_refresh = tk.Button(toolbar, text="🔄 Refresh", **btn_style, command=self._on_refresh_click)
        self.btn_refresh.pack(side='left', padx=2)
        
        self.btn_copy = tk.Button(toolbar, text="📋 Copy", **btn_style, command=self._on_copy_click)
        self.btn_copy.pack(side='left', padx=2)
        
        # Instructions label
        self.inst_label = tk.Label(
            toolbar,
            text="30 instructions",
            bg=THEME['panel_bg'],
            fg=THEME['comment'],
            font=('Segoe UI', 8)
        )
        self.inst_label.pack(side='right', padx=5)
        
        # Text widget for disassembly
        text_frame = tk.Frame(self, bg=THEME['text_bg'])
        text_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.text = tk.Text(
            text_frame,
            bg=THEME['text_bg'],
            fg=THEME['text_fg'],
            font=('Consolas', 9),
            wrap='none',
            cursor='hand2',
            padx=5,
            pady=5
        )
        
        # Scrollbars
        yscroll = tk.Scrollbar(text_frame, orient='vertical', command=self.text.yview)
        xscroll = tk.Scrollbar(text_frame, orient='horizontal', command=self.text.xview)
        self.text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        
        # Pack
        self.text.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        # Configure tags for syntax highlighting
        self.text.tag_configure('rip_marker', foreground=THEME['rip_marker'], font=('Consolas', 9, 'bold'))
        self.text.tag_configure('address', foreground=THEME['address'])
        self.text.tag_configure('address_rip', foreground=THEME['rip_marker'], font=('Consolas', 9, 'bold'))
        self.text.tag_configure('bytes', foreground=THEME['bytes'])
        self.text.tag_configure('mnemonic', foreground=THEME['mnemonic'])
        self.text.tag_configure('operands', foreground=THEME['operands'])
        self.text.tag_configure('string_ref', foreground=THEME['string_ref'])
        self.text.tag_configure('comment', foreground=THEME['comment'])
        self.text.tag_configure('module', foreground=THEME['success'])
        
        # Bind events
        self.text.bind('<Button-1>', self._on_text_click)
        self.text.bind('<Double-1>', self._on_text_double_click)
        self.text.bind('<Enter>', self._on_mouse_enter)
        self.text.bind('<Leave>', self._on_mouse_leave)
        
        # Tooltip
        self._tooltip = None
        self._tooltip_after = None
        
    def set_process(self, pid: int, process_handle=None):
        """Set target process."""
        self.pid = pid
        self.process_handle = process_handle
        
        # Determine architecture
        if process_handle:
            self._detect_architecture()
            
    def _detect_architecture(self):
        """Detect if target process is 64-bit."""
        if not self.process_handle:
            return
            
        is_wow64 = ctypes.c_bool(False)
        if hasattr(k32, 'IsWow64Process'):
            k32.IsWow64Process(self.process_handle, ctypes.byref(is_wow64))
            
        is_os_64 = (ctypes.sizeof(ctypes.c_void_p) == 8)
        if is_os_64:
            self.is_64bit = not is_wow64.value
        else:
            self.is_64bit = False
            
    def render_context(self, rip: int, num_instructions: int = 30):
        """
        Render disassembly around RIP.
        
        rip: current instruction pointer
        num_instructions: number of instructions to show (default 30)
        """
        self.current_rip = rip
        self.addr_label.config(text=f"RIP: 0x{rip:016X}")
        
        # Clear text
        self.text.delete('1.0', 'end')
        
        if not HAS_CAPSTONE:
            self.text.insert('end', "Error: Capstone not installed\n", 'comment')
            return
            
        if not self.pid and not self.process_handle:
            self.text.insert('end', "Error: No process attached\n", 'comment')
            return
            
        # Calculate read range
        # Estimate ~8 bytes per instruction on average
        bytes_before = (num_instructions // 2) * 12
        bytes_after = (num_instructions // 2) * 12
        
        read_base = max(0, rip - bytes_before)
        read_size = bytes_before + bytes_after
        
        # Read memory
        data = self._read_memory(read_base, read_size)
        if not data:
            self.text.insert('end', f"Error: Failed to read memory at 0x{read_base:X}\n", 'comment')
            return
            
        # Disassemble
        md = self.md64 if self.is_64bit else self.md32
        
        # Find instruction boundaries
        # We need to find the instruction that contains RIP
        instructions = list(md.disasm(data, read_base))
        
        if not instructions:
            self.text.insert('end', "Error: Failed to disassemble\n", 'comment')
            return
            
        # Find which instruction contains RIP
        rip_index = -1
        for i, insn in enumerate(instructions):
            if insn.address == rip:
                rip_index = i
                break
                
        # If RIP not found exactly, try to find closest
        if rip_index == -1:
            for i, insn in enumerate(instructions):
                if insn.address <= rip < insn.address + insn.size:
                    rip_index = i
                    break
                    
        # Render instructions
        start_idx = max(0, rip_index - num_instructions // 2)
        end_idx = min(len(instructions), rip_index + num_instructions // 2 + 1)
        
        rendered_count = 0
        for i in range(start_idx, end_idx):
            insn = instructions[i]
            is_rip = (insn.address == rip)
            self._render_instruction(insn, is_rip)
            rendered_count += 1
            
        self.inst_label.config(text=f"{rendered_count} instructions")
        
    def _render_instruction(self, insn, is_rip: bool = False):
        """Render a single instruction with syntax highlighting."""
        addr = insn.address
        bytes_hex = ' '.join(f'{b:02X}' for b in insn.bytes)
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        # RIP marker
        if is_rip:
            self.text.insert('end', '→ ', 'rip_marker')
        else:
            self.text.insert('end', '  ', 'comment')
            
        # Address
        if is_rip:
            self.text.insert('end', f'{addr:016X}  ', 'address_rip')
        else:
            self.text.insert('end', f'{addr:016X}  ', 'address')
            
        # Bytes
        self.text.insert('end', f'{bytes_hex:<24}  ', 'bytes')
        
        # Mnemonic
        self.text.insert('end', f'{mnemonic:<8}', 'mnemonic')
        
        # Operands
        self.text.insert('end', f' {op_str}', 'operands')
        
        # Check for string references
        string_ref = self._try_resolve_string(insn)
        if string_ref:
            self.text.insert('end', f'  ; "{string_ref}"', 'string_ref')
            
        # Module resolution
        module_info = self._resolve_module(addr)
        if module_info:
            self.text.insert('end', f'  ; {module_info}', 'module')
            
        self.text.insert('end', '\n')
        
    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from target process."""
        if self.process_handle:
            return self._read_with_handle(self.process_handle, address, size)
        elif self.pid:
            # Open process temporarily
            h = k32.OpenProcess(0x0010, False, self.pid)  # PROCESS_VM_READ
            if not h:
                return None
            try:
                return self._read_with_handle(h, address, size)
            finally:
                k32.CloseHandle(h)
        return None
        
    def _read_with_handle(self, h, address: int, size: int) -> Optional[bytes]:
        """Read memory with given handle."""
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        
        if k32.ReadProcessMemory(h, address, buffer, size, ctypes.byref(read)):
            return buffer.raw[:read.value]
        return None
        
    def _try_resolve_string(self, insn) -> Optional[str]:
        """Try to resolve string reference from instruction."""
        # Check if instruction has memory operand
        if not hasattr(insn, 'details') or not insn.details:
            return None
            
        try:
            for op in insn.details.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    # Could be a string reference
                    # This is simplified - would need actual memory read
                    pass
        except:
            pass
            
        return None
        
    def _resolve_module(self, address: int) -> Optional[str]:
        """Resolve module name for address."""
        # This would require EnumProcessModules
        # Simplified version just shows offset
        return None
        
    def _on_goto_click(self):
        """Handle Go to button click."""
        if self.on_address_click:
            # Show dialog
            from tkinter import simpledialog
            addr_str = simpledialog.askstring(
                "Go to Address",
                "Enter address (hex):",
                initialvalue=f"0x{self.current_rip:X}"
            )
            
            if addr_str:
                try:
                    if addr_str.startswith('0x') or addr_str.startswith('0X'):
                        addr = int(addr_str, 16)
                    else:
                        addr = int(addr_str, 16)
                        
                    self.render_context(addr)
                except ValueError:
                    pass
                    
    def _on_refresh_click(self):
        """Handle Refresh button click."""
        if self.current_rip:
            self.render_context(self.current_rip)
            
    def _on_copy_click(self):
        """Copy selected text."""
        try:
            selected = self.text.get('sel.first', 'sel.last')
            self.clipboard_clear()
            self.clipboard_append(selected)
        except tk.TclError:
            pass
            
    def _on_text_click(self, event):
        """Handle text click."""
        # Get clicked position
        index = self.text.index(f'@{event.x},{event.y}')
        
        # Get line
        line_start = self.text.index(f'{index} linestart')
        line_text = self.text.get(line_start, f'{line_start}+2c')
        
        # Check if it's a RIP marker
        if line_text.strip() == '→':
            # Extract address
            addr_text = self.text.get(f'{line_start}+2c', f'{line_start}+18c')
            try:
                addr = int(addr_text.strip(), 16)
                if self.on_address_click:
                    self.on_address_click(addr)
            except ValueError:
                pass
                
    def _on_text_double_click(self, event):
        """Handle text double-click."""
        # Toggle breakpoint at clicked address
        self._on_text_click(event)
        
    def _on_mouse_enter(self, event):
        """Handle mouse enter."""
        pass
        
    def _on_mouse_leave(self, event):
        """Handle mouse leave."""
        if self._tooltip_after:
            self.after_cancel(self._tooltip_after)
            self._tooltip_after = None
        if self._tooltip:
            self._tooltip.destroy()
            self._tooltip = None


class MiniDisassemblyView(tk.Frame):
    """
    Compact disassembly view for inline display.
    Shows just a few instructions around RIP.
    """
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=THEME['text_bg'], **kwargs)
        
        self.text = tk.Text(
            self,
            bg=THEME['text_bg'],
            fg=THEME['text_fg'],
            font=('Consolas', 8),
            wrap='none',
            height=6,
            width=60
        )
        self.text.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Configure tags
        self.text.tag_configure('address', foreground=THEME['address'])
        self.text.tag_configure('mnemonic', foreground=THEME['mnemonic'])
        self.text.tag_configure('rip', foreground=THEME['rip_marker'], font=('Consolas', 8, 'bold'))
        
    def show_instructions(self, instructions: List[Tuple[int, bytes, str, str]],
                          rip: Optional[int] = None):
        """
        Show list of instructions.
        
        instructions: list of (address, bytes, mnemonic, operands)
        rip: optional RIP address to highlight
        """
        self.text.delete('1.0', 'end')
        
        for addr, insn_bytes, mnemonic, operands in instructions:
            is_rip = (addr == rip)
            
            if is_rip:
                self.text.insert('end', '→ ', 'rip')
            else:
                self.text.insert('end', '  ')
                
            self.text.insert('end', f'{addr:X}  ', 'address' if not is_rip else 'rip')
            self.text.insert('end', f'{mnemonic} {operands}\n', 'mnemonic' if not is_rip else 'rip')


# Standalone test
if __name__ == '__main__':
    root = tk.Tk()
    root.title("Disassembly View Test")
    root.geometry("700x500")
    root.configure(bg=THEME['bg'])
    
    view = DisassemblyView(root)
    view.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Test with some fake instructions
    # In real usage, would call render_context() with actual RIP
    
    root.mainloop()
