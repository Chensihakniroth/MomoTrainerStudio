"""
studio_gui.py - MomoTrainer Studio (Modern Cheat Engine-Style UI)
made by Momo aka Steav Beoung Salang

Features:
  - Cheat Engine-inspired split layout:
      * Process header with attachment status & privilege indicator
      * Upper Split: Found Results Table (Left) + Streamlined Memory Scanner (Right)
      * Lower Split: Studio Notebook (Cheat Table / Trainer Spec / Standalone Compiler)
  - Designed with Hick's Law:
      * Reduced cognitive clutter: 3 primary scan decisions (Value, Type, Mode)
      * Progressive disclosure: Collapsible Advanced Scan Options (Alignment, Flags, AOB)
      * Staged decision workflow from process attachment to trainer compilation
  - Live address tracking with color flashes on change & atomic freeze engine
  - Built-in Hex viewer, Pointer Scanner, and Signature (AOB) scanner
  - Standalone Trainer Compiler with live build log terminal
"""

import ctypes
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


VTYPE_LABELS = [
    ('4 Bytes (Int32)',    'int32'),
    ('Float (4 bytes)',    'float'),
    ('Double (8 bytes)',   'double'),
    ('Byte (1 byte)',      'uint8'),
    ('2 Bytes (Short)',    'int16'),
    ('8 Bytes (Int64)',    'int64'),
    ('UInt32 (4 bytes)',   'uint32'),
    ('UInt64 (8 bytes)',   'uint64'),
    ('UShort (2 bytes)',   'uint16'),
    ('String (ASCII)',     'string'),
]

MODE_LABELS = [
    ('Exact value',          'exact'),
    ('Greater than',         'greater'),
    ('Less than',            'less'),
    ('Between X and Y',      'between'),
    ('Increased by',         'increased'),
    ('Decreased by',         'decreased'),
    ('Changed',              'changed'),
    ('Unchanged',            'unchanged'),
    ('Initial value (1st)',  'initial'),
]

SKIP_PROCS = {
    'svchost.exe', 'System', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'explorer.exe', 'dwm.exe',
    'fontdrvhost.exe', 'WmiPrvSE.exe', 'taskhostw.exe',
    'RuntimeBroker.exe', 'ShellExperienceHost.exe',
    'StartMenuExperienceHost.exe', 'SearchHost.exe', 'LockApp.exe',
    'TextInputHost.exe', 'sihost.exe', 'ctfmon.exe', 'audiodg.exe',
    'spoolsv.exe', 'Wcmsvc.exe', 'dasHost.exe', 'SearchUI.exe',
    'SecurityHealthService.exe', 'SecurityHealthSystray.exe',
    'MoUsoCoreWorker.exe', 'AggregatorHost.exe', 'LogonUI.exe',
    'dllhost.exe', 'ChsIME.exe', 'conhost.exe'
}


def list_processes():
    out = []
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPPROCESS = 0x02

    class PE(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE()
    pe.dwSize = ctypes.sizeof(pe)
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            out.append((pe.th32ProcessID, pe.szExeFile.decode('latin-1', errors='replace')))
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return out


# ============================================================
# Pointer Scan Options Dialog
# ============================================================
class PointerScanDialog:
    """Dialog to configure pointer scan parameters."""

    def __init__(self, parent):
        self.result = None
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Pointer Scan Options")
        self._dlg.geometry("400x310")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        self._dlg.resizable(False, False)

        body = ttk.Frame(self._dlg, padding=14)
        body.pack(fill='both', expand=True)

        ttk.Label(body, text="Max Depth (Pointer Levels):", font=('Segoe UI', 9, 'bold')).pack(anchor='w', pady=(0, 2))
        self.depth_var = tk.IntVar(value=1)
        ttk.Spinbox(body, from_=1, to=5, textvariable=self.depth_var, width=12).pack(anchor='w', pady=(0, 8))

        ttk.Label(body, text="Max Offset per Level (Hex):", font=('Segoe UI', 9, 'bold')).pack(anchor='w', pady=(0, 2))
        self.offset_var = tk.StringVar(value="1000")
        ttk.Entry(body, textvariable=self.offset_var, width=16, font=('Consolas', 9)).pack(anchor='w', pady=(0, 10))

        self.no_loop_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="No-Loop (skip self-referencing pointers)",
                        variable=self.no_loop_var).pack(anchor='w', pady=(0, 4))

        self.use_heap_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(body, text="Use Heap Data Only (filter to heap pointers)",
                        variable=self.use_heap_var).pack(anchor='w', pady=(0, 12))

        btns = ttk.Frame(body)
        btns.pack(fill='x', side='bottom')
        ttk.Button(btns, text="Start Scan", command=self._on_scan).pack(side='left', padx=4)
        ttk.Button(btns, text="Cancel", command=self._dlg.destroy).pack(side='left', padx=4)

        self._dlg.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() // 2) - 200
        py = parent.winfo_y() + (parent.winfo_height() // 2) - 155
        self._dlg.geometry(f"+{max(10, px)}+{max(10, py)}")
        self._dlg.wait_window()

    def _on_scan(self):
        try:
            max_offset = int(self.offset_var.get().strip(), 16)
        except Exception:
            messagebox.showerror("Invalid Offset", "Max offset must be a valid hex number (e.g. 1000)")
            return
        self.result = {
            'max_depth': self.depth_var.get(),
            'max_offset': max_offset,
            'no_loop': self.no_loop_var.get(),
            'use_heap_data': self.use_heap_var.get(),
        }
        self._dlg.destroy()


# ============================================================
# Debugger Opcodes Window (Cheat Engine-style What Accesses / Writes)
# ============================================================
class DebuggerOpcodesDialog:
    """Cheat Engine-style 'The following opcodes accessed/wrote to 0x...' window."""

    def __init__(self, parent, pid, address, mode='access', size=4, colors=None):
        self.parent = parent
        self.pid = pid
        self.address = address
        self.mode = mode
        self.size = size
        self.colors = colors or {
            'bg': '#0d1117', 'panel': '#161b22', 'border': '#30363d',
            'fg': '#c9d1d9', 'muted': '#8b949e', 'accent': '#58a6ff',
            'btn_bg': '#21262d', 'btn_fg': '#c9d1d9'
        }

        self.hit_q = queue.Queue()
        self.rows = {}       # rip -> item_id in Treeview
        self.row_data = {}   # rip -> hit_dict
        self._is_stopped = False

        self._dlg = tk.Toplevel(parent)
        action_verb = "accessed" if mode == 'access' else "wrote to"
        self._dlg.title(f"The following opcodes {action_verb} 0x{address:X}")
        self._dlg.geometry("820x600")
        self._dlg.minsize(700, 460)
        self._dlg.configure(bg=self.colors['bg'])
        self._dlg.protocol("WM_DELETE_WINDOW", self._on_close)

        self.engine_type = 'stealth'
        self._build_ui()
        self._start_debugger('stealth')
        self._poll_hits()

    def _build_ui(self):
        # 1. Header Toolbar
        top_bar = tk.Frame(self._dlg, bg=self.colors['panel'], padx=10, pady=8,
                           highlightthickness=1, highlightbackground=self.colors['border'])
        top_bar.pack(fill='x')

        desc = f"Watching: 0x{self.address:X} ({self.size} bytes) | Mode: {self.mode.upper()} | PID: {self.pid}"
        tk.Label(top_bar, text=desc, font=('Consolas', 10, 'bold'),
                 bg=self.colors['panel'], fg=self.colors['accent']).pack(side='left')

        self.btn_toggle = tk.Button(
            top_bar, text="⏹️ Stop", font=('Segoe UI', 8, 'bold'),
            bg=self.colors['btn_bg'], fg=self.colors['fg'],
            activebackground=self.colors['border'], activeforeground='#ffffff',
            relief='flat', padx=10, pady=2, cursor='hand2',
            highlightthickness=1, highlightbackground=self.colors['border'],
            command=self._toggle_debug
        )
        self.btn_toggle.pack(side='right', padx=4)

        self.btn_engine = tk.Button(
            top_bar, text="🛡️ Engine: Stealth VEH", font=('Segoe UI', 8, 'bold'),
            bg=self.colors['btn_bg'], fg='#38bdf8',
            activebackground=self.colors['border'], activeforeground='#ffffff',
            relief='flat', padx=8, pady=2, cursor='hand2',
            highlightthickness=1, highlightbackground=self.colors['border'],
            command=self._toggle_engine
        )
        self.btn_engine.pack(side='right', padx=4)

        self.btn_nop = tk.Button(
            top_bar, text="🚫 Replace with NOPs", font=('Segoe UI', 8),
            bg=self.colors['btn_bg'], fg='#f87171',
            activebackground=self.colors['border'], activeforeground='#ffffff',
            relief='flat', padx=10, pady=2, cursor='hand2',
            highlightthickness=1, highlightbackground=self.colors['border'],
            command=self._on_replace_nop
        )
        self.btn_nop.pack(side='right', padx=4)

        self.btn_copy = tk.Button(
            top_bar, text="📋 Copy Info", font=('Segoe UI', 8),
            bg=self.colors['btn_bg'], fg=self.colors['fg'],
            activebackground=self.colors['border'], activeforeground='#ffffff',
            relief='flat', padx=10, pady=2, cursor='hand2',
            highlightthickness=1, highlightbackground=self.colors['border'],
            command=self._on_copy_info
        )
        self.btn_copy.pack(side='right', padx=4)

        # 2. Split: Upper Table + Lower Register Details
        main_paned = ttk.PanedWindow(self._dlg, orient='vertical')
        main_paned.pack(fill='both', expand=True, padx=8, pady=6)

        # Upper Frame: Treeview
        tree_fr = tk.Frame(main_paned, bg=self.colors['bg'])
        main_paned.add(tree_fr, weight=3)

        cols = ('count', 'insn', 'addr')
        self.tree = ttk.Treeview(tree_fr, columns=cols, show='headings', selectmode='browse', height=10)
        self.tree.heading('count', text='Count', anchor='center')
        self.tree.heading('insn',  text='Instruction', anchor='w')
        self.tree.heading('addr',  text='Address', anchor='w')

        self.tree.column('count', width=80, anchor='center')
        self.tree.column('insn',  width=420, anchor='w')
        self.tree.column('addr',  width=180, anchor='w')
        self.tree.pack(side='left', fill='both', expand=True)

        sc = ttk.Scrollbar(tree_fr, orient='vertical', command=self.tree.yview)
        sc.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=sc.set)
        self.tree.bind('<<TreeviewSelect>>', self._on_select_row)

        # Lower Frame: Register & Instruction Inspector
        detail_card = tk.Frame(main_paned, bg=self.colors['panel'], padx=10, pady=8,
                               highlightthickness=1, highlightbackground=self.colors['border'])
        main_paned.add(detail_card, weight=2)

        tk.Label(detail_card, text="Detailed Register & Instruction Snapshot:",
                 font=('Segoe UI', 9, 'bold'), bg=self.colors['panel'],
                 fg=self.colors['muted']).pack(anchor='w', pady=(0, 4))

        self.insn_lbl = tk.Label(detail_card, text="Select an instruction row above to inspect registers.",
                                 font=('Consolas', 10, 'bold'), bg=self.colors['panel'],
                                 fg=self.colors['fg'], anchor='w')
        self.insn_lbl.pack(fill='x', pady=(0, 6))

        # Register Text Area (Monospace)
        self.reg_text = tk.Text(detail_card, font=('Consolas', 9), height=7,
                                bg='#0d1117', fg=self.colors['fg'],
                                relief='flat', highlightthickness=1,
                                highlightbackground=self.colors['border'], wrap='none')
        self.reg_text.pack(fill='both', expand=True)

        # Bottom Status Bar
        self.status_var = tk.StringVar(value="Stealth PAGE_GUARD monitor active. Waiting for access...")
        status_bar = tk.Frame(self._dlg, bg=self.colors['panel'], padx=8, pady=4,
                              highlightthickness=1, highlightbackground=self.colors['border'])
        status_bar.pack(fill='x', side='bottom')
        tk.Label(status_bar, textvariable=self.status_var, font=('Segoe UI', 8),
                 bg=self.colors['panel'], fg=self.colors['muted'], anchor='w').pack(fill='x')

    def _poll_hits(self):
        try:
            while True:
                hit = self.hit_q.get_nowait()
                rip = hit['rip']
                count = hit['count']
                insn = hit['insn']
                addr_str = f"0x{rip:X}"

                if rip in self.rows:
                    item_id = self.rows[rip]
                    self.tree.item(item_id, values=(f"{count:,}", insn, addr_str))
                else:
                    item_id = self.tree.insert('', 'end', values=(f"{count:,}", insn, addr_str))
                    self.rows[rip] = item_id

                self.row_data[rip] = hit

                # Auto-select first row if nothing selected
                if not self.tree.selection():
                    self.tree.selection_set(item_id)
                    self._display_hit(hit)

        except queue.Empty:
            pass

        if not self._is_stopped and self._dlg.winfo_exists():
            self._dlg.after(60, self._poll_hits)

    def _on_select_row(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']
        try:
            rip = int(str(vals[2]), 16)
        except Exception:
            return
        if rip in self.row_data:
            self._display_hit(self.row_data[rip])

    def _display_hit(self, hit):
        rip = hit['rip']
        insn = hit['insn']
        raw_bytes = hit.get('bytes', b'')
        hex_bytes = " ".join(f"{b:02X}" for b in raw_bytes)
        self.insn_lbl.config(text=f"0x{rip:X} - {hex_bytes} - {insn}")

        regs = hit.get('regs', {})
        self.reg_text.delete('1.0', 'end')

        reg_lines = []
        if 'RAX' in regs:
            reg_lines.append(f"RAX = {regs.get('RAX', '')}   RBX = {regs.get('RBX', '')}   RCX = {regs.get('RCX', '')}   RDX = {regs.get('RDX', '')}")
            reg_lines.append(f"RSI = {regs.get('RSI', '')}   RDI = {regs.get('RDI', '')}   RBP = {regs.get('RBP', '')}   RSP = {regs.get('RSP', '')}")
            reg_lines.append(f"R8  = {regs.get('R8',  '')}   R9  = {regs.get('R9',  '')}   R10 = {regs.get('R10', '')}   R11 = {regs.get('R11', '')}")
            reg_lines.append(f"R12 = {regs.get('R12', '')}   R13 = {regs.get('R13', '')}   R14 = {regs.get('R14', '')}   R15 = {regs.get('R15', '')}")
            reg_lines.append(f"RIP = {regs.get('RIP', '')}   EFLAGS = {regs.get('EFLAGS', '')}")
        else:
            reg_lines.append(f"EAX = {regs.get('EAX', '')}   EBX = {regs.get('EBX', '')}   ECX = {regs.get('ECX', '')}   EDX = {regs.get('EDX', '')}")
            reg_lines.append(f"ESI = {regs.get('ESI', '')}   EDI = {regs.get('EDI', '')}   EBP = {regs.get('EBP', '')}   ESP = {regs.get('ESP', '')}")
            reg_lines.append(f"EIP = {regs.get('EIP', '')}   EFLAGS = {regs.get('EFLAGS', '')}")

        self.reg_text.insert('end', "\n".join(reg_lines))

    def _start_debugger(self, engine='stealth'):
        self.engine_type = engine
        if engine == 'stealth':
            self.debugger = sdbg.StealthDebugger(
                pid=self.pid,
                address=self.address,
                mode=self.mode,
                size=self.size,
                on_hit=lambda h: self.hit_q.put(h),
                on_status=lambda s: self._on_debugger_status(s)
            )
            if hasattr(self, 'btn_engine'):
                self.btn_engine.config(text="🛡️ Engine: Stealth VEH", fg='#38bdf8')
        else:
            self.debugger = dbg.HardwareDebugger(
                pid=self.pid,
                address=self.address,
                mode=self.mode,
                size=self.size,
                on_hit=lambda h: self.hit_q.put(h),
                on_status=lambda s: self._dlg.after(0, lambda: self.status_var.set(s))
            )
            if hasattr(self, 'btn_engine'):
                self.btn_engine.config(text="⚙️ Engine: Hardware (DR0)", fg='#f59e0b')
        self.debugger.start()

    def _on_debugger_status(self, msg):
        self._dlg.after(0, lambda: self.status_var.set(msg))

    def _toggle_engine(self):
        new_engine = 'hardware' if self.engine_type == 'stealth' else 'stealth'
        try:
            self.debugger.stop()
        except Exception:
            pass
        self._start_debugger(new_engine)
        self.status_var.set(f"Switched engine to {new_engine.upper()}.")

    def _toggle_debug(self):
        if self._is_stopped:
            self._is_stopped = False
            self.btn_toggle.config(text="⏹️ Stop")
            self._start_debugger(self.engine_type)
            self._poll_hits()
            self.status_var.set(f"Resumed {self.engine_type} monitoring.")
        else:
            self._is_stopped = True
            self.btn_toggle.config(text="▶️ Resume")
            self.debugger.stop()
            self.status_var.set("Monitoring stopped. Target running normally.")

    def _on_replace_nop(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Pick Instruction", "Select an instruction to replace with NOPs.")
            return
        vals = self.tree.item(sel[0])['values']
        rip = int(str(vals[2]), 16)
        hit = self.row_data.get(rip)
        if not hit:
            return
        size = hit.get('size', 1)
        insn = hit.get('insn', '')

        if messagebox.askyesno("Confirm NOP", f"Are you sure you want to replace:\n\n0x{rip:X}: {insn}\n\nwith {size} NOP byte(s)?"):
            ok = self.debugger.replace_with_nops(rip, size)
            if ok:
                messagebox.showinfo("Success", f"Replaced with {size} NOP(s) successfully!")
                self.tree.item(sel[0], values=(vals[0], f"[NOP] {insn}", vals[2]))
                self.status_var.set(f"Patched 0x{rip:X} with {size} NOP(s).")
            else:
                messagebox.showerror("Failed", "WriteProcessMemory failed to write NOPs.")

    def _on_copy_info(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']
        rip = int(str(vals[2]), 16)
        hit = self.row_data.get(rip)
        if not hit:
            return
        lines = [
            f"Instruction: {hit.get('insn', '')}",
            f"Address: 0x{rip:X}",
            f"Bytes: {' '.join(f'{b:02X}' for b in hit.get('bytes', b''))}",
            f"Hit Count: {hit.get('count', 0)}",
            "",
            "Registers:",
            self.reg_text.get('1.0', 'end').strip()
        ]
        text = "\n".join(lines)
        self._dlg.clipboard_clear()
        self._dlg.clipboard_append(text)
        self.status_var.set("Copied instruction & register details to clipboard.")

    def _on_close(self):
        self._is_stopped = True
        try:
            self.debugger.stop()
        except Exception:
            pass
        self._dlg.destroy()


# ============================================================
# Main Studio GUI
# ============================================================
class StudioGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MomoTrainer Studio — Advanced Memory Scanner & Trainer Compiler")
        self.root.geometry("1280x800")
        self.root.minsize(1050, 680)

        # Core state
        self.h = self.pid = self.exe_name = None
        self.candidates = []
        self.addresses = []
        self.scan_stop = threading.Event()
        self.scan_prog_q = queue.Queue()
        self.q = queue.Queue()
        self.live_stop = threading.Event()
        # v4 scan state
        self.ss_stop = threading.Event()
        self.ss_prog_q = queue.Queue()
        self.ss_q = queue.Queue()
        self.ss_active = False
        self.ss_engine = None
        self.sc_stop = threading.Event()
        self.sc_prog_q = queue.Queue()
        self.sc_q = queue.Queue()
        self.sc_active = False
        self.sc_engine = None
        self._worker_last_update = {}
        self._worker_scanned = {}
        self._scan_total = 0
        self._freeze_engine = None

        # Spec & Compiler state
        self.spec_path = None
        self.spec = {
            'name': 'My Trainer',
            'game': '',
            'brand': 'MomoTrainer — by Momo aka Steav Beoung Salang',
            'hotkey_toggle': 'VK_F8',
            'hotkey_panic': 'VK_END',
            'window_size': [460, 380],
            'window_title_color': '#38bdf8',
            'features': [],
            'actions': [],
        }

        # Theme
        self._current_theme_name = "modern_dark"
        self._current_theme = th.THEMES["modern_dark"]
        self.theme_var = tk.StringVar(value="modern_dark")

        # UI reactive variables
        self.game_var = tk.StringVar(value="No process attached")
        self.admin_var = tk.StringVar(value="Checking admin...")
        self.status_var = tk.StringVar(value="Ready — Press F5 or click [Select Process] to attach")
        self.spec_label_var = tk.StringVar(value="(unsaved)")
        self.build_status = tk.StringVar(value="Ready to build standalone executable.")
        self.found_count_var = tk.StringVar(value="0 hits")
        
        # Kernel mode state
        self.kernel_mode_var = tk.BooleanVar(value=False)
        self.kernel_driver_available = False
        self._kernel_driver = None
        self._hybrid_memory = None
        self.scan_info_var = tk.StringVar(value="Ready to scan")
        self.freeze_stats_var = tk.StringVar(value="Freeze Engine: Idle")

        # Scan controls variables
        self.val_var = tk.StringVar(value="100")
        self.high_var = tk.StringVar(value="")
        self.sig_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value="Exact value")
        self.vtype_var = tk.StringVar(value="4 Bytes (Int32)")
        self.fastscan_var = tk.StringVar(value="Aligned (4 bytes)")
        self.align_var = tk.StringVar(value="4")
        self.mem_writable_var = tk.BooleanVar(value=True)
        self.mem_executable_var = tk.BooleanVar(value=False)
        self.mem_cow_var = tk.BooleanVar(value=False)
        self.hex_mode_var = tk.BooleanVar(value=False)

        # Mapping dicts
        self.mode_map = dict(MODE_LABELS)
        self.vtype_map = dict(VTYPE_LABELS)

        # Initialize kernel driver (async check)
        self._kernel_driver = None
        self._hybrid_memory = None
        self.kernel_driver_available = False

        # Build UI layout
        self._build_ui()

        # Background threads & periodic pumps
        self._start_live_thread()
        self.root.after(100, self._pump)
        self.root.after(500, self._check_admin)
        self.root.after(500, self._check_kernel_driver)

    # ============================================================
    # UI CONSTRUCTION
    # ============================================================
    def _build_ui(self):
        # Base ttk style configuration
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except Exception:
            pass

        # Color constants for custom canvas/frames
        self._c_bg = self._current_theme["bg"]
        self._c_panel = self._current_theme["panel_bg"]
        self._c_border = self._current_theme["input_border"]
        self._c_text = self._current_theme["fg"]
        self._c_muted = self._current_theme["fg_muted"]
        self._c_accent = self._current_theme["fg_accent"]
        self._c_btn_bg = self._current_theme["button_bg"]
        self._c_btn_fg = self._current_theme["button_fg"]

        self.root.configure(bg=self._c_bg)

        # 1. Menu bar
        self._build_menu_bar()

        # 2. Modern Cheat Engine Process & Action Header Bar
        self._build_header_bar()

        # 3. Main Vertical Splitter (PanedWindow)
        # Upper: Found List (Left) + Scan Controls (Right)
        # Lower: Cheat Table & Studio Notebook Tabs
        self.main_paned = ttk.PanedWindow(self.root, orient='vertical')
        self.main_paned.pack(fill='both', expand=True, padx=8, pady=(4, 4))

        # Upper container frame
        self.upper_frame = tk.Frame(self.main_paned, bg=self._c_bg)
        self.main_paned.add(self.upper_frame, weight=1)

        # Lower container frame
        self.lower_frame = tk.Frame(self.main_paned, bg=self._c_bg)
        self.main_paned.add(self.lower_frame, weight=2)

        # Construct sections
        self._build_upper_scanner_area()
        self._build_lower_notebook()

        # 4. Status Bar
        self._build_status_bar()

        # Apply active theme
        self._apply_current_theme()

        # Global keyboard shortcuts
        self.root.bind('<F5>', lambda _: self._open_process_picker())
        self.root.bind('<Control-p>', lambda _: self._open_process_picker())
        self.root.bind('<Control-s>', lambda _: self._save_spec())
        self.root.bind('<Control-o>', lambda _: self._open_spec())

    # -----------------------------------------------------------
    # MENU BAR
    # -----------------------------------------------------------
    def _build_menu_bar(self):
        mb = tk.Menu(self.root, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff',
                     tearoff=0, font=('Segoe UI', 9))
        self.root.config(menu=mb)

        # File Menu
        fm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='File', menu=fm)
        fm.add_command(label='New Table', accelerator='Ctrl+N', command=self._new_spec)
        fm.add_command(label='Open Table…', accelerator='Ctrl+O', command=self._open_spec)
        fm.add_command(label='Save Table', accelerator='Ctrl+S', command=self._save_spec)
        fm.add_command(label='Save Table As…', command=self._save_spec_as)
        fm.add_separator()
        fm.add_command(label='Generate Trainer (.cpp)', command=lambda: self._build(False))
        fm.add_command(label='Build Standalone (.exe)', accelerator='F7', command=lambda: self._build(True))
        fm.add_separator()
        fm.add_command(label='Exit', accelerator='Alt+F4', command=self._on_quit)

        # Process Menu
        pm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='Process', menu=pm)
        pm.add_command(label='Select Target Process…', accelerator='F5', command=self._open_process_picker)
        pm.add_command(label='Detach from Process', command=self._detach)

        # Table Menu
        tm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='Table', menu=tm)
        tm.add_command(label='Add Address Manually…', accelerator='Ctrl+A', command=self._add_address_manually)
        tm.add_command(label='Pointer Scan Selected Address…', command=self._do_ptrscan)
        tm.add_separator()
        tm.add_command(label='Find out what accesses this address…', command=lambda: self._open_debugger_for_selected('access'))
        tm.add_command(label='Find out what writes to this address…', command=lambda: self._open_debugger_for_selected('write'))
        tm.add_separator()
        tm.add_command(label='Freeze All Addresses', command=self._freeze_all)
        tm.add_command(label='Unfreeze All Addresses', command=self._unfreeze_all)
        tm.add_command(label='Clear Cheat Table', command=self._clear_addresses)

        # Memory Menu
        mm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='Memory', menu=mm)
        mm.add_command(label='Hex Memory Viewer…', command=self._view_hex)
        mm.add_command(label='Find Pattern (AOB SigScan)…', command=self._focus_aob_scan)
        mm.add_separator()
        mm.add_command(label='🔤 String Scan…', command=self._focus_string_scan)
        mm.add_command(label='📐 Structure Compare Scan…', command=self._focus_struct_compare)
        mm.add_command(label='📦 Resolve Module+Offset Address…', command=self._open_address_parser)

        # Theme Menu
        thm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                      activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='Theme', menu=thm)
        thm.add_radiobutton(label='Modern Dark (Cyan/Slate)', variable=self.theme_var,
                            value='modern_dark', command=self._apply_current_theme)
        thm.add_radiobutton(label='Cheat Engine Dark (Pink)', variable=self.theme_var,
                            value='dark', command=self._apply_current_theme)
        thm.add_radiobutton(label='Warm Kawaii (Cream/Amber)', variable=self.theme_var,
                            value='warm', command=self._apply_current_theme)

        # Help Menu
        hm = tk.Menu(mb, bg=self._c_panel, fg=self._c_text,
                     activebackground=self._c_accent, activeforeground='#ffffff', tearoff=0)
        mb.add_cascade(label='Help', menu=hm)
        hm.add_command(label='About MomoTrainer Studio', command=self._show_about)

    # -----------------------------------------------------------
    # HEADER BAR (Process Attachment & Studio Status)
    # -----------------------------------------------------------
    def _build_header_bar(self):
        hdr = tk.Frame(self.root, bg=self._c_panel, height=48)
        hdr.pack(fill='x', padx=8, pady=(6, 2))
        hdr.pack_propagate(False)

        # Left: Process Selector Button + Attached Status Badge
        left_box = tk.Frame(hdr, bg=self._c_panel)
        left_box.pack(side='left', fill='y', padx=4)

        # Clean GitHub-styled Process Selector Button
        self.btn_pick_proc = tk.Button(
            left_box, text='🖥️  Select Process (F5)', font=('Segoe UI', 9),
            bg='#21262d', fg='#c9d1d9', activebackground='#30363d', activeforeground='#ffffff',
            relief='flat', padx=12, pady=4, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._open_process_picker
        )
        self.btn_pick_proc.pack(side='left', pady=7)

        # Attached Badge Pill (Smooth inset look)
        self.proc_pill = tk.Frame(left_box, bg='#0d1117', padx=10, pady=4,
                                  highlightthickness=1, highlightbackground=self._c_border)
        self.proc_pill.pack(side='left', padx=(8, 4), pady=7)

        self.proc_dot = tk.Label(self.proc_pill, text='●', font=('Segoe UI', 8),
                                 bg='#0d1117', fg='#8b949e')
        self.proc_dot.pack(side='left', padx=(0, 6))

        self.proc_label = tk.Label(self.proc_pill, textvariable=self.game_var,
                                   font=('Segoe UI', 9), bg='#0d1117', fg=self._c_muted)
        self.proc_label.pack(side='left')

        # Detach Button
        self.btn_detach = tk.Button(
            left_box, text='✕ Detach', font=('Segoe UI', 8),
            bg='#21262d', fg='#8b949e', activebackground='#da3633', activeforeground='#ffffff',
            relief='flat', padx=8, pady=3, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._detach
        )
        self.btn_detach.pack(side='left', padx=6)
        self.btn_detach.pack_forget()

        # Right: Quick Utilities & Admin Indicator
        right_box = tk.Frame(hdr, bg=self._c_panel)
        right_box.pack(side='right', fill='y', padx=4)

        # Table file pill
        tbl_box = tk.Frame(right_box, bg='#0d1117', padx=8, pady=4,
                           highlightthickness=1, highlightbackground=self._c_border)
        tbl_box.pack(side='left', padx=6, pady=7)
        tk.Label(tbl_box, text='Table:', font=('Segoe UI', 8),
                 bg='#0d1117', fg=self._c_muted).pack(side='left', padx=(0, 4))
        tk.Label(tbl_box, textvariable=self.spec_label_var, font=('Consolas', 8),
                 bg='#0d1117', fg='#58a6ff').pack(side='left')

        # Admin privilege indicator
        self.admin_pill = tk.Frame(right_box, bg='#0d1117', padx=8, pady=4,
                                   highlightthickness=1, highlightbackground=self._c_border)
        self.admin_pill.pack(side='left', padx=6, pady=7)
        self.admin_label = tk.Label(self.admin_pill, textvariable=self.admin_var,
                                    font=('Segoe UI', 8), bg='#0d1117', fg='#8b949e')
        self.admin_label.pack(side='left')

        self.admin_btn = tk.Button(
            right_box, text='Elevate Admin', font=('Segoe UI', 8),
            bg='#21262d', fg='#d29922', activebackground='#30363d', activeforeground='#ffffff',
            relief='flat', padx=8, pady=3, highlightthickness=1, highlightbackground=self._c_border,
            command=self._run_as_admin
        )
        self.admin_btn.pack(side='left', padx=4)
        self.admin_btn.pack_forget()

        # Quick Build Button (GitHub Green)
        tk.Button(
            right_box, text='🔨 Build (.exe)', font=('Segoe UI', 8, 'bold'),
            bg='#238636', fg='#ffffff', activebackground='#2ea043', activeforeground='#ffffff',
            relief='flat', padx=12, pady=4, cursor='hand2',
            command=lambda: self._build(True)
        ).pack(side='left', padx=4)

    # -----------------------------------------------------------
    # UPPER SCANNER AREA (Split: Found List Left, Scanner Right)
    # -----------------------------------------------------------
    def _c_engine_active(self):
        """Return True if the C scan engine is available for the current scan config."""
        import scan_engine as _se
        return _se.is_available()

    def _build_upper_scanner_area(self):
        upper_paned = ttk.PanedWindow(self.upper_frame, orient='horizontal')
        upper_paned.pack(fill='both', expand=True)

        # Left Container: Found Results
        found_container = tk.Frame(upper_paned, bg=self._c_panel,
                                   highlightbackground=self._c_border, highlightthickness=1)
        upper_paned.add(found_container, weight=5)

        # Right Container: Scan Options Card
        scan_container = tk.Frame(upper_paned, bg=self._c_panel,
                                  highlightbackground=self._c_border, highlightthickness=1)
        upper_paned.add(scan_container, weight=4)

        # === 1. FOUND RESULTS PANEL (LEFT) ===
        f_top = tk.Frame(found_container, bg=self._c_panel)
        f_top.pack(fill='x', padx=8, pady=(8, 4))

        tk.Label(f_top, text='FOUND ADDRESSES', font=('Segoe UI', 8, 'bold'),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left')

        self.found_badge = tk.Label(f_top, textvariable=self.found_count_var,
                                    font=('Consolas', 8), bg='#21262d',
                                    fg='#58a6ff', padx=8, pady=2,
                                    highlightthickness=1, highlightbackground=self._c_border)
        self.found_badge.pack(side='left', padx=8)

        tk.Button(f_top, text='Clear', font=('Segoe UI', 8),
                  bg='#21262d', fg=self._c_muted, activebackground='#30363d', activeforeground='#ffffff',
                  relief='flat', padx=8, pady=2, cursor='hand2',
                  highlightthickness=1, highlightbackground=self._c_border,
                  command=self._clear_found_tree).pack(side='right')

        # Treeview for Found addresses
        f_tree_frame = tk.Frame(found_container, bg=self._c_border)
        f_tree_frame.pack(fill='both', expand=True, padx=8, pady=4)

        self.found_tree = ttk.Treeview(
            f_tree_frame, columns=('addr', 'val', 'prev'),
            show='headings', selectmode='extended', height=9
        )
        self.found_tree.heading('addr', text='Address', anchor='w')
        self.found_tree.heading('val',  text='Value', anchor='e')
        self.found_tree.heading('prev', text='Previous', anchor='e')

        self.found_tree.column('addr', width=130, anchor='w')
        self.found_tree.column('val',  width=120, anchor='e')
        self.found_tree.column('prev', width=120, anchor='e')
        self.found_tree.pack(side='left', fill='both', expand=True)

        f_scroll = ttk.Scrollbar(f_tree_frame, orient='vertical', command=self.found_tree.yview)
        f_scroll.pack(side='right', fill='y')
        self.found_tree.configure(yscrollcommand=f_scroll.set)

        self.found_tree.bind('<Double-1>', lambda _: self._add_found_to_address_list())
        self.found_tree.bind('<Return>',   lambda _: self._add_found_to_address_list())
        self.found_tree.bind('<Button-3>', self._show_found_context_menu)

        # Transfer button (Clean GitHub Action bar)
        transfer_bar = tk.Frame(found_container, bg=self._c_panel)
        transfer_bar.pack(fill='x', padx=8, pady=(4, 8))

        self.btn_add_found = tk.Button(
            transfer_bar, text='▼  Add Selected to Cheat Table (or Double-Click row)',
            font=('Segoe UI', 8), bg='#21262d', fg='#58a6ff',
            activebackground='#30363d', activeforeground='#ffffff',
            relief='flat', padx=12, pady=4, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._add_found_to_address_list
        )
        self.btn_add_found.pack(side='left', fill='x', expand=True)

        # === 2. SCAN CONTROLS PANEL (RIGHT) ===
        # Hick's Law: 3 primary choices in prominent view (Type, Mode, Value)
        sc = tk.Frame(scan_container, bg=self._c_panel)
        sc.pack(fill='both', expand=True, padx=12, pady=8)

        # Card Title
        tk.Label(sc, text='MEMORY SCANNER', font=('Segoe UI', 8, 'bold'),
                 bg=self._c_panel, fg=self._c_muted).pack(anchor='w', pady=(0, 6))

        # Row 1: Scan Type + Value Type (Side by Side)
        r1 = tk.Frame(sc, bg=self._c_panel)
        r1.pack(fill='x', pady=2)

        c_vtype = tk.Frame(r1, bg=self._c_panel)
        c_vtype.pack(side='left', fill='x', expand=True, padx=(0, 4))
        tk.Label(c_vtype, text='Value Type:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(anchor='w')
        ttk.Combobox(c_vtype, textvariable=self.vtype_var,
                     values=[lbl for lbl, _ in VTYPE_LABELS],
                     state='readonly').pack(fill='x', pady=(2, 0))

        c_mode = tk.Frame(r1, bg=self._c_panel)
        c_mode.pack(side='right', fill='x', expand=True, padx=(4, 0))
        tk.Label(c_mode, text='Scan Mode:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(anchor='w')
        cb_mode = ttk.Combobox(c_mode, textvariable=self.mode_var,
                               values=[lbl for lbl, _ in MODE_LABELS],
                               state='readonly')
        cb_mode.pack(fill='x', pady=(2, 0))
        self.mode_var.trace_add('write', lambda *_: self._on_mode_change())

        # Row 2: Value Input (Primary & Between High Value)
        r2 = tk.Frame(sc, bg=self._c_panel)
        r2.pack(fill='x', pady=(6, 2))

        self.lbl_val = tk.Label(r2, text='Value:', font=('Segoe UI', 8),
                                bg=self._c_panel, fg=self._c_muted)
        self.lbl_val.pack(anchor='w')

        vbox = tk.Frame(r2, bg=self._c_panel)
        vbox.pack(fill='x', pady=(2, 0))

        self.val_entry = tk.Entry(
            vbox, textvariable=self.val_var, font=('Consolas', 10),
            bg='#0d1117', fg='#e6edf3', insertbackground='#58a6ff',
            relief='flat', highlightthickness=1, highlightbackground=self._c_border,
            highlightcolor='#58a6ff'
        )
        self.val_entry.pack(side='left', fill='x', expand=True)
        self.val_entry.bind('<Return>', lambda _: self._trigger_scan_enter())

        self.lbl_between = tk.Label(vbox, text=' and ', font=('Segoe UI', 8),
                                    bg=self._c_panel, fg=self._c_muted)
        self.high_entry = tk.Entry(
            vbox, textvariable=self.high_var, font=('Consolas', 10),
            bg='#0d1117', fg='#e6edf3', insertbackground='#58a6ff',
            relief='flat', highlightthickness=1, highlightbackground=self._c_border,
            highlightcolor='#58a6ff', width=10
        )
        self.lbl_between.pack(side='left', padx=4)
        self.high_entry.pack(side='left')
        self.lbl_between.pack_forget()
        self.high_entry.pack_forget()

        # Row 3: Primary Action Buttons (GitHub Palette: Green primary, Blue secondary, Gray neutral)
        r3 = tk.Frame(sc, bg=self._c_panel)
        r3.pack(fill='x', pady=(10, 4))

        self.btn_first = tk.Button(
            r3, text='First Scan', font=('Segoe UI', 9, 'bold'),
            bg='#238636', fg='#ffffff', activebackground='#2ea043', activeforeground='#ffffff',
            relief='flat', padx=14, pady=5, cursor='hand2',
            command=self._do_first_scan
        )
        self.btn_first.pack(side='left', fill='x', expand=True, padx=(0, 4))

        self.btn_next = tk.Button(
            r3, text='Next Scan', font=('Segoe UI', 9, 'bold'),
            bg='#1f6feb', fg='#ffffff', activebackground='#388bfd', activeforeground='#ffffff',
            relief='flat', padx=14, pady=5, cursor='hand2',
            command=self._do_next_scan, state='disabled'
        )
        self.btn_next.pack(side='left', fill='x', expand=True, padx=4)

        self.btn_reset = tk.Button(
            r3, text='New Scan', font=('Segoe UI', 9),
            bg='#21262d', fg='#c9d1d9', activebackground='#30363d', activeforeground='#ffffff',
            relief='flat', padx=10, pady=5, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._reset_scan
        )
        self.btn_reset.pack(side='left', padx=4)

        self.btn_stop = tk.Button(
            r3, text='Stop', font=('Segoe UI', 9),
            bg='#21262d', fg='#f85149', activebackground='#da3633', activeforeground='#ffffff',
            relief='flat', padx=10, pady=5, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._stop_scan, state='disabled'
        )
        self.btn_stop.pack(side='left', padx=(4, 0))

        # Progress bar & Info label
        self.scan_prog = ttk.Progressbar(sc, mode='determinate')
        self.scan_prog.pack(fill='x', pady=(8, 2))

        self.scan_info_lbl = tk.Label(sc, textvariable=self.scan_info_var,
                                      font=('Consolas', 8), bg=self._c_panel,
                                      fg=self._c_muted, anchor='w')
        self.scan_info_lbl.pack(fill='x')

        # Progressive Disclosure: Collapsible Advanced Scan Options
        self.adv_btn = tk.Button(
            sc, text='▶  Advanced Scan Options (Alignment, Flags, AOB)',
            font=('Segoe UI', 8), bg=self._c_panel, fg='#58a6ff', activebackground=self._c_panel,
            relief='flat', anchor='w', cursor='hand2',
            command=self._toggle_advanced_options
        )
        self.adv_btn.pack(fill='x', pady=(8, 2))

        self.adv_frame = tk.Frame(sc, bg=self._c_panel, padx=8, pady=6,
                                  highlightthickness=1, highlightbackground=self._c_border)
        # Inside advanced frame:
        adv_r1 = tk.Frame(self.adv_frame, bg=self._c_panel)
        adv_r1.pack(fill='x', pady=2)

        tk.Label(adv_r1, text='Fast Scan:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left', padx=(0, 4))
        ttk.Combobox(adv_r1, textvariable=self.fastscan_var,
                     values=['Not Aligned', 'Aligned (2 bytes)', 'Aligned (4 bytes)',
                             'Aligned (8 bytes)', 'Aligned (16 bytes)'],
                     state='readonly', width=16).pack(side='left', padx=2)

        # Memory type flags
        adv_r2 = tk.Frame(self.adv_frame, bg=self._c_panel)
        adv_r2.pack(fill='x', pady=4)
        tk.Checkbutton(adv_r2, text='Writable', variable=self.mem_writable_var,
                       font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_text,
                       selectcolor='#0d1117', activebackground=self._c_panel).pack(side='left', padx=4)
        tk.Checkbutton(adv_r2, text='Executable', variable=self.mem_executable_var,
                       font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_text,
                       selectcolor='#0d1117', activebackground=self._c_panel).pack(side='left', padx=4)
        tk.Checkbutton(adv_r2, text='CopyOnWrite', variable=self.mem_cow_var,
                       font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_text,
                       selectcolor='#0d1117', activebackground=self._c_panel).pack(side='left', padx=4)

        # AOB signature scan row
        adv_r3 = tk.Frame(self.adv_frame, bg=self._c_panel)
        adv_r3.pack(fill='x', pady=2)
        tk.Label(adv_r3, text='AOB Sig:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left', padx=(0, 4))
        tk.Entry(adv_r3, textvariable=self.sig_var, font=('Consolas', 8),
                 bg='#0d1117', fg=self._c_text, insertbackground='#58a6ff',
                 relief='flat', highlightthickness=1, highlightbackground=self._c_border).pack(side='left', fill='x', expand=True, padx=2)
        self.btn_sigscan = tk.Button(
            adv_r3, text='Scan AOB', font=('Segoe UI', 8),
            bg='#21262d', fg='#58a6ff', activebackground='#30363d', activeforeground='#ffffff',
            relief='flat', padx=8, pady=1, cursor='hand2',
            highlightthickness=1, highlightbackground=self._c_border,
            command=self._do_sigscan
        )
        self.btn_sigscan.pack(side='left', padx=(4, 0))

    # -----------------------------------------------------------
    # LOWER NOTEBOOK (Cheat Table / Trainer Spec / Compiler)
    # -----------------------------------------------------------
    def _build_lower_notebook(self):
        self.notebook = ttk.Notebook(self.lower_frame)
        self.notebook.pack(fill='both', expand=True)

        # Tab 1: Cheat Table (Address List)
        self.tab_table = tk.Frame(self.notebook, bg=self._c_bg)
        self.notebook.add(self.tab_table, text='  📋 Cheat Table (Address List)  ')

        # Tab 2: Trainer Spec Editor
        self.tab_spec = tk.Frame(self.notebook, bg=self._c_bg)
        self.notebook.add(self.tab_spec, text='  ⚙️ Trainer Spec Editor  ')

        # Tab 3: Compiler & Build Log
        self.tab_build = tk.Frame(self.notebook, bg=self._c_bg)
        self.notebook.add(self.tab_build, text='  🔨 Standalone Trainer Compiler  ')

        # Tab 4: String Scan
        self.tab_stringscan = tk.Frame(self.notebook, bg=self._c_bg)
        self.notebook.add(self.tab_stringscan, text='  🔤 String Scan  ')

        # Tab 5: Structure Compare
        self.tab_struct = tk.Frame(self.notebook, bg=self._c_bg)
        self.notebook.add(self.tab_struct, text='  📐 Struct Compare  ')

        # Construct each tab
        self._build_cheat_table_tab()
        self._build_trainer_spec_tab()
        self._build_compiler_tab()
        self._build_string_scan_tab()
        self._build_struct_compare_tab()

    # --- TAB 1: CHEAT TABLE ---
    def _build_cheat_table_tab(self):
        # Action Toolbar (GitHub style action bar)
        tb = tk.Frame(self.tab_table, bg=self._c_panel,
                      highlightbackground=self._c_border, highlightthickness=1)
        tb.pack(fill='x', padx=4, pady=(6, 4))

        tk.Button(tb, text='+ Add Address', font=('Segoe UI', 8, 'bold'),
                  bg='#1f6feb', fg='#ffffff', activebackground='#388bfd', activeforeground='#ffffff',
                  relief='flat', padx=10, pady=3, cursor='hand2',
                  command=self._add_address_manually).pack(side='left', padx=(4, 2), pady=4)

        for txt, cmd in [
            ('❄ Toggle Freeze (Space)', self._toggle_freeze),
            ('✏ Edit Value', self._edit_address_value),
            ('🔍 Pointer Scan', self._do_ptrscan),
            ('👁 Hex View', self._view_hex),
            ('✕ Remove', self._remove_selected_addr),
            ('Clear All', self._clear_addresses),
        ]:
            tk.Button(tb, text=txt, font=('Segoe UI', 8),
                      bg='#21262d', fg='#c9d1d9', activebackground='#30363d', activeforeground='#ffffff',
                      relief='flat', padx=8, pady=3, cursor='hand2',
                      highlightthickness=1, highlightbackground=self._c_border,
                      command=cmd).pack(side='left', padx=2, pady=4)

        # Add to trainer button (Right side - GitHub Green)
        tk.Button(tb, text='🚀 Add Selected to Trainer Spec →', font=('Segoe UI', 8, 'bold'),
                  bg='#238636', fg='#ffffff', activebackground='#2ea043', activeforeground='#ffffff',
                  relief='flat', padx=12, pady=3, cursor='hand2',
                  command=self._add_selected_to_spec).pack(side='right', padx=6, pady=4)

        # Address Treeview Frame
        tree_fr = tk.Frame(self.tab_table, bg=self._c_border)
        tree_fr.pack(fill='both', expand=True, padx=2, pady=(0, 2))

        self.addr_tree = ttk.Treeview(
            tree_fr, columns=('frz', 'desc', 'addr', 'type', 'val'),
            show='headings', selectmode='extended'
        )
        self.addr_tree.heading('frz',  text='Active', anchor='center')
        self.addr_tree.heading('desc', text='Description', anchor='w')
        self.addr_tree.heading('addr', text='Address', anchor='w')
        self.addr_tree.heading('type', text='Type', anchor='w')
        self.addr_tree.heading('val',  text='Value', anchor='e')

        self.addr_tree.column('frz',  width=70,  anchor='center')
        self.addr_tree.column('desc', width=260, anchor='w')
        self.addr_tree.column('addr', width=160, anchor='w')
        self.addr_tree.column('type', width=110, anchor='w')
        self.addr_tree.column('val',  width=150, anchor='e')
        self.addr_tree.pack(side='left', fill='both', expand=True)

        a_scroll = ttk.Scrollbar(tree_fr, orient='vertical', command=self.addr_tree.yview)
        a_scroll.pack(side='right', fill='y')
        self.addr_tree.configure(yscrollcommand=a_scroll.set)

        # Visual state tags
        self.addr_tree.tag_configure('changed',  background='#144a26', foreground='#86efac')
        self.addr_tree.tag_configure('frozen',   background='#683610', foreground='#fde68a')
        self.addr_tree.tag_configure('frozench', background='#7c2d12', foreground='#fed7aa')

        # Double click & key bindings
        self.addr_tree.bind('<Double-1>', self._on_addr_tree_double_click)
        self.addr_tree.bind('<space>',    lambda _: self._toggle_freeze())
        self.addr_tree.bind('<Delete>',   lambda _: self._remove_selected_addr())
        self.addr_tree.bind('<Button-3>', self._show_addr_context_menu)
        self.addr_tree.bind('<F5>',       lambda _: self._open_debugger_for_selected('access'))
        self.addr_tree.bind('<F6>',       lambda _: self._open_debugger_for_selected('write'))

    def _on_addr_tree_double_click(self, event):
        region = self.addr_tree.identify_region(event.x, event.y)
        if region != 'cell':
            return
        col = self.addr_tree.identify_column(event.x)
        if col == '#1':  # Active (Freeze)
            self._toggle_freeze()
        elif col == '#2':  # Description
            self._edit_address_description()
        elif col == '#3':  # Address -> Open Hex View
            self._view_hex()
        elif col == '#5':  # Value -> Edit Value
            self._edit_address_value()
        else:
            self._edit_address_value()

    def _show_addr_context_menu(self, event):
        iid = self.addr_tree.identify_row(event.y)
        if iid:
            if iid not in self.addr_tree.selection():
                self.addr_tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0, bg=self._c_panel, fg=self._c_text,
                       activebackground=self._c_accent, activeforeground='#ffffff')
        menu.add_command(label='Toggle Freeze (Active)', command=self._toggle_freeze)
        menu.add_command(label='Change Value…', command=self._edit_address_value)
        menu.add_command(label='Change Description…', command=self._edit_address_description)
        menu.add_separator()
        menu.add_command(label='🔍 Find out what accesses this address (F5)', command=lambda: self._open_debugger_for_selected('access'))
        menu.add_command(label='✏️ Find out what writes to this address (F6)', command=lambda: self._open_debugger_for_selected('write'))
        menu.add_separator()
        menu.add_command(label='Pointer Scan for this Address…', command=self._do_ptrscan)
        menu.add_command(label='Hex Memory Viewer…', command=self._view_hex)
        menu.add_command(label='Add to Trainer Spec', command=self._add_selected_to_spec)
        menu.add_separator()
        menu.add_command(label='Remove', command=self._remove_selected_addr)
        menu.tk_popup(event.x_root, event.y_root)

    # --- TAB 2: TRAINER SPEC EDITOR ---
    def _build_trainer_spec_tab(self):
        body = tk.Frame(self.tab_spec, bg=self._c_bg)
        body.pack(fill='both', expand=True, padx=4, pady=4)

        # Metadata Card
        meta_card = tk.Frame(body, bg=self._c_panel,
                             highlightbackground=self._c_border, highlightthickness=1)
        meta_card.pack(fill='x', pady=(0, 6), padx=2)

        tk.Label(meta_card, text='TRAINER CONFIGURATION', font=('Segoe UI', 9, 'bold'),
                 bg=self._c_panel, fg=self._c_text).grid(row=0, column=0, columnspan=4, sticky='w', padx=10, pady=(6, 4))

        self.meta_name = tk.StringVar(value='My Trainer')
        self.meta_game = tk.StringVar(value='')
        self.meta_toggle = tk.StringVar(value='VK_F8')
        self.meta_panic = tk.StringVar(value='VK_END')
        self.meta_color = tk.StringVar(value='#38bdf8')
        self.meta_wh = tk.StringVar(value='460x380')

        def _add_meta_entry(r, c, lbl, var, is_combo=False, vals=None):
            tk.Label(meta_card, text=lbl, font=('Segoe UI', 8),
                     bg=self._c_panel, fg=self._c_muted).grid(row=r, column=c*2, sticky='e', padx=8, pady=3)
            if is_combo:
                ttk.Combobox(meta_card, textvariable=var, values=vals,
                             state='readonly', width=18).grid(row=r, column=c*2+1, sticky='w', padx=4, pady=3)
            else:
                tk.Entry(meta_card, textvariable=var, font=('Consolas', 9),
                         bg=self._c_border, fg=self._c_text, insertbackground='#ffffff',
                         relief='flat', width=22).grid(row=r, column=c*2+1, sticky='w', padx=4, pady=3)

        _add_meta_entry(1, 0, 'Trainer Title:', self.meta_name)
        _add_meta_entry(1, 1, 'Target Game Exe:', self.meta_game)
        _add_meta_entry(2, 0, 'Toggle Hotkey:', self.meta_toggle, True,
                        ['VK_F1', 'VK_F2', 'VK_F3', 'VK_F4', 'VK_F5', 'VK_F6', 'VK_F7', 'VK_F8', 'VK_F9', 'VK_F10', 'VK_F11', 'VK_F12'])
        _add_meta_entry(2, 1, 'Panic Hotkey:', self.meta_panic, True,
                        ['VK_END', 'VK_HOME', 'VK_DELETE', 'VK_F12'])
        _add_meta_entry(3, 0, 'Title Accent Color:', self.meta_color)
        _add_meta_entry(3, 1, 'Window Size (WxH):', self.meta_wh)

        # Features Table
        feat_card = tk.Frame(body, bg=self._c_panel,
                             highlightbackground=self._c_border, highlightthickness=1)
        feat_card.pack(fill='both', expand=True, padx=2)

        feat_header = tk.Frame(feat_card, bg=self._c_panel)
        feat_header.pack(fill='x', padx=10, pady=6)
        tk.Label(feat_header, text='TRAINER FEATURES (CHEATS)', font=('Segoe UI', 9, 'bold'),
                 bg=self._c_panel, fg=self._c_text).pack(side='left')

        # Feature table toolbar
        ftb = tk.Frame(feat_card, bg=self._c_panel)
        ftb.pack(fill='x', padx=10, pady=(0, 4))
        tk.Button(ftb, text='+ Add Feature', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=self._add_feature_row).pack(side='left', padx=2)
        tk.Button(ftb, text='Edit Feature', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=self._edit_feature_row).pack(side='left', padx=2)
        tk.Button(ftb, text='Remove', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=self._remove_feature_row).pack(side='left', padx=2)
        tk.Button(ftb, text='↑ Move Up', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=lambda: self._move_feature(-1)).pack(side='left', padx=2)
        tk.Button(ftb, text='↓ Move Down', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=lambda: self._move_feature(1)).pack(side='left', padx=2)
        tk.Button(ftb, text='Preview YAML', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=8, pady=2, command=self._show_yaml).pack(side='right', padx=2)

        feat_tree_fr = tk.Frame(feat_card, bg=self._c_border)
        feat_tree_fr.pack(fill='both', expand=True, padx=10, pady=(0, 10))

        cols = [('name', 'Feature Name', 160), ('type', 'Type', 90),
                ('address', 'Address / Pointer', 180), ('value', 'Value', 80),
                ('width', 'Width', 60), ('on', 'Default ON', 80), ('desc', 'Description', 200)]
        self.feat_tree = ttk.Treeview(feat_tree_fr, columns=[c for c, _, _ in cols], show='headings')
        for c, lbl, w in cols:
            self.feat_tree.heading(c, text=lbl, anchor='w')
            self.feat_tree.column(c, width=w, anchor='w')
        self.feat_tree.pack(side='left', fill='both', expand=True)

        ft_sb = ttk.Scrollbar(feat_tree_fr, orient='vertical', command=self.feat_tree.yview)
        ft_sb.pack(side='right', fill='y')
        self.feat_tree.configure(yscrollcommand=ft_sb.set)
        self.feat_tree.bind('<Double-1>', lambda _: self._edit_feature_row())

    # --- TAB 3: COMPILER & BUILD ---
    def _build_compiler_tab(self):
        card = tk.Frame(self.tab_build, bg=self._c_panel,
                        highlightbackground=self._c_border, highlightthickness=1)
        card.pack(fill='both', expand=True, padx=6, pady=6)

        top_ctrl = tk.Frame(card, bg=self._c_panel)
        top_ctrl.pack(fill='x', padx=10, pady=8)

        tk.Label(top_ctrl, text='STANDALONE TRAINER COMPILER', font=('Segoe UI', 10, 'bold'),
                 bg=self._c_panel, fg=self._c_text).pack(anchor='w', pady=(0, 6))

        tk.Label(top_ctrl, textvariable=self.build_status, font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_accent).pack(anchor='w', pady=(0, 6))

        btn_row = tk.Frame(top_ctrl, bg=self._c_panel)
        btn_row.pack(fill='x')

        tk.Button(
            btn_row, text='🚀  Build Standalone Executable (.exe)',
            font=('Segoe UI', 9, 'bold'), bg='#16a34a', fg='#ffffff',
            activebackground='#15803d', activeforeground='#ffffff',
            relief='flat', padx=16, pady=6, cursor='hand2',
            command=lambda: self._build(True)
        ).pack(side='left', padx=(0, 6))

        tk.Button(
            btn_row, text='Generate C++ Code (.cpp)',
            font=('Segoe UI', 9), bg=self._c_accent, fg='#ffffff',
            relief='flat', padx=12, pady=6, cursor='hand2',
            command=lambda: self._build(False)
        ).pack(side='left', padx=6)

        tk.Button(
            btn_row, text='Open Output Folder',
            font=('Segoe UI', 9), bg=self._c_btn_bg, fg=self._c_btn_fg,
            relief='flat', padx=12, pady=6, cursor='hand2',
            command=self._open_out_dir
        ).pack(side='left', padx=6)

        # Embedded ScrolledText Build Log
        log_frame = tk.Frame(card, bg=self._c_border)
        log_frame.pack(fill='both', expand=True, padx=10, pady=(6, 10))

        tk.Label(card, text='Compilation Log Output:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(anchor='w', padx=10)

        self.build_log = scrolledtext.ScrolledText(
            log_frame, font=('Consolas', 9), bg='#0f0f12', fg='#a1a1aa',
            insertbackground='#ffffff', relief='flat', wrap='word'
        )
        self.build_log.pack(fill='both', expand=True)
        self.build_log.insert('end', "MomoTrainer Compiler Engine v2.0 Ready.\nConfigure features in the Spec tab or Add from Cheat Table, then click Build.\n")

    # -----------------------------------------------------------
    # STATUS BAR
    # -----------------------------------------------------------
    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=self._c_panel, height=26,
                      highlightbackground=self._c_border, highlightthickness=1)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)

        # Left status (General)
        tk.Label(sb, textvariable=self.status_var, font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_text, anchor='w').pack(side='left', padx=10)

        # Kernel mode toggle (center-left)
        kernel_frame = tk.Frame(sb, bg=self._c_panel)
        kernel_frame.pack(side='left', padx=(0, 12))
        
        self.kernel_mode_var = tk.BooleanVar(value=False)
        self.kernel_mode_cb = tk.Checkbutton(
            kernel_frame, text="Kernel Mode", variable=self.kernel_mode_var,
            font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_muted,
            selectcolor=self._c_panel, activebackground=self._c_bg,
            command=self._on_kernel_mode_toggle,
            state='disabled'
        )
        self.kernel_mode_cb.pack(side='left')
        
        # Kernel driver status indicator
        self.kernel_status_var = tk.StringVar(value="🔴 Driver: Not Loaded")
        self.kernel_status_label = tk.Label(
            kernel_frame, textvariable=self.kernel_status_var,
            font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_muted
        )
        self.kernel_status_label.pack(side='left', padx=(8, 0))

        # Right branding
        tk.Label(sb, text='MomoTrainer Studio v2.0 — CE Architecture', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='right', padx=10)

        # Center freeze stats
        tk.Label(sb, textvariable=self.freeze_stats_var, font=('Consolas', 8),
                 bg=self._c_panel, fg=self._c_accent).pack(side='right', padx=16)

    # ============================================================
    # PROCESS MANAGEMENT (CE Process Window)
    # ============================================================
    def _open_process_picker(self):
        dlg = tk.Toplevel(self.root, bg=self._c_bg)
        dlg.title('Select Process to Attach — MomoTrainer')
        dlg.geometry('540x450')
        dlg.transient(self.root)
        dlg.grab_set()

        hdr = tk.Frame(dlg, bg=self._c_panel, padx=10, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='SELECT TARGET PROCESS', font=('Segoe UI', 10, 'bold'),
                 bg=self._c_panel, fg=self._c_text).pack(anchor='w')

        # Filter bar
        sr = tk.Frame(dlg, bg=self._c_bg, padx=10, pady=8)
        sr.pack(fill='x')
        tk.Label(sr, text='Filter:', font=('Segoe UI', 9), bg=self._c_bg, fg=self._c_text).pack(side='left', padx=(0, 6))

        p_search = tk.StringVar(value='')
        ent_search = tk.Entry(sr, textvariable=p_search, font=('Consolas', 10),
                              bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat')
        ent_search.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ent_search.focus_set()

        show_sys_var = tk.BooleanVar(value=False)
        tk.Checkbutton(sr, text='Show System Procs', variable=show_sys_var,
                       font=('Segoe UI', 8), bg=self._c_bg, fg=self._c_muted,
                       selectcolor=self._c_panel, activebackground=self._c_bg).pack(side='right')

        # Process list
        list_fr = tk.Frame(dlg, bg=self._c_border)
        list_fr.pack(fill='both', expand=True, padx=10, pady=(0, 8))

        p_tree = ttk.Treeview(list_fr, columns=('pid', 'name'), show='headings', selectmode='browse')
        p_tree.heading('pid',  text='PID', anchor='e')
        p_tree.heading('name', text='Executable Name', anchor='w')
        p_tree.column('pid',  width=90,  anchor='e')
        p_tree.column('name', width=380, anchor='w')
        p_tree.pack(side='left', fill='both', expand=True)

        p_sb = ttk.Scrollbar(list_fr, orient='vertical', command=p_tree.yview)
        p_sb.pack(side='right', fill='y')
        p_tree.configure(yscrollcommand=p_sb.set)

        all_procs = list_processes()

        def _populate(q=''):
            p_tree.delete(*p_tree.get_children())
            query = q.lower().strip()
            show_sys = show_sys_var.get()
            filtered = []
            for pid, name in all_procs:
                if not show_sys and name in SKIP_PROCS:
                    continue
                if query and query not in name.lower() and query not in str(pid):
                    continue
                filtered.append((pid, name))
            filtered.sort(key=lambda x: x[1].lower())
            for pid, name in filtered:
                p_tree.insert('', 'end', values=(pid, name))

        p_search.trace_add('write', lambda *_: _populate(p_search.get()))
        show_sys_var.trace_add('write', lambda *_: _populate(p_search.get()))
        _populate()

        def _do_attach():
            sel = p_tree.selection()
            if not sel:
                return
            vals = p_tree.item(sel[0])['values']
            pid, name = int(vals[0]), str(vals[1])
            dlg.destroy()
            self._attach(pid, name)

        p_tree.bind('<Double-1>', lambda _: _do_attach())
        p_tree.bind('<Return>',   lambda _: _do_attach())

        # Buttons
        br = tk.Frame(dlg, bg=self._c_bg, padx=10, pady=8)
        br.pack(fill='x', side='bottom')

        tk.Button(br, text='Attach', font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=18, pady=4,
                  command=_do_attach).pack(side='left', padx=(0, 6))

        tk.Button(br, text='Refresh', font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=12, pady=4,
                  command=lambda: [globals().update(all_procs=list_processes()), _populate(p_search.get())]).pack(side='left')

        tk.Button(br, text='Cancel', font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=12, pady=4,
                  command=dlg.destroy).pack(side='right')

        # Center modal over parent
        dlg.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() // 2) - 270
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 225
        dlg.geometry(f"+{max(10, px)}+{max(10, py)}")

    # ============================================================
    # v4 FEATURES: STRING SCAN TAB
    # ============================================================
    def _build_string_scan_tab(self):
        """CE: frmStringMapUnit — regex memory string scanner."""
        body = tk.Frame(self.tab_stringscan, bg=self._c_bg)
        body.pack(fill='both', expand=True, padx=4, pady=4)

        # Controls card
        ctrl = tk.Frame(body, bg=self._c_panel,
                        highlightbackground=self._c_border, highlightthickness=1)
        ctrl.pack(fill='x', pady=(0, 4), padx=2)

        r1 = tk.Frame(ctrl, bg=self._c_panel)
        r1.pack(fill='x', padx=8, pady=6)
        tk.Label(r1, text='Pattern:', font=('Segoe UI', 8), bg=self._c_panel,
                 fg=self._c_muted).pack(side='left')
        self.ss_pat_var = tk.StringVar()
        tk.Entry(r1, textvariable=self.ss_pat_var, font=('Consolas', 9),
                 bg=self._c_border, fg=self._c_text, insertbackground='#ffffff',
                 relief='flat', width=30).pack(side='left', fill='x', expand=True, padx=(6, 0))

        r2 = tk.Frame(ctrl, bg=self._c_panel)
        r2.pack(fill='x', padx=8, pady=(0, 6))
        self.ss_case_var = tk.BooleanVar(value=False)
        tk.Checkbutton(r2, text='Case Sensitive', variable=self.ss_case_var,
                       font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_text,
                       selectcolor=self._c_accent, activebackground=self._c_panel).pack(side='left', padx=(0, 8))
        self.ss_unicode_var = tk.BooleanVar(value=True)
        tk.Checkbutton(r2, text='Unicode (UTF-16)', variable=self.ss_unicode_var,
                       font=('Segoe UI', 8), bg=self._c_panel, fg=self._c_text,
                       selectcolor=self._c_accent, activebackground=self._c_panel).pack(side='left', padx=(0, 8))
        tk.Label(r2, text='Min Length:', font=('Segoe UI', 8), bg=self._c_panel,
                 fg=self._c_muted).pack(side='left', padx=(8, 2))
        self.ss_minlen_var = tk.IntVar(value=4)
        tk.Entry(r2, textvariable=self.ss_minlen_var, font=('Consolas', 8),
                 bg=self._c_border, fg=self._c_text, insertbackground='#ffffff',
                 relief='flat', width=5).pack(side='left')

        r3 = tk.Frame(ctrl, bg=self._c_panel)
        r3.pack(fill='x', padx=8, pady=(0, 6))
        self.btn_ss_start = tk.Button(r3, text='▶ Start Scan', font=('Segoe UI', 8, 'bold'),
                                      bg='#238636', fg='#ffffff', activebackground='#2ea043',
                                      activeforeground='#ffffff', relief='flat', padx=12, pady=4,
                                      command=self._do_string_scan)
        self.btn_ss_start.pack(side='left', padx=(0, 4))
        self.btn_ss_stop = tk.Button(r3, text='■ Stop', font=('Segoe UI', 8),
                                     bg='#21262d', fg='#f85149', activebackground='#da3633',
                                     activeforeground='#ffffff', relief='flat', padx=10, pady=4,
                                     state='disabled', command=self._stop_string_scan)
        self.btn_ss_stop.pack(side='left', padx=4)
        tk.Button(r3, text='Clear', font=('Segoe UI', 8), bg=self._c_btn_bg,
                  fg=self._c_btn_fg, relief='flat', padx=10, pady=4,
                  command=self._clear_string_scan).pack(side='left', padx=4)
        self.ss_info_var = tk.StringVar(value='Ready — attach a process and start scan.')
        tk.Label(r3, textvariable=self.ss_info_var, font=('Consolas', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left', padx=(8, 0))

        # Results tree
        tree_fr = tk.Frame(body, bg=self._c_border,
                          highlightbackground=self._c_border, highlightthickness=1)
        tree_fr.pack(fill='both', expand=True, padx=2)

        cols = [('addr', 'Address'), ('str', 'String')]
        self.ss_tree = ttk.Treeview(tree_fr, columns=[c[0] for c in cols],
                                     show='headings', selectmode='extended')
        widths = {'addr': 160, 'str': 500}
        for col_id, col_lbl in cols:
            self.ss_tree.heading(col_id, text=col_lbl)
            self.ss_tree.column(col_id, width=widths.get(col_id, 130), anchor='w')
        self.ss_tree.pack(side='left', fill='both', expand=True)
        ss_sb = ttk.Scrollbar(tree_fr, orient='vertical', command=self.ss_tree.yview)
        ss_sb.pack(side='right', fill='y')
        self.ss_tree.configure(yscrollcommand=ss_sb.set)

        # Context menu
        def _ss_ctx(e):
            menu = tk.Menu(self.root, tearoff=0, bg=self._c_panel, fg=self._c_text,
                          activebackground=self._c_accent, activeforeground='#ffffff')
            menu.add_command(label='Add to Cheat Table', command=self._ss_add_to_table)
            menu.add_command(label='Copy Address', command=self._ss_copy_addr)
            menu.tk_popup(e.x_root, e.y_root)
        self.ss_tree.bind('<Button-3>', _ss_ctx)
        self.ss_tree.bind('<Double-1>', lambda _: self._ss_add_to_table())

    def _do_string_scan(self):
        if not self.h:
            messagebox.showwarning("No Process", "Attach to a process first.")
            return
        if self.ss_active:
            return
        self.ss_active = True
        self.ss_stop.clear()
        self.btn_ss_start.config(state='disabled')
        self.btn_ss_stop.config(state='normal')
        self.ss_tree.delete(*self.ss_tree.get_children())
        self.ss_info_var.set("Scanning memory for strings...")
        self._ss_result_count = 0

        def worker():
            try:
                engine = ms.StringScan(
                    self.h,
                    pattern=self.ss_pat_var.get(),
                    case_sensitive=self.ss_case_var.get(),
                    unicode_scan=self.ss_unicode_var.get(),
                    min_length=max(1, self.ss_minlen_var.get()),
                )
                self.ss_engine = engine
                engine.execute(
                    progress_cb=lambda addr, n: self.ss_prog_q.put(('ss_progress', addr, n))
                )
                self.ss_q.put(('ss_done', engine.get_results()))
            except Exception as e:
                self.ss_q.put(('ss_error', str(e)))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._pump_ss)

    def _pump_ss(self):
        """Pump string-scan queue from main thread."""
        # Progress updates
        try:
            while True:
                kind, *rest = self.ss_prog_q.get_nowait()
                if kind == 'ss_progress':
                    addr, n = rest
                    self.ss_info_var.set(f"Found {n} string(s) — last: 0x{addr:X}")
                    self._ss_result_count = n
                    # Batch-insert results every 200
                    if n % 200 == 0 and hasattr(self, '_ss_batch') and self._ss_batch:
                        for a, s in self._ss_batch:
                            safe = repr(s)[:80] if len(s) > 80 else s
                            self.ss_tree.insert('', 'end', values=(f"0x{a:X}", safe))
                        self._ss_batch = []
                elif kind == 'ss_done':
                    results = rest[0]
                    self._ss_finished = results
                    self.ss_q.put(('ss_done', results))
        except queue.Empty:
            pass

        # Check results queue
        try:
            while True:
                kind, *rest = self.ss_q.get_nowait()
                if kind == 'ss_done':
                    results = rest[0]
                    self.ss_active = False
                    self.btn_ss_start.config(state='normal')
                    self.btn_ss_stop.config(state='disabled')
                    # Show results (limit to 2000 to avoid UI freeze)
                    self.ss_tree.delete(*self.ss_tree.get_children())
                    for addr, s in results[:2000]:
                        safe = repr(s)[:80] if len(s) > 80 else s
                        self.ss_tree.insert('', 'end', values=(f"0x{addr:X}", safe))
                    total = len(results)
                    shown = min(total, 2000)
                    self.ss_info_var.set(f"Done — {total:,} string(s) found (showing {shown:,}).")
                    self._status(f"String scan complete: {total:,} string(s).")
                elif kind == 'ss_error':
                    err = rest[0]
                    self.ss_active = False
                    self.btn_ss_start.config(state='normal')
                    self.btn_ss_stop.config(state='disabled')
                    self.ss_info_var.set(f"Error: {err}")
                    self._status(f"String scan error: {err}")
        except queue.Empty:
            pass

        if self.ss_active:
            self.root.after(200, self._pump_ss)

    def _stop_string_scan(self):
        if self.ss_engine:
            self.ss_engine._cancelled = True
        self.ss_active = False
        self.btn_ss_start.config(state='normal')
        self.btn_ss_stop.config(state='disabled')
        self.ss_info_var.set("Scan stopped.")

    def _clear_string_scan(self):
        self.ss_tree.delete(*self.ss_tree.get_children())
        self.ss_info_var.set('Ready — attach a process and start scan.')

    def _ss_add_to_table(self):
        for item in self.ss_tree.selection():
            vals = self.ss_tree.item(item)['values']
            try:
                addr = int(vals[0], 16)
            except Exception:
                continue
            if not any(a['addr'] == addr for a in self.addresses):
                self.addresses.append({
                    'addr': addr, 'vtype': 'string', 'name': vals[1][:40],
                    'frozen': False, 'freeze_value': None,
                    'current': b'', 'previous': b'',
                })
        self._refresh_addr_tree()
        self._status(f"Added {len(self.ss_tree.selection())} string(s) to Cheat Table.")
        self.notebook.select(self.tab_table)

    def _ss_copy_addr(self):
        sel = self.ss_tree.selection()
        if sel:
            vals = self.ss_tree.item(sel[0])['values']
            self.root.clipboard_clear()
            self.root.clipboard_append(vals[0])

    def _focus_string_scan(self):
        self.notebook.select(self.tab_stringscan)

    # ============================================================
    # v4 FEATURES: STRUCT COMPARE TAB
    # ============================================================
    def _build_struct_compare_tab(self):
        """CE: frmstructurecompareunit — multi-level struct comparison scan."""
        body = tk.Frame(self.tab_struct, bg=self._c_bg)
        body.pack(fill='both', expand=True, padx=4, pady=4)

        # Controls card
        ctrl = tk.Frame(body, bg=self._c_panel,
                        highlightbackground=self._c_border, highlightthickness=1)
        ctrl.pack(fill='x', pady=(0, 4), padx=2)

        tk.Label(ctrl, text='STRUCT COMPARE SCAN', font=('Segoe UI', 9, 'bold'),
                 bg=self._c_panel, fg=self._c_accent).pack(anchor='w', padx=8, pady=(6, 2))

        r1 = tk.Frame(ctrl, bg=self._c_panel)
        r1.pack(fill='x', padx=8, pady=2)
        tk.Label(r1, text='Candidate Addresses:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left')
        self.sc_addr_var = tk.StringVar()
        tk.Entry(r1, textvariable=self.sc_addr_var, font=('Consolas', 9),
                 bg=self._c_border, fg=self._c_text, insertbackground='#ffffff',
                 relief='flat', width=40).pack(side='left', fill='x', expand=True, padx=(6, 0))
        tk.Label(r1, text='(hex, comma-separated)', font=('Segoe UI', 7),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left', padx=(4, 0))

        r2 = tk.Frame(ctrl, bg=self._c_panel)
        r2.pack(fill='x', padx=8, pady=2)
        tk.Label(r2, text='Struct Size (bytes):', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left')
        self.sc_size_var = tk.IntVar(value=16)
        tk.Entry(r2, textvariable=self.sc_size_var, font=('Consolas', 9),
                 bg=self._c_border, fg=self._c_text, insertbackground='#ffffff',
                 relief='flat', width=6).pack(side='left', padx=(4, 12))
        tk.Label(r2, text='Alignment:', font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left')
        self.sc_align_var = tk.StringVar(value='4 bytes')
        ttk.Combobox(r2, textvariable=self.sc_align_var, values=['1 byte', '2 bytes', '4 bytes', '8 bytes'],
                     state='readonly', width=10).pack(side='left', padx=(4, 0))

        r3 = tk.Frame(ctrl, bg=self._c_panel)
        r3.pack(fill='x', padx=8, pady=(0, 6))
        self.btn_sc_start = tk.Button(r3, text='▶ Start Scan', font=('Segoe UI', 8, 'bold'),
                                      bg='#238636', fg='#ffffff', activebackground='#2ea043',
                                      activeforeground='#ffffff', relief='flat', padx=12, pady=4,
                                      command=self._do_struct_compare)
        self.btn_sc_start.pack(side='left', padx=(0, 4))
        self.btn_sc_stop = tk.Button(r3, text='■ Stop', font=('Segoe UI', 8),
                                     bg='#21262d', fg='#f85149', activebackground='#da3633',
                                     activeforeground='#ffffff', relief='flat', padx=10, pady=4,
                                     state='disabled', command=self._stop_struct_compare)
        self.btn_sc_stop.pack(side='left', padx=4)
        tk.Button(r3, text='Use Selected from Found List', font=('Segoe UI', 8),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=8, pady=4,
                  command=self._sc_from_found).pack(side='left', padx=4)
        self.sc_info_var = tk.StringVar(value='Ready — add candidate addresses from scan results.')
        tk.Label(r3, textvariable=self.sc_info_var, font=('Consolas', 8),
                 bg=self._c_panel, fg=self._c_muted).pack(side='left', padx=(8, 0))

        # Results tree
        tree_fr = tk.Frame(body, bg=self._c_border,
                          highlightbackground=self._c_border, highlightthickness=1)
        tree_fr.pack(fill='both', expand=True, padx=2)

        cols = [('addr', 'Address'), ('size', 'Size'), ('note', 'Note')]
        self.sc_tree = ttk.Treeview(tree_fr, columns=[c[0] for c in cols],
                                    show='headings', selectmode='extended')
        widths = {'addr': 130, 'size': 80, 'note': 300}
        for col_id, col_lbl in cols:
            self.sc_tree.heading(col_id, text=col_lbl)
            self.sc_tree.column(col_id, width=widths.get(col_id, 130), anchor='w')
        self.sc_tree.pack(side='left', fill='both', expand=True)
        sc_sb = ttk.Scrollbar(tree_fr, orient='vertical', command=self.sc_tree.yview)
        sc_sb.pack(side='right', fill='y')
        self.sc_tree.configure(yscrollcommand=sc_sb.set)

        def _sc_ctx(e):
            menu = tk.Menu(self.root, tearoff=0, bg=self._c_panel, fg=self._c_text,
                          activebackground=self._c_accent, activeforeground='#ffffff')
            menu.add_command(label='Add to Cheat Table', command=self._sc_add_to_table)
            menu.add_command(label='Copy Address', command=self._sc_copy_addr)
            menu.tk_popup(e.x_root, e.y_root)
        self.sc_tree.bind('<Button-3>', _sc_ctx)
        self.sc_tree.bind('<Double-1>', lambda _: self._sc_add_to_table())

    def _do_struct_compare(self):
        if not self.h:
            messagebox.showwarning("No Process", "Attach to a process first.")
            return
        raw = self.sc_addr_var.get().strip()
        if not raw:
            messagebox.showwarning("No Addresses", "Enter candidate addresses (comma-separated hex).")
            return
        try:
            addrs = [int(a.strip(), 16) for a in raw.split(',') if a.strip()]
        except Exception:
            messagebox.showwarning("Invalid", "Addresses must be comma-separated hex values (e.g. 140000000,140001000).")
            return
        struct_size = max(1, self.sc_size_var.get())
        align_map = {'1 byte': 1, '2 bytes': 2, '4 bytes': 4, '8 bytes': 8}
        align = align_map.get(self.sc_align_var.get(), 4)

        self.sc_active = True
        self.sc_stop.clear()
        self.btn_sc_start.config(state='disabled')
        self.btn_sc_stop.config(state='normal')
        self.sc_tree.delete(*self.sc_tree.get_children())
        self.sc_info_var.set("Scanning memory for matching struct patterns...")

        def worker():
            try:
                engine = ms.StructCompareScanner(self.h, addrs, struct_size, alignment=align)
                engine.execute()
                self.sc_q.put(('sc_done', engine.get_results()))
            except Exception as e:
                self.sc_q.put(('sc_error', str(e)))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._pump_sc)

    def _pump_sc(self):
        try:
            while True:
                kind, *rest = self.sc_q.get_nowait()
                if kind == 'sc_done':
                    results = rest[0]
                    self.sc_active = False
                    self.btn_sc_start.config(state='normal')
                    self.btn_sc_stop.config(state='disabled')
                    for addr in results[:2000]:
                        sz = self.sc_size_var.get()
                        self.sc_tree.insert('', 'end', values=(f"0x{addr:X}", sz, 'Matching struct'))
                    self.sc_info_var.set(f"Done — {len(results):,} matching struct(s) found.")
                    self._status(f"Struct compare complete: {len(results):,} match(es).")
                elif kind == 'sc_error':
                    err = rest[0]
                    self.sc_active = False
                    self.btn_sc_start.config(state='normal')
                    self.btn_sc_stop.config(state='disabled')
                    self.sc_info_var.set(f"Error: {err}")
                    self._status(f"Struct compare error: {err}")
        except queue.Empty:
            pass
        if self.sc_active:
            self.root.after(200, self._pump_sc)

    def _stop_struct_compare(self):
        if self.sc_engine:
            self.sc_engine._cancelled = True
        self.sc_active = False
        self.btn_sc_start.config(state='normal')
        self.btn_sc_stop.config(state='disabled')
        self.sc_info_var.set("Scan stopped.")

    def _sc_from_found(self):
        sel = self.found_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Select addresses in the Found Results list first.")
            return
        addrs = []
        for item in sel:
            try:
                a = int(self.found_tree.item(item)['values'][0], 16)
                addrs.append(a)
            except Exception:
                pass
        if addrs:
            self.sc_addr_var.set(','.join(f"0x{a:X}" for a in addrs))
            self.sc_info_var.set(f"Loaded {len(addrs)} candidate address(es).")

    def _sc_add_to_table(self):
        for item in self.sc_tree.selection():
            vals = self.sc_tree.item(item)['values']
            try:
                addr = int(vals[0], 16)
            except Exception:
                continue
            if not any(a['addr'] == addr for a in self.addresses):
                self.addresses.append({
                    'addr': addr, 'vtype': 'uint8', 'name': f'struct_0x{addr:X}',
                    'frozen': False, 'freeze_value': None,
                    'current': b'', 'previous': b'',
                })
        self._refresh_addr_tree()
        self._status(f"Added {len(self.sc_tree.selection())} struct match(es) to Cheat Table.")
        self.notebook.select(self.tab_table)

    def _sc_copy_addr(self):
        sel = self.sc_tree.selection()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.sc_tree.item(sel[0])['values'][0])

    def _focus_struct_compare(self):
        self.notebook.select(self.tab_struct)

    # ============================================================
    # v4 FEATURES: MODULE+OFFSET ADDRESS RESOLVER
    # ============================================================
    def _open_address_parser(self):
        """Dialog to resolve module+offset addresses like 'game.exe+0x1234'."""
        dlg = tk.Toplevel(self.root, bg=self._c_bg)
        dlg.title("Resolve Module+Offset Address")
        dlg.geometry("420x180")
        dlg.transient(self.root)
        dlg.grab_set()

        fr = tk.Frame(dlg, bg=self._c_panel, padx=14, pady=12)
        fr.pack(fill='both', expand=True, padx=6, pady=6)

        tk.Label(fr, text="Address String:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).grid(row=0, column=0, sticky='e', pady=4)
        addr_e = tk.Entry(fr, font=('Consolas', 10), bg=self._c_border, fg=self._c_text,
                          insertbackground='#ffffff', relief='flat')
        addr_e.grid(row=0, column=1, sticky='w', padx=6, pady=4)
        addr_e.focus_set()

        # Hint
        tk.Label(fr, text="Examples:", font=('Segoe UI', 8),
                 bg=self._c_panel, fg=self._c_muted).grid(row=1, column=0, sticky='ne', pady=(2, 4))
        tk.Label(fr, text='game.exe+0x1234  |  game.exe-0x100  |  0x140000000',
                 font=('Consolas', 8), bg=self._c_panel, fg=self._c_muted).grid(
                     row=1, column=1, sticky='w', padx=6, pady=(2, 4))

        tk.Label(fr, text="Resolved Address:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).grid(row=2, column=0, sticky='e', pady=4)
        result_var = tk.StringVar(value="—")
        tk.Label(fr, textvariable=result_var, font=('Consolas', 10, 'bold'),
                 bg=self._c_panel, fg=self._c_accent).grid(row=2, column=1, sticky='w', padx=6, pady=4)

        def do_resolve():
            raw = addr_e.get().strip()
            if not raw:
                return
            addr, err = ms.parse_address_string(self.h, raw) if self.h else (0, "No process attached")
            if err:
                result_var.set(f"Error: {err}")
            else:
                result_var.set(f"0x{addr:X}")

        btn_box = tk.Frame(fr, bg=self._c_panel)
        btn_box.grid(row=3, column=0, columnspan=2, pady=(12, 0))
        tk.Button(btn_box, text="Resolve", font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=16, pady=3,
                  command=do_resolve).pack(side='left', padx=4)
        tk.Button(btn_box, text="Add to Table", font=('Segoe UI', 9),
                  bg='#238636', fg='#ffffff', relief='flat', padx=12, pady=3,
                  command=lambda: (
                      do_resolve(),
                      self._add_resolved_to_table(result_var.get())
                  ) if result_var.get() and not result_var.get().startswith('Error') else None
                  ).pack(side='left', padx=4)
        tk.Button(btn_box, text="Close", font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=12, pady=3,
                  command=dlg.destroy).pack(side='left', padx=4)

        dlg.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() // 2) - 210
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 90
        dlg.geometry(f"+{max(10, px)}+{max(10, py)}")

    def _add_resolved_to_table(self, resolved_str):
        if not resolved_str or resolved_str.startswith('Error') or resolved_str == '—':
            return
        try:
            addr = int(resolved_str, 16)
        except Exception:
            return
        if not any(a['addr'] == addr for a in self.addresses):
            self.addresses.append({
                'addr': addr, 'vtype': 'uint32', 'name': f'manual_0x{addr:X}',
                'frozen': False, 'freeze_value': None,
                'current': b'', 'previous': b'',
            })
            self._refresh_addr_tree()
            self._status(f"Added resolved address 0x{addr:X} to table.")

    def _attach(self, pid, name):
        if self.h:
            self._detach()
        ms.clear_region_tree()
        ms._page_cache.clear()

        if not self._enable_debug_privilege():
            reply = messagebox.askyesno(
                "Administrator Required",
                f"Cannot acquire SeDebugPrivilege to attach to PID {pid}.\n"
                "Relaunch MomoTrainer Studio as Administrator?"
            )
            if reply:
                self._run_as_admin()
                return

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x1000, False, pid)
        if not self.h:
            err = ctypes.get_last_error()
            msg = f"OpenProcess(PID: {pid}) failed with error {err}."
            if err == 5:
                msg += " Access Denied. Please run as Administrator."
            elif err == 87:
                msg += " The process may have exited."
            self._status(msg)
            messagebox.showerror("Attach Failed", msg)
            return

        self.pid = pid
        self.exe_name = name
        self.game_var.set(f"[{pid}] {name}")
        self.proc_dot.configure(fg='#3fb950')  # GitHub green dot
        self.proc_label.configure(fg='#e6edf3')
        self.btn_detach.pack(side='left', padx=6)
        self.meta_game.set(name)
        self.spec['game'] = name
        if self.spec.get('name') in ('My Trainer', '') or self.spec.get('name', '').endswith(' Trainer'):
            base = os.path.splitext(name)[0]
            self.spec['name'] = f"{base} Trainer"
            self.meta_name.set(self.spec['name'])
        self._refresh_feat_tree()
        self._status(f"Attached successfully to {name} (PID: {pid}).")

    def _detach(self):
        if self._freeze_engine:
            try:
                self._freeze_engine.stop()
            except Exception:
                pass
            self._freeze_engine = None
        if self.h:
            try:
                ctypes.windll.kernel32.CloseHandle(self.h)
            except Exception:
                pass
        self.h = self.pid = self.exe_name = None
        self.game_var.set("No process attached")
        self.proc_dot.configure(fg='#8b949e')  # Muted dot
        self.proc_label.configure(fg='#8b949e')
        self.btn_detach.pack_forget()
        self.freeze_stats_var.set("Freeze Engine: Idle")
        self._status("Detached from process.")

    def _check_admin(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if is_admin:
            self.admin_var.set("🔒 Administrator")
            self.admin_label.configure(fg='#3fb950')
            self.admin_btn.pack_forget()
        else:
            self.admin_var.set("⚠️ Standard User")
            self.admin_label.configure(fg='#d29922')
            self.admin_btn.pack(side='left', padx=4)

    # ============================================================
    # KERNEL DRIVER MANAGEMENT
    # ============================================================

    def _init_kernel_driver(self):
        """Initialize kernel driver integration"""
        try:
            # Import the hybrid memory layer
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'kernel_driver'))
            from hybrid_memory import HybridMemory

            # Check if driver is available (built .sys exists)
            driver_path = os.path.join(os.path.dirname(__file__), 'kernel_driver', 'MomoTrainerDrv.sys')
            if os.path.exists(driver_path):
                self.kernel_driver_available = True
                self._hybrid_memory = HybridMemory(use_driver=True)
                self._kernel_driver = self._hybrid_memory.driver

                # Update UI
                self.kernel_mode_cb.configure(state='normal')
                self.kernel_status_var.set("🟢 Driver: Available")
                self.kernel_status_label.configure(fg='#3fb950')
                self._status("Kernel driver loaded and ready")
            else:
                self.kernel_driver_available = False
                self.kernel_status_var.set("⚠️ Driver: Not Built")
                self.kernel_status_label.configure(fg='#d29922')
                self._status("Kernel driver .sys not found — build with kernel_driver/build.bat")

        except ImportError as e:
            self.kernel_driver_available = False
            self.kernel_status_var.set("🔴 Driver: Import Failed")
            self.kernel_status_label.configure(fg='#f85149')
            self._status(f"Kernel driver import failed: {e}")
        except Exception as e:
            self.kernel_driver_available = False
            self.kernel_status_var.set("🔴 Driver: Init Error")
            self.kernel_status_label.configure(fg='#f85149')
            self._status(f"Kernel driver init error: {e}")

    def _on_kernel_mode_toggle(self):
        """Handle kernel mode toggle"""
        if self.kernel_mode_var.get():
            # Enable kernel mode
            if not self.kernel_driver_available:
                self.kernel_mode_var.set(False)
                self._status("⚠️ Kernel driver not available — enabling user-mode fallback")
                return

            try:
                if self._hybrid_memory and not self._hybrid_memory._is_open:
                    self._hybrid_memory.open()
                self._status("Kernel mode enabled — driver fallback active")
                self.kernel_status_var.set("🟢 Kernel: Active")
                self.kernel_status_label.configure(fg='#3fb950')
            except Exception as e:
                self.kernel_mode_var.set(False)
                self.kernel_status_var.set("🔴 Kernel: Failed")
                self.kernel_status_label.configure(fg='#f85149')
                self._status(f"Kernel mode activation failed: {e}")
        else:
            # Disable kernel mode
            if self._hybrid_memory and self._hybrid_memory._is_open:
                self._hybrid_memory.close()
            self._status("User-mode memory access active")
            self.kernel_status_var.set("🔴 Driver: Standby")
            self.kernel_status_label.configure(fg='#d29922')

    def _check_kernel_driver(self):
        """Periodic check for kernel driver availability"""
        driver_path = os.path.join(os.path.dirname(__file__), 'kernel_driver', 'MomoTrainerDrv.sys')
        if os.path.exists(driver_path):
            self.kernel_driver_available = True
            if not self._hybrid_memory:
                self._init_kernel_driver()
        self.root.after(5000, self._check_kernel_driver)

    def _run_as_admin(self):
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Elevation Failed", str(e))

    def _enable_debug_privilege(self):
        try:
            adv = ctypes.WinDLL("advapi32", use_last_error=True)
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PI = 0x0400; TQ = 0x0008; AP = 0x0020; SPE = 2

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

            class LAA(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

            class TP(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_uint32), ("Privileges", LAA)]

            hp = k32.OpenProcess(PI, False, k32.GetCurrentProcessId())
            if not hp:
                return False
            token = ctypes.c_void_p()
            if not adv.OpenProcessToken(hp, AP | TQ, ctypes.byref(token)):
                k32.CloseHandle(hp)
                return False
            luid = LUID()
            if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                k32.CloseHandle(token)
                k32.CloseHandle(hp)
                return False
            tp = TP()
            tp.PrivilegeCount = 1
            tp.Privileges.Luid = luid
            tp.Privileges.Attributes = SPE
            ok = adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
            k32.CloseHandle(token)
            k32.CloseHandle(hp)
            return ok != 0
        except Exception:
            return False

    # ============================================================
    # SCANNER LOGIC
    # ============================================================
    def _toggle_advanced_options(self):
        """Show or hide the advanced scan options panel and adjust the main paned window sash to prevent clipping."""
        if getattr(self, 'adv_options_open', False):
            # Hide panel
            self.adv_frame.pack_forget()
            self.adv_btn.configure(text='▶  Advanced Scan Options (Alignment, Flags, AOB)')
            self.adv_options_open = False
            # Restore previous sash height to give room back to the cheat table
            try:
                prev = getattr(self, '_prev_sash_pos', 260)
                self.main_paned.sashpos(0, max(240, prev))
            except Exception:
                pass
        else:
            # Show panel
            self.adv_frame.pack(fill='x', pady=2)
            self.adv_btn.configure(text='▼  Advanced Scan Options (Alignment, Flags, AOB)')
            self.adv_options_open = True
            # Expand upper pane height dynamically to comfortably display controls without clipping
            try:
                cur_pos = self.main_paned.sashpos(0)
                self._prev_sash_pos = cur_pos
                if cur_pos < 365:
                    self.main_paned.sashpos(0, 365)
            except Exception:
                pass

    def _focus_aob_scan(self):
        if not getattr(self, 'adv_options_open', False):
            self._toggle_advanced_options()
        self.notebook.select(self.tab_table)

    def _on_mode_change(self):
        mode = self.mode_map.get(self.mode_var.get(), 'exact')
        if mode == 'between':
            self.lbl_between.pack(side='left', padx=4)
            self.high_entry.pack(side='left')
        else:
            self.lbl_between.pack_forget()
            self.high_entry.pack_forget()

    def _trigger_scan_enter(self):
        if self.btn_first['state'] != 'disabled':
            self._do_first_scan()
        elif self.btn_next['state'] != 'disabled':
            self._do_next_scan()

    def _parse_val(self, vtype, s):
        s = s.strip()
        if vtype == 'string':
            return s.encode('utf-8')
        if vtype in ('float', 'double'):
            return float(s)
        return int(s, 0)

    def _do_first_scan(self):
        if not self.h:
            messagebox.showwarning("No Process", "Please attach to a process first (Press F5).")
            return
        vtype = self.vtype_map[self.vtype_var.get()]
        mode = self.mode_map[self.mode_var.get()]
        if mode not in ('exact', 'between', 'greater', 'less', 'initial'):
            messagebox.showwarning("Scan Mode", "Use 'Exact value', 'Between', or 'Greater/Less' for the first scan.")
            return
        try:
            value = self._parse_val(vtype, self.val_var.get())
        except Exception as e:
            messagebox.showerror("Invalid Value", f"Could not parse '{self.val_var.get()}': {e}")
            return

        high = None
        if mode == 'between':
            try:
                high = self._parse_val(vtype, self.high_var.get())
            except Exception as e:
                messagebox.showerror("Invalid High Value", str(e))
                return

        self.candidates = []
        nthreads = min(4, max(1, os.cpu_count() or 1))

        self.btn_first.config(state='disabled')
        self.btn_next.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.scan_stop.clear()
        self._worker_scanned = {}
        self._scan_total = 0

        self.scan_info_var.set(f"Scanning memory with {nthreads} threads…")
        try:
            self.scan_prog.stop()
            self.scan_prog.config(mode='indeterminate')
            self.scan_prog.start(60)
        except Exception:
            pass

        def progress_cb(wid, scanned_bytes, hits):
            self.scan_prog_q.put(('worker_progress', wid, scanned_bytes, hits))

        def stop_cb():
            return self.scan_stop.is_set()

        def worker():
            import time
            t0 = time.perf_counter()
            try:
                cands = ms.first_scan(self.h, vtype, value, mode=mode, high=high,
                                       progress_cb=progress_cb, stop_cb=stop_cb,
                                       nthreads=nthreads)
                elapsed = time.perf_counter() - t0
                self.q.put(('first_done', cands, elapsed))
            except Exception as e:
                self.q.put(('scan_error', str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _do_next_scan(self):
        if not self.candidates:
            messagebox.showinfo("No Candidates", "Run a First Scan first.")
            return
        vtype = self.vtype_map[self.vtype_var.get()]
        mode = self.mode_map[self.mode_var.get()]
        try:
            value = self._parse_val(vtype, self.val_var.get())
        except Exception as e:
            messagebox.showerror("Invalid Value", str(e))
            return

        high = None
        if mode == 'between':
            try:
                high = self._parse_val(vtype, self.high_var.get())
            except Exception as e:
                messagebox.showerror("Invalid High Value", str(e))
                return

        nthreads = min(4, max(1, os.cpu_count() or 1))
        total_cands = len(self.candidates)
        self.btn_first.config(state='disabled')
        self.btn_next.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.scan_stop.clear()
        self._worker_scanned = {}
        self._scan_total = total_cands

        self.scan_info_var.set(f"Filtering {total_cands:,} candidates with {nthreads} threads…")
        try:
            self.scan_prog.stop()
            self.scan_prog.config(mode='indeterminate')
            self.scan_prog.start(60)
        except Exception:
            pass

        def progress_cb(wid, scanned, hits):
            self.scan_prog_q.put(('worker_progress', wid, scanned, hits, total_cands))

        def stop_cb():
            return self.scan_stop.is_set()

        def worker():
            import time
            t0 = time.perf_counter()
            try:
                cands = ms.rescan(self.h, self.candidates, vtype, value, mode=mode, high=high,
                                   progress_cb=progress_cb, stop_cb=stop_cb,
                                   nthreads=nthreads)
                elapsed = time.perf_counter() - t0
                self.q.put(('next_done', cands, elapsed))
            except Exception as e:
                self.q.put(('scan_error', str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _stop_scan(self):
        self.scan_stop.set()
        self._status("Cancelling memory scan…")

    def _reset_scan(self):
        self.candidates = []
        self.found_count_var.set("0 hits")
        self.scan_info_var.set("Ready to scan")
        self.scan_prog.stop()
        self.scan_prog.config(mode='determinate', value=0)
        self.btn_first.config(state='normal')
        self.btn_next.config(state='disabled')
        self.btn_stop.config(state='disabled')
        self.found_tree.delete(*self.found_tree.get_children())
        self._status("Scan reset.")

    def _clear_found_tree(self):
        self.found_tree.delete(*self.found_tree.get_children())
        self.found_count_var.set("0 hits")

    def _show_found_context_menu(self, event):
        iid = self.found_tree.identify_row(event.y)
        if iid:
            if iid not in self.found_tree.selection():
                self.found_tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0, bg=self._c_panel, fg=self._c_text,
                       activebackground=self._c_accent, activeforeground='#ffffff')
        menu.add_command(label='Add to Cheat Table', command=self._add_found_to_address_list)
        menu.add_separator()
        menu.add_command(label='🔍 Find out what accesses this address', command=lambda: self._open_debugger_for_found('access'))
        menu.add_command(label='✏️ Find out what writes to this address', command=lambda: self._open_debugger_for_found('write'))
        menu.tk_popup(event.x_root, event.y_root)

    def _do_sigscan(self):
        if not self.h:
            messagebox.showwarning("No Process", "Attach to a process first.")
            return
        sig_str = self.sig_var.get().strip()
        if not sig_str:
            messagebox.showwarning("Missing Signature", "Enter a signature like '48 8B 05 ?? ?? ?? ??'")
            return
        self.btn_sigscan.config(state='disabled')
        self.scan_stop.clear()
        self.scan_info_var.set(f"Signature scanning: {sig_str[:50]}...")
        nthreads = max(1, os.cpu_count() or 1)
        self.scan_prog.config(mode='indeterminate', value=0)
        self.scan_prog.start(10)
        self.root.update_idletasks()

        def worker():
            try:
                hits = ms.signature_scan(self.h, sig_str, nthreads=nthreads,
                                         stop_cb=lambda: self.scan_stop.is_set())
                self.q.put(('sigscan_done', hits, sig_str))
            except Exception as e:
                self.q.put(('scan_error', f"SigScan Error: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _update_worker_progress(self, wid, scanned, total=None):
        _now = time.time()
        if hasattr(self, '_last_progress_update') and _now - self._last_progress_update < 0.05:
            return
        self._last_progress_update = _now

        if wid == -1:
            self._scan_total = scanned
            try:
                self.scan_prog.config(mode='determinate', maximum=scanned or 1, value=0)
            except Exception:
                pass
            return

        self._worker_scanned[wid] = scanned
        tot = self._scan_total or total
        if tot and tot > 0:
            if total and total > 0:
                cur = max(self._worker_scanned.values())
                self.scan_prog.config(value=cur)
                self.scan_info_var.set(f"{cur:,} / {tot:,} candidates ({cur/tot*100:.0f}%)")
            else:
                cur = sum(self._worker_scanned.values())
                mb = cur / (1024 * 1024)
                tot_mb = tot / (1024 * 1024)
                pct = min(cur / tot * 100, 100)
                self.scan_prog.config(value=cur)
                self.scan_info_var.set(f"{mb:.1f} / {tot_mb:.1f} MB ({pct:.0f}%)")

    # ============================================================
    # QUEUE PUMP (Main Thread UI Updates)
    # ============================================================
    def _pump(self):
        _count = 0
        try:
            while _count < 25:
                kind, *rest = self.scan_prog_q.get_nowait()
                if kind == 'worker_progress':
                    if len(rest) == 4:
                        wid, scanned, hits, total = rest
                        self._update_worker_progress(wid, scanned, total)
                    else:
                        wid, scanned, hits = rest
                        self._update_worker_progress(wid, scanned)
                elif kind == 'ptrscan_progress':
                    if len(rest) >= 3:
                        _wid, _scanned, _hits = rest[0], rest[1], rest[2]
                        if not hasattr(self, '_ptr_worker_scanned'):
                            self._ptr_worker_scanned = {}
                            self._ptr_worker_hits = {}
                        self._ptr_worker_scanned[_wid] = _scanned
                        self._ptr_worker_hits[_wid] = _hits
                        tot_scanned = sum(self._ptr_worker_scanned.values())
                        tot_hits = sum(self._ptr_worker_hits.values())
                        mb = tot_scanned / (1024 * 1024)
                        self.scan_info_var.set(f"Pointer scan: {mb:.1f} MB ({tot_hits:,} ptrs)")
                _count += 1
        except queue.Empty:
            pass

        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == 'first_done':
                    cands, elapsed = rest[0], rest[1]
                    self.candidates = cands
                    self.scan_prog.stop()
                    self.scan_prog.config(mode='determinate', value=100)
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if cands else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.found_count_var.set(f"{len(cands):,} hits")
                    engine_badge = " ⚡C" if self._c_engine_active() else ""
                    self.scan_info_var.set(
                        f"✓ {len(cands):,} hits in {elapsed:.2f}s{engine_badge}")
                    self._populate_found_tree(cands)
                    self._status(f"First scan finished in {elapsed:.2f}s{engine_badge}. "
                                 f"Found {len(cands):,} results.")

                elif kind == 'next_done':
                    cands, elapsed = rest[0], rest[1]
                    self.candidates = cands
                    self.scan_prog.stop()
                    self.scan_prog.config(mode='determinate', value=100)
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if cands else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.found_count_var.set(f"{len(cands):,} hits")
                    engine_badge = " ⚡C" if self._c_engine_active() else ""
                    self.scan_info_var.set(
                        f"✓ {len(cands):,} hits in {elapsed:.2f}s{engine_badge}")
                    self._populate_found_tree(cands)
                    self._status(f"Next scan finished in {elapsed:.2f}s{engine_badge}. "
                                 f"Remaining: {len(cands):,} hits.")

                elif kind == 'scan_error':
                    err_msg = rest[0]
                    self.scan_prog.stop()
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if self.candidates else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.btn_sigscan.config(state='normal')
                    self.scan_info_var.set(f"Scan error: {err_msg}")
                    self._status(f"Scan Error: {err_msg}")

                elif kind == 'sigscan_done':
                    hits, sig_str = rest
                    self.btn_sigscan.config(state='normal')
                    self.scan_prog.stop()
                    self.scan_prog.config(mode='determinate', value=0)
                    self.scan_info_var.set(f"SigScan finished: {len(hits):,} match(es)")
                    pat, _ = ms.parse_signature(sig_str)
                    for addr in hits:
                        self.addresses.append({
                            'addr': addr, 'vtype': 'uint8', 'name': f'sig@0x{addr:X}',
                            'frozen': False, 'freeze_value': None,
                            'current': pat, 'previous': pat,
                        })
                    self._refresh_addr_tree()
                    self._status(f"SigScan found {len(hits)} match(es).")

                elif kind == 'ptrscan_done':
                    results, max_depth, target_addr = rest
                    self.scan_prog.stop()
                    self.scan_prog.config(mode='determinate', value=0)
                    self.scan_info_var.set(f"Pointer scan completed: {results.count():,} found")
                    self._show_ptrscan_results(results, max_depth, target_addr)

                elif kind == 'addresses_dirty':
                    self._refresh_addr_tree_live()

        except queue.Empty:
            pass

        self.root.after(100, self._pump)

    def _populate_found_tree(self, cands):
        self.found_tree.delete(*self.found_tree.get_children())
        vtype = self.vtype_map[self.vtype_var.get()]
        # Display first 2,000 in tree to avoid Tkinter UI slowdown on millions of hits
        display_limit = 2000
        for i, c in enumerate(cands[:display_limit]):
            val_str = ms.format_value(vtype, c.last) if c.last else '?'
            self.found_tree.insert('', 'end', values=(f"0x{c.addr:08X}", val_str, ''))

    # ============================================================
    # ADDRESS TABLE & LIVE VALUES (CE Address List)
    # ============================================================
    def _add_found_to_address_list(self):
        sel = self.found_tree.selection()
        if not sel:
            messagebox.showinfo("Select Address", "Select one or more found addresses first.")
            return
        vtype = self.vtype_map[self.vtype_var.get()]
        added = 0
        for item in sel:
            vals = self.found_tree.item(item)['values']
            try:
                addr = int(vals[0], 16)
            except Exception:
                continue
            if not any(a['addr'] == addr for a in self.addresses):
                self.addresses.append({
                    'addr': addr, 'vtype': vtype, 'name': f'Value_{addr:X}',
                    'frozen': False, 'freeze_value': None,
                    'current': b'', 'previous': b'',
                })
                added += 1
        self._refresh_addr_tree()
        self._status(f"Added {added} address(es) to Cheat Table.")
        self.notebook.select(self.tab_table)

    def _add_address_manually(self):
        dlg = tk.Toplevel(self.root, bg=self._c_bg)
        dlg.title("Add Address Manually")
        dlg.geometry("380x210")
        dlg.transient(self.root)
        dlg.grab_set()

        fr = tk.Frame(dlg, bg=self._c_panel, padx=14, pady=12)
        fr.pack(fill='both', expand=True, padx=6, pady=6)

        tk.Label(fr, text="Address (Hex or Base+Offset):", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).grid(row=0, column=0, sticky='e', pady=4)
        addr_e = tk.Entry(fr, font=('Consolas', 10), bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat')
        addr_e.grid(row=0, column=1, sticky='w', padx=6, pady=4)
        addr_e.focus_set()

        tk.Label(fr, text="Description:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).grid(row=1, column=0, sticky='e', pady=4)
        desc_e = tk.Entry(fr, font=('Segoe UI', 9), bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat')
        desc_e.grid(row=1, column=1, sticky='w', padx=6, pady=4)
        desc_e.insert(0, "No Description")

        tk.Label(fr, text="Type:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).grid(row=2, column=0, sticky='e', pady=4)
        type_var = tk.StringVar(value='4 Bytes (Int32)')
        ttk.Combobox(fr, textvariable=type_var, values=[lbl for lbl, _ in VTYPE_LABELS],
                     state='readonly', width=16).grid(row=2, column=1, sticky='w', padx=6, pady=4)

        def do_add():
            raw_addr = addr_e.get().strip()
            desc = desc_e.get().strip() or "Manual Address"
            vtype = self.vtype_map[type_var.get()]
            try:
                if self.h and any(op in raw_addr for op in ('+', '-', '*')):
                    addr, err = ms.parse_address_string(self.h, raw_addr)
                    if err:
                        messagebox.showerror("Error", err)
                        return
                else:
                    addr, err = ms.parse_address_string(self.h, raw_addr)
                    if err:
                        addr = int(raw_addr, 16)
                self.addresses.append({
                    'addr': addr, 'vtype': vtype, 'name': desc,
                    'frozen': False, 'freeze_value': None,
                    'current': b'', 'previous': b'',
                })
                self._refresh_addr_tree()
                dlg.destroy()
                self._status(f"Added address 0x{addr:X} to table.")
            except Exception as e:
                messagebox.showerror("Invalid Address", f"Error parsing address: {e}")

        btn_box = tk.Frame(fr, bg=self._c_panel)
        btn_box.grid(row=3, column=0, columnspan=2, pady=(12, 0))
        tk.Button(btn_box, text="Add", font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=16, pady=3,
                  command=do_add).pack(side='left', padx=4)
        tk.Button(btn_box, text="Cancel", font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=12, pady=3,
                  command=dlg.destroy).pack(side='left', padx=4)

        dlg.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() // 2) - 190
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 105
        dlg.geometry(f"+{max(10, px)}+{max(10, py)}")

    def _refresh_addr_tree(self):
        self.addr_tree.delete(*self.addr_tree.get_children())
        frozen_count = 0
        for a in self.addresses:
            tag = ('frozench' if (a['frozen'] and a['current'] != a['previous']) else
                   'frozen'   if a['frozen'] else
                   'changed'  if (a['current'] and a['previous'] and a['current'] != a['previous']) else '')
            if a['frozen']:
                frozen_count += 1
            cur_str = ms.format_value(a['vtype'], a['current']) if a['current'] else '?'
            self.addr_tree.insert(
                '', 'end', iid=str(id(a)), tags=(tag,) if tag else (),
                values=(
                    ' [X] ' if a['frozen'] else ' [   ] ',
                    a['name'] or '(No description)',
                    f"0x{a['addr']:08X}",
                    a['vtype'],
                    cur_str
                )
            )
        self.freeze_stats_var.set(f"Addresses: {len(self.addresses)} | Frozen: {frozen_count}")

    def _refresh_addr_tree_live(self):
        # Update existing rows in place without deleting/reinserting to keep selection
        frozen_count = 0
        for a in self.addresses:
            iid = str(id(a))
            if not self.addr_tree.exists(iid):
                continue
            if a['frozen']:
                frozen_count += 1
            tag = ('frozench' if (a['frozen'] and a['current'] != a['previous']) else
                   'frozen'   if a['frozen'] else
                   'changed'  if (a['current'] and a['previous'] and a['current'] != a['previous']) else '')
            cur_str = ms.format_value(a['vtype'], a['current']) if a['current'] else '?'
            self.addr_tree.item(
                iid, tags=(tag,) if tag else (),
                values=(
                    ' [X] ' if a['frozen'] else ' [   ] ',
                    a['name'] or '(No description)',
                    f"0x{a['addr']:08X}",
                    a['vtype'],
                    cur_str
                )
            )
        self.freeze_stats_var.set(f"Addresses: {len(self.addresses)} | Frozen: {frozen_count}")

    def _start_live_thread(self):
        self.live_stop.clear()

        def loop():
            while not self.live_stop.is_set():
                time.sleep(0.4)
                if not self.h or not self.addresses:
                    continue
                changed = False
                for a in self.addresses:
                    size = 64 if a['vtype'] == 'string' else ms.scan_size(a['vtype'])
                    cur = ms.rblock(self.h, a['addr'], size)
                    if cur is None:
                        continue
                    if cur != a['current']:
                        a['previous'] = a['current']
                        a['current'] = cur
                        changed = True
                if changed:
                    self.q.put(('addresses_dirty',))

        threading.Thread(target=loop, daemon=True).start()

    def _toggle_freeze(self):
        sel = self.addr_tree.selection()
        if not sel:
            return
        if self._freeze_engine is None and self.h:
            self._freeze_engine = ms.AtomicFreezeEngine(self.h)
            self._freeze_engine.start()

        for s in sel:
            a = next((x for x in self.addresses if str(id(x)) == s), None)
            if not a:
                continue
            a['frozen'] = not a['frozen']
            if a['frozen']:
                if a['vtype'] == 'string':
                    a['freeze_value'] = a['current']
                else:
                    try:
                        a['freeze_value'] = struct.unpack('<' + ms.VTYPES[a['vtype']][1], a['current'])[0]
                    except Exception:
                        a['freeze_value'] = 0
                if self._freeze_engine and a['freeze_value'] is not None:
                    fv = (a['freeze_value'].decode('utf-8', errors='replace')
                          if isinstance(a['freeze_value'], bytes) else a['freeze_value'])
                    self._freeze_engine.add(a['addr'], a['vtype'], fv)
            else:
                if self._freeze_engine:
                    self._freeze_engine.remove(a['addr'])
        self._refresh_addr_tree()

    def _freeze_all(self):
        if self._freeze_engine is None and self.h:
            self._freeze_engine = ms.AtomicFreezeEngine(self.h)
            self._freeze_engine.start()
        for a in self.addresses:
            a['frozen'] = True
            if self._freeze_engine and a.get('freeze_value') is not None:
                self._freeze_engine.add(a['addr'], a['vtype'], a['freeze_value'])
        self._refresh_addr_tree()

    def _unfreeze_all(self):
        for a in self.addresses:
            a['frozen'] = False
            if self._freeze_engine:
                self._freeze_engine.remove(a['addr'])
        self._refresh_addr_tree()

    def _edit_address_value(self):
        sel = self.addr_tree.selection()
        if not sel:
            return
        a = next((x for x in self.addresses if str(id(x)) == sel[0]), None)
        if not a:
            return

        win = tk.Toplevel(self.root, bg=self._c_bg)
        win.title(f"Change Value @ 0x{a['addr']:X}")
        win.geometry("380x210")
        win.transient(self.root)
        win.grab_set()

        fr = tk.Frame(win, bg=self._c_panel, padx=14, pady=12)
        fr.pack(fill='both', expand=True, padx=6, pady=6)

        tk.Label(fr, text=f"Address: 0x{a['addr']:08X}   ({a['vtype']})", font=('Consolas', 10, 'bold'),
                 bg=self._c_panel, fg=self._c_accent).pack(anchor='w', pady=(0, 8))

        tk.Label(fr, text="Enter New Value:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).pack(anchor='w')

        cur_formatted = ms.format_value(a['vtype'], a['current']) if a['current'] else ''
        new_val_var = tk.StringVar(value=cur_formatted)
        ent = tk.Entry(fr, textvariable=new_val_var, font=('Consolas', 10),
                       bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat')
        ent.pack(fill='x', pady=(4, 12))
        ent.focus_set()

        def write():
            if not self.h:
                messagebox.showerror("No Process", "Not attached to any process.")
                return
            try:
                if a['vtype'] == 'string':
                    nb = new_val_var.get().encode('utf-8')
                else:
                    nv = self._parse_val(a['vtype'], new_val_var.get())
                    nb = ms.pack_value(a['vtype'], nv)
                ok = ms.wblock(self.h, a['addr'], nb)
                if not ok:
                    err = ctypes.get_last_error()
                    messagebox.showerror("Write Failed", f"Could not write to 0x{a['addr']:X}\nError: {err}")
                    return
                a['current'] = nb
                if a['frozen'] and self._freeze_engine:
                    self._freeze_engine.add(a['addr'], a['vtype'], nv)
                self._refresh_addr_tree()
                win.destroy()
                self._status(f"Updated memory at 0x{a['addr']:X}")
            except Exception as e:
                messagebox.showerror("Bad Value", str(e))

        btn_box = tk.Frame(fr, bg=self._c_panel)
        btn_box.pack(fill='x')
        tk.Button(btn_box, text="Write Value", font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=14, pady=3,
                  command=write).pack(side='left', padx=(0, 4))
        tk.Button(btn_box, text="Cancel", font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=10, pady=3,
                  command=win.destroy).pack(side='left')

    def _edit_address_description(self):
        sel = self.addr_tree.selection()
        if not sel:
            return
        a = next((x for x in self.addresses if str(id(x)) == sel[0]), None)
        if not a:
            return

        win = tk.Toplevel(self.root, bg=self._c_bg)
        win.title("Change Description")
        win.geometry("360x160")
        win.transient(self.root)
        win.grab_set()

        fr = tk.Frame(win, bg=self._c_panel, padx=14, pady=12)
        fr.pack(fill='both', expand=True, padx=6, pady=6)

        tk.Label(fr, text="Enter Description:", font=('Segoe UI', 9),
                 bg=self._c_panel, fg=self._c_text).pack(anchor='w')

        desc_var = tk.StringVar(value=a.get('name', ''))
        ent = tk.Entry(fr, textvariable=desc_var, font=('Segoe UI', 10),
                       bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat')
        ent.pack(fill='x', pady=(4, 12))
        ent.focus_set()

        def save():
            a['name'] = desc_var.get().strip() or "Unnamed"
            self._refresh_addr_tree()
            win.destroy()

        btn_box = tk.Frame(fr, bg=self._c_panel)
        btn_box.pack(fill='x')
        tk.Button(btn_box, text="Save", font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=14, pady=3,
                  command=save).pack(side='left', padx=(0, 4))
        tk.Button(btn_box, text="Cancel", font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=10, pady=3,
                  command=win.destroy).pack(side='left')

    def _remove_selected_addr(self):
        sel = list(self.addr_tree.selection())
        if not sel:
            return
        for s in sel:
            a = next((x for x in self.addresses if str(id(x)) == s), None)
            if a and a['frozen'] and self._freeze_engine:
                self._freeze_engine.remove(a['addr'])
        self.addresses = [a for a in self.addresses if str(id(a)) not in sel]
        self._refresh_addr_tree()

    def _clear_addresses(self):
        if self._freeze_engine:
            for a in self.addresses:
                if a['frozen']:
                    self._freeze_engine.remove(a['addr'])
        self.addresses = []
        self._refresh_addr_tree()

    def _view_hex(self):
        sel = self.addr_tree.selection()
        if not sel:
            messagebox.showinfo("Hex View", "Select an address in the table first.")
            return
        a = next((x for x in self.addresses if str(id(x)) == sel[0]), None)
        if not a:
            return
        if not self.h:
            messagebox.showinfo("Hex View", "Attach to a process first.")
            return

        start_addr = max(0, a['addr'] - 64)
        data = ms.rblock(self.h, start_addr, 128)
        if not data:
            messagebox.showinfo("Hex View", f"Could not read memory at 0x{a['addr']:X}.")
            return

        win = tk.Toplevel(self.root, bg=self._c_bg)
        win.title(f"Hex Memory View @ 0x{a['addr']:016X}")
        win.geometry("700x350")
        win.transient(self.root)

        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off+16]
            hexs = ' '.join(f'{b:02X}' for b in chunk)
            ascs = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
            cur_line_addr = start_addr + off
            marker = " ► " if (cur_line_addr <= a['addr'] < cur_line_addr + 16) else "   "
            lines.append(f"{marker}0x{cur_line_addr:08X}   {hexs:<48}   {ascs}")

        txt = scrolledtext.ScrolledText(win, font=('Consolas', 10), bg='#0f0f12', fg='#e4e4e7', relief='flat')
        txt.pack(fill='both', expand=True, padx=6, pady=6)
        txt.insert('end', '\n'.join(lines))
        txt.configure(state='disabled')

    def _open_debugger_for_selected(self, mode='access'):
        """Open Cheat Engine-style 'Find out what accesses/writes to this address' window."""
        if not self.pid:
            messagebox.showwarning("No Process", "Please attach to a game process first.")
            return
        sel = self.addr_tree.selection()
        if not sel:
            messagebox.showinfo("Pick Address", "Select an address from the Cheat Table first.")
            return
        vals = self.addr_tree.item(sel[0])['values']
        try:
            addr = int(str(vals[2]), 16)
        except Exception:
            messagebox.showerror("Invalid Address", f"Could not parse address: {vals[2]}")
            return

        vtype = vals[3] if len(vals) > 3 else 'int32'
        size_map = {'int32': 4, 'uint32': 4, 'float': 4, 'double': 8, 'int64': 8, 'uint64': 8, 'int16': 2, 'uint16': 2, 'uint8': 1}
        size = size_map.get(vtype, 4)

        colors = {
            'bg': self._c_bg, 'panel': self._c_panel, 'border': self._c_border,
            'fg': self._c_text, 'muted': self._c_muted, 'accent': self._c_accent,
            'btn_bg': self._c_btn_bg, 'btn_fg': self._c_btn_fg
        }
        DebuggerOpcodesDialog(self.root, self.pid, addr, mode=mode, size=size, colors=colors)

    def _open_debugger_for_found(self, mode='access'):
        """Open debugger for the selected address in the Found Results table."""
        if not self.pid:
            messagebox.showwarning("No Process", "Please attach to a game process first.")
            return
        sel = self.found_tree.selection()
        if not sel:
            messagebox.showinfo("Pick Address", "Select an address from the Found Results table first.")
            return
        vals = self.found_tree.item(sel[0])['values']
        try:
            addr = int(str(vals[0]), 16)
        except Exception:
            messagebox.showerror("Invalid Address", f"Could not parse address: {vals[0]}")
            return

        vtype = self.vtype_map.get(self.vtype_var.get(), 'int32')
        size_map = {'int32': 4, 'uint32': 4, 'float': 4, 'double': 8, 'int64': 8, 'uint64': 8, 'int16': 2, 'uint16': 2, 'uint8': 1}
        size = size_map.get(vtype, 4)

        colors = {
            'bg': self._c_bg, 'panel': self._c_panel, 'border': self._c_border,
            'fg': self._c_text, 'muted': self._c_muted, 'accent': self._c_accent,
            'btn_bg': self._c_btn_bg, 'btn_fg': self._c_btn_fg
        }
        DebuggerOpcodesDialog(self.root, self.pid, addr, mode=mode, size=size, colors=colors)

    def _on_addr_tree_f5(self):
        if self.addr_tree.selection():
            self._open_debugger_for_selected('access')
        else:
            self._open_process_picker()

    def _do_ptrscan(self):
        if not self.h:
            messagebox.showwarning("No Process", "Attach to a process first.")
            return
        sel = self.addr_tree.selection()
        if not sel:
            messagebox.showinfo("Pick Address", "Select an address in the table first.")
            return
        target_addrs = []
        for item in sel:
            vals = self.addr_tree.item(item)['values']
            try:
                target_addrs.append(int(vals[2], 16))
            except Exception:
                pass
        if not target_addrs:
            messagebox.showwarning("No Address", "Could not parse selected address.")
            return

        dlg = PointerScanDialog(self.root)
        if not dlg.result:
            return

        max_depth = dlg.result['max_depth']
        max_offset = dlg.result['max_offset']
        no_loop = dlg.result['no_loop']
        use_heap = dlg.result['use_heap_data']

        self.scan_stop.clear()
        self.scan_prog.config(mode='indeterminate', value=0)
        self.scan_prog.start(10)
        self.scan_info_var.set(f"Pointer scan depth={max_depth} offset=0x{max_offset:X}…")
        self.root.update_idletasks()

        def progress_cb(wid, scanned, hits):
            self.scan_prog_q.put(('ptrscan_progress', wid, scanned, hits))

        def stop_cb():
            return self.scan_stop.is_set()

        def worker():
            try:
                ctrl = ms.PointerScanController(self.h, max_depth=max_depth,
                                                max_offset=max_offset, no_loop=no_loop,
                                                use_heap_data=use_heap)
                results = ctrl.scan(target_addrs=target_addrs, depth=0,
                                    progress_cb=progress_cb, stop_cb=stop_cb)
                self.q.put(('ptrscan_done', results, max_depth, target_addrs[0]))
            except Exception as e:
                self.q.put(('scan_error', f"Pointer Scan Error: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_narrow_results(self, results, target_addr):
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
                self.status_var.set("Error during narrow")

        import threading
        threading.Thread(target=narrow_thread, daemon=True).start()

    def _show_ptrscan_results(self, results, max_depth, target_addr=0):
        count = results.count()
        dlg = tk.Toplevel(self.root, bg=self._c_bg)
        dlg.title(f"Pointer Scan Results ({count:,} found)")
        dlg.geometry("720x460")
        dlg.transient(self.root)
        dlg.grab_set()

        body = ttk.Frame(dlg, padding=8)
        body.pack(fill='both', expand=True)

        ttk.Label(body, text=f"Found {count:,} pointer(s) pointing to 0x{target_addr:X} (depth ≤ {max_depth})",
                  font=('Segoe UI', 9, 'bold')).pack(anchor='w', pady=(0, 6))

        tree_fr = tk.Frame(body, bg=self._c_border)
        tree_fr.pack(fill='both', expand=True)

        tree = ttk.Treeview(tree_fr, columns=('addr', 'ptr'), show='headings', height=14)
        tree.heading('addr', text='Base Pointer Address', anchor='w')
        tree.heading('ptr',  text='Dereferenced Pointer',  anchor='w')
        tree.column('addr', width=240)
        tree.column('ptr',  width=240)
        tree.pack(side='left', fill='both', expand=True)

        sb = ttk.Scrollbar(tree_fr, orient='vertical', command=tree.yview)
        sb.pack(side='right', fill='y')
        tree.configure(yscrollcommand=sb.set)

        shown = 0
        for addr in results.addresses():
            if shown >= 4000:
                break
            try:
                raw = ms.rblock(self.h, addr, 8)
                val = struct.unpack('<Q', raw)[0] if raw else 0
            except Exception:
                val = 0
            tree.insert('', 'end', values=(f'0x{addr:X}', f'0x{val:X}'))
            shown += 1

        btns = ttk.Frame(dlg, padding=8)
        btns.pack(fill='x', side='bottom')

        def _add_ptr():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0])['values']
            addr = int(vals[0], 16)
            self.spec.setdefault('features', []).append({
                'name': f'ptr@0x{addr:X}', 'type': 'value',
                'pointer': {'base': f'+0x{addr:X}', 'offsets': [0x0]},
                'width': 4, 'value': 0, 'delta': 0,
                'description': f'Pointer to 0x{target_addr:X}',
                'default_on': False,
            })
            self._refresh_feat_tree()
            self._status(f"Added pointer 0x{addr:X} to trainer spec.")
            dlg.destroy()

        ttk.Button(btns, text="Add to Trainer Spec", command=_add_ptr).pack(side='left', padx=4)
        ttk.Button(btns, text="Close", command=dlg.destroy).pack(side='left', padx=4)

    # ============================================================
    # TRAINER SPEC & COMPILER
    # ============================================================
    def _add_selected_to_spec(self):
        sel = self.addr_tree.selection()
        if not sel:
            messagebox.showinfo("Select Addresses", "Select one or more rows in the Cheat Table first.")
            return
        added = 0
        for s in sel:
            a = next((x for x in self.addresses if str(id(x)) == s), None)
            if not a:
                continue
            cur_str = ms.format_value(a['vtype'], a['current']) if a['current'] else "0"
            try:
                if a['vtype'] == 'string':
                    val = cur_str
                elif a['vtype'] in ('float', 'double'):
                    val = float(cur_str)
                else:
                    val = int(cur_str, 0) if cur_str.lower().startswith('0x') else int(cur_str)
            except Exception:
                val = 0

            width = ms.scan_size(a['vtype']) if a['vtype'] != 'string' else 4
            is_flt = a['vtype'] in ('float', 'double')

            self.spec['features'].append({
                'name': a['name'] or f"Cheat_0x{a['addr']:X}",
                'type': 'value',
                'address': f"0x{a['addr']:X}",
                'value': val,
                'width': width,
                'is_float': is_flt,
                'description': f"Auto-added from Cheat Table ({a['vtype']})",
                'default_on': False,
            })
            added += 1

        self._sync_meta_to_spec()
        self._refresh_feat_tree()
        self._status(f"Added {added} address(es) to Trainer Spec.")
        self.notebook.select(self.tab_spec)

    def _sync_meta_to_spec(self):
        self.spec['name'] = self.meta_name.get() or 'My Trainer'
        self.spec['game'] = self.meta_game.get() or ''
        self.spec['hotkey_toggle'] = self.meta_toggle.get()
        self.spec['hotkey_panic'] = self.meta_panic.get()
        self.spec['window_title_color'] = self.meta_color.get() or '#38bdf8'
        ws = self.meta_wh.get().lower().split('x')
        if len(ws) == 2:
            try:
                self.spec['window_size'] = [int(ws[0]), int(ws[1])]
            except Exception:
                pass

    def _sync_meta_from_spec(self):
        self.meta_name.set(self.spec.get('name', 'My Trainer'))
        self.meta_game.set(self.spec.get('game', ''))
        self.meta_toggle.set(self.spec.get('hotkey_toggle', 'VK_F8'))
        self.meta_panic.set(self.spec.get('hotkey_panic', 'VK_END'))
        self.meta_color.set(self.spec.get('window_title_color', '#38bdf8'))
        ws = self.spec.get('window_size', [460, 380])
        self.meta_wh.set(f"{ws[0]}x{ws[1]}")

    def _refresh_feat_tree(self):
        for iid in self.feat_tree.get_children():
            self.feat_tree.delete(iid)
        for i, f in enumerate(self.spec.get('features', [])):
            addr = f.get('address', '')
            if 'pointer' in f:
                p = f['pointer']
                addr = f"{p.get('base', '?')}+[{','.join(hex(o) for o in p.get('offsets', []))}]"
            self.feat_tree.insert('', 'end', iid=str(i), values=(
                f.get('name', ''),
                f.get('type', 'value'),
                addr,
                str(f.get('value', '')),
                f.get('width', 4),
                'YES' if f.get('default_on') else 'NO',
                f.get('description', '')
            ))

    def _add_feature_row(self):
        self._sync_meta_to_spec()
        self.spec.setdefault('features', []).append({
            'name': 'New Cheat',
            'type': 'value',
            'address': '0x00000000',
            'value': 100,
            'width': 4,
            'is_float': False,
            'description': '',
            'default_on': False,
        })
        self._refresh_feat_tree()

    def _edit_feature_row(self):
        sel = self.feat_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        flist = self.spec.setdefault('features', [])
        f = flist[idx]

        win = tk.Toplevel(self.root, bg=self._c_bg)
        win.title(f"Edit Feature #{idx + 1}")
        win.geometry("420x340")
        win.transient(self.root)
        win.grab_set()

        fr = tk.Frame(win, bg=self._c_panel, padx=14, pady=12)
        fr.pack(fill='both', expand=True, padx=6, pady=6)

        fields = [
            ('name', 'Name:', f.get('name', '')),
            ('address', 'Address (Hex):', f.get('address', '0x0')),
            ('value', 'Value:', str(f.get('value', '0'))),
            ('width', 'Width (Bytes):', str(f.get('width', 4))),
            ('description', 'Description:', f.get('description', '')),
        ]
        ents = {}
        for r, (k, lbl, val) in enumerate(fields):
            tk.Label(fr, text=lbl, font=('Segoe UI', 9),
                     bg=self._c_panel, fg=self._c_text).grid(row=r, column=0, sticky='e', padx=6, pady=4)
            v = tk.StringVar(value=val)
            tk.Entry(fr, textvariable=v, font=('Consolas', 9),
                     bg=self._c_border, fg=self._c_text, insertbackground='#ffffff', relief='flat', width=26).grid(row=r, column=1, sticky='w', padx=6, pady=4)
            ents[k] = v

        def_on_var = tk.BooleanVar(value=bool(f.get('default_on', False)))
        tk.Checkbutton(fr, text='Default Active (ON)', variable=def_on_var,
                       font=('Segoe UI', 9), bg=self._c_panel, fg=self._c_text,
                       selectcolor=self._c_border, activebackground=self._c_panel).grid(row=len(fields), column=1, sticky='w', padx=6, pady=4)

        def save():
            for k in ents:
                val = ents[k].get()
                if k == 'width':
                    try: val = int(val)
                    except Exception: val = 4
                f[k] = val
            f['default_on'] = def_on_var.get()
            self._refresh_feat_tree()
            win.destroy()

        btn_box = tk.Frame(fr, bg=self._c_panel)
        btn_box.grid(row=len(fields)+1, column=0, columnspan=2, pady=10)
        tk.Button(btn_box, text="Save", font=('Segoe UI', 9, 'bold'),
                  bg=self._c_accent, fg='#ffffff', relief='flat', padx=14, pady=3,
                  command=save).pack(side='left', padx=4)
        tk.Button(btn_box, text="Cancel", font=('Segoe UI', 9),
                  bg=self._c_btn_bg, fg=self._c_btn_fg, relief='flat', padx=10, pady=3,
                  command=win.destroy).pack(side='left', padx=4)

    def _remove_feature_row(self):
        sel = self.feat_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        self.spec.setdefault('features', []).pop(idx)
        self._refresh_feat_tree()

    def _move_feature(self, delta):
        sel = self.feat_tree.selection()
        if not sel:
            return
        i = int(sel[0])
        j = i + delta
        flist = self.spec.setdefault('features', [])
        if 0 <= j < len(flist):
            flist[i], flist[j] = flist[j], flist[i]
            self._refresh_feat_tree()
            self.feat_tree.selection_set(str(j))

    def _new_spec(self):
        self.spec_path = None
        self.spec = {
            'name': 'My Trainer', 'game': self.exe_name or '',
            'brand': 'MomoTrainer — by Momo aka Steav Beoung Salang',
            'hotkey_toggle': 'VK_F8', 'hotkey_panic': 'VK_END',
            'window_size': [460, 380], 'window_title_color': '#38bdf8',
            'features': [], 'actions': [],
        }
        self._sync_meta_from_spec()
        self._refresh_feat_tree()
        self.spec_label_var.set("(unsaved)")
        self._status("Created new Trainer Table.")

    def _open_spec(self):
        path = filedialog.askopenfilename(initialdir=os.path.abspath('trainers'),
                                          filetypes=[("Trainer Table (YAML)", "*.yaml *.yml")])
        if not path:
            return
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                self.spec = yaml.safe_load(f) or {}
            self.spec_path = path
            self._sync_meta_from_spec()
            self._refresh_feat_tree()
            self.spec_label_var.set(os.path.basename(path))
            self._status(f"Loaded table: {path}")
        except Exception as e:
            messagebox.showerror("YAML Load Error", str(e))

    def _save_spec(self):
        self._sync_meta_to_spec()
        if not self.spec_path:
            path = filedialog.asksaveasfilename(initialdir=os.path.abspath('trainers'),
                                                defaultextension=".yaml",
                                                filetypes=[("Trainer Table (YAML)", "*.yaml *.yml")])
            if not path:
                return
            self.spec_path = path
        import yaml
        with open(self.spec_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(self.spec, f, sort_keys=False, allow_unicode=True)
        self.spec_label_var.set(os.path.basename(self.spec_path))
        self._status(f"Saved table to {self.spec_path}")

    def _save_spec_as(self):
        path = filedialog.asksaveasfilename(initialdir=os.path.abspath('trainers'),
                                            defaultextension=".yaml",
                                            filetypes=[("Trainer Table (YAML)", "*.yaml *.yml")])
        if path:
            self.spec_path = path
            self._save_spec()

    def _show_yaml(self):
        self._sync_meta_to_spec()
        import yaml
        text = yaml.safe_dump(self.spec, sort_keys=False, allow_unicode=True)
        win = tk.Toplevel(self.root, bg=self._c_bg)
        win.title("Trainer Spec YAML Preview")
        win.geometry("640x500")
        st = scrolledtext.ScrolledText(win, font=('Consolas', 10), bg='#0f0f12', fg='#e4e4e7', relief='flat')
        st.pack(fill='both', expand=True, padx=6, pady=6)
        st.insert('1.0', text)
        st.configure(state='disabled')

    def _build(self, with_exe):
        self._sync_meta_to_spec()
        if not self.spec.get('game'):
            messagebox.showerror("Missing Target Game", "Please set the Target Game executable name first.")
            self.notebook.select(self.tab_spec)
            return

        self.notebook.select(self.tab_build)
        os.makedirs('trainers', exist_ok=True)
        name = self.spec.get('name') or 'trainer'
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip() or 'trainer'
        out_cpp = os.path.abspath(f"trainers/{safe_name}_gen.cpp")
        out_exe = os.path.abspath(f"trainers/{safe_name}.exe")

        self._log_build(f"\n==================================================")
        self._log_build(f"MomoTrainer Build Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._log_build(f"Target Executable: {self.spec['game']}")
        self._log_build(f"Features: {len(self.spec.get('features', []))} cheat(s)")

        try:
            base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            template_path = os.path.join(base_dir, 'templates', 'trainer_template.cpp')
            if not os.path.isfile(template_path):
                template_path = os.path.abspath('templates/trainer_template.cpp')
            tc.compile_template(self.spec, template_path, out_cpp)
            self._log_build(f"Generated C++ Source: {out_cpp}")
        except Exception as e:
            self._log_build(f"ERROR: Template generation failed: {e}")
            self.build_status.set(f"FAIL: {e}")
            return

        if with_exe:
            gpp = 'g++'
            if not __import__('shutil').which(gpp):
                self._log_build("ERROR: MinGW g++ compiler not found in PATH.")
                self._log_build("Please install MinGW-w64 or add g++ to your system PATH.")
                self.build_status.set("FAIL: g++ compiler not found in PATH")
                return

            self._log_build(f"Compiling with g++ -> {out_exe}...")
            self.root.update_idletasks()

            ok = tc.build_exe(out_cpp, out_exe, gpp)
            if ok:
                self.build_status.set(f"SUCCESS: Built {os.path.basename(out_exe)} ✓")
                self._log_build(f"Build Complete! Executable ready at:\n{out_exe}\n")
                self._status(f"Built trainer: {out_exe}")
            else:
                self.build_status.set("BUILD FAILED (See compiler output above)")
                self._log_build("Compilation failed.\n")
        else:
            self.build_status.set(f"Generated C++: {os.path.basename(out_cpp)}")
            self._log_build("C++ code generated successfully.\n")

    def _log_build(self, msg):
        self.build_log.insert('end', msg + '\n')
        self.build_log.see('end')

    def _open_out_dir(self):
        path = os.path.abspath('trainers')
        os.makedirs(path, exist_ok=True)
        subprocess.Popen(['explorer', path])

    def _show_about(self):
        messagebox.showinfo(
            "About MomoTrainer Studio",
            "MomoTrainer Studio v2.0\n"
            "by Momo aka Steav Beoung Salang\n\n"
            "High-performance memory scanner, Cheat Table manager,\n"
            "and C++ Standalone Trainer compiler.\n"
            "Built with Cheat Engine architecture & Hick's Law principles."
        )

    # ============================================================
    # THEME & CLEANUP
    # ============================================================
    def _apply_current_theme(self):
        name = self.theme_var.get()
        if name not in th.THEMES:
            name = "modern_dark"
        self._current_theme_name = name
        self._current_theme = th.THEMES[name]
        th.apply_theme(
            self.style,
            self._current_theme,
            root=self.root,
            address_tree=self.addr_tree,
            build_log=self.build_log,
            status_label=None,
            scan_prog=self.scan_prog
        )

    def _status(self, msg):
        self.status_var.set(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _on_quit(self):
        self.live_stop.set()
        if self._freeze_engine:
            try:
                self._freeze_engine.stop()
            except Exception:
                pass
        if self.h:
            try:
                ctypes.windll.kernel32.CloseHandle(self.h)
            except Exception:
                pass
        # Clean up kernel driver if open
        if self._hybrid_memory and self._hybrid_memory._is_open:
            try:
                self._hybrid_memory.close()
            except Exception:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = StudioGUI(root)
    root.protocol("WM_DELETE_WINDOW", app._on_quit)
    root.mainloop()


if __name__ == "__main__":
    main()