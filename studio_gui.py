"""
studio_gui.py - MomoTrainer Studio (Cheat Engine-style UI)
made by Momo aka Steav Beoung Salang

The full CE-style studio:
  - Process picker with auto-refresh
  - Value scanner panel (10 value types, 9 scan modes)
  - Address table with LIVE values, color on change, edit-in-place
  - Hex viewer for any address
  - "Add to trainer" button to bake findings into the spec
  - Structured feature editor (no raw YAML required)
  - Build tab: compile to standalone .exe
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
from tkinter import ttk, filedialog, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memory_scanner as ms
import trainer_compiler as tc
import themes as th


VTYPE_LABELS = [
    ('Byte (1 byte)',    'uint8'),
    ('Short (2 bytes)',  'int16'),
    ('UShort (2 bytes)', 'uint16'),
    ('Int (4 bytes)',    'int32'),
    ('UInt (4 bytes)',   'uint32'),
    ('Int64 (8 bytes)',  'int64'),
    ('UInt64 (8 bytes)', 'uint64'),
    ('Float (4 bytes)',  'float'),
    ('Double (8 bytes)', 'double'),
    ('String (ASCII)',   'string'),
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

SKIP_PROCS = {'svchost.exe','System','smss.exe','csrss.exe','wininit.exe',
              'services.exe','lsass.exe','explorer.exe','dwm.exe',
              'fontdrvhost.exe','WmiPrvSE.exe','taskhostw.exe',
              'RuntimeBroker.exe','ShellExperienceHost.exe',
              'StartMenuExperienceHost.exe','SearchHost.exe','LockApp.exe',
              'TextInputHost.exe','sihost.exe','ctfmon.exe','audiodg.exe',
              'spoolsv.exe','Wcmsvc.exe','dasHost.exe','SearchUI.exe',
              'SecurityHealthService.exe','SecurityHealthSystray.exe',
              'MoUsoCoreWorker.exe','AggregatorHost.exe','LogonUI.exe',
              'dllhost.exe','ChsIME.exe'}


def list_processes():
    out = []
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPPROCESS = 0x02
    class PE(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_char*260)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE(); pe.dwSize = ctypes.sizeof(pe)
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            out.append((pe.th32ProcessID, pe.szExeFile.decode('latin-1', errors='replace')))
            if not k32.Process32Next(snap, ctypes.byref(pe)): break
    k32.CloseHandle(snap)
    return out


class StudioGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MomoTrainer Studio — by Momo aka Steav Beoung Salang")
        self.root.geometry("1280x780")
        self.root.minsize(1100, 680)

        self.h = self.pid = self.exe_name = None
        self.candidates = []
        self.addresses = []        # list of dicts: addr, vtype, name, frozen, freeze_value, current, previous
        self.scan_stop = threading.Event()
        self.scan_prog_q = queue.Queue()
        self.q = queue.Queue()
        self.live_stop = threading.Event()

        self.spec_path = None
        self.spec = {
            'name': 'My Trainer', 'game': '',
            'brand': 'MomoTrainer — by Momo aka Steav Beoung Salang',
            'hotkey_toggle': 'VK_F8', 'hotkey_panic': 'VK_END',
            'window_size': [460, 380], 'window_title_color': '#FF66CC',
            'features': [], 'actions': [],
        }
        # theme state — default warm (kawaii)
        self._current_theme_name = "warm"
        self._current_theme = th.THEMES["warm"]

        self._build_ui()
        self._refresh_process_list()
        self._start_live_thread()
        self.root.after(100, self._pump)
        self.root.after(3000, self._refresh_process_list_periodic)

    # ============================================================
    # UI
    # ============================================================
    def _build_ui(self):
        self.style = ttk.Style()
        try: self.style.theme_use('clam')
        except Exception: pass
        self.style.configure('Treeview', rowheight=22)

        # Top bar
        top = ttk.Frame(self.root); top.pack(fill='x', padx=6, pady=(6, 2))
        ttk.Label(top, text="MomoTrainer Studio", font=('Segoe UI', 12, 'bold')).pack(side='left', padx=4)
        self.game_var = tk.StringVar(value="(no game selected)")
        ttk.Label(top, textvariable=self.game_var, font=('Consolas', 10)).pack(side='left', padx=8)

        # Theme picker (kawaii dropdown)
        theme_frame = ttk.Frame(top)
        theme_frame.pack(side='right', padx=8)
        ttk.Label(theme_frame, text="Theme:", font=('Segoe UI', 9)).pack(side='left', padx=4)
        self.theme_var = tk.StringVar(value="warm")
        theme_cb = ttk.Combobox(theme_frame, textvariable=self.theme_var,
                                  values=list(th.THEMES.keys()),
                                  state='readonly', width=10)
        theme_cb.pack(side='left', padx=2)
        theme_cb.bind('<<ComboboxSelected>>', lambda _: self._apply_current_theme())

        main = ttk.PanedWindow(self.root, orient='horizontal')
        main.pack(fill='both', expand=True, padx=6, pady=2)

        # LEFT: process picker
        left = ttk.Frame(main); main.add(left, weight=1)
        ttk.Label(left, text="Processes", font=('Segoe UI', 9, 'bold')).pack(anchor='w', padx=4, pady=(4, 0))
        pf = ttk.Frame(left); pf.pack(fill='both', expand=True, padx=4, pady=2)
        self.proc_tree = ttk.Treeview(pf, columns=('pid','name'), show='headings', height=20)
        self.proc_tree.heading('pid',  text='PID');    self.proc_tree.column('pid',  width=70, anchor='e')
        self.proc_tree.heading('name', text='Name');   self.proc_tree.column('name', width=180)
        self.proc_tree.pack(side='left', fill='both', expand=True)
        psb = ttk.Scrollbar(pf, orient='vertical', command=self.proc_tree.yview)
        psb.pack(side='right', fill='y')
        self.proc_tree.configure(yscrollcommand=psb.set)
        self.proc_tree.bind('<Double-1>', lambda _: self._attach_selected())
        bf = ttk.Frame(left); bf.pack(fill='x', padx=4, pady=2)
        ttk.Button(bf, text="Refresh", command=self._refresh_process_list, width=10).pack(side='left', padx=2)
        ttk.Button(bf, text="Attach",  command=self._attach_selected,      width=10).pack(side='left', padx=2)
        ttk.Button(bf, text="Detach",  command=self._detach,                width=10).pack(side='left', padx=2)

        # RIGHT: tabs
        right = ttk.Frame(main); main.add(right, weight=5)
        nb = ttk.Notebook(right); nb.pack(fill='both', expand=True)
        self.tab_scan  = ttk.Frame(nb)
        self.tab_spec  = ttk.Frame(nb)
        self.tab_build = ttk.Frame(nb)
        nb.add(self.tab_scan,  text=' Scanner ')
        nb.add(self.tab_spec,  text=' Trainer Spec ')
        nb.add(self.tab_build, text=' Build ')
        self._build_scan_tab(self.tab_scan)
        self._build_spec_tab(self.tab_spec)
        self._build_build_tab(self.tab_build)

        # BOTTOM: status
        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = ttk.Label(self.root, textvariable=self.status_var,
                                       style='Status.TLabel', padding=4, anchor='w')
        self.status_label.pack(fill='x', padx=6, pady=(0, 6))

        # Apply default theme now that all widgets exist
        self._apply_current_theme()

    def _apply_current_theme(self):
        """Restyle the whole UI to the selected theme."""
        name = self.theme_var.get() if hasattr(self, 'theme_var') else self._current_theme_name
        if name not in th.THEMES:
            name = "warm"
        self._current_theme_name = name
        self._current_theme = th.THEMES[name]
        th.apply_theme(self.style,
                        self._current_theme,
                        root=self.root,
                        address_tree=getattr(self, 'addr_tree', None),
                        hex_widget=getattr(self, 'hex_text', None),
                        build_log=getattr(self, 'build_log', None),
                        status_label=getattr(self, 'status_label', None),
                        scan_prog=getattr(self, 'scan_prog', None),
                        info_widgets=[getattr(self, 'scan_info_var', None)] if hasattr(self, 'scan_info_var') else [])

    def _build_scan_tab(self, parent):
        sp = ttk.LabelFrame(parent, text="Value scanner")
        sp.pack(fill='x', padx=6, pady=6)
        ttk.Label(sp, text="Type:").grid(row=0, column=0, padx=4, pady=4, sticky='e')
        self.vtype_var = tk.StringVar(value='Int (4 bytes)')
        self.vtype_map = dict(VTYPE_LABELS)
        self.vtype_cb = ttk.Combobox(sp, textvariable=self.vtype_var,
                                      values=[l for l, _ in VTYPE_LABELS],
                                      state='readonly', width=20)
        self.vtype_cb.grid(row=0, column=1, padx=4, pady=4, sticky='w')
        ttk.Label(sp, text="Scan:").grid(row=1, column=0, padx=4, pady=4, sticky='e')
        self.mode_var = tk.StringVar(value='Exact value')
        self.mode_map = dict(MODE_LABELS)
        self.mode_cb = ttk.Combobox(sp, textvariable=self.mode_var,
                                     values=[l for l, _ in MODE_LABELS],
                                     state='readonly', width=20)
        self.mode_cb.grid(row=1, column=1, padx=4, pady=4, sticky='w')
        self.mode_cb.bind('<<ComboboxSelected>>', lambda _: self._on_mode_change())
        ttk.Label(sp, text="Value:").grid(row=2, column=0, padx=4, pady=4, sticky='e')
        self.val_var = tk.StringVar(value='100')
        self.val_entry = ttk.Entry(sp, textvariable=self.val_var, width=24)
        self.val_entry.grid(row=2, column=1, padx=4, pady=4, sticky='w')
        ttk.Label(sp, text="High:").grid(row=3, column=0, padx=4, pady=4, sticky='e')
        self.high_var = tk.StringVar(value='')
        self.high_entry = ttk.Entry(sp, textvariable=self.high_var, width=24, state='disabled')
        self.high_entry.grid(row=3, column=1, padx=4, pady=4, sticky='w')
        btnrow = ttk.Frame(sp); btnrow.grid(row=4, column=0, columnspan=4, padx=4, pady=8, sticky='w')
        self.btn_first = ttk.Button(btnrow, text="First scan", command=self._do_first_scan, width=14)
        self.btn_next  = ttk.Button(btnrow, text="Next scan",  command=self._do_next_scan,  width=14, state='disabled')
        self.btn_stop  = ttk.Button(btnrow, text="Stop",       command=self._stop_scan,     width=10, state='disabled')
        self.btn_reset = ttk.Button(btnrow, text="Reset",      command=self._reset_scan,    width=10)
        for i, b in enumerate([self.btn_first, self.btn_next, self.btn_stop, self.btn_reset]):
            b.grid(row=0, column=i, padx=2)
        self.scan_prog = ttk.Progressbar(sp, mode='determinate', length=400)
        self.scan_prog.grid(row=5, column=0, columnspan=4, padx=4, pady=4, sticky='we')
        self.scan_info_var = tk.StringVar(value="Ready.")
        self.scan_info_var_label = ttk.Label(sp, textvariable=self.scan_info_var,
                                            font=('Consolas', 9),
                                            foreground='#006')
        self.scan_info_var_label.grid(row=6, column=0, columnspan=4, padx=4, sticky='w')

        # Signature (AoB) scan row - lets you find a byte pattern across memory
        sigrow = ttk.Frame(sp)
        sigrow.grid(row=7, column=0, columnspan=4, padx=4, pady=4, sticky='we')
        ttk.Label(sigrow, text="Signature:").pack(side='left', padx=(0, 4))
        self.sig_var = tk.StringVar(value="48 8B 05 ?? ?? ?? ?? 48 85 C0 74")
        sig_entry = ttk.Entry(sigrow, textvariable=self.sig_var, font=('Consolas', 10), width=50)
        sig_entry.pack(side='left', fill='x', expand=True, padx=4)
        self.btn_sigscan = ttk.Button(sigrow, text="Find", command=self._do_sigscan, width=10)
        self.btn_sigscan.pack(side='left', padx=2)
        ttk.Label(sigrow, text="(?? = wildcard, e.g. 48 8B 05 ?? ?? ?? ??)",
                  font=('Consolas', 8), foreground='#666').pack(side='left', padx=4)

        # Per-worker thread progress (CE-style: see each scanner thread's progress)
        self.worker_frame = ttk.LabelFrame(parent, text="Worker threads (per-CPU scanner progress)")
        self.worker_frame.pack(fill='x', padx=6, pady=4)
        # Container for per-worker rows; rebuilt each scan based on nthreads
        self.worker_rows_frame = ttk.Frame(self.worker_frame)
        self.worker_rows_frame.pack(fill='x', padx=4, pady=4)
        self._worker_progs = {}        # wid -> Progressbar
        self._worker_labels = {}       # wid -> StringVar for "MB scanned / hits"
        self._worker_total_bytes = {}  # wid -> last reported total bytes (for ETA)

        # Address table
        at = ttk.LabelFrame(parent, text="Address list  (green=changed, yellow=frozen, orange=frozen+changed)")
        at.pack(fill='both', expand=True, padx=6, pady=6)
        at_cols = ('addr','name','value','prev','type','frozen')
        self.addr_tree = ttk.Treeview(at, columns=at_cols, show='headings', height=10)
        for c, w in [('addr',130), ('name',140), ('value',120), ('prev',120), ('type',80), ('frozen',70)]:
            self.addr_tree.heading(c, text=c.title())
            self.addr_tree.column(c, width=w, anchor='w' if c != 'frozen' else 'center')
        # Tag colors are configured by the active theme (see _apply_current_theme)
        # These placeholders will be overwritten when the theme is applied.
        self.addr_tree.tag_configure('changed',  background='#888888')
        self.addr_tree.tag_configure('frozen',   background='#888888')
        self.addr_tree.tag_configure('frozench', background='#888888')
        self.addr_tree.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        asb = ttk.Scrollbar(at, orient='vertical', command=self.addr_tree.yview)
        asb.pack(side='right', fill='y')
        self.addr_tree.configure(yscrollcommand=asb.set)
        self.addr_tree.bind('<Double-1>', lambda _: self._edit_address_value())
        ab = ttk.Frame(at); ab.pack(side='right', fill='y', padx=2, pady=4)
        ttk.Button(ab, text="Add to trainer", command=self._add_selected_to_spec, width=14).pack(pady=2)
        ttk.Button(ab, text="View hex",       command=self._view_hex,            width=14).pack(pady=2)
        ttk.Button(ab, text="Toggle freeze",  command=self._toggle_freeze,       width=14).pack(pady=2)
        ttk.Button(ab, text="Edit value",     command=self._edit_address_value,  width=14).pack(pady=2)
        ttk.Button(ab, text="Remove",         command=self._remove_selected_addr, width=14).pack(pady=2)
        ttk.Button(ab, text="Clear all",      command=self._clear_addresses,     width=14).pack(pady=2)

        hv = ttk.LabelFrame(parent, text="Hex viewer (selected address, +/- 64 bytes)")
        hv.pack(fill='x', padx=6, pady=6)
        self.hex_text = scrolledtext.ScrolledText(hv, height=6, font=('Consolas', 10), wrap='word')
        self.hex_text.pack(fill='both', expand=True, padx=4, pady=4)

    def _build_spec_tab(self, parent):
        top = ttk.Frame(parent); top.pack(fill='x', padx=6, pady=6)
        ttk.Button(top, text="New",          command=self._new_spec).pack(side='left', padx=2)
        ttk.Button(top, text="Open YAML...", command=self._open_spec).pack(side='left', padx=2)
        ttk.Button(top, text="Save YAML...", command=self._save_spec).pack(side='left', padx=2)
        ttk.Button(top, text="Reload",       command=self._reload_spec).pack(side='left', padx=2)
        self.spec_label_var = tk.StringVar(value="(unsaved)")
        ttk.Label(top, textvariable=self.spec_label_var, font=('Consolas', 9)).pack(side='right', padx=4)

        body = ttk.Frame(parent); body.pack(fill='both', expand=True, padx=6, pady=4)
        meta = ttk.LabelFrame(body, text="Trainer meta")
        meta.pack(fill='x', padx=4, pady=4)
        ttk.Label(meta, text="Name:").grid(row=0, column=0, padx=4, pady=4, sticky='e')
        self.meta_name = tk.StringVar(value=self.spec['name'])
        ttk.Entry(meta, textvariable=self.meta_name, width=30).grid(row=0, column=1, padx=4, pady=4, sticky='w')
        ttk.Label(meta, text="Game exe:").grid(row=0, column=2, padx=4, pady=4, sticky='e')
        self.meta_game = tk.StringVar(value=self.spec['game'])
        ttk.Entry(meta, textvariable=self.meta_game, width=24).grid(row=0, column=3, padx=4, pady=4, sticky='w')
        ttk.Label(meta, text="Toggle key:").grid(row=1, column=0, padx=4, pady=4, sticky='e')
        self.meta_toggle = tk.StringVar(value=self.spec['hotkey_toggle'])
        ttk.Combobox(meta, textvariable=self.meta_toggle,
                     values=['VK_F1','VK_F2','VK_F4','VK_F5','VK_F6','VK_F7','VK_F8','VK_F9','VK_F10','VK_F11','VK_F12','VK_INSERT','VK_HOME','VK_END'],
                     state='readonly', width=10).grid(row=1, column=1, padx=4, pady=4, sticky='w')
        ttk.Label(meta, text="Panic key:").grid(row=1, column=2, padx=4, pady=4, sticky='e')
        self.meta_panic = tk.StringVar(value=self.spec['hotkey_panic'])
        ttk.Combobox(meta, textvariable=self.meta_panic,
                     values=['VK_END','VK_HOME','VK_DELETE','VK_F12','VK_INSERT'],
                     state='readonly', width=10).grid(row=1, column=3, padx=4, pady=4, sticky='w')
        ttk.Label(meta, text="Title color:").grid(row=2, column=0, padx=4, pady=4, sticky='e')
        self.meta_color = tk.StringVar(value=self.spec['window_title_color'])
        ttk.Entry(meta, textvariable=self.meta_color, width=10).grid(row=2, column=1, padx=4, pady=4, sticky='w')
        ttk.Label(meta, text="Window:").grid(row=2, column=2, padx=4, pady=4, sticky='e')
        self.meta_wh = tk.StringVar(value=f"{self.spec['window_size'][0]}x{self.spec['window_size'][1]}")
        ttk.Entry(meta, textvariable=self.meta_wh, width=10).grid(row=2, column=3, padx=4, pady=4, sticky='w')

        feat = ttk.LabelFrame(body, text="Features (one row per trainer toggle)")
        feat.pack(fill='both', expand=True, padx=4, pady=4)
        cols = ('name','type','address','value','width','frozen','desc')
        self.feat_tree = ttk.Treeview(feat, columns=cols, show='headings', height=10)
        for c, w in [('name',120),('type',80),('address',220),('value',80),('width',50),('frozen',60),('desc',160)]:
            self.feat_tree.heading(c, text=c.title())
            self.feat_tree.column(c, width=w, anchor='w')
        self.feat_tree.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        fsb = ttk.Scrollbar(feat, orient='vertical', command=self.feat_tree.yview)
        fsb.pack(side='right', fill='y')
        self.feat_tree.configure(yscrollcommand=fsb.set)
        self.feat_tree.bind('<Double-1>', lambda _: self._edit_feature_row())
        fb = ttk.Frame(feat); fb.pack(side='right', fill='y', padx=2, pady=4)
        ttk.Button(fb, text="Add",    command=self._add_feature_row,   width=12).pack(pady=2)
        ttk.Button(fb, text="Edit",   command=self._edit_feature_row,  width=12).pack(pady=2)
        ttk.Button(fb, text="Remove", command=self._remove_feature_row, width=12).pack(pady=2)
        ttk.Button(fb, text="Up",     command=lambda: self._move_feature(-1), width=12).pack(pady=2)
        ttk.Button(fb, text="Down",   command=lambda: self._move_feature(+1), width=12).pack(pady=2)
        self._refresh_feat_tree()

        bot = ttk.Frame(parent); bot.pack(fill='x', padx=6, pady=8)
        ttk.Button(bot, text="Generate .cpp", command=lambda: self._build(False)).pack(side='left', padx=2)
        ttk.Button(bot, text="Build .exe",    command=lambda: self._build(True)).pack(side='left', padx=2)
        ttk.Button(bot, text="Show YAML",     command=self._show_yaml).pack(side='left', padx=2)

    def _build_build_tab(self, parent):
        top = ttk.LabelFrame(parent, text="Build status")
        top.pack(fill='x', padx=6, pady=6)
        self.build_status = tk.StringVar(value="No build yet.")
        ttk.Label(top, textvariable=self.build_status, font=('Consolas', 10)).pack(fill='x', padx=4, pady=4)
        body = ttk.LabelFrame(parent, text="Build log")
        body.pack(fill='both', expand=True, padx=6, pady=4)
        self.build_log = scrolledtext.ScrolledText(body, font=('Consolas', 9), wrap='word')
        self.build_log.pack(fill='both', expand=True, padx=4, pady=4)
        bot = ttk.Frame(parent); bot.pack(fill='x', padx=6, pady=8)
        ttk.Button(bot, text="Open output folder", command=self._open_out_dir).pack(side='right', padx=2)
        ttk.Button(bot, text="Clear log", command=lambda: self.build_log.delete('1.0','end')).pack(side='right', padx=2)

    # ============================================================
    # PROCESS MGMT
    # ============================================================
    def _refresh_process_list_periodic(self):
        self._refresh_process_list()
        self.root.after(3000, self._refresh_process_list_periodic)

    def _refresh_process_list(self):
        try:
            procs = list_processes()
            shown = sorted([(p, n) for p, n in procs if n not in SKIP_PROCS], key=lambda x: x[1].lower())
            sel_pid = None
            if self.pid:
                sel_pid = self.pid
            self.proc_tree.delete(*self.proc_tree.get_children())
            for pid, name in shown:
                iid = self.proc_tree.insert('', 'end', values=(pid, name))
                if pid == sel_pid:
                    self.proc_tree.selection_set(iid)
        except Exception as e:
            self._status(f"Refresh failed: {e}")

    def _attach_selected(self):
        sel = self.proc_tree.selection()
        if not sel:
            messagebox.showinfo("Pick a process", "Select a process from the list first."); return
        pid = int(self.proc_tree.item(sel[0])['values'][0])
        name = self.proc_tree.item(sel[0])['values'][1]
        self._attach(pid, name)

    def _attach(self, pid, name):
        if self.h:
            self._detach()
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.h = k32.OpenProcess(0x10 | 0x20 | 0x08 | 0x0400, False, pid)
        if not self.h:
            self._status(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
            return
        self.pid = pid
        self.exe_name = name
        self.game_var.set(f"Game: {name}   PID: {pid}")
        self.meta_game.set(name)
        self.spec['game'] = name
        if self.spec['name'] in ('My Trainer',) or self.spec['name'].endswith(' Trainer'):
            self.spec['name'] = f"{os.path.splitext(name)[0]} Trainer"
            self.meta_name.set(self.spec['name'])
        self._refresh_feat_tree()
        self._status(f"Attached to {name} (PID {pid})")

    def _detach(self):
        if self.h:
            try: ctypes.windll.kernel32.CloseHandle(self.h)
            except Exception: pass
        self.h = self.pid = self.exe_name = None
        self.game_var.set("(no game selected)")
        self._status("Detached.")

    # ============================================================
    # SCANNER
    # ============================================================
    def _on_mode_change(self):
        mode = self.mode_map[self.mode_var.get()]
        self.high_entry.config(state='normal' if mode == 'between' else 'disabled')

    def _parse_val(self, vtype, s):
        s = s.strip()
        if vtype == 'string': return s.encode('utf-8')
        if vtype in ('float','double'): return float(s)
        return int(s, 0)

    def _build_worker_rows(self, nthreads):
        """Create one mini-progressbar + label per worker thread."""
        # Clear old rows
        for w in self.worker_rows_frame.winfo_children():
            w.destroy()
        self._worker_progs = {}
        self._worker_labels = {}
        self._worker_total_bytes = {}
        self._worker_start_time = {}
        self._worker_hits = {}          # wid -> last reported hit count
        for wid in range(nthreads):
            row = ttk.Frame(self.worker_rows_frame)
            row.pack(fill='x', padx=2, pady=1)
            ttk.Label(row, text=f"W{wid}", font=('Consolas', 9), width=3).pack(side='left')
            pb = ttk.Progressbar(row, mode='determinate', length=300)
            pb.pack(side='left', fill='x', expand=True, padx=4)
            var = tk.StringVar(value="(idle)")
            ttk.Label(row, textvariable=var, font=('Consolas', 9), width=24, anchor='w').pack(side='left', padx=4)
            self._worker_progs[wid] = pb
            self._worker_labels[wid] = var
            self._worker_total_bytes[wid] = 0
            self._worker_start_time[wid] = None
            self._worker_hits[wid] = 0
        # Note: total page bytes is unknown here; we use a "no total" progress
        # mode and just show scanned bytes per worker.

    def _update_worker_progress(self, wid, scanned, hits):
        """Called by scanner worker threads via queue. Update mini progressbar + aggregate."""
        if wid not in self._worker_progs:
            return
        pb = self._worker_progs[wid]
        var = self._worker_labels[wid]
        mb = scanned / (1024 * 1024)
        # Cap visual bar at 100 MB so it doesn't max out immediately on huge processes
        pb.config(mode='determinate', maximum=100, value=min(mb, 100))
        if self._worker_start_time[wid] is None:
            self._worker_start_time[wid] = time.time()
        elapsed = max(time.time() - self._worker_start_time[wid], 1e-6)
        rate_mbps = mb / elapsed
        self._worker_hits[wid] = hits
        var.set(f"{mb:6.1f} MB  {hits:,} hits  {rate_mbps:5.1f} MB/s")
        # Aggregate: sum of MB across workers and hits
        total_mb = sum(self._worker_progs[w]['value'] for w in self._worker_progs)
        total_hits = sum(self._worker_hits.values())
        n = max(1, len(self._worker_progs))
        self.scan_prog.config(maximum=100 * n, value=total_mb)
        self.scan_info_var.set(
            f"Workers: {n}  Aggregate: {total_mb:.1f} MB scanned  "
            f"{total_hits:,} hits  ({total_mb/n:.1f} MB avg/worker)"
        )

    def _do_first_scan(self):
        if not self.h:
            messagebox.showwarning("No process", "Attach to a process first."); return
        vtype = self.vtype_map[self.vtype_var.get()]
        mode  = self.mode_map[self.mode_var.get()]
        if mode not in ('exact','between','greater','less','initial'):
            messagebox.showwarning("Mode", "Use 'Exact value' or 'Between' or 'Greater/Less' for first scan."); return
        try: value = self._parse_val(vtype, self.val_var.get())
        except Exception as e: messagebox.showerror("Bad value", str(e)); return
        high = None
        if mode == 'between':
            try: high = self._parse_val(vtype, self.high_var.get())
            except Exception as e: messagebox.showerror("Bad high", str(e)); return
        self.candidates = []
        nthreads = max(1, os.cpu_count() or 1)
        self._build_worker_rows(nthreads)
        self.btn_first.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_next.config(state='disabled')
        self.scan_stop.clear()
        self.scan_info_var.set(f"First scan with {nthreads} worker thread(s)...")
        self.scan_prog.config(value=0, maximum=100)
        # New scanner signature: progress_cb(wid, scanned_bytes, hits)
        def progress_cb(wid, scanned_bytes, hits):
            self.scan_prog_q.put(('worker_progress', wid, scanned_bytes, hits))
        def stop_cb(): return self.scan_stop.is_set()
        def worker():
            try:
                cands = ms.first_scan(self.h, vtype, value, mode=mode, high=high,
                                       progress_cb=progress_cb, stop_cb=stop_cb,
                                       nthreads=nthreads)
                self.q.put(('first_done', cands))
            except Exception as e:
                self.q.put(('scan_error', str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _do_next_scan(self):
        if not self.candidates:
            messagebox.showinfo("No candidates", "Do a first scan first."); return
        vtype = self.vtype_map[self.vtype_var.get()]
        mode  = self.mode_map[self.mode_var.get()]
        try: value = self._parse_val(vtype, self.val_var.get())
        except Exception as e: messagebox.showerror("Bad value", str(e)); return
        high = None
        if mode == 'between':
            try: high = self._parse_val(vtype, self.high_var.get())
            except Exception as e: messagebox.showerror("Bad high", str(e)); return
        nthreads = max(1, os.cpu_count() or 1)
        self._build_worker_rows(nthreads)
        self.btn_first.config(state='disabled')
        self.btn_next.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.scan_stop.clear()
        self.scan_info_var.set(f"Re-scanning with {nthreads} worker thread(s)...")
        self.scan_prog.config(value=0, maximum=100)
        def progress_cb(wid, scanned, hits):
            self.scan_prog_q.put(('worker_progress', wid, scanned, hits))
        def stop_cb(): return self.scan_stop.is_set()
        def worker():
            try:
                cands = ms.rescan(self.h, self.candidates, vtype, value, mode=mode, high=high,
                                   progress_cb=progress_cb, stop_cb=stop_cb,
                                   nthreads=nthreads)
                self.q.put(('next_done', cands))
            except Exception as e:
                self.q.put(('scan_error', str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _stop_scan(self):
        self.scan_stop.set()
        self._status("Scan cancellation requested.")

    def _reset_scan(self):
        self.candidates = []
        self.scan_info_var.set("Ready.")
        self.scan_prog.config(value=0)
        self.btn_first.config(state='normal')
        self.btn_next.config(state='disabled')
        self._status("Scan reset.")

    def _do_sigscan(self):
        """Signature (AoB) scan: find a byte pattern in memory."""
        if not self.h:
            messagebox.showwarning("No process", "Attach to a process first.")
            return
        sig_str = self.sig_var.get().strip()
        if not sig_str:
            messagebox.showwarning("No signature", "Enter a signature like '48 8B 05 ?? ?? ?? ??'")
            return
        # Disable button + show status
        self.btn_sigscan.config(state='disabled')
        self.scan_stop.clear()
        self.scan_info_var.set(f"Signature scan: {sig_str[:60]}{'...' if len(sig_str)>60 else ''}")
        nthreads = max(1, os.cpu_count() or 1)
        self._build_worker_rows(nthreads)
        # Indeterminate progress bar (no animation; even one .start() callback
        # every 20ms was enough to starve worker threads on wildcard-heavy patterns).
        for w in range(nthreads):
            self._worker_progs[w].config(mode='indeterminate', value=0)
            self._worker_labels[w].set("scanning...")
        self.scan_prog.config(mode='indeterminate', value=0)
        # Force the "scanning..." text to be drawn before we block
        self.root.update_idletasks()
        self.root.update()
        # Run the scan on the main thread. The inner loop releases the GIL
        # for every ReadProcessMemory call, so the window won't repaint but
        # the scan completes in 1-3 seconds. We tried worker threads but
        # the GIL contention between the scanner's tight Python bytecode
        # loop and Tk's mainloop was deadlocking wildcard scans.
        try:
            hits = ms.signature_scan(self.h, sig_str, nthreads=nthreads)
            pat, _ = ms.parse_signature(sig_str)
            # Stop animation, switch to determinate
            try:
                for w in range(len(self._worker_progs)):
                    self._worker_progs[w].stop()
                    self._worker_progs[w].config(mode='determinate', value=0)
                self.scan_prog.stop()
                self.scan_prog.config(mode='determinate', value=self.scan_prog['maximum'])
            except Exception:
                pass
            # Add each hit to the address table
            for addr in hits:
                self.addresses.append({
                    'addr': addr,
                    'vtype': 'uint8',
                    'name': f'sig@0x{addr:X}',
                    'frozen': False,
                    'freeze_value': None,
                    'current': pat,
                    'previous': pat,
                })
            self._refresh_addr_tree()
            self.scan_info_var.set(f"Signature scan done: {len(hits):,} match(es)")
            self._status(
                f"Found {len(hits)} signature match(es); first at 0x{hits[0]:X}"
                if hits else "No signature matches found."
            )
        except Exception as e:
            self._status(f"Sigscan error: {e}")
        finally:
            self.btn_sigscan.config(state='normal')

    # ============================================================
    # ADDRESS TABLE & LIVE UPDATES
    # ============================================================
    def _add_candidates_to_table(self, cands):
        vtype = self.vtype_map[self.vtype_var.get()]
        for c in cands:
            self.addresses.append({
                'addr': c.addr, 'vtype': vtype, 'name': '',
                'frozen': False, 'freeze_value': None,
                'current': c.last, 'previous': c.last,
            })
        self._refresh_addr_tree()

    def _refresh_addr_tree(self):
        for iid in self.addr_tree.get_children():
            self.addr_tree.delete(iid)
        for a in self.addresses:
            tag = ('frozench' if (a['frozen'] and a['current'] != a['previous']) else
                   'frozen'   if a['frozen'] else
                   'changed'  if a['current'] != a['previous'] else '')
            self.addr_tree.insert('', 'end', iid=str(id(a)),
                    tags=(tag,) if tag else (),
                    values=(f"0x{a['addr']:016X}", a['name'] or '(unnamed)',
                            ms.format_value(a['vtype'], a['current']),
                            ms.format_value(a['vtype'], a['previous']),
                            a['vtype'], 'YES' if a['frozen'] else ''))

    def _start_live_thread(self):
        self.live_stop.clear()
        def loop():
            while not self.live_stop.is_set():
                time.sleep(0.5)
                if not self.h or not self.addresses:
                    continue
                changed = False
                for a in self.addresses:
                    if a['vtype'] == 'string':
                        size = 64
                    else:
                        size = ms.scan_size(a['vtype'])
                    cur = ms.rblock(self.h, a['addr'], size)
                    if cur is None:
                        continue
                    if cur != a['current']:
                        a['previous'] = a['current']
                        a['current'] = cur
                        changed = True
                    if a['frozen'] and a['freeze_value'] is not None:
                        if a['vtype'] == 'string':
                            want = a['freeze_value']
                        else:
                            want = struct.pack('<' + ms.VTYPES[a['vtype']][1], a['freeze_value'])
                        if cur != want:
                            ms.k32.WriteProcessMemory(self.h, a['addr'],
                                (ctypes.c_uint8*len(want))(*want), len(want), None)
                if changed:
                    self.q.put(('addresses_dirty',))
        threading.Thread(target=loop, daemon=True).start()

    def _edit_address_value(self):
        sel = self.addr_tree.selection()
        if not sel: return
        a = next((x for x in self.addresses if str(id(x)) == sel[0]), None)
        if not a: return
        win = tk.Toplevel(self.root)
        win.title(f"Edit @ 0x{a['addr']:X}"); win.geometry("360x200")
        ttk.Label(win, text=f"Address: 0x{a['addr']:016X}\nType: {a['vtype']}\nCurrent: {ms.format_value(a['vtype'], a['current'])}",
                  font=('Consolas', 10)).pack(padx=10, pady=10)
        new_var = tk.StringVar(value=ms.format_value(a['vtype'], a['current']))
        ttk.Entry(win, textvariable=new_var, width=30).pack(padx=10, pady=4)
        def write():
            try:
                if a['vtype'] == 'string':
                    nb = new_var.get().encode('utf-8'); size = len(nb)
                else:
                    nv = self._parse_val(a['vtype'], new_var.get())
                    nb = ms.pack_value(a['vtype'], nv); size = len(nb)
                ok = ms.k32.WriteProcessMemory(self.h, a['addr'],
                          (ctypes.c_uint8*size)(*nb), size, None)
                if not ok:
                    messagebox.showerror("Write failed", f"err={ctypes.get_last_error()}"); return
                a['current'] = nb
                self._refresh_addr_tree()
                win.destroy()
            except Exception as e:
                messagebox.showerror("Bad value", str(e))
        ttk.Button(win, text="Write to memory", command=write).pack(pady=10)

    def _toggle_freeze(self):
        sel = self.addr_tree.selection()
        for s in sel:
            a = next((x for x in self.addresses if str(id(x)) == s), None)
            if not a: continue
            a['frozen'] = not a['frozen']
            if a['frozen']:
                if a['vtype'] == 'string':
                    a['freeze_value'] = a['current']
                else:
                    a['freeze_value'] = struct.unpack('<' + ms.VTYPES[a['vtype']][1], a['current'])[0]
        self._refresh_addr_tree()

    def _remove_selected_addr(self):
        sel = list(self.addr_tree.selection())
        for s in sel:
            try: self.addr_tree.delete(s)
            except Exception: pass
        self.addresses = [a for a in self.addresses if str(id(a)) not in sel]
        self._refresh_addr_tree()

    def _clear_addresses(self):
        self.addresses = []
        self._refresh_addr_tree()

    def _view_hex(self):
        sel = self.addr_tree.selection()
        if not sel:
            return
        a = next((x for x in self.addresses if str(id(x)) == sel[0]), None)
        if not a: return
        data = ms.rblock(self.h, a['addr'] - 64, 128)
        self.hex_text.delete('1.0', 'end')
        if not data:
            self.hex_text.insert('end', "(could not read)\n"); return
        for off in range(0, len(data), 16):
            chunk = data[off:off+16]
            hexs = ' '.join(f'{b:02x}' for b in chunk)
            ascs = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
            self.hex_text.insert('end', f"0x{a['addr']-64+off:08X}  {hexs:<48}  {ascs}\n")

    # ============================================================
    # SPEC
    # ============================================================
    def _add_selected_to_spec(self):
        sel = self.addr_tree.selection()
        if not sel:
            messagebox.showinfo("Pick addresses", "Select rows in the address table first."); return
        added = 0
        for s in sel:
            a = next((x for x in self.addresses if str(id(x)) == s), None)
            if not a: continue
            cur_str = ms.format_value(a['vtype'], a['current'])
            try:
                if a['vtype'] == 'string':
                    val = cur_str
                elif a['vtype'] in ('float','double'):
                    val = float(cur_str)
                else:
                    val = int(cur_str, 0) if cur_str.lower().startswith('0x') else int(cur_str)
            except Exception:
                val = 0
            width = ms.scan_size(a['vtype']) if a['vtype'] != 'string' else 4
            is_flt = a['vtype'] in ('float','double')
            self.spec['features'].append({
                'name': a['name'] or f"Addr_0x{a['addr']:X}",
                'type': 'value',
                'address': f"0x{a['addr']:X}",
                'value': val,
                'width': width,
                'is_float': is_flt,
                'description': f"Found via scanner (type={a['vtype']})",
                'default_on': False,
            })
            added += 1
        self._sync_meta_to_spec()
        self._refresh_feat_tree()
        self._status(f"Added {added} address(es) to trainer spec.")

    def _sync_meta_to_spec(self):
        self.spec['name'] = self.meta_name.get() or 'My Trainer'
        self.spec['game'] = self.meta_game.get() or ''
        self.spec['hotkey_toggle'] = self.meta_toggle.get()
        self.spec['hotkey_panic']  = self.meta_panic.get()
        self.spec['window_title_color'] = self.meta_color.get() or '#FF66CC'
        try:
            w_, h_ = self.meta_wh.get().lower().split('x')
            self.spec['window_size'] = [int(w_), int(h_)]
        except Exception: pass

    def _sync_meta_from_spec(self):
        self.meta_name.set(self.spec.get('name',''))
        self.meta_game.set(self.spec.get('game',''))
        self.meta_toggle.set(self.spec.get('hotkey_toggle','VK_F8'))
        self.meta_panic.set(self.spec.get('hotkey_panic','VK_END'))
        self.meta_color.set(self.spec.get('window_title_color','#FF66CC'))
        ws = self.spec.get('window_size',[460,380])
        self.meta_wh.set(f"{ws[0]}x{ws[1]}")

    def _refresh_feat_tree(self):
        self._sync_meta_to_spec()
        for iid in self.feat_tree.get_children():
            self.feat_tree.delete(iid)
        for i, f in enumerate(self.spec['features']):
            addr = f.get('address','')
            if 'pointer' in f:
                p = f['pointer']
                addr = f"{p.get('base','?')}+{'+'.join(f.get('offsets', []))}"
            self.feat_tree.insert('', 'end', iid=str(i), values=(
                f.get('name',''), f.get('type','value'), addr,
                str(f.get('value','')), f.get('width',4),
                'YES' if f.get('default_on') else '', f.get('description','')))

    def _add_feature_row(self):
        self._sync_meta_to_spec()
        self.spec['features'].append({
            'name': 'New Feature', 'type': 'value',
            'address': '0x00000000', 'value': 0, 'width': 4,
            'is_float': False, 'description': '', 'default_on': False,
        })
        self._refresh_feat_tree()

    def _edit_feature_row(self):
        sel = self.feat_tree.selection()
        if not sel: return
        idx = int(sel[0])
        f = dict(self.spec['features'][idx])  # copy
        win = tk.Toplevel(self.root); win.title(f"Edit feature #{idx}")
        win.geometry("380x320")
        fields = [
            ('Name', 'name'),
            ('Type', 'type'),
            ('Address (hex)', 'address'),
            ('Value', 'value'),
            ('Width (bytes)', 'width'),
            ('Is float?', 'is_float'),
            ('Description', 'description'),
            ('Default on?', 'default_on'),
        ]
        vars_ = {}
        for i, (lbl, key) in enumerate(fields):
            ttk.Label(win, text=lbl+":").grid(row=i, column=0, padx=4, pady=2, sticky='e')
            v = f.get(key, '')
            if key == 'type':
                var = tk.StringVar(value=v)
                cb = ttk.Combobox(win, textvariable=var,
                    values=['value','freeze','nudge'], state='readonly', width=20)
                cb.grid(row=i, column=1, padx=4, pady=2, sticky='w')
                vars_[key] = var
            elif key == 'default_on' or key == 'is_float':
                var = tk.BooleanVar(value=bool(v))
                ttk.Checkbutton(win, variable=var).grid(row=i, column=1, padx=4, pady=2, sticky='w')
                vars_[key] = var
            else:
                var = tk.StringVar(value=str(v))
                ttk.Entry(win, textvariable=var, width=30).grid(row=i, column=1, padx=4, pady=2, sticky='w')
                vars_[key] = var
        def save():
            f2 = {k: var.get() for k, var in vars_.items()}
            if isinstance(f2.get('value'), str):
                try:
                    v = f2['value']
                    f2['value'] = float(v) if f2.get('is_float') else int(v, 0) if v.startswith('0x') else int(v)
                except Exception: pass
            try: f2['width'] = int(f2['width'])
            except Exception: f2['width'] = 4
            self.spec['features'][idx] = f2
            self._refresh_feat_tree()
            win.destroy()
        ttk.Button(win, text="Save", command=save).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def _remove_feature_row(self):
        sel = self.feat_tree.selection()
        for s in sel:
            try: del self.spec['features'][int(s)]
            except Exception: pass
        self._refresh_feat_tree()

    def _move_feature(self, delta):
        sel = self.feat_tree.selection()
        if not sel: return
        i = int(sel[0]); j = i + delta
        if j < 0 or j >= len(self.spec['features']): return
        self.spec['features'][i], self.spec['features'][j] = \
            self.spec['features'][j], self.spec['features'][i]
        self._refresh_feat_tree()
        iid = self.feat_tree.get_children()[j]
        self.feat_tree.selection_set(iid)

    def _new_spec(self):
        self.spec_path = None
        self.spec = {'name':'My Trainer','game': self.exe_name or '',
                     'brand':'MomoTrainer — by Momo aka Steav Beoung Salang',
                     'hotkey_toggle':'VK_F8','hotkey_panic':'VK_END',
                     'window_size':[460,380],'window_title_color':'#FF66CC',
                     'features':[],'actions':[]}
        self._sync_meta_from_spec()
        self._refresh_feat_tree()
        self.spec_label_var.set("(unsaved)")

    def _open_spec(self):
        path = filedialog.askopenfilename(initialdir=os.path.abspath('trainers'),
                                           filetypes=[("YAML","*.yaml *.yml")])
        if not path: return
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                self.spec = yaml.safe_load(f)
            self.spec_path = path
            self._sync_meta_from_spec()
            self._refresh_feat_tree()
            self.spec_label_var.set(path)
        except Exception as e:
            messagebox.showerror("YAML error", str(e))

    def _save_spec(self):
        self._sync_meta_to_spec()
        if not self.spec_path:
            path = filedialog.asksaveasfilename(initialdir=os.path.abspath('trainers'),
                                                 defaultextension=".yaml",
                                                 filetypes=[("YAML","*.yaml *.yml")])
            if not path: return
            self.spec_path = path
        import yaml
        with open(self.spec_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(self.spec, f, sort_keys=False, allow_unicode=True)
        self.spec_label_var.set(self.spec_path)
        self._status(f"Saved spec -> {self.spec_path}")

    def _reload_spec(self):
        if not self.spec_path: return
        try:
            import yaml
            with open(self.spec_path, 'r', encoding='utf-8') as f:
                self.spec = yaml.safe_load(f)
            self._sync_meta_from_spec()
            self._refresh_feat_tree()
        except Exception as e:
            messagebox.showerror("YAML error", str(e))

    def _show_yaml(self):
        self._sync_meta_to_spec()
        import yaml
        text = yaml.safe_dump(self.spec, sort_keys=False, allow_unicode=True)
        win = tk.Toplevel(self.root); win.title("YAML preview"); win.geometry("600x600")
        st = scrolledtext.ScrolledText(win, font=('Consolas', 10), wrap='word')
        st.pack(fill='both', expand=True, padx=4, pady=4)
        st.insert('1.0', text)

    # ============================================================
    # BUILD
    # ============================================================
    def _build(self, with_exe):
        self._sync_meta_to_spec()
        if not self.spec.get('game'):
            messagebox.showerror("Missing game", "Game exe is empty."); return
        os.makedirs('trainers', exist_ok=True)
        name = self.spec.get('name') or 'trainer'
        out_cpp = os.path.abspath(f"trainers/{name}_gen.cpp")
        out_exe = os.path.abspath(f"trainers/{name}.exe")
        self._log_build(f"=== Build start: {time.strftime('%H:%M:%S')} ===")
        try:
            tc.compile_template(self.spec,
                                os.path.abspath('templates/trainer_template.cpp'),
                                out_cpp)
        except Exception as e:
            self._log_build(f"FAILED: {e}")
            self.build_status.set(f"FAIL: {e}"); return
        if with_exe:
            gpp = 'g++'
            if not __import__('shutil').which(gpp):
                self._log_build("g++ not in PATH. Set PATH or call with full path.")
                self.build_status.set("FAIL: g++ not found"); return
            ok = tc.build_exe(out_cpp, out_exe, gpp)
            self.build_status.set(("Built " + out_exe) if ok else "Build FAILED")
            self._log_build("=== Build done ===\n" if ok else "=== Build FAILED ===\n")
        else:
            self.build_status.set(f"Generated {out_cpp}")
            self._log_build("=== Generated cpp ===\n")

    def _log_build(self, msg):
        self.build_log.insert('end', msg + '\n')
        self.build_log.see('end')

    def _open_out_dir(self):
        path = os.path.abspath('trainers'); os.makedirs(path, exist_ok=True)
        subprocess.Popen(['explorer', path])

    # ============================================================
    # QUEUE PUMP
    # ============================================================
    def _pump(self):
        # Per-worker progress (each message already updates aggregate via _update_worker_progress)
        try:
            while True:
                kind, *rest = self.scan_prog_q.get_nowait()
                if kind == 'worker_progress':
                    wid, scanned, hits = rest
                    self._update_worker_progress(wid, scanned, hits)
        except queue.Empty: pass

        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == 'first_done':
                    cands = rest[0]
                    self.candidates = cands
                    self.scan_prog.config(value=self.scan_prog['maximum'])
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if cands else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.scan_info_var.set(f"First scan done: {len(cands):,} hits")
                    self._add_candidates_to_table(cands)
                elif kind == 'next_done':
                    cands = rest[0]
                    self.candidates = cands
                    self.scan_prog.config(value=self.scan_prog['maximum'])
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if cands else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.scan_info_var.set(f"After filter: {len(cands):,} hits")
                    self._replace_addresses_from_candidates(cands)
                elif kind == 'scan_error':
                    self._status(f"Scan error: {rest[0]}")
                    self.btn_first.config(state='normal')
                    self.btn_next.config(state='normal' if self.candidates else 'disabled')
                    self.btn_stop.config(state='disabled')
                    self.btn_sigscan.config(state='normal')
                    # Stop indeterminate animation if it was running
                    try:
                        for w in range(len(self._worker_progs)):
                            self._worker_progs[w].stop()
                            self._worker_progs[w].config(mode='determinate', value=0)
                        self.scan_prog.stop()
                    except Exception:
                        pass
                elif kind == 'sigscan_done':
                    hits, pat = rest[0], rest[1]
                    self.btn_sigscan.config(state='normal')
                    # Stop the indeterminate animation
                    try:
                        for w in range(len(self._worker_progs)):
                            self._worker_progs[w].stop()
                            self._worker_progs[w].config(mode='determinate', value=0)
                        self.scan_prog.stop()
                        self.scan_prog.config(mode='determinate', value=self.scan_prog['maximum'])
                    except Exception:
                        pass
                    self.scan_info_var.set(
                        f"Signature scan done: {len(hits):,} match(es)"
                    )
                    # Add each hit as an address entry with a 'sig' label
                    for addr in hits:
                        self.addresses.append({
                            'addr': addr,
                            'vtype': 'uint8',  # display as raw bytes
                            'name': f'sig@0x{addr:X}',
                            'frozen': False,
                            'freeze_value': None,
                            'current': pat,        # show the pattern bytes
                            'previous': pat,
                        })
                    self._refresh_addr_tree()
                    self._status(
                        f"Found {len(hits)} signature match(es); first at 0x{hits[0]:X}"
                        if hits else "No signature matches found."
                    )
                elif kind == 'addresses_dirty':
                    self._refresh_addr_tree()
        except queue.Empty: pass
        self.root.after(100, self._pump)

    def _replace_addresses_from_candidates(self, cands):
        """After a re-scan, keep names/labels but only show survivors."""
        new_addrs = {c.addr for c in cands}
        self.addresses = [a for a in self.addresses if a['addr'] in new_addrs]
        for c in cands:
            if not any(a['addr'] == c.addr for a in self.addresses):
                self.addresses.append({
                    'addr': c.addr,
                    'vtype': self.vtype_map[self.vtype_var.get()],
                    'name': '', 'frozen': False, 'freeze_value': None,
                    'current': c.last, 'previous': c.last,
                })
        self._refresh_addr_tree()

    # ============================================================
    # MISC
    # ============================================================
    def _status(self, msg):
        self.status_var.set(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _on_quit(self):
        self.live_stop.set()
        if self.h:
            try: ctypes.windll.kernel32.CloseHandle(self.h)
            except Exception: pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = StudioGUI(root)
    root.protocol("WM_DELETE_WINDOW", app._on_quit)
    root.mainloop()


if __name__ == "__main__":
    main()