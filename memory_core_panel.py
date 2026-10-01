"""
memory_core_panel.py — Memory.h Engine GUI for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

A live console for the ported Memory.h engine (memory_core.py):
  - attach to any process by exe name or PID (the C++ `Memory("name")` flow)
  - module browser with base addresses
  - read/write a value at an address, with type selection
  - pointer-chain read/write (module + offsets -> value), the exact
    "god mode" flow from the original Memory.h README
  - import/export a .ini of offset entries

ASCII-safe: no emoji in any Tkinter string (Windows cp1252 encoder).
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import memory_core as mc

BG = "#0d1117"
PANEL = "#161b22"
BORDER = "#30363d"
TEXT = "#c9d1d9"
MUTED = "#8b949e"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
YELLOW = "#d29922"
INPUT = "#0d1117"

BTN = dict(bg=PANEL, fg=TEXT, activebackground=BORDER,
           activeforeground="#ffffff", font=("Consolas", 9),
           relief="flat", padx=10, pady=4, highlightthickness=1,
           highlightbackground=BORDER, highlightcolor=ACCENT)

ENTRY = dict(bg=INPUT, fg=TEXT, insertbackground=TEXT,
             font=("Consolas", 9), relief="flat", highlightthickness=1,
             highlightbackground=BORDER, highlightcolor=ACCENT)

LABEL = dict(bg=BG, fg=MUTED, font=("Segoe UI", 8))


def safe(s: str) -> str:
    """Tkinter on Windows cannot encode non-ASCII; scrub it."""
    return str(s).encode("ascii", errors="replace").decode(
        "ascii").replace("\ufffd", "?")


def btn(parent, text, fg, command):
    """Button with the panel style and a specific foreground colour."""
    style = dict(BTN)
    style["fg"] = fg
    return tk.Button(parent, text=text, command=command, **style)


class MemoryCoreWindow(tk.Toplevel):
    """Memory.h engine console."""

    def __init__(self, parent, pid: int = None, process_name: str = None,
                 process_handle=None):
        super().__init__(parent)
        self.title("Memory.h Engine")
        self.geometry("900x640")
        self.configure(bg=BG)

        self.mem = None            # memory_core.Memory
        self.pid = pid
        self.process_name = process_name or ""
        self.shared_handle = process_handle   # handle from studio_gui
        self.modules = []
        self.entries = []          # saved (name, address, vtype) rows

        self._build_ui()
        self._log("memory_core engine ready. Attach to a process to begin.")

        if pid:
            self.after(60, lambda: self._attach_pid(pid))

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=8, pady=(8, 4))

        tk.Label(top, text="Process", **LABEL).pack(side="left")
        self.proc_var = tk.StringVar(value=self.process_name)
        self.proc_entry = tk.Entry(top, textvariable=self.proc_var, width=26,
                                   **ENTRY)
        self.proc_entry.pack(side="left", padx=(4, 2))
        self.proc_entry.bind("<Return>", lambda e: self._attach_by_name())

        tk.Label(top, text="PID", **LABEL).pack(side="left", padx=(8, 0))
        self.pid_var = tk.StringVar(value=str(self.pid or ""))
        self.pid_entry = tk.Entry(top, textvariable=self.pid_var, width=8,
                                  **ENTRY)
        self.pid_entry.pack(side="left", padx=(4, 8))

        tk.Button(top, text="Attach by Name", **BTN,
                  command=self._attach_by_name).pack(side="left", padx=2)
        tk.Button(top, text="Attach by PID", **BTN,
                  command=self._attach_pid_from_field).pack(side="left", padx=2)
        tk.Button(top, text="Detach", **BTN,
                  command=self._detach).pack(side="left", padx=2)

        self.status = tk.Label(top, text="Not attached", bg=BG, fg=MUTED,
                               font=("Consolas", 9), anchor="e")
        self.status.pack(side="right", padx=6)

        # --- middle split: modules | console ---
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat",
                               borderwidth=0)
        paned.pack(fill="both", expand=True, padx=8, pady=4)

        # modules pane
        mod_frame = tk.Frame(paned, bg=PANEL, highlightthickness=1,
                             highlightbackground=BORDER)
        paned.add(mod_frame, minsize=260)

        mtop = tk.Frame(mod_frame, bg=PANEL)
        mtop.pack(fill="x", padx=6, pady=(6, 2))
        tk.Label(mtop, text="Modules", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Button(mtop, text="Refresh", **BTN,
                  command=self._refresh_modules).pack(side="right")
        tk.Button(mtop, text="Use Base", **BTN,
                  command=self._use_selected_module).pack(side="right", padx=2)

        self.mod_tree = ttk.Treeview(mod_frame, columns=("name", "base"),
                                     show="headings", height=12)
        self.mod_tree.heading("name", text="Module", anchor="w")
        self.mod_tree.heading("base", text="Base Address", anchor="e")
        self.mod_tree.column("name", width=150, anchor="w")
        self.mod_tree.column("base", width=125, anchor="e")
        self.mod_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self.mod_tree.bind("<Double-1>", lambda e: self._use_selected_module())

        frow = tk.Frame(mod_frame, bg=PANEL)
        frow.pack(fill="x", padx=6, pady=(0, 6))
        tk.Label(frow, text="Filter", **LABEL).pack(side="left")
        self.filter_var = tk.StringVar()
        fe = tk.Entry(frow, textvariable=self.filter_var, width=18, **ENTRY)
        fe.pack(side="left", padx=4)
        fe.bind("<KeyRelease>", lambda e: self._refresh_modules())

        # right pane
        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=420)

        self._build_rw(right)
        self._build_chain(right)
        self._build_console(right)
        self._build_saved(right)

    def _build_rw(self, parent):
        f = tk.LabelFrame(parent, text="Read / Write", bg=BG, fg=MUTED,
                          font=("Segoe UI", 8, "bold"), bd=1,
                          highlightthickness=1, highlightbackground=BORDER)
        f.pack(fill="x", padx=4, pady=3)

        r1 = tk.Frame(f, bg=BG)
        r1.pack(fill="x", padx=6, pady=(6, 2))
        tk.Label(r1, text="Address (hex)", **LABEL).pack(side="left")
        self.addr_var = tk.StringVar()
        tk.Entry(r1, textvariable=self.addr_var, width=20, **ENTRY).pack(
            side="left", padx=4)
        tk.Label(r1, text="Type", **LABEL).pack(side="left", padx=(8, 0))
        self.type_var = tk.StringVar(value="int32")
        self.type_box = ttk.Combobox(r1, textvariable=self.type_var,
                                     values=mc.TYPE_NAMES, width=10,
                                     state="readonly")
        self.type_box.pack(side="left", padx=4)

        r2 = tk.Frame(f, bg=BG)
        r2.pack(fill="x", padx=6, pady=2)
        tk.Label(r2, text="Value", **LABEL).pack(side="left")
        self.val_var = tk.StringVar()
        self.val_entry = tk.Entry(r2, textvariable=self.val_var, width=20,
                                  **ENTRY)
        self.val_entry.pack(side="left", padx=4)
        self.val_entry.bind("<Return>", lambda e: self._do_read())

        r3 = tk.Frame(f, bg=BG)
        r3.pack(fill="x", padx=6, pady=(2, 6))
        btn(r3, "Read", GREEN, self._do_read).pack(side="left")
        btn(r3, "Write", YELLOW, self._do_write).pack(side="left", padx=4)
        tk.Button(r3, text="Save Entry", **BTN,
                  command=self._save_entry).pack(side="left")
        tk.Button(r3, text="Watch", **BTN,
                  command=self._watch_current).pack(side="left", padx=4)

    def _build_chain(self, parent):
        f = tk.LabelFrame(parent, text="Pointer Chain", bg=BG, fg=MUTED,
                          font=("Segoe UI", 8, "bold"), bd=1,
                          highlightthickness=1, highlightbackground=BORDER)
        f.pack(fill="x", padx=4, pady=3)

        r1 = tk.Frame(f, bg=BG)
        r1.pack(fill="x", padx=6, pady=(6, 2))
        tk.Label(r1, text="Base addr", **LABEL).pack(side="left")
        self.chain_base_var = tk.StringVar()
        tk.Entry(r1, textvariable=self.chain_base_var, width=20,
                 **ENTRY).pack(side="left", padx=4)
        tk.Label(r1, text="Type", **LABEL).pack(side="left", padx=(8, 0))
        self.chain_type_var = tk.StringVar(value="int32")
        ttk.Combobox(r1, textvariable=self.chain_type_var,
                     values=mc.TYPE_NAMES, width=10,
                     state="readonly").pack(side="left", padx=4)

        r2 = tk.Frame(f, bg=BG)
        r2.pack(fill="x", padx=6, pady=2)
        tk.Label(r2, text="Offsets (0x10,0x20,0xEC)", **LABEL).pack(side="left")
        self.chain_off_var = tk.StringVar()
        tk.Entry(r2, textvariable=self.chain_off_var, width=26,
                 **ENTRY).pack(side="left", padx=4)

        r3 = tk.Frame(f, bg=BG)
        r3.pack(fill="x", padx=6, pady=(2, 6))
        tk.Button(r3, text="Resolve", **BTN,
                  command=self._do_resolve).pack(side="left")
        btn(r3, "Read Chain", GREEN, self._do_chain_read).pack(side="left", padx=4)
        btn(r3, "Write Chain", YELLOW, self._do_chain_write).pack(side="left")
        tk.Button(r3, text="From Selected Module", **BTN,
                  command=self._chain_from_module).pack(side="left", padx=4)

    def _build_console(self, parent):
        f = tk.LabelFrame(parent, text="Console", bg=BG, fg=MUTED,
                          font=("Segoe UI", 8, "bold"), bd=1,
                          highlightthickness=1, highlightbackground=BORDER)
        f.pack(fill="both", expand=True, padx=4, pady=3)
        self.console = tk.Text(f, bg="#010409", fg=TEXT, insertbackground=TEXT,
                               font=("Consolas", 9), relief="flat",
                               highlightthickness=1, highlightbackground=BORDER,
                               wrap="none")
        self.console.pack(fill="both", expand=True, padx=4, pady=4)
        self.console.tag_configure("ok", foreground=GREEN)
        self.console.tag_configure("err", foreground=RED)
        self.console.tag_configure("warn", foreground=YELLOW)
        self.console.tag_configure("dim", foreground=MUTED)
        self.console.tag_configure("hi", foreground=ACCENT)
        self.console.configure(state="disabled")

    def _build_saved(self, parent):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", padx=4, pady=(0, 6))
        tk.Label(f, text="Saved entries:", **LABEL).pack(side="left")
        self.saved_list = tk.Listbox(f, bg=INPUT, fg=TEXT, height=3,
                                     font=("Consolas", 8), relief="flat",
                                     highlightthickness=1,
                                     highlightbackground=BORDER)
        self.saved_list.pack(side="left", fill="x", expand=True, padx=6)
        self.saved_list.bind("<Double-1>", lambda e: self._load_saved())
        tk.Button(f, text="Load", **BTN,
                  command=self._load_saved).pack(side="left", padx=2)
        tk.Button(f, text="Remove", **BTN,
                  command=self._remove_saved).pack(side="left", padx=2)
        tk.Button(f, text="Import", **BTN,
                  command=self._import_ini).pack(side="left", padx=2)
        tk.Button(f, text="Export", **BTN,
                  command=self._export_ini).pack(side="left", padx=2)

    # ---------------------------------------------------------
    # helpers
    # ---------------------------------------------------------
    def _log(self, msg, tag=""):
        self.console.configure(state="normal")
        self.console.insert("end", safe(msg) + "\n", tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _set_status(self, msg, color=MUTED):
        self.status.config(text=safe(msg), fg=color)

    @staticmethod
    def _parse_addr(text):
        """Accept '0x1234', '1234' (hex), '7FF6...' — return int."""
        s = str(text).strip().replace(" ", "").replace("_", "")
        if not s:
            raise ValueError("empty address")
        if s.lower().startswith("0x"):
            return int(s, 16)
        # bare hex is the convention in this UI
        return int(s, 16)

    @staticmethod
    def _parse_offsets(text):
        """'0x10, 0x20,0xEC' -> [16, 32, 236]; also accepts '+0x10+0x20'."""
        s = str(text).strip()
        if not s:
            return []
        if "," in s:
            parts = [p for p in s.split(",") if p.strip()]
        elif "+" in s:
            parts = [p for p in s.split("+") if p.strip()]
        else:
            parts = [s]
        out = []
        for p in parts:
            p = p.strip()
            neg = p.startswith("-")
            if neg:
                p = p[1:]
            val = int(p, 16) if p.lower().startswith("0x") else int(p, 0)
            out.append(-val if neg else val)
        return out

    def _require_attached(self):
        if not self.mem or not self.mem.is_attached():
            self._log("Not attached. Use Attach by Name or Attach by PID.",
                      "err")
            return False
        return True

    # ---------------------------------------------------------
    # attach
    # ---------------------------------------------------------
    def _attach_by_name(self):
        name = self.proc_var.get().strip()
        if not name:
            self._log("Enter a process name first.", "warn")
            return

        # A bare name lookup binds to the FIRST matching PID, which for a
        # multi-instance exe is very often a helper process with no window
        # (brave.exe, msedgewebview2.exe, svchost.exe all do this). Ask
        # which one before attaching instead of warning after the fact.
        try:
            instances = mc.list_instances(name)
        except Exception as e:
            self._log("Process lookup failed: %s" % e, "err")
            return

        if not instances:
            self._log("Attach failed: process not found: %s" % name, "err")
            self._set_status("Not found", RED)
            return

        if len(instances) > 1:
            chosen = self._pick_instance(name, instances)
            if chosen is None:
                self._log("Attach cancelled: %d instances of %s"
                          % (len(instances), name), "warn")
                return
            self._attach_pid(chosen)
            return

        self._attach_pid(instances[0][0])

    def _pick_instance(self, name, instances):
        """Modal list of matching instances -> chosen PID, or None.

        Shows the window title because the PID alone cannot tell two
        instances of the same exe apart.
        """
        dlg = tk.Toplevel(self)
        dlg.withdraw()
        dlg.title("Select process - %s" % safe(name))
        dlg.configure(bg=PANEL)
        dlg.transient(self)
        dlg.resizable(False, False)

        tk.Label(dlg, text="%d instances of '%s' are running."
                            % (len(instances), safe(name)),
                 bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold"),
                 anchor="w").pack(fill="x", padx=12, pady=(12, 2))
        tk.Label(dlg, text="Pick the one you want to attach to.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8),
                 anchor="w").pack(fill="x", padx=12, pady=(0, 8))

        lb = tk.Listbox(dlg, bg=INPUT, fg=TEXT, font=("Consolas", 9),
                        activestyle="none", highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT,
                        selectbackground=ACCENT, selectforeground="#0d1117",
                        width=62, height=min(len(instances) + 1, 14),
                        borderwidth=0)
        lb.pack(fill="both", expand=True, padx=12)

        rows = []
        for pid, exe, titles in instances:
            label = mc.describe_instance(pid, exe, titles)
            if len(titles) > 1:
                label += "  (+%d more windows)" % (len(titles) - 1)
            rows.append((pid, safe(label)))
            lb.insert("end", rows[-1][1])

        chosen = {"pid": None}

        def _use(_event=None):
            sel = lb.curselection()
            if sel:
                chosen["pid"] = rows[sel[0]][0]
            dlg.destroy()

        def _cancel(_event=None):
            chosen["pid"] = None
            dlg.destroy()

        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(fill="x", padx=12, pady=10)
        btn(bar, "Cancel", MUTED, _cancel).pack(side="right")
        btn(bar, "Attach", ACCENT, _use).pack(side="right", padx=(0, 6))

        lb.bind("<Double-Button-1>", _use)
        lb.bind("<Return>", _use)
        dlg.bind("<Escape>", _cancel)

        if rows:
            lb.selection_set(0)
            lb.focus_set()

        dlg.update_idletasks()
        dlg.deiconify()
        # Centre on the parent, then grab: without grab_set the user can
        # keep typing into the panel behind the dialog.
        try:
            x = self.winfo_rootx() + (self.winfo_width() - dlg.winfo_width()) // 2
            y = self.winfo_rooty() + (self.winfo_height() - dlg.winfo_height()) // 2
            dlg.geometry("+%d+%d" % (max(x, 0), max(y, 0)))
        except Exception:
            pass
        dlg.grab_set()
        self.wait_window(dlg)
        return chosen["pid"]

    def _attach_pid_from_field(self):
        try:
            pid = int(self.pid_var.get().strip(), 0)
        except ValueError:
            self._log("PID must be a number.", "err")
            return
        self._attach_pid(pid)

    def _attach_pid(self, pid):
        # Drop any previous engine FIRST. Reusing self.mem when it is
        # already set meant a failed re-attach left the panel silently
        # bound to the OLD process — the status said one pid while every
        # read went to another. Attach is all-or-nothing.
        if self.mem:
            try:
                self.mem.close()
            except Exception:
                pass
            self.mem = None
        self.modules = []
        try:
            self.mod_tree.delete(*self.mod_tree.get_children())
        except Exception:
            pass

        # Reuse the handle studio_gui already opened (it may hold debug
        # privilege we cannot get, or be attached to an elevated target).
        if self.shared_handle:
            try:
                self.mem = mc.Memory.from_handle(
                    self.shared_handle, pid,
                    self.proc_var.get().strip() or "target",
                    owns_handle=False)
                self._log("Reusing the studio's process handle for pid %d"
                          % pid, "ok")
            except Exception as e:
                self._log("Shared handle unavailable (%s), opening own."
                          % e, "warn")
                self.mem = None
                self.shared_handle = None

        if not self.mem:
            try:
                self.mem = mc.Memory(pid=pid)
            except mc.MemoryError_ as e:
                self._log("Attach failed: %s" % e, "err")
                self._set_status("Attach failed", RED)
                return
        self.pid = self.mem.pid
        self.pid_var.set(str(self.mem.pid))
        if not self.proc_var.get().strip():
            self.proc_var.set(self.mem.process_name)
        self._log("Attached to %s (pid %d) by PID"
                  % (self.mem.process_name, self.mem.pid), "ok")
        try:
            base = self.mem.get_module_address("")
            if base:
                self._log("Main module base: 0x%X" % base, "hi")
        except Exception as e:
            self._log("Module base lookup failed: %s" % e, "warn")
        self._set_status("Attached pid %d" % self.mem.pid, GREEN)
        self._refresh_modules()

    def _detach(self):
        if self.mem:
            self.mem.close()
            self._log("Detached.", "dim")
        self.mem = None
        self.modules = []
        self.mod_tree.delete(*self.mod_tree.get_children())
        self._set_status("Not attached")

    # ---------------------------------------------------------
    # modules
    # ---------------------------------------------------------
    def _refresh_modules(self):
        if not self._require_attached():
            return
        flt = self.filter_var.get().strip().lower()
        self.mod_tree.delete(*self.mod_tree.get_children())
        try:
            mods = self.mem.get_modules()
        except Exception as e:
            self._log("Module enumeration failed: %s" % e, "err")
            return
        self.modules = mods
        shown = 0
        for name, base, size, _path in mods:
            if flt and flt not in name.lower():
                continue
            self.mod_tree.insert("", "end", values=(name, "0x%X" % base))
            shown += 1
        self._log("Loaded %d modules (%d shown)."
                  % (len(mods), shown), "dim")

    def _use_selected_module(self):
        sel = self.mod_tree.selection()
        if not sel:
            self._log("Select a module first.", "warn")
            return
        name, base_hex = self.mod_tree.item(sel[0])["values"]
        base = int(str(base_hex), 16)
        self.addr_var.set("0x%X" % base)
        self.chain_base_var.set("0x%X" % base)
        self._log("Module %s base 0x%X loaded into address fields."
                  % (name, base), "hi")
        # chain offsets default to the README flow: base + offset
        if not self.chain_off_var.get().strip():
            self.chain_off_var.set("0x0")

    def _chain_from_module(self):
        self._use_selected_module()

    # ---------------------------------------------------------
    # read / write
    # ---------------------------------------------------------
    def _do_read(self):
        if not self._require_attached():
            return
        try:
            addr = self._parse_addr(self.addr_var.get())
        except ValueError as e:
            self._log("Bad address: %s" % e, "err")
            return
        vtype = self.type_var.get().strip()
        try:
            val = self.mem.read(addr, vtype)
        except mc.MemoryError_ as e:
            self._log("Read failed: %s" % e, "err")
            return
        self.val_var.set(self._format_value(val, vtype))
        self._log("Read  [0x%X] %s = %s"
                  % (addr, vtype, self._format_value(val, vtype)), "ok")

    def _do_write(self):
        if not self._require_attached():
            return
        try:
            addr = self._parse_addr(self.addr_var.get())
        except ValueError as e:
            self._log("Bad address: %s" % e, "err")
            return
        vtype = self.type_var.get().strip()
        text = self.val_var.get().strip()
        try:
            if vtype in ("float", "double", "float32", "float64"):
                value = float(text)
            elif vtype == "bool":
                value = text.lower() in ("1", "true", "yes", "on")
            else:
                # Accept 0x-prefixed hex, else decimal
                value = (int(text, 16) if text.lower().startswith("0x")
                         else int(text, 0))
            n = self.mem.write(addr, value, vtype)
        except mc.MemoryError_ as e:
            self._log("Write failed: %s" % e, "err")
            return
        except ValueError as e:
            self._log("Bad value for type %s: %s" % (vtype, e), "err")
            return
        self._log("Wrote %s (%d bytes) to [0x%X] as %s"
                  % (value, n, addr, vtype), "ok")
        back = self.mem.read(addr, vtype)
        self._log("Verify: %s" % self._format_value(back, vtype), "dim")

    @staticmethod
    def _format_value(val, vtype):
        if isinstance(val, float):
            return repr(val)
        if vtype in ("uint32", "uint64", "uintptr", "ptr", "uint8", "uint16"):
            return "0x%X (%d)" % (val, val)
        return str(val)

    # ---------------------------------------------------------
    # chains
    # ---------------------------------------------------------
    def _do_resolve(self):
        if not self._require_attached():
            return
        try:
            base = self._parse_addr(self.chain_base_var.get())
            offsets = self._parse_offsets(self.chain_off_var.get())
            addr = self.mem.resolve_chain(base, offsets, deref_last=False)
        except mc.MemoryError_ as e:
            self._log("Resolve failed: %s" % e, "err")
            return
        except ValueError as e:
            self._log("Bad chain: %s" % e, "err")
            return
        self.addr_var.set("0x%X" % addr)
        self._log("Chain %s + [%s] -> 0x%X"
                  % ("0x%X" % base,
                     ", ".join("0x%X" % o for o in offsets), addr), "hi")

    def _do_chain_read(self):
        if not self._require_attached():
            return
        try:
            base = self._parse_addr(self.chain_base_var.get())
            offsets = self._parse_offsets(self.chain_off_var.get())
            vtype = self.chain_type_var.get().strip()
            val = self.mem.read_chain(base, offsets, vtype)
        except mc.MemoryError_ as e:
            self._log("Chain read failed: %s" % e, "err")
            return
        except ValueError as e:
            self._log("Bad chain: %s" % e, "err")
            return
        self._log("Chain [0x%X][%s] %s = %s"
                  % (base, ", ".join("0x%X" % o for o in offsets), vtype,
                     self._format_value(val, vtype)), "ok")

    def _do_chain_write(self):
        if not self._require_attached():
            return
        try:
            base = self._parse_addr(self.chain_base_var.get())
            offsets = self._parse_offsets(self.chain_off_var.get())
            vtype = self.chain_type_var.get().strip()
            text = self.val_var.get().strip()
            value = (float(text) if vtype in ("float", "double", "float32",
                                              "float64")
                     else (int(text, 16) if text.lower().startswith("0x")
                           else int(text, 0)))
            n = self.mem.write_chain(base, offsets, value, vtype)
        except mc.MemoryError_ as e:
            self._log("Chain write failed: %s" % e, "err")
            return
        except ValueError as e:
            self._log("Bad chain or value: %s" % e, "err")
            return
        self._log("Wrote %s (%d bytes) through chain [0x%X][%s]"
                  % (value, n, base,
                     ", ".join("0x%X" % o for o in offsets)), "ok")

    # ---------------------------------------------------------
    # saved entries
    # ---------------------------------------------------------
    def _save_entry(self):
        try:
            addr = self._parse_addr(self.addr_var.get())
        except ValueError:
            self._log("Set a valid address before saving.", "warn")
            return
        label = self.type_var.get().strip()
        self.entries.append((addr, label, self.val_var.get().strip()))
        self.saved_list.insert("end", "0x%X  %s  = %s"
                               % (addr, label, self.val_var.get().strip()))
        self._log("Saved entry 0x%X (%s)." % (addr, label), "dim")

    def _load_saved(self):
        sel = self.saved_list.curselection()
        if not sel:
            return
        addr, label, val = self.entries[sel[0]]
        self.addr_var.set("0x%X" % addr)
        self.type_var.set(label)
        self.val_var.set(val)
        self._log("Loaded entry 0x%X (%s) = %s" % (addr, label, val), "hi")

    def _remove_saved(self):
        sel = self.saved_list.curselection()
        if not sel:
            return
        self.saved_list.delete(sel[0])
        del self.entries[sel[0]]

    def _export_ini(self):
        if not self.entries:
            self._log("No saved entries to export.", "warn")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".ini", filetypes=[("INI", "*.ini")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("; MomoTrainer Studio - Memory.h engine entries\n")
            fh.write("[Entries]\n")
            for addr, label, val in self.entries:
                fh.write("0x%X=%s,%s\n" % (addr, label, val))
        self._log("Exported %d entries to %s"
                  % (len(self.entries), path), "ok")

    def _import_ini(self):
        path = filedialog.askopenfilename(filetypes=[("INI", "*.ini"),
                                                     ("All", "*.*")])
        if not path:
            return
        count = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith(("[", ";", "#")):
                        continue
                    if "=" not in line:
                        continue
                    lhs, rhs = line.split("=", 1)
                    parts = [p.strip() for p in rhs.split(",", 1)]
                    try:
                        addr = int(lhs.strip(), 16)
                    except ValueError:
                        continue
                    label = parts[0] if parts else "int32"
                    val = parts[1] if len(parts) > 1 else ""
                    self.entries.append((addr, label, val))
                    self.saved_list.insert("end", "0x%X  %s  = %s"
                                           % (addr, label, val))
                    count += 1
        except Exception as e:
            self._log("Import failed: %s" % e, "err")
            return
        self._log("Imported %d entries from %s" % (count, path), "ok")

    # ---------------------------------------------------------
    def _watch_current(self):
        """Open the selected address in Memory Watch Pro if available."""
        try:
            addr = self._parse_addr(self.addr_var.get())
        except ValueError:
            self._log("Set a valid address before watching.", "warn")
            return
        try:
            import studio_gui
        except Exception:
            pass
        parent_app = self.master
        opener = getattr(parent_app, "_open_memory_watch_pro", None)
        if opener is None:
            self._log("Memory Watch Pro is only available from the main "
                      "window (Tools > Memory Watch Pro).", "warn")
            return
        try:
            opener()
            win = getattr(parent_app, "_mem_watch_pro_win", None)
            if win:
                win.add_watch(addr)
                self._log("Watching 0x%X in Memory Watch Pro." % addr, "ok")
        except Exception as e:
            self._log("Could not open Memory Watch Pro: %s" % e, "err")

    def on_close(self):
        if self.mem:
            self.mem.close()
        self.destroy()
