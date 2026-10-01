"""Embedded Evolution Engine / Warframe offset dumper panel for MomoTrainer Studio."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import evolution_offset_dumper as dumper

APP_ROOT = Path(__file__).resolve().parent
DEFAULT_BINARY = Path(r"D:\game\warframe_menu\bin\Warframe.x64.exe")
DEFAULT_OUTPUT = APP_ROOT / "offset_reports"
DEFAULT_PATTERNS = APP_ROOT / "evolution_offset_patterns.json"


class EvolutionOffsetDumperPanel(ttk.Frame):
    """Native tab for running the static/live Evolution Engine offset dumper."""

    def __init__(self, master, *, default_pid=None, default_binary=None, default_output=None):
        super().__init__(master, padding=8)
        self.master_app = master
        self.default_pid = default_pid
        self.default_binary = Path(default_binary or DEFAULT_BINARY)
        self.default_output = Path(default_output or DEFAULT_OUTPUT)
        self._running = False
        self._last_report = None

        self.binary_var = tk.StringVar(value=str(self.default_binary))
        self.pattern_var = tk.StringVar(value=str(DEFAULT_PATTERNS))
        self.output_var = tk.StringVar(value=str(self.default_output))
        self.pid_var = tk.StringVar(value=str(default_pid or ""))
        self.status_var = tk.StringVar(value="Ready — run a static dump or attach a live Warframe PID.")
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(header, text="Evolution Engine / Warframe Offset Dumper v2", font=("Segoe UI", 12, "bold")).pack(side="left")
        ttk.Label(header, textvariable=self.status_var).pack(side="right")

        paths = ttk.LabelFrame(self, text="Scan configuration", padding=8)
        paths.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        paths.columnconfigure(1, weight=1)

        self._path_row(paths, 0, "Warframe binary", self.binary_var, self._browse_binary)
        self._path_row(paths, 1, "Pattern library", self.pattern_var, self._browse_patterns)
        self._path_row(paths, 2, "Output folder", self.output_var, self._browse_output)

        live = ttk.Frame(paths)
        live.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        ttk.Label(live, text="Live PID (optional)", width=18).pack(side="left")
        ttk.Entry(live, textvariable=self.pid_var, width=18).pack(side="left", padx=(0, 8))
        ttk.Label(live, text="Attached Warframe PID is prefilled when available.", style="Muted.TLabel").pack(side="left")

        actions = ttk.Frame(self)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        self.run_button = ttk.Button(actions, text="Run Static Dump", command=self.run_dump)
        self.run_button.pack(side="left")
        self.live_button = ttk.Button(actions, text="Run + Live Verify", command=self.run_live)
        self.live_button.pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Refresh Report", command=self.refresh_report).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Open Output Folder", command=self.open_output).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Copy Header to Mwtrainer", command=self.copy_header).pack(side="left", padx=(6, 0))

        body = ttk.PanedWindow(self, orient="horizontal")
        body.grid(row=3, column=0, sticky="nsew")
        self.tree_frame = ttk.Frame(body)
        self.log_frame = ttk.Frame(body)
        body.add(self.tree_frame, weight=3)
        body.add(self.log_frame, weight=2)

        ttk.Label(self.tree_frame, text="Pattern status", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        tree_wrap = ttk.Frame(self.tree_frame)
        tree_wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=("name", "hits", "status", "rva"), show="headings", height=15)
        self.tree.heading("name", text="Pattern")
        self.tree.heading("hits", text="Hits")
        self.tree.heading("status", text="Status")
        self.tree.heading("rva", text="First RVA")
        self.tree.column("name", width=210, anchor="w")
        self.tree.column("hits", width=55, anchor="e")
        self.tree.column("status", width=170, anchor="w")
        self.tree.column("rva", width=120, anchor="w")
        tree_scroll = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        ttk.Label(self.log_frame, text="Dumper log", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        self.log = tk.Text(self.log_frame, height=15, wrap="word", bg="#0d1117", fg="#c9d1d9", insertbackground="#58a6ff", relief="flat", font=("Consolas", 9))
        log_scroll = ttk.Scrollbar(self.log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self._append_log("Ready. Static scans do not require an attached process.\n")

    def _path_row(self, parent, row, label, variable, command):
        ttk.Label(parent, text=label, width=18).grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=(0, 6), pady=2)
        ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2, pady=2)

    def _browse_binary(self):
        path = filedialog.askopenfilename(title="Select Warframe.x64.exe", filetypes=[("Warframe executable", "Warframe.x64.exe"), ("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.binary_var.set(path)

    def _browse_patterns(self):
        path = filedialog.askopenfilename(title="Select patterns.json", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if path:
            self.pattern_var.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select output folder", initialdir=self.output_var.get())
        if path:
            self.output_var.set(path)

    def _append_log(self, text):
        self.log.insert("end", text)
        self.log.see("end")

    def _validate(self, live):
        binary = Path(self.binary_var.get().strip())
        patterns = Path(self.pattern_var.get().strip())
        output = Path(self.output_var.get().strip())
        if not binary.is_file():
            messagebox.showerror("Offset Dumper", f"Warframe binary not found:\n{binary}", parent=self)
            return None
        if not patterns.is_file():
            messagebox.showerror("Offset Dumper", f"Pattern library not found:\n{patterns}", parent=self)
            return None
        args = ["--binary", str(binary), "--patterns", str(patterns), "--out-dir", str(output)]
        if live:
            try:
                pid = int(self.pid_var.get().strip(), 0)
            except ValueError:
                messagebox.showerror("Offset Dumper", "Live PID must be a number.", parent=self)
                return None
            if pid <= 0:
                messagebox.showerror("Offset Dumper", "Live PID must be positive.", parent=self)
                return None
            args += ["--live-pid", str(pid)]
        return args

    def run_dump(self):
        self._start(live=False)

    def run_live(self):
        self._start(live=True)

    def _start(self, live):
        if self._running:
            return
        args = self._validate(live)
        if args is None:
            return
        output = Path(self.output_var.get().strip())
        output.mkdir(parents=True, exist_ok=True)
        self._running = True
        self.run_button.configure(state="disabled")
        self.live_button.configure(state="disabled")
        self.status_var.set("Scanning..." if not live else "Scanning + live verification...")
        self._append_log("\n" + "=" * 72 + "\n" + ("Starting static dump...\n" if not live else "Starting dump + live verification...\n"))
        threading.Thread(target=self._worker, args=(args,), daemon=True).start()

    def _worker(self, args):
        capture = io.StringIO()
        code = 0
        error = None
        try:
            with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                code = dumper.main(args)
        except BaseException as exc:
            error = exc
            code = 1
        self.after(0, self._finished, capture.getvalue(), code, error)

    def _finished(self, output, code, error):
        self._running = False
        self.run_button.configure(state="normal")
        self.live_button.configure(state="normal")
        self._append_log(output)
        if error is not None:
            self.status_var.set("Failed")
            messagebox.showerror("Offset Dumper", f"Dumper failed:\n{error}", parent=self)
        elif code == 0:
            self.status_var.set("Completed")
            self.refresh_report()
            messagebox.showinfo("Offset Dumper", f"Dump completed.\n\nReports saved to:\n{self.output_var.get()}", parent=self)
        else:
            self.status_var.set(f"Finished with exit code {code}")
            messagebox.showwarning("Offset Dumper", f"Dumper finished with exit code {code}.\nSee the log for details.", parent=self)

    def refresh_report(self):
        path = Path(self.output_var.get().strip()) / "warframe_offsets_latest.json"
        if not path.is_file():
            return
        try:
            import json
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._append_log(f"Could not read report: {exc}\n")
            return
        self._last_report = report
        self.tree.delete(*self.tree.get_children())
        for item in report.get("patterns", []):
            self.tree.insert("", "end", values=(item.get("name", ""), item.get("hits", 0), item.get("status", ""), item.get("first_offset_rva") or "-"))

    def open_output(self):
        path = Path(self.output_var.get().strip())
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(path))
        except OSError:
            pass

    def copy_header(self):
        source = Path(self.output_var.get().strip()) / "warframe_offsets.h"
        target = Path(r"D:\game\warframe_menu\Mwtrainer\src\hooks\warframe_offsets.h")
        if not source.is_file():
            messagebox.showerror("Offset Dumper", "Generate a report before copying the header.", parent=self)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        self.status_var.set(f"Header copied to {target}")
        messagebox.showinfo("Offset Dumper", f"Header copied to:\n{target}", parent=self)
