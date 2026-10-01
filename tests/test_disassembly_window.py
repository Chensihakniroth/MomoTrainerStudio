import ctypes
import os
import tkinter as tk
from types import SimpleNamespace

import disassembly_view
import studio_gui


def test_open_disassembly_pro_renders_requested_x86_address(monkeypatch):
    """The Disassembly View menu must render code, not open an empty stub."""
    root = tk.Tk()
    root.withdraw()

    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    kernel32.VirtualFree.restype = ctypes.c_bool
    allocation = kernel32.VirtualAlloc(
        None, 4096, 0x3000, 0x04
    )  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    assert allocation

    try:
        target = allocation + 1024
        code = bytes.fromhex("55 8B EC 83 EC 10 53 56 57 5F 5E 5B 5D C3")
        ctypes.memmove(target, code, len(code))

        monkeypatch.setattr(
            disassembly_view.DisassemblyView,
            "_detect_architecture",
            lambda self: setattr(self, "is_64bit", False),
        )

        gui = object.__new__(studio_gui.StudioGUI)
        gui.root = root
        gui.pid = os.getpid()
        gui.h = kernel32.GetCurrentProcess()
        gui.addr_tree = SimpleNamespace(selection=lambda: ())
        gui._ask_input = lambda *_args: f"{target:X}"

        gui._open_disassembly_pro()
        root.update_idletasks()
        root.update()

        windows = [
            widget
            for widget in root.winfo_children()
            if isinstance(widget, tk.Toplevel)
        ]
        assert windows, "Disassembly View window was not created"

        views = [
            widget
            for widget in windows[-1].winfo_children()
            if isinstance(widget, disassembly_view.DisassemblyView)
        ]
        assert views, "menu opened MiniDisassemblyView instead of the functional view"

        rendered = views[-1].text.get("1.0", "end").lower()
        assert "push" in rendered
        assert "ebp" in rendered
    finally:
        for widget in root.winfo_children():
            if isinstance(widget, tk.Toplevel):
                widget.destroy()
        root.destroy()
        kernel32.VirtualFree(allocation, 0, 0x8000)
