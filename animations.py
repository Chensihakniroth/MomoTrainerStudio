"""
animations.py - Motion engine for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Pure-stdlib Tkinter animation utilities:
  - lerp / lerp_color      — value interpolation
  - animate_property       — generic numeric property animator
  - animate_theme          — crossfade between two theme palettes
  - row_flash              — flash a Treeview row on value change
  - ToastManager           — slide-in notifications
  - count_up               — number count-up effect
  - HoverAnim              — smooth button hover transitions

All animations run on Tk's after() loop — no threads, no deps.
"""

import colorsys
import math
import re
import time
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, Optional, Tuple


# ============================================================
# Easing functions
# ============================================================

def _ease_linear(t: float) -> float:
    return t


def _ease_in_out(t: float) -> float:
    """Smooth step — accelerate then decelerate."""
    return t * t * (3.0 - 2.0 * t)


def _ease_out_back(t: float) -> float:
    """Slight overshoot for a snappy feel."""
    c1 = 1.70158
    c3 = c1 + 1.0
    return 1.0 + c3 * (t - 1.0) ** 3 + c1 * (t - 1.0) ** 2


def _ease_out_expo(t: float) -> float:
    """Fast start, gentle landing."""
    return 1.0 - pow(2.0, -10.0 * t) if t < 1.0 else 1.0


EASING = {
    "linear": _ease_linear,
    "in_out": _ease_in_out,
    "out_back": _ease_out_back,
    "out_expo": _ease_out_expo,
}


# ============================================================
# Color utilities
# ============================================================

def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    """Convert '#rrggbb' → (r, g, b)."""
    h = hex_color.lstrip("#")
    if len(h) != 6:
        raise ValueError(f"Expected #rrggbb, got {hex_color!r}")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _rgb_to_hex(r: int, g: int, b: int) -> str:
    """(r, g, b) → '#rrggbb'."""
    return f"#{max(0, min(255, int(r))):02x}{max(0, min(255, int(g))):02x}{max(0, min(255, int(b))):02x}"


def lerp(start: float, end: float, t: float) -> float:
    """Linear interpolation."""
    return start + (end - start) * max(0.0, min(1.0, t))


def lerp_color(start_hex: str, end_hex: str, t: float) -> str:
    """Interpolate between two hex colors.  t=0 → start, t=1 → end."""
    sr, sg, sb = _hex_to_rgb(start_hex)
    er, eg, eb = _hex_to_rgb(end_hex)
    return _rgb_to_hex(
        lerp(sr, er, t),
        lerp(sg, eg, t),
        lerp(sb, eb, t),
    )


def scale_brightness(hex_color: str, factor: float) -> str:
    """Scale brightness. factor>1 brightens, <1 darkens."""
    r, g, b = _hex_to_rgb(hex_color)
    h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
    v = max(0.0, min(1.0, v * factor))
    nr, ng, nb = colorsys.hsv_to_rgb(h, s, v)
    return _rgb_to_hex(int(nr * 255), int(ng * 255), int(nb * 255))


# ============================================================
# Core animator — runs a callback over N frames
# ============================================================

def animate_property(
    root: tk.Tk,
    duration_ms: int,
    on_frame: Callable[[float], None],
    on_done: Optional[Callable[[], None]] = None,
    easing: str = "in_out",
    fps: int = 60,
):
    """
    Run an animation.  on_frame receives t in [0,1] (eased).
    """
    ease_fn = EASING.get(easing, _ease_in_out)
    frame_delay = max(1, int(1000 / fps))
    total_frames = max(1, duration_ms // frame_delay)
    start_time = time.monotonic()

    def _tick():
        elapsed = (time.monotonic() - start_time) * 1000
        raw_t = min(1.0, elapsed / duration_ms)
        on_frame(ease_fn(raw_t))

        if raw_t < 1.0:
            root.after(frame_delay, _tick)
        elif on_done:
            try:
                on_done()
            except Exception:
                pass

    _tick()


# ============================================================
# Theme crossfade
# ============================================================

def animate_theme(
    root: tk.Tk,
    style: ttk.Style,
    apply_theme_fn: Callable,
    old_theme: Dict,
    new_theme: Dict,
    duration_ms: int = 300,
):
    """
    Crossfade every color key from old_theme → new_theme.
    Calls apply_theme_fn with the interpolated palette each frame.
    """
    # Only interpolate keys present in both themes (color values only)
    shared_keys = []
    for k in old_theme:
        if k in new_theme and isinstance(old_theme[k], str) and old_theme[k].startswith("#"):
            shared_keys.append(k)

    def _frame(t: float):
        blended = dict(new_theme)  # start with new theme's structure
        for k in shared_keys:
            blended[k] = lerp_color(old_theme[k], new_theme[k], t)
        apply_theme_fn(blended)

    animate_property(root, duration_ms, _frame, easing="in_out")


# ============================================================
# Row flash — Treeview row highlight pulse
# ============================================================

def row_flash(
    tree: ttk.Treeview,
    item: str,
    flash_color: str,
    normal_bg: str,
    normal_fg: str,
    duration_ms: int = 400,
):
    """
    Flash a Treeview row to flash_color, then fade back to normal.
    Uses tag_configure with the item's tag.
    """
    root = tree.winfo_toplevel()
    steps = 20
    step_ms = duration_ms // steps

    def _set_color(hex_color: str):
        try:
            tree.tag_configure("flash", background=hex_color, foreground=normal_fg)
            tree.item(item, tags=("flash",))
        except Exception:
            pass

    # Phase 1: flash bright
    _set_color(flash_color)

    # Phase 2: fade back
    def _fade_step(frame: int):
        t = frame / steps
        color = lerp_color(flash_color, normal_bg, t)
        _set_color(color)
        if frame < steps:
            root.after(step_ms, _fade_step, frame + 1)
        else:
            # Restore normal appearance
            try:
                tree.tag_configure("flash", background=normal_bg, foreground=normal_fg)
                tree.item(item, tags=())  # remove flash tag
            except Exception:
                pass

    root.after(step_ms * 3, _fade_step, 0)  # brief hold on bright color


# ============================================================
# Toast notification manager
# ============================================================

class ToastManager:
    """
    Slide-in notifications from bottom-right.

    Usage:
        toasts = ToastManager(root)
        toasts.show("Scan complete!", kind="success")
        toasts.show("Process not found", kind="error")
    """

    COLORS = {
        "info":    {"bg": "#1f6feb", "fg": "#ffffff", "icon": "ℹ"},
        "success": {"bg": "#238636", "fg": "#ffffff", "icon": "✓"},
        "warning": {"bg": "#9e6a03", "fg": "#ffffff", "icon": "⚠"},
        "error":   {"bg": "#da3633", "fg": "#ffffff", "icon": "✕"},
        "scan":    {"bg": "#6e40c9", "fg": "#ffffff", "icon": "🔍"},
    }

    def __init__(self, root: tk.Tk, max_visible: int = 3, width: int = 280):
        self.root = root
        self.max_visible = max_visible
        self.width = width
        self._toasts: list = []  # list of (frame, after_id)

    def show(self, message: str, kind: str = "info", duration_ms: int = 3000):
        """Show a toast notification."""
        colors = self.COLORS.get(kind, self.COLORS["info"])
        icon = colors["icon"]
        bg = colors["bg"]
        fg = colors["fg"]

        # Create toast frame
        toast = tk.Frame(self.root, bg=bg, padx=12, pady=8,
                         highlightbackground="#ffffff33", highlightthickness=1)
        toast_label = tk.Label(toast, text=f" {icon}  {message}",
                                font=("Segoe UI", 10), bg=bg, fg=fg,
                                anchor="w", justify="left")
        toast_label.pack(fill="x")

        # Position — start off-screen right
        self.root.update_idletasks()
        screen_w = self.root.winfo_width()
        screen_h = self.root.winfo_height()
        rx = self.root.winfo_rootx()
        ry = self.root.winfo_rooty()

        x_off = screen_w + 20  # off-screen
        base_y = screen_h - 60

        toast.place(in_=self.root, x=x_off, y=base_y, width=self.width)
        self._toasts.append(toast)
        self._reposition()

        # Slide-in animation
        target_x = screen_w - self.width - 16

        def _slide_in(t: float):
            cur_x = _lerp(x_off, target_x, t)
            toast.place_configure(x=int(cur_x))

        animate_property(self.root, 350, _slide_in, easing="out_back", on_done=None)

        # Auto-dismiss
        def _dismiss():
            self._dismiss_toast(toast)

        dismiss_id = self.root.after(duration_ms, _dismiss)
        toast._dismiss_id = dismiss_id

    def _reposition(self):
        """Stack toasts from bottom up."""
        base_y = self.root.winfo_height() - 60
        for i, toast in enumerate(reversed(self._toasts)):
            if toast.winfo_exists():
                y_off = base_y - (i * 56)
                toast.place_configure(y=max(10, y_off))

    def _dismiss_toast(self, toast: tk.Frame):
        """Slide out and destroy."""
        if not toast.winfo_exists():
            return
        try:
            self.root.after_cancel(toast._dismiss_id)
        except Exception:
            pass

        cur_x = toast.winfo_x()
        target_x = self.root.winfo_width() + 50

        def _slide_out(t: float):
            x = _lerp(cur_x, target_x, t)
            if toast.winfo_exists():
                toast.place_configure(x=int(x))

        def _cleanup():
            if toast.winfo_exists():
                toast.destroy()
            if toast in self._toasts:
                self._toasts.remove(toast)
            self._reposition()

        animate_property(self.root, 250, _slide_out, on_done=_cleanup, easing="in_out")


def _lerp(start: float, end: float, t: float) -> float:
    return start + (end - start) * max(0.0, min(1.0, t))


# ============================================================
# Count-up number animation
# ============================================================

def count_up(
    root: tk.Tk,
    set_fn: Callable[[int], None],
    target: int,
    duration_ms: int = 600,
):
    """
    Animate a number from 0 to target.
    set_fn is called with the current integer value each frame.
    """
    def _frame(t: float):
        val = int(lerp(0, target, t))
        set_fn(val)

    animate_property(root, duration_ms, _frame, easing="out_expo")


# ============================================================
# Button hover transitions
# ============================================================

class HoverAnim:
    """
    Smooth color transition for buttons on hover.

    Usage:
        hover = HoverAnim(root)
        hover.bind(button, normal_bg="#3a3a3a", hover_bg="#FF66CC")
    """

    def __init__(self, root: tk.Tk, duration_ms: int = 120):
        self.root = root
        self.duration_ms = duration_ms

    def bind(self, widget: tk.Widget, normal_bg: str, hover_bg: str,
             normal_fg: Optional[str] = None, hover_fg: Optional[str] = None):
        """Bind hover animation to a widget."""

        def _on_enter(_):
            self._transition(widget, normal_bg, hover_bg, normal_fg, hover_fg)

        def _on_leave(_):
            self._transition(widget, hover_bg, normal_bg, hover_fg, normal_fg)

        widget.bind("<Enter>", _on_enter)
        widget.bind("<Leave>", _on_leave)

    def _transition(self, widget, bg_from, bg_to, fg_from, fg_to):
        if not widget.winfo_exists():
            return
        self.root.update_idletasks()

        def _frame(t: float):
            if not widget.winfo_exists():
                return
            bg = lerp_color(bg_from, bg_to, t)
            try:
                kw = {"background": bg}
                if fg_from and fg_to:
                    kw["foreground"] = lerp_color(fg_from, fg_to, t)
                widget.configure(**kw)
            except Exception:
                pass

        animate_property(self.root, self.duration_ms, _frame, easing="in_out")
