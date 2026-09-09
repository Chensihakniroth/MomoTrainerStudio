"""
themes.py - Color themes for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

Two themes:
  - dark  : charcoal/black bg, kawaii pink (#FF66CC) accents
  - warm  : cream/peach bg, amber/orange (#E08A4B) accents

Each theme defines colors for every UI element so apply_theme() can
flip a single switch to restyle the whole app.

Use:
    from themes import THEMES, apply_theme
    apply_theme(style, THEMES["dark"])
"""

# ============================================================
# theme palette definitions
# ============================================================
MODERN_DARK = {
    "name":          "modern_dark",
    # base - GitHub Dark Primer tokens
    "bg":            "#0d1117",      # GitHub canvas default
    "panel_bg":      "#161b22",      # GitHub canvas sub / card surface
    "panel_fg":      "#c9d1d9",      # GitHub primary text
    "input_bg":      "#0d1117",      # GitHub input background
    "input_fg":      "#e6edf3",      # GitHub high-contrast input text
    "input_border":  "#30363d",      # GitHub border default (smooth, low-glare)
    # text
    "fg":            "#c9d1d9",      # GitHub default text
    "fg_muted":      "#8b949e",      # GitHub secondary / muted text
    "fg_accent":     "#58a6ff",      # GitHub blue accent
    "fg_accent2":    "#79c0ff",      # light blue
    "fg_success":    "#3fb950",      # GitHub green
    "fg_warning":    "#d29922",      # GitHub amber
    # buttons
    "button_bg":     "#21262d",      # GitHub neutral button
    "button_fg":     "#c9d1d9",
    "button_border": "#30363d",
    "button_active": "#30363d",
    "button_active_fg": "#ffffff",
    "button_primary": "#238636",     # GitHub primary green
    "button_primary_fg": "#ffffff",
    "button_blue":   "#1f6feb",      # GitHub blue button
    "button_danger": "#da3633",      # GitHub danger red
    # treeview
    "tree_bg":       "#0d1117",
    "tree_fg":       "#c9d1d9",
    "tree_field":    "#0d1117",
    "tree_header_bg":"#161b22",
    "tree_header_fg":"#8b949e",
    "tree_select_bg":"#1f6feb",
    "tree_select_fg":"#ffffff",
    "tree_row_alt":  "#13171f",
    # address table status tags (smooth, soft backgrounds)
    "tag_changed":   "#0e3a1e",      # soft dark emerald
    "tag_changed_fg":"#7ee787",
    "tag_frozen":    "#3d2805",      # soft dark amber
    "tag_frozen_fg": "#f0b72f",
    "tag_frozench":  "#4d1f0c",      # soft dark orange
    "tag_frozench_fg":"#ffa657",
    # progress bars
    "progress_bg":   "#21262d",
    "progress_fg":   "#238636",
    # status bar
    "status_bg":     "#161b22",
    "status_fg":     "#8b949e",
    # scrollbar
    "scroll_bg":     "#161b22",
    "scroll_fg":     "#30363d",
}

DARK = {
    "name":          "dark",
    # base
    "bg":            "#1e1e1e",      # main background
    "panel_bg":      "#262626",      # LabelFrame, frames
    "panel_fg":      "#e8e8e8",      # text in panels
    "input_bg":      "#1a1a1a",      # Entry, Combobox, ScrolledText
    "input_fg":      "#f0f0f0",
    "input_border":  "#3a3a3a",
    # text
    "fg":            "#e8e8e8",      # default text
    "fg_muted":      "#909090",      # secondary text
    "fg_accent":     "#FF66CC",      # kawaii pink — primary accent
    "fg_accent2":    "#88DDFF",      # cyan secondary accent
    "fg_warning":    "#FFAA66",      # amber for warnings
    # buttons
    "button_bg":     "#3a3a3a",
    "button_fg":     "#ffffff",
    "button_active": "#FF66CC",
    "button_active_fg": "#1e1e1e",
    # treeview (address list)
    "tree_bg":       "#1a1a1a",
    "tree_fg":       "#e8e8e8",
    "tree_field":    "#1a1a1a",      # background of row columns
    "tree_header_bg":"#2e2e2e",
    "tree_header_fg":"#FF66CC",
    "tree_select_bg":"#4a4a4a",
    "tree_select_fg":"#ffffff",
    # address table status tags (changed / frozen / frozen+changed)
    "tag_changed":   "#2d6b2d",      # dark green
    "tag_changed_fg":"#ffffff",
    "tag_frozen":    "#8a6d3b",      # amber-ish
    "tag_frozen_fg": "#ffffff",
    "tag_frozench":  "#a04a2a",      # orange
    "tag_frozench_fg":"#ffffff",
    # progress bars
    "progress_bg":   "#2a2a2a",
    "progress_fg":   "#FF66CC",
    # status bar
    "status_bg":     "#0a0a0a",
    "status_fg":     "#88FF88",
    # scrollbar
    "scroll_bg":     "#2a2a2a",
    "scroll_fg":     "#FF66CC",
}

WARM = {
    "name":          "warm",
    # base
    "bg":            "#FFF4E6",      # cream/peach
    "panel_bg":      "#FFE8D0",      # warmer panel
    "panel_fg":      "#3a2418",      # dark warm brown
    "input_bg":      "#FFFBF3",      # lighter cream
    "input_fg":      "#3a2418",
    "input_border":  "#D4A574",
    # text
    "fg":            "#3a2418",
    "fg_muted":      "#7a5a40",
    "fg_accent":     "#E08A4B",      # warm amber — primary accent
    "fg_accent2":    "#B8702E",      # deeper amber secondary
    "fg_warning":    "#A04020",      # burnt orange for warnings
    # buttons
    "button_bg":     "#FFD8A8",
    "button_fg":     "#3a2418",
    "button_active": "#E08A4B",
    "button_active_fg": "#FFFBF3",
    # treeview
    "tree_bg":       "#FFFBF3",
    "tree_fg":       "#3a2418",
    "tree_field":    "#FFFBF3",
    "tree_header_bg":"#F4D8B0",
    "tree_header_fg":"#7a3a14",
    "tree_select_bg":"#FFB870",
    "tree_select_fg":"#3a2418",
    # address table status tags
    "tag_changed":   "#B5E0A0",      # warm soft green
    "tag_changed_fg":"#1a4010",
    "tag_frozen":    "#FFD080",      # warm amber
    "tag_frozen_fg": "#5a3010",
    "tag_frozench":  "#FFA060",      # warm orange
    "tag_frozench_fg":"#3a1408",
    # progress bars
    "progress_bg":   "#F4D8B0",
    "progress_fg":   "#E08A4B",
    # status bar
    "status_bg":     "#3a2418",
    "status_fg":     "#FFD080",
    # scrollbar
    "scroll_bg":     "#F4D8B0",
    "scroll_fg":     "#E08A4B",
}

NEON_DARK = {
    "name":          "neon_dark",
    # base — Deep navy
    "bg":            "#0a0e27",      # Deep navy
    "panel_bg":      "#1a1f3a",      # Slightly lighter navy
    "panel_fg":      "#e4e4e7",      # Bright white text
    "input_bg":      "#151929",      # Slightly darker for inputs
    "input_fg":      "#ffffff",      # Pure white
    "input_border":  "#00d4ff",      # Cyan border (neon accent)
    # text
    "fg":            "#ffffff",      # White
    "fg_muted":      "#a0aec0",      # Light gray
    "fg_accent":     "#00d4ff",      # Bright cyan — PRIMARY neon accent
    "fg_accent2":    "#ff006e",      # Hot pink — SECONDARY neon accent
    "fg_warning":    "#fbbf24",      # Amber
    # buttons
    "button_bg":     "#1e2749",      # Navy button
    "button_fg":     "#ffffff",      # White text
    "button_active": "#00d4ff",      # Cyan when active
    "button_active_fg": "#0a0e27",   # Dark text on cyan
    # treeview (address list)
    "tree_bg":       "#0f1229",      # Very dark navy
    "tree_fg":       "#e4e4e7",      # Light text
    "tree_field":    "#0a0e27",
    "tree_header_bg":"#1a1f3a",
    "tree_header_fg":"#00d4ff",      # Cyan headers
    "tree_select_bg":"#00d4ff",      # Cyan selection
    "tree_select_fg":"#0a0e27",      # Dark text on cyan
    "tree_row_alt":  "#151929",
    # address table status tags (neon variants)
    "tag_changed":   "#10b981",      # Green (softer)
    "tag_changed_fg":"#ffffff",
    "tag_frozen":    "#f59e0b",      # Amber
    "tag_frozen_fg": "#0a0e27",
    "tag_frozench":  "#ef4444",      # Red
    "tag_frozench_fg":"#ffffff",
    # progress bars
    "progress_bg":   "#1a1f3a",
    "progress_fg":   "#00d4ff",      # Cyan progress
    # status bar
    "status_bg":     "#0f1229",
    "status_fg":     "#00d4ff",      # Cyan status
    # scrollbar
    "scroll_bg":     "#1a1f3a",
    "scroll_fg":     "#00d4ff",      # Cyan scrollbar
}

ZEN = {
    "name":          "zen",
    # Quiet sage + paper palette: low contrast surfaces and one calm accent.
    "bg":            "#F3F6F3",
    "panel_bg":      "#FFFFFF",
    "panel_fg":      "#26352D",
    "input_bg":      "#F8FAF8",
    "input_fg":      "#26352D",
    "input_border":  "#D6E1D9",
    "fg":            "#26352D",
    "fg_muted":      "#728078",
    "fg_accent":     "#5C846C",
    "fg_accent2":    "#7A9C88",
    "fg_success":    "#4F8162",
    "fg_warning":    "#A47745",
    "button_bg":     "#EAF1EC",
    "button_fg":     "#304137",
    "button_border": "#D6E1D9",
    "button_active": "#D7E7DB",
    "button_active_fg": "#26352D",
    "button_primary": "#5C846C",
    "button_primary_fg": "#FFFFFF",
    "button_blue":   "#789C9A",
    "button_danger": "#B56F6F",
    "tree_bg":       "#FCFDFC",
    "tree_fg":       "#304137",
    "tree_field":    "#FCFDFC",
    "tree_header_bg":"#EEF4EF",
    "tree_header_fg":"#5C7464",
    "tree_select_bg":"#DDEBE1",
    "tree_select_fg":"#26352D",
    "tree_row_alt":  "#F5F9F6",
    "tag_changed":   "#E2F0E5",
    "tag_changed_fg":"#3E6E4C",
    "tag_frozen":    "#F5ECD9",
    "tag_frozen_fg": "#805F32",
    "tag_frozench":  "#F3E1D8",
    "tag_frozench_fg":"#87513E",
    "progress_bg":   "#E6EEE8",
    "progress_fg":   "#789C84",
    "status_bg":     "#EAF1EC",
    "status_fg":     "#5C7464",
    "scroll_bg":     "#EEF4EF",
    "scroll_fg":     "#C2D2C7",
}
THEMES = {
    "zen": ZEN,
    "modern_dark": MODERN_DARK,
    "dark": DARK,
    "warm": WARM,
    "neon_dark": NEON_DARK,
}


# Role lookup lets the direct Tk widgets follow the selected theme too.
# studio_gui.py intentionally uses a few lightweight tk.Button/tk.Entry widgets
# for the primary scan controls, so styling ttk alone leaves visible seams.
_ROLE_KEYS = (
    "bg", "panel_bg", "input_bg", "button_bg", "status_bg", "tree_bg",
    "tree_header_bg", "progress_bg", "scroll_bg", "fg", "fg_muted",
    "fg_accent", "fg_accent2", "button_primary", "button_blue", "button_danger",
    "input_border",
)


def _role_for_color(value):
    if not value:
        return None
    value = str(value).lower()
    for palette in THEMES.values():
        for role in _ROLE_KEYS:
            if str(palette.get(role, "")).lower() == value:
                return role
    return None


def _restyle_direct_widgets(root, theme):
    """Restyle the hand-built Tk controls without changing their behavior."""
    def visit(widget, inherited_bg):
        try:
            cls = widget.winfo_class()
            old_bg = widget.cget("background")
        except Exception:
            cls, old_bg = "", None
        role = _role_for_color(old_bg)
        bg = inherited_bg

        try:
            if cls == "Frame":
                # Preserve the visual role of nested cards, inputs, and status bars.
                role = role or ("bg" if widget.master is root else "panel_bg")
                bg = theme.get(role, theme["panel_bg"])
                widget.configure(background=bg)
            elif cls == "Button":
                label = str(widget.cget("text")).lower()
                if "first scan" in label or "build" in label:
                    bg, fg = theme["button_primary"], theme["button_primary_fg"]
                elif "next scan" in label or "scan aob" in label:
                    bg, fg = theme["button_blue"], theme["button_primary_fg"]
                elif "stop" in label or "detach" in label:
                    bg, fg = theme["button_danger"], theme["button_primary_fg"]
                else:
                    bg, fg = theme["button_bg"], theme["button_fg"]
                widget.configure(background=bg, foreground=fg,
                                 activebackground=theme["button_active"],
                                 activeforeground=theme["button_active_fg"],
                                 highlightbackground=theme["input_border"])
            elif cls == "Entry":
                bg = theme["input_bg"]
                widget.configure(background=bg, foreground=theme["input_fg"],
                                 insertbackground=theme["fg_accent"],
                                 highlightbackground=theme["input_border"],
                                 highlightcolor=theme["fg_accent"])
            elif cls == "Checkbutton":
                widget.configure(background=inherited_bg, foreground=theme["fg"],
                                 activebackground=inherited_bg,
                                 activeforeground=theme["fg"], selectcolor=theme["input_bg"])
            elif cls == "Label":
                role = role or _role_for_color(widget.master.cget("background"))
                bg = theme.get(role, inherited_bg)
                fg_role = _role_for_color(widget.cget("foreground"))
                widget.configure(background=bg, foreground=theme.get(fg_role, theme["fg"]))
            elif cls in ("Text", "Listbox"):
                bg = theme["input_bg"]
                widget.configure(background=bg, foreground=theme["input_fg"],
                                 insertbackground=theme["fg_accent"],
                                 selectbackground=theme["tree_select_bg"],
                                 selectforeground=theme["tree_select_fg"])
        except Exception:
            # Some platform-specific Tk options are unavailable; keep styling best-effort.
            pass

        try:
            for child in widget.winfo_children():
                visit(child, bg)
        except Exception:
            pass

    for child in root.winfo_children():
        visit(child, theme["bg"])

# ============================================================
# apply_theme — configures ttk.Style + direct tk widgets
# ============================================================
def apply_theme(style, theme, root=None, address_tree=None, proc_tree=None,
                addr_tree=None, feat_tree=None, hex_widget=None, build_log=None,
                status_label=None, scan_prog=None, info_widgets=None,
                button_widgets=None):
    """
    Apply theme to a ttk Style and any direct tk widgets.
    Pass root for window background; pass trees/log widgets for direct config.
    """
    t = theme

    # ---- root window ----
    if root is not None:
        try:
            root.configure(bg=t["bg"])
        except Exception:
            pass

    # ---- base ttk styles ----
    style.configure(".",
                     background=t["bg"],
                     foreground=t["fg"],
                     fieldbackground=t["input_bg"],
                     bordercolor=t["input_border"])
    style.map(".",
                background=[("active", t["panel_bg"]), ("selected", t["tree_select_bg"])],
                foreground=[("active", t["fg"]), ("selected", t["tree_select_fg"])])

    # ---- TFrame / TLabelframe ----
    style.configure("TFrame", background=t["bg"])
    style.configure("TLabelframe",
                     background=t["panel_bg"],
                     foreground=t["panel_fg"],
                     bordercolor=t["input_border"])
    style.configure("TLabelframe.Label",
                     background=t["panel_bg"],
                     foreground=t["fg_accent"],
                     font=("Segoe UI", 9, "bold"))
    # TLabel needs explicit handling for bg because some platforms ignore it
    style.configure("TLabel",
                     background=t["bg"],
                     foreground=t["fg"])
    style.configure("Status.TLabel",
                     background=t["status_bg"],
                     foreground=t["status_fg"])
    style.configure("Hdr.TLabel",
                     background=t["panel_bg"],
                     foreground=t["fg_accent"],
                     font=("Consolas", 10, "bold"))

    # ---- TButton ----
    style.configure("TButton",
                     background=t["button_bg"],
                     foreground=t["button_fg"],
                     bordercolor=t["input_border"],
                     focuscolor=t["fg_accent"])
    style.map("TButton",
                background=[("active", t["button_active"]),
                            ("disabled", t["panel_bg"])],
                foreground=[("active", t["button_active_fg"]),
                            ("disabled", t["fg_muted"])])

    # ---- TEntry / TCombobox ----
    style.configure("TEntry",
                     fieldbackground=t["input_bg"],
                     foreground=t["input_fg"],
                     bordercolor=t["input_border"],
                     insertcolor=t["input_fg"])
    style.configure("TCombobox",
                     fieldbackground=t["input_bg"],
                     background=t["button_bg"],
                     foreground=t["input_fg"],
                     arrowcolor=t["fg_accent"],
                     bordercolor=t["input_border"])
    style.map("TCombobox",
                fieldbackground=[("readonly", t["input_bg"])],
                foreground=[("readonly", t["input_fg"])],
                selectbackground=[("readonly", t["tree_select_bg"])],
                selectforeground=[("readonly", t["tree_select_fg"])])

    # ---- TNotebook (tabs) ----
    style.configure("TNotebook",
                     background=t["bg"],
                     bordercolor=t["input_border"],
                     borderwidth=0)
    style.configure("TNotebook.Tab",
                     background=t["panel_bg"],
                     foreground=t["fg_muted"],
                     padding=(16, 7),
                     font=("Segoe UI", 9),
                     bordercolor=t["input_border"])
    style.map("TNotebook.Tab",
                background=[("selected", t["bg"]), ("active", t["panel_bg"])],
                foreground=[("selected", t["fg_accent"]), ("active", t["fg"])])

    # ---- TProgressbar ----
    style.configure("Horizontal.TProgressbar",
                     background=t["progress_fg"],
                     troughcolor=t["progress_bg"],
                     bordercolor=t["input_border"],
                     lightcolor=t["progress_fg"],
                     darkcolor=t["progress_fg"])

    # ---- Treeview (the big one) ----
    style.configure("Treeview",
                     background=t["tree_bg"],
                     foreground=t["tree_fg"],
                     fieldbackground=t["tree_field"],
                     bordercolor=t["input_border"],
                     borderwidth=0,
                     rowheight=25,
                     font=("Consolas", 9))
    style.configure("Treeview.Heading",
                     background=t["tree_header_bg"],
                     foreground=t["tree_header_fg"],
                     relief="flat",
                     borderwidth=0,
                     padding=(6, 6),
                     font=("Segoe UI", 9, "bold"))
    style.map("Treeview",
                background=[("selected", t["tree_select_bg"])],
                foreground=[("selected", t["tree_select_fg"])])
    style.map("Treeview.Heading",
                background=[("active", t["panel_bg"])],
                foreground=[("active", t["fg_accent"])])

    # ---- Treeview tags (status colors for address list) ----
    if address_tree is not None:
        try:
            address_tree.tag_configure("changed",
                background=t["tag_changed"],
                foreground=t["tag_changed_fg"])
            address_tree.tag_configure("frozen",
                background=t["tag_frozen"],
                foreground=t["tag_frozen_fg"])
            address_tree.tag_configure("frozench",
                background=t["tag_frozench"],
                foreground=t["tag_frozench_fg"])
        except Exception:
            pass

    # ---- direct tk widgets (ScrolledText uses tk Text under the hood) ----
    direct_widgets = []
    if hex_widget is not None:
        direct_widgets.append((hex_widget, t["input_bg"], t["input_fg"], t["input_border"]))
    if build_log is not None:
        direct_widgets.append((build_log, t["input_bg"], t["input_fg"], t["input_border"]))
    if info_widgets:
        for w in info_widgets:
            try:
                w.configure(background=t["bg"], foreground=t["fg_accent"],
                             font=("Consolas", 9))
            except Exception:
                pass
    if status_label is not None:
        try:
            status_label.configure(background=t["status_bg"],
                                    foreground=t["status_fg"])
        except Exception:
            pass
    if scan_prog is not None:
        # Progressbar is configured via style above; nothing more to do.
        pass
    for w, bg, fg, bd in direct_widgets:
        try:
            w.configure(background=bg, foreground=fg,
                         insertbackground=fg,
                         selectbackground=t["tree_select_bg"],
                         selectforeground=t["tree_select_fg"],
                         bordercolor=bd, relief="flat")
        except Exception:
            pass

    # Keep hand-built Tk controls visually aligned with ttk.
    if root is not None:
        _restyle_direct_widgets(root, t)

    # ---- PanedWindow sash ----
    style.configure("TPanedwindow",
                     background=t["bg"])
    style.configure("Sash",
                     background=t["panel_bg"],
                     bordercolor=t["input_border"],
                     sashthickness=4)