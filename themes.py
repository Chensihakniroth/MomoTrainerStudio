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

THEMES = {
    "dark": DARK,
    "warm": WARM,
}


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
                     bordercolor=t["input_border"])
    style.configure("TNotebook.Tab",
                     background=t["panel_bg"],
                     foreground=t["fg"],
                     padding=(12, 6),
                     bordercolor=t["input_border"])
    style.map("TNotebook.Tab",
                background=[("selected", t["fg_accent"])],
                foreground=[("selected", t["button_active_fg"])])

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
                     rowheight=22)
    style.configure("Treeview.Heading",
                     background=t["tree_header_bg"],
                     foreground=t["tree_header_fg"],
                     relief="flat",
                     font=("Segoe UI", 9, "bold"))
    style.map("Treeview",
                background=[("selected", t["tree_select_bg"])],
                foreground=[("selected", t["tree_select_fg"])])
    style.map("Treeview.Heading",
                background=[("active", t["fg_accent"])])

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

    # ---- PanedWindow sash ----
    style.configure("TPanedwindow",
                     background=t["bg"])
    style.configure("Sash",
                     background=t["panel_bg"],
                     bordercolor=t["input_border"],
                     sashthickness=4)