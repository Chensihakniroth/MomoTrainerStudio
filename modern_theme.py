"""
modern_theme.py - CustomTkinter Theme for MomoTrainer Studio
Modern dark theme with neon accents (cyan/pink/purple)
"""

# Modern Color Palette (Dark Mode + Neon Accents)
COLORS = {
    # Backgrounds
    "bg_primary": "#0a0e27",        # Deep navy (main bg)
    "bg_secondary": "#1a1f3a",      # Slightly lighter (panels)
    "bg_tertiary": "#252d47",       # Even lighter (buttons, inputs)
    "bg_hover": "#3a4263",          # Hover state
    
    # Accents (Neon)
    "accent_cyan": "#00d4ff",       # Bright cyan (primary accent)
    "accent_pink": "#ff006e",       # Hot pink (secondary)
    "accent_purple": "#8338ec",     # Purple (tertiary)
    
    # Text
    "text_primary": "#ffffff",      # White
    "text_secondary": "#a0aec0",    # Light gray
    "text_muted": "#718096",        # Muted gray
    
    # Status
    "success": "#10b981",           # Green
    "warning": "#f59e0b",           # Amber
    "error": "#ef4444",             # Red
    "info": "#06b6d4",              # Cyan variant
    
    # Borders
    "border_light": "#3a4263",
    "border_focus": "#00d4ff",
}

# CTkEntry/Button styling constants
BUTTON_CORNER_RADIUS = 8
ENTRY_CORNER_RADIUS = 6
FRAME_CORNER_RADIUS = 12
LABEL_FONT = ("Segoe UI", 10)
TITLE_FONT = ("Segoe UI", 12, "bold")
MONO_FONT = ("Consolas", 10)
MONO_FONT_SMALL = ("Consolas", 9)

def get_color(key: str, default="#1a1f3a") -> str:
    """Get a color from the theme, with fallback."""
    return COLORS.get(key, default)
