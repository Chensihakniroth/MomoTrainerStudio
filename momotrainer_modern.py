"""
momotrainer_modern.py - Modern launcher for MomoTrainer Studio
Applies CustomTkinter theming to the existing studio_gui without modifying core code.
"""

import sys
import os

# Inject customtkinter into sys.modules BEFORE studio_gui imports tkinter
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

# Configure CustomTkinter appearance globally
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Modern color palette
MODERN_COLORS = {
    "bg": "#0a0e27",           # Primary background (deep navy)
    "panel": "#1a1f3a",        # Panel background
    "accent": "#00d4ff",       # Cyan accent (your neon vibe)
    "text": "#ffffff",         # Primary text
    "muted": "#a0aec0",        # Secondary text
    "border": "#3a4263",       # Border color
}

# Monkey-patch tkinter widgets to CustomTkinter equivalents
import tkinter as tk

# Store references to original tkinter
original_tk_Frame = tk.Frame
original_tk_Label = tk.Label
original_tk_Button = tk.Button
original_tk_Entry = tk.Entry
original_tk_Checkbutton = tk.Checkbutton
original_tk_Canvas = tk.Canvas
original_tk_Toplevel = tk.Toplevel
original_tk_Text = tk.Text

# Create wrapper functions that use CustomTkinter
def tk_Frame(*args, **kwargs):
    # Filter out tkinter-specific kwargs that CTkFrame doesn't support
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness', 'highlightcolor']}
    
    # Map common bgcolor to CTk's fg_color
    if 'bg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['fg_color'] = MODERN_COLORS.get('panel', ctkfriendly_kwargs['bg'])
        del ctkfriendly_kwargs['bg']
    
    return ctk.CTkFrame(*args, **ctkfriendly_kwargs)

def tk_Label(*args, **kwargs):
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness']}
    if 'bg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['fg_color'] = ctkfriendly_kwargs.get('bg', MODERN_COLORS['panel'])
        del ctkfriendly_kwargs['bg']
    if 'fg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['text_color'] = ctkfriendly_kwargs['fg']
        del ctkfriendly_kwargs['fg']
    
    return ctk.CTkLabel(*args, **ctkfriendly_kwargs)

def tk_Button(*args, **kwargs):
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness', 'activebackground', 'activeforeground']}
    
    # Handle colors
    if 'bg' in ctkfriendly_kwargs:
        bg_val = ctkfriendly_kwargs.pop('bg')
        if bg_val == MODERN_COLORS['accent']:
            ctkfriendly_kwargs['fg_color'] = MODERN_COLORS['accent']
        else:
            ctkfriendly_kwargs['fg_color'] = MODERN_COLORS['panel']
    
    if 'fg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['text_color'] = ctkfriendly_kwargs.pop('fg')
    
    # Set corner radius for modern look
    if 'corner_radius' not in ctkfriendly_kwargs:
        ctkfriendly_kwargs['corner_radius'] = 8
    
    return ctk.CTkButton(*args, **ctkfriendly_kwargs)

def tk_Entry(*args, **kwargs):
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness']}
    
    if 'bg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['fg_color'] = ctkfriendly_kwargs.pop('bg')
    if 'fg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['text_color'] = ctkfriendly_kwargs.pop('fg')
    
    if 'corner_radius' not in ctkfriendly_kwargs:
        ctkfriendly_kwargs['corner_radius'] = 6
    
    return ctk.CTkEntry(*args, **ctkfriendly_kwargs)

def tk_Checkbutton(*args, **kwargs):
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness', 'activebackground']}
    
    if 'bg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['fg_color'] = ctkfriendly_kwargs.pop('bg')
    if 'fg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['text_color'] = ctkfriendly_kwargs.pop('fg')
    
    return ctk.CTkCheckBox(*args, **ctkfriendly_kwargs)

def tk_Canvas(*args, **kwargs):
    # Canvas has limited CustomTkinter support, so keep original but style it
    if 'bg' in kwargs:
        kwargs['bg'] = MODERN_COLORS['bg']
    return original_tk_Canvas(*args, **kwargs)

def tk_Toplevel(*args, **kwargs):
    # Toplevel stays as tkinter for now, just update colors
    if 'bg' not in kwargs:
        kwargs['bg'] = MODERN_COLORS['bg']
    return original_tk_Toplevel(*args, **kwargs)

def tk_Text(*args, **kwargs):
    # Text widget - use CTkTextbox
    ctkfriendly_kwargs = {k: v for k, v in kwargs.items() 
                         if k not in ['relief', 'bd', 'highlightthickness', 'insertbackground']}
    
    if 'bg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['fg_color'] = ctkfriendly_kwargs.pop('bg')
    if 'fg' in ctkfriendly_kwargs:
        ctkfriendly_kwargs['text_color'] = ctkfriendly_kwargs.pop('fg')
    
    return ctk.CTkTextbox(*args, **ctkfriendly_kwargs)

# Apply the monkey patches
tk.Frame = tk_Frame
tk.Label = tk_Label
tk.Button = tk_Button
tk.Entry = tk_Entry
tk.Checkbutton = tk_Checkbutton
tk.Canvas = tk_Canvas
tk.Toplevel = tk_Toplevel
tk.Text = tk_Text

# Also patch the ttk styles to match the modern theme
from tkinter import font

# Now import and run the original studio_gui
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from studio_gui import StudioGUI
    
    def main():
        """Launch the modern MomoTrainer Studio."""
        gui = StudioGUI()
        
        # Apply modern styling to the root window
        gui.root.configure(bg=MODERN_COLORS['bg'])
        gui.root.update_idletasks()
        
        # Start the main loop
        gui.root.mainloop()
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"Error importing studio_gui: {e}")
    sys.exit(1)
