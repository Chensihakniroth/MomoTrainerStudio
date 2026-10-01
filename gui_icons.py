"""Small image-icon helper for MomoTrainer Studio's Tkinter UI."""
from __future__ import annotations

import os
import tkinter as tk


class GuiIcons:
    def __init__(self, root: tk.Misc):
        self.root = root
        base = getattr(root, "_momo_icon_base", None)
        if base is None:
            base = getattr(__import__("sys"), "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        self.base = os.path.join(base, "assets", "icons")
        self._cache: dict[tuple[str, int], tk.PhotoImage] = {}

    def get(self, name: str, size: int = 16) -> tk.PhotoImage:
        key = (name, size)
        if key not in self._cache:
            path = os.path.join(self.base, f"{name}.png")
            if not os.path.isfile(path):
                raise FileNotFoundError(path)
            image = tk.PhotoImage(master=self.root, file=path)
            if size != 64:
                image = image.subsample(max(1, round(64 / size)))
            self._cache[key] = image
        return self._cache[key]

    def apply(self, widget, name: str, size: int = 16, text: str | None = None):
        """Attach an image to a Button/Label and keep a strong reference alive."""
        image = self.get(name, size)
        widget._momo_icon_ref = image
        if text is None:
            widget.configure(image=image)
        else:
            widget.configure(image=image, compound="left", text=text)
        return widget

    def button(self, parent, name: str, text: str = "", size: int = 16, **kwargs):
        button = tk.Button(parent, **kwargs)
        return self.apply(button, name, size, text)
