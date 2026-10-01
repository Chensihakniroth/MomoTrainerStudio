from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

# Resolve assets/ relative to the repo root, not a hardcoded absolute
# path, so this keeps working wherever the repo is cloned.
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "icons"
OUT.mkdir(parents=True, exist_ok=True)
S = 64
FG = (156, 196, 255, 255)
CYAN = (102, 217, 239, 255)
VIOLET = (167, 139, 250, 255)
GREEN = (85, 230, 165, 255)
YELLOW = (255, 200, 87, 255)
RED = (239, 107, 115, 255)
WHITE = (235, 245, 255, 255)
DARK = (10, 16, 32, 0)


def icon(name, kind, color=FG):
    im = Image.new("RGBA", (S, S), DARK)
    d = ImageDraw.Draw(im)
    c = color
    w = 4
    if kind == "table":
        d.rounded_rectangle((10, 13, 54, 51), 5, outline=c, width=w)
        d.line((10, 25, 54, 25), fill=c, width=w)
        d.line((32, 25, 32, 51), fill=c, width=w)
    elif kind == "dna":
        d.arc((16, 9, 48, 55), 90, 270, fill=c, width=w)
        d.arc((16, 9, 48, 55), 270, 90, fill=VIOLET, width=w)
        d.line((20, 16, 44, 48), fill=c, width=3)
        d.line((44, 16, 20, 48), fill=c, width=3)
        d.line((19, 22, 45, 22), fill=c, width=3)
        d.line((19, 42, 45, 42), fill=c, width=3)
    elif kind == "engine":
        d.ellipse((10, 10, 54, 54), outline=c, width=w)
        d.ellipse((23, 23, 41, 41), outline=c, width=3)
        d.line((32, 4, 32, 14), fill=c, width=w)
        d.line((32, 50, 32, 60), fill=c, width=w)
        d.line((4, 32, 14, 32), fill=c, width=w)
        d.line((50, 32, 60, 32), fill=c, width=w)
    elif kind == "search":
        d.ellipse((11, 11, 42, 42), outline=c, width=w)
        d.line((39, 39, 55, 55), fill=c, width=w)
    elif kind == "ruler":
        d.rounded_rectangle((9, 21, 55, 43), 4, outline=c, width=w)
        for x in (18, 27, 36, 45):
            d.line((x, 21, x, 31), fill=c, width=2)
    elif kind == "add":
        d.line((32, 12, 32, 52), fill=c, width=w)
        d.line((12, 32, 52, 32), fill=c, width=w)
    elif kind == "freeze":
        d.line((32, 9, 32, 55), fill=CYAN, width=w)
        d.line((13, 20, 51, 44), fill=CYAN, width=3)
        d.line((51, 20, 13, 44), fill=CYAN, width=3)
        d.ellipse((25, 25, 39, 39), outline=VIOLET, width=3)
    elif kind == "edit":
        d.line((16, 46, 21, 51, 48, 24, 41, 17, 16, 46), fill=c, width=3)
        d.line((38, 15, 45, 8, 52, 15, 45, 22), fill=VIOLET, width=3)
    elif kind == "pointer":
        d.line((16, 12, 47, 43), fill=c, width=w)
        d.line((47, 43, 38, 39), fill=c, width=w)
        d.line((47, 43, 43, 34), fill=c, width=w)
        d.ellipse((10, 8, 22, 20), outline=VIOLET, width=3)
    elif kind == "eye":
        d.ellipse((7, 22, 57, 42), outline=c, width=w)
        d.ellipse((26, 26, 38, 38), fill=VIOLET)
    elif kind == "remove":
        d.line((17, 17, 47, 47), fill=RED, width=w)
        d.line((47, 17, 17, 47), fill=RED, width=w)
    elif kind == "clear":
        d.rounded_rectangle((12, 14, 52, 50), 5, outline=c, width=w)
        d.line((21, 25, 43, 25), fill=RED, width=3)
        d.line((21, 33, 43, 33), fill=RED, width=3)
    elif kind == "play":
        d.polygon([(22, 13), (51, 32), (22, 51)], fill=GREEN)
    elif kind == "stop":
        d.rounded_rectangle((16, 16, 48, 48), 5, fill=RED)
    elif kind == "folder":
        d.polygon([(9, 23), (28, 23), (33, 28), (55, 28), (48, 50), (14, 50)], fill=c)
    elif kind == "build":
        d.rectangle((13, 26, 50, 51), outline=c, width=w)
        d.line((19, 26, 19, 14, 28, 14, 28, 26), fill=VIOLET, width=w)
        d.line((36, 26, 36, 14, 45, 14, 45, 26), fill=VIOLET, width=w)
        d.line((13, 36, 50, 36), fill=c, width=3)
    elif kind == "open":
        d.line((14, 51, 23, 14, 41, 14, 50, 51), fill=c, width=w)
        d.line((11, 51, 53, 51), fill=VIOLET, width=w)
    elif kind == "upload":
        d.line((32, 46, 32, 16), fill=c, width=w)
        d.line((21, 27, 32, 16, 43, 27), fill=c, width=w)
        d.arc((13, 9, 51, 47), 210, 330, fill=VIOLET, width=3)
    elif kind == "record":
        d.ellipse((19, 19, 45, 45), fill=RED)
    elif kind == "gear":
        d.ellipse((18, 18, 46, 46), outline=c, width=w)
        d.ellipse((28, 28, 36, 36), outline=c, width=3)
        for x, y in ((32, 6), (32, 52), (6, 32), (52, 32)):
            d.line((32, 32, x, y), fill=VIOLET, width=w)
    elif kind == "bolt":
        d.polygon([(36, 5), (17, 35), (29, 35), (25, 59), (48, 27), (35, 27)], fill=YELLOW)
    elif kind == "structure":
        for x, y in ((10, 10), (34, 10), (10, 34), (34, 34)):
            d.rectangle((x, y, x + 19, y + 19), outline=c, width=3)
    elif kind == "save":
        d.rounded_rectangle((12, 10, 52, 54), 4, outline=c, width=w)
        d.rectangle((20, 10, 44, 23), fill=VIOLET)
        d.rectangle((20, 33, 44, 54), outline=c, width=3)
    elif kind == "load":
        d.rounded_rectangle((12, 10, 52, 54), 4, outline=c, width=w)
        d.line((20, 32, 43, 32), fill=c, width=3)
        d.line((37, 25, 45, 32, 37, 39), fill=GREEN, width=3)
    elif kind == "window":
        d.rounded_rectangle((10, 13, 54, 51), 4, outline=c, width=w)
        d.line((10, 25, 54, 25), fill=VIOLET, width=3)
        d.ellipse((16, 18, 20, 22), fill=GREEN)
    elif kind == "export":
        d.line((14, 50, 14, 15, 38, 15), fill=c, width=w)
        d.line((14, 50, 48, 50, 48, 27), fill=c, width=w)
        d.line((29, 32, 49, 12), fill=GREEN, width=w)
        d.line((39, 12, 49, 12, 49, 22), fill=GREEN, width=w)
    elif kind == "map":
        d.polygon([(8, 17), (23, 10), (41, 17), (56, 10), (56, 47), (41, 54), (23, 47), (8, 54)], outline=c)
        d.line((23, 10, 23, 47), fill=VIOLET, width=3)
        d.line((41, 17, 41, 54), fill=VIOLET, width=3)
    elif kind == "book":
        d.polygon([(11, 13), (32, 18), (32, 53), (11, 48)], fill=c)
        d.polygon([(53, 13), (32, 18), (32, 53), (53, 48)], fill=VIOLET)
    elif kind == "box":
        d.polygon([(32, 7), (55, 20), (32, 33), (9, 20)], outline=c)
        d.polygon([(9, 20), (32, 33), (32, 57), (9, 44)], outline=c)
        d.polygon([(55, 20), (32, 33), (32, 57), (55, 44)], outline=c)
    elif kind == "breakpoint":
        d.ellipse((20, 20, 44, 44), outline=RED, width=w)
        d.line((32, 8, 32, 20), fill=RED, width=w)
        d.line((32, 44, 32, 56), fill=RED, width=w)
        d.line((8, 32, 20, 32), fill=RED, width=w)
        d.line((44, 32, 56, 32), fill=RED, width=w)
    elif kind == "group":
        for x, y in ((9, 12), (34, 12), (21, 34), (9, 52), (34, 52)):
            d.ellipse((x, y, x + 16, y + 16), outline=c, width=3)
        d.line((25, 20, 34, 20), fill=VIOLET, width=3)
    else:
        d.ellipse((12, 12, 52, 52), outline=c, width=w)
    im.save(OUT / f"{name}.png")

names = {
    "table": "table", "dll": "dna", "engine": "engine", "search": "search", "ruler": "ruler",
    "add": "add", "freeze": "freeze", "edit": "edit", "pointer": "pointer", "eye": "eye",
    "remove": "remove", "clear": "clear", "play": "play", "stop": "stop", "folder": "folder",
    "build": "build", "open": "open", "upload": "upload", "record": "record", "gear": "gear",
    "bolt": "bolt", "structure": "structure", "save": "save", "load": "load", "window": "window",
    "export": "export", "map": "map", "book": "book", "box": "box", "breakpoint": "breakpoint",
    "group": "group", "attach": "engine",
}
for name, kind in names.items():
    icon(name, kind)
print("Wrote", len(names), "icons to", OUT)
