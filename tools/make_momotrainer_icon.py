from PIL import Image, ImageDraw, ImageFont, ImageFilter
from pathlib import Path

# Resolve assets/ relative to the repo root, not a hardcoded absolute
# path, so this keeps working wherever the repo is cloned.
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"
OUT.mkdir(parents=True, exist_ok=True)
S = 1024
img = Image.new("RGBA", (S, S), (8, 14, 32, 255))
p = img.load()
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * S)
        p[x, y] = (
            int(9 + 22 * t),
            int(17 + 27 * t),
            int(36 + 50 * t),
            255,
        )

# Soft aurora glow behind the mark.
glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
gd.ellipse((120, 105, 900, 885), fill=(0, 217, 239, 105))
gd.ellipse((300, 70, 1080, 850), fill=(124, 92, 255, 95))
glow = glow.filter(ImageFilter.GaussianBlur(110))
img = Image.alpha_composite(img, glow)

# Glass card.
draw = ImageDraw.Draw(img)
draw.rounded_rectangle((92, 92, 932, 932), radius=210, fill=(20, 31, 61, 218), outline=(150, 190, 255, 150), width=8)
draw.rounded_rectangle((132, 132, 892, 892), radius=178, outline=(102, 217, 239, 95), width=4)

# Orbit / crosshair motif.
draw.ellipse((215, 215, 809, 809), outline=(102, 217, 239, 175), width=12)
draw.arc((170, 280, 854, 744), start=205, end=335, fill=(167, 139, 250, 220), width=18)
draw.arc((170, 280, 854, 744), start=25, end=155, fill=(167, 139, 250, 220), width=18)
draw.line((512, 170, 512, 854), fill=(235, 245, 255, 75), width=4)
draw.line((170, 512, 854, 512), fill=(235, 245, 255, 75), width=4)

# Clean M mark.
try:
    font = ImageFont.truetype("C:/Windows/Fonts/seguisb.ttf", 360)
except OSError:
    font = ImageFont.load_default()
text = "M"
bbox = draw.textbbox((0, 0), text, font=font, stroke_width=0)
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
tx, ty = (S - tw) // 2, (S - th) // 2 - 18
draw.text((tx, ty), text, font=font, fill=(245, 250, 255, 255), stroke_width=2, stroke_fill=(102, 217, 239, 220))

# Small status dot.
draw.ellipse((744, 206, 812, 274), fill=(85, 230, 165, 255), outline=(225, 255, 245, 220), width=5)

# ICO with multiple sizes + transparent PNG mark.
img.save(OUT / "momotrainer_icon.ico", format="ICO", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
img.resize((256, 256), Image.Resampling.LANCZOS).save(OUT / "momotrainer_icon.png")
img.crop((250, 250, 774, 774)).resize((256, 256), Image.Resampling.LANCZOS).save(OUT / "momotrainer_mark.png")
print("Wrote", OUT / "momotrainer_icon.ico")
print("Wrote", OUT / "momotrainer_icon.png")
print("Wrote", OUT / "momotrainer_mark.png")
