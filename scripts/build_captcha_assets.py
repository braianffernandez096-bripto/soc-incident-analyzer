"""Genera las figuras del captcha (dispositivos y animales) con Pillow.

Son ilustraciones originales dibujadas con primitivas (sin imágenes de terceros, sin licencias, sin internet).
Salida: backend/captcha_assets/<nombre>.png (RGBA, 256x256). Se versionan en el repo; este script permite regenerarlas.

    python scripts/build_captcha_assets.py            # escribe los PNG
    python scripts/build_captcha_assets.py --sheet x.png   # además guarda una hoja de contacto para revisarlas
"""
import argparse
import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "backend" / "captcha_assets"
BIG, SIZE = 1024, 256          # se dibuja a 1024 y se reduce a 256 (suavizado)
INK = "#1f2933"
W = 14                         # grosor del contorno


class Canvas:
    def __init__(self):
        self.im = Image.new("RGBA", (BIG, BIG), (0, 0, 0, 0))
        self.d = ImageDraw.Draw(self.im)

    def rr(self, box, fill, r=30, w=W):
        self.d.rounded_rectangle(box, r, fill=fill, outline=INK, width=w)

    def el(self, box, fill, w=W):
        self.d.ellipse(box, fill=fill, outline=INK, width=w)

    def poly(self, pts, fill, w=W):
        self.d.polygon(pts, fill=fill)
        self.d.line(list(pts) + [pts[0]], fill=INK, width=w, joint="curve")

    def line(self, pts, w=W, fill=INK):
        self.d.line(pts, fill=fill, width=w, joint="curve")
        for p in (pts[0], pts[-1]):
            self.d.ellipse((p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2), fill=fill)

    def arc(self, box, a0, a1, w=W, fill=INK):
        self.d.arc(box, a0, a1, fill=fill, width=w)

    def done(self):
        return self.im.resize((SIZE, SIZE), Image.LANCZOS)


# ------------------------------------------------------------------ dispositivos
def router():
    c = Canvas()
    for x0, x1 in ((250, 190), (750, 810)):
        c.line([(x0, 560), (x1, 200)], w=26)
        c.el((x1 - 38, 160, x1 + 38, 236), "#ef4444")
    c.rr((80, 540, 920, 780), "#3b82f6", r=50)
    for i in range(4):
        c.el((170 + i * 90, 640, 230 + i * 90, 700), "#22c55e", w=10)
    c.rr((600, 625, 860, 705), "#1e3a8a", r=18, w=10)
    for i in range(3):
        c.d.rectangle((630 + i * 75, 645, 665 + i * 75, 685), fill="#facc15")
    c.arc((380, 330, 620, 570), 225, 315, w=18)
    c.arc((330, 280, 670, 620), 225, 315, w=18)
    return c.done()


def switch():
    c = Canvas()
    c.rr((40, 360, 960, 680), "#64748b", r=40)
    for row, y in enumerate((420, 540)):
        for i in range(8):
            x = 90 + i * 105
            c.d.rectangle((x, y, x + 78, y + 90), fill="#0f172a", outline=INK, width=8)
            c.d.rectangle((x + 14, y + 52, x + 64, y + 78), fill="#facc15")
    for i in range(4):
        c.el((70 + i * 36, 380, 94 + i * 36, 404), "#22c55e", w=6)
    return c.done()


def smartphone():
    c = Canvas()
    c.rr((300, 70, 700, 940), "#111827", r=80)
    c.rr((328, 170, 672, 830), "#7dd3fc", r=24, w=8)
    colors = ["#ef4444", "#f59e0b", "#22c55e", "#3b82f6", "#a855f7", "#ec4899", "#14b8a6", "#eab308", "#6366f1"]
    for i, col in enumerate(colors):
        x, y = 350 + (i % 3) * 100, 210 + (i // 3) * 110
        c.rr((x, y, x + 72, y + 72), col, r=18, w=6)
    c.el((482, 108, 518, 144), "#374151", w=6)
    c.rr((430, 870, 570, 890), "#9ca3af", r=10, w=4)
    return c.done()


def laptop():
    c = Canvas()
    c.rr((170, 150, 830, 650), "#334155", r=34)
    c.rr((210, 190, 790, 610), "#bae6fd", r=14, w=8)
    for i, w_ in enumerate((420, 330, 380)):
        c.d.rectangle((250, 240 + i * 60, 250 + w_, 270 + i * 60), fill="#38bdf8")
    c.d.rectangle((250, 430, 470, 570), fill="#fb923c")
    c.rr((50, 650, 950, 750), "#94a3b8", r=36)
    c.rr((400, 650, 600, 682), "#475569", r=12, w=8)
    return c.done()


def desktop():
    c = Canvas()
    c.rr((60, 150, 640, 620), "#334155", r=30)
    c.rr((95, 185, 605, 585), "#a7f3d0", r=12, w=8)
    c.d.polygon([(140, 540), (250, 330), (330, 470), (400, 380), (560, 540)], fill="#10b981")
    c.el((470, 220, 550, 300), "#fde047", w=8)
    c.rr((310, 620, 390, 730), "#64748b", r=10, w=10)
    c.rr((200, 725, 500, 785), "#64748b", r=22)
    c.rr((690, 210, 940, 790), "#e5e7eb", r=34)
    c.rr((730, 270, 900, 310), "#6b7280", r=8, w=8)
    c.rr((730, 340, 900, 380), "#6b7280", r=8, w=8)
    c.el((790, 650, 850, 710), "#22c55e", w=10)
    return c.done()


def server():
    c = Canvas()
    c.rr((200, 60, 800, 940), "#1e293b", r=36)
    for i in range(4):
        y = 100 + i * 210
        c.rr((235, y, 765, y + 170), "#cbd5e1", r=14, w=10)
        for j in range(5):
            c.d.rectangle((270 + j * 62, y + 40, 312 + j * 62, y + 130), fill="#475569", outline=INK, width=6)
        c.el((640, y + 60, 690, y + 110), "#22c55e" if i != 2 else "#ef4444", w=8)
        c.d.rectangle((705, y + 50, 745, y + 66), fill=INK)
        c.d.rectangle((705, y + 104, 745, y + 120), fill=INK)
    return c.done()


def printer():
    c = Canvas()
    c.rr((260, 140, 740, 420), "#ffffff", r=10, w=10)
    for i in range(3):
        c.d.rectangle((310, 210 + i * 50, 690 - i * 60, 228 + i * 50), fill="#9ca3af")
    c.rr((80, 380, 920, 740), "#d1d5db", r=50)
    c.rr((130, 450, 870, 520), "#374151", r=18, w=10)
    c.rr((640, 590, 860, 690), "#1f2937", r=14, w=10)
    c.el((680, 620, 720, 660), "#22c55e", w=6)
    c.rr((230, 700, 770, 930), "#ffffff", r=10, w=10)
    for i in range(3):
        c.d.rectangle((290, 770 + i * 44, 710 - i * 70, 788 + i * 44), fill="#9ca3af")
    return c.done()


def keyboard():
    c = Canvas()
    c.rr((40, 290, 960, 720), "#475569", r=50)
    for r_ in range(4):
        n = 10 if r_ < 3 else 0
        for i in range(n):
            x, y = 90 + i * 84 + (r_ % 2) * 20, 335 + r_ * 85
            c.rr((x, y, x + 66, y + 66), "#e2e8f0", r=12, w=8)
    c.rr((200, 590, 700, 656), "#e2e8f0", r=12, w=8)
    c.rr((90, 590, 180, 656), "#fbbf24", r=12, w=8)
    c.rr((720, 590, 900, 656), "#e2e8f0", r=12, w=8)
    return c.done()


# ------------------------------------------------------------------ animales
def cat():
    c = Canvas()
    c.poly([(190, 440), (210, 110), (440, 290)], "#f59e0b")
    c.poly([(810, 440), (790, 110), (560, 290)], "#f59e0b")
    c.poly([(250, 350), (262, 210), (360, 295)], "#fbcfe8", w=6)
    c.poly([(750, 350), (738, 210), (640, 295)], "#fbcfe8", w=6)
    c.el((170, 250, 830, 880), "#f59e0b")
    for x in (350, 650):
        c.el((x - 70, 430, x + 70, 570), "#bef264", w=10)
        c.d.ellipse((x - 16, 440, x + 16, 560), fill=INK)
    c.poly([(470, 620), (530, 620), (500, 665)], "#f472b6", w=8)
    c.line([(500, 665), (500, 710)], w=8)
    c.arc((410, 690, 500, 770), 0, 180, w=8)
    c.arc((500, 690, 590, 770), 0, 180, w=8)
    for dy in (-25, 20):
        c.line([(150, 690 + dy), (350, 665 + dy * 0.5)], w=6)
        c.line([(850, 690 + dy), (650, 665 + dy * 0.5)], w=6)
    for x in (400, 500, 600):
        c.line([(x, 275), (x, 335)], w=12, fill="#b45309")
    return c.done()


def fish():
    c = Canvas()
    c.poly([(740, 500), (960, 300), (930, 500), (960, 700)], "#fb923c")
    c.poly([(380, 330), (500, 170), (650, 340)], "#fb923c")
    c.poly([(420, 680), (480, 800), (600, 690)], "#fb923c")
    c.el((80, 290, 800, 720), "#f97316")
    c.arc((380, 330, 560, 690), 100, 260, w=12)
    for r_ in range(3):
        for i in range(3):
            x, y = 530 + i * 85, 400 + r_ * 85 + (i % 2) * 30
            c.arc((x, y, x + 70, y + 70), 180, 360, w=8)
    c.el((190, 410, 290, 510), "#ffffff", w=10)
    c.el((225, 440, 265, 480), INK, w=2)
    c.line([(95, 560), (160, 575)], w=10)
    return c.done()


def owl():
    c = Canvas()
    c.poly([(260, 280), (250, 100), (400, 220)], "#92400e")
    c.poly([(740, 280), (750, 100), (600, 220)], "#92400e")
    c.el((200, 180, 800, 900), "#a16207")
    c.el((290, 520, 710, 870), "#fde68a", w=10)
    for i in range(3):
        for j in range(3):
            c.arc((350 + j * 100, 590 + i * 85, 430 + j * 100, 660 + i * 85), 20, 160, w=8)
    c.el((120, 400, 300, 760), "#78350f")
    c.el((700, 400, 880, 760), "#78350f")
    for x in (385, 615):
        c.el((x - 115, 270, x + 115, 500), "#fffbeb")
        c.el((x - 50, 335, x + 50, 435), INK, w=2)
        c.el((x - 18, 355, x + 6, 379), "#ffffff", w=2)
    c.poly([(450, 480), (550, 480), (500, 575)], "#f97316")
    c.poly([(380, 900), (330, 960), (440, 960)], "#f97316", w=8)
    c.poly([(620, 900), (560, 960), (670, 960)], "#f97316", w=8)
    return c.done()


def rabbit():
    c = Canvas()
    c.el((290, 40, 450, 520), "#e5e7eb")
    c.el((550, 40, 710, 520), "#e5e7eb")
    c.el((330, 120, 410, 450), "#fbcfe8", w=6)
    c.el((590, 120, 670, 450), "#fbcfe8", w=6)
    c.el((220, 400, 780, 940), "#e5e7eb")
    for x in (390, 610):
        c.el((x - 36, 560, x + 36, 632), INK, w=2)
        c.el((x - 12, 574, x + 8, 594), "#ffffff", w=2)
    c.poly([(465, 670), (535, 670), (500, 710)], "#f472b6", w=8)
    c.line([(500, 710), (500, 750)], w=8)
    c.arc((420, 720, 500, 790), 0, 180, w=8)
    c.arc((500, 720, 580, 790), 0, 180, w=8)
    c.rr((465, 770, 535, 850), "#ffffff", r=10, w=8)
    c.line([(500, 775), (500, 850)], w=6)
    for dy in (-20, 20):
        c.line([(240, 720 + dy), (400, 710 + dy * 0.4)], w=6)
        c.line([(760, 720 + dy), (600, 710 + dy * 0.4)], w=6)
    return c.done()


def turtle():
    c = Canvas()
    c.poly([(190, 640), (70, 700), (200, 700)], "#65a30d", w=10)
    c.el((780, 440, 960, 640), "#84cc16")
    c.el((870, 490, 905, 525), INK, w=2)
    c.line([(905, 590), (940, 585)], w=8)
    for x0 in (250, 620):
        c.el((x0, 640, x0 + 130, 830), "#84cc16")
    c.rr((170, 590, 830, 690), "#fde68a", r=40)
    c.d.pieslice((140, 250, 860, 940), 180, 360, fill="#16a34a", outline=INK, width=W)
    c.d.line([(140, 595), (860, 595)], fill=INK, width=W)
    hexa = [(500, 300), (640, 380), (640, 520), (500, 590), (360, 520), (360, 380)]
    c.poly(hexa, "#4ade80", w=10)
    for p in hexa[:3] + hexa[4:]:
        ang = math.atan2(p[1] - 445, p[0] - 500)
        c.line([p, (p[0] + 90 * math.cos(ang), p[1] + 90 * math.sin(ang))], w=10)
    return c.done()


def snail():
    c = Canvas()
    c.rr((70, 560, 900, 720), "#fcd34d", r=80)
    c.el((730, 400, 910, 640), "#fcd34d")
    c.line([(790, 420), (760, 250)], w=12)
    c.line([(870, 430), (910, 270)], w=12)
    c.el((730, 215, 790, 275), "#fcd34d", w=10)
    c.el((880, 235, 940, 295), "#fcd34d", w=10)
    c.el((835, 470, 875, 510), INK, w=2)
    c.line([(850, 585), (895, 580)], w=8)
    c.el((170, 130, 690, 650), "#b45309")
    for i, r_ in enumerate((200, 135, 75, 25)):
        cx, cy = 430, 390
        c.arc((cx - r_, cy - r_, cx + r_, cy + r_), 30 + i * 25, 330 + i * 25, w=14)
    return c.done()


def duck():
    c = Canvas()
    c.poly([(170, 540), (40, 440), (60, 640), (190, 700)], "#facc15")
    c.el((130, 430, 780, 820), "#facc15")
    c.d.pieslice((250, 520, 640, 800), 0, 180, fill="#fde047", outline=INK, width=10)
    c.el((560, 150, 840, 450), "#facc15")
    c.el((810, 290, 990, 380), "#f97316", w=12)
    c.el((690, 240, 740, 290), INK, w=2)
    c.line([(400, 830), (400, 930)], w=12)
    c.line([(580, 830), (580, 930)], w=12)
    c.poly([(400, 930), (310, 940), (330, 910)], "#f97316", w=8)
    c.poly([(580, 930), (490, 940), (510, 910)], "#f97316", w=8)
    return c.done()


def elephant():
    c = Canvas()
    c.el((40, 230, 360, 700), "#94a3b8")
    c.el((640, 230, 960, 700), "#94a3b8")
    c.el((90, 300, 320, 620), "#fbcfe8", w=8)
    c.el((680, 300, 910, 620), "#fbcfe8", w=8)
    c.el((230, 150, 770, 720), "#94a3b8")
    trunk = [(500, 560), (500, 800), (570, 900), (660, 880)]
    c.line(trunk, w=170, fill=INK)
    c.line(trunk, w=142, fill="#94a3b8")
    c.el((230, 150, 770, 720), "#94a3b8")
    for x in (400, 600):
        c.el((x - 24, 380, x + 24, 428), INK, w=2)
    c.poly([(330, 620), (290, 800), (380, 700)], "#ffffff", w=10)
    c.poly([(670, 620), (710, 800), (620, 700)], "#ffffff", w=10)
    return c.done()


FIGURES = {f.__name__: f for f in (router, switch, smartphone, laptop, desktop, server, printer, keyboard,
                                   cat, fish, owl, rabbit, turtle, snail, duck, elephant)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sheet", help="guarda una hoja de contacto (PNG) para revisar visualmente las figuras")
    args = ap.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    tiles = []
    for name, fn in FIGURES.items():
        im = fn()
        im.save(OUT / f"{name}.png", optimize=True)
        tiles.append((name, im))
    if args.sheet:
        cols = 4
        rows = math.ceil(len(tiles) / cols)
        sheet = Image.new("RGB", (cols * SIZE, rows * SIZE), "#f1f5f9")
        for i, (_, im) in enumerate(tiles):
            sheet.paste(im, ((i % cols) * SIZE, (i // cols) * SIZE), im)
        sheet.save(args.sheet)
    print(f"{len(tiles)} figuras en {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
