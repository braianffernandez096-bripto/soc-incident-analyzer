"""Captcha local (opcional, apagado por defecto: CAPTCHA=on lo activa). Dos tipos; CAPTCHA_TYPE elige:
``imagenes`` · ``rompecabezas`` · ``aleatorio`` (por defecto: el servidor sortea uno en cada desafío).

- Imágenes: se muestran 6; 3 son la misma figura (en distintas rotaciones, colores y ruido) y 3 son figuras distintas.
  La persona marca las 3 que muestran lo mismo.
- Rompecabezas: una escena con un hueco y una pieza que se desliza hasta encajarla. La posición del hueco solo vive en el
  servidor; se acepta con unos píxeles de tolerancia y se revisa de forma básica que el arrastre sea un movimiento (no un salto).

Todo ocurre en el propio servidor: sin servicios de terceros, sin internet, sin claves.

- La respuesta correcta vive solo en el servidor, ligada a un token de un solo uso que caduca (CHALLENGE_TTL).
- Acertar entrega un «pase» de UN solo uso, ligado a la IP y válido apenas unos segundos (lo justo para enviar el archivo);
  se manda en la cabecera X-Captcha-Pass. Cada análisis pide su propio captcha; ver los resultados no depende de ningún tiempo.
- Cada imagen se re-renderiza al azar en cada desafío (rotación, escala, color, fondo, ruido): no hay dos iguales byte a byte.
- Límites honestos: frena bots genéricos; no detiene a un atacante dirigido. No sustituye a APP_ACCESS_TOKEN.
"""
from __future__ import annotations

import base64
import io
import os
import random
import secrets
import threading
import time
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter, ImageOps

ASSETS = Path(__file__).parent / "captcha_assets"
TILE = 168                  # lado de cada imagen entregada (px)
GRID, TARGETS = 6, 3        # 6 imágenes, 3 correctas
CHALLENGE_TTL = 180         # segundos para resolver un desafío
PASS_TTL = 120              # el pase solo cubre el envío inmediato del archivo tras resolver el captcha
PASS_USES = 1               # un análisis por captcha
MAX_PENDING = 500           # tope de desafíos/pases en memoria (evita agotar memoria pidiendo desafíos)
PROMPT = "Marca las 3 imágenes que muestran la misma figura. Pueden estar giradas o tener otro color."
PUZZLE_PROMPT = "Desliza la pieza hasta que encaje en el hueco de la imagen."
TYPES = ("imagenes", "rompecabezas")
PUZ_W, PUZ_H, PW = 320, 160, 64     # escena y pieza (px)
TOL = 6                             # tolerancia de encaje (px)
MIN_DRAG_MS, MAX_DRAG_MS, MIN_SAMPLES = 300, 90_000, 5

_rng = random.SystemRandom()
_lock = threading.Lock()
_challenges: dict[str, tuple[frozenset[int], float]] = {}
_passes: dict[str, list] = {}           # pase -> [caduca, usos_restantes, ip]
_cache: dict[str, Image.Image] = {}


def enabled() -> bool:
    return os.environ.get("CAPTCHA", "").strip().lower() in ("1", "true", "yes", "on")


def reset() -> None:
    """Vacía el estado (pruebas)."""
    with _lock:
        _challenges.clear()
        _passes.clear()


def figures() -> list[str]:
    return sorted(p.stem for p in ASSETS.glob("*.png"))


def _base(name: str) -> Image.Image:
    if name not in _cache:
        with Image.open(ASSETS / f"{name}.png") as im:
            _cache[name] = im.convert("RGBA")
    return _cache[name]


def _hue_shift(im: Image.Image, shift: int) -> Image.Image:
    a = im.getchannel("A")
    h, s, v = im.convert("RGB").convert("HSV").split()
    h = h.point(lambda x: (x + shift) % 256)
    out = Image.merge("HSV", (h, s, v)).convert("RGB").convert("RGBA")
    out.putalpha(a)
    return out


def render_tile(name: str, quarter_turns: int, rng: random.Random | None = None) -> bytes:
    """Una imagen del desafío (JPEG): la figura girada n·90° (+ pequeña inclinación), con color, escala, fondo y ruido al azar."""
    rng = rng or _rng
    im = _hue_shift(_base(name), rng.randint(-14, 14))
    im = ImageEnhance.Brightness(im).enhance(rng.uniform(0.92, 1.08))
    im = im.rotate(quarter_turns * 90 + rng.uniform(-9, 9), resample=Image.BICUBIC, expand=True)
    box = im.getbbox()
    if box:
        im = im.crop(box)
    side = int(TILE * rng.uniform(0.62, 0.84))
    im.thumbnail((side, side), Image.LANCZOS)
    base = rng.randint(222, 244)
    bg = Image.new("RGB", (TILE, TILE), (base - rng.randint(0, 10), base - rng.randint(0, 10), base - rng.randint(0, 10)))
    d = ImageDraw.Draw(bg)
    for _ in range(rng.randint(5, 9)):                    # trazos y puntos de fondo: estorban a un detector simple
        c = base - rng.randint(18, 40)
        p = [(rng.randint(0, TILE), rng.randint(0, TILE)) for _ in range(2)]
        if rng.random() < 0.6:
            d.line(p, fill=(c, c, c), width=rng.randint(1, 3))
        else:
            d.ellipse((p[0][0], p[0][1], p[0][0] + 10, p[0][1] + 10), outline=(c, c, c))
    x = (TILE - im.width) // 2 + rng.randint(-8, 8)
    y = (TILE - im.height) // 2 + rng.randint(-8, 8)
    bg.paste(im, (max(0, x), max(0, y)), im)
    noise = Image.effect_noise((TILE, TILE), rng.uniform(14, 24)).convert("RGB")
    bg = ImageChops.add(bg, noise, scale=1.0, offset=-128)
    out = io.BytesIO()
    bg.save(out, "JPEG", quality=82)
    return out.getvalue()


def _purge(now: float) -> None:
    for k in [k for k, (_, exp) in _challenges.items() if exp < now]:
        _challenges.pop(k, None)
    for k in [k for k, v in _passes.items() if v[0] < now or v[1] <= 0]:
        _passes.pop(k, None)
    while len(_challenges) >= MAX_PENDING:                # tope duro: descarta el más antiguo
        _challenges.pop(min(_challenges, key=lambda k: _challenges[k][1]))
    while len(_passes) >= MAX_PENDING:
        _passes.pop(min(_passes, key=lambda k: _passes[k][0]))


def _new_images() -> dict:
    names = figures()
    if len(names) < GRID - TARGETS + 1:
        raise RuntimeError("Faltan las figuras del captcha (backend/captcha_assets).")
    target, *others = _rng.sample(names, 1 + (GRID - TARGETS))
    turns = _rng.sample(range(4), TARGETS)                # las 3 correctas, con orientaciones distintas
    tiles = [(target, t, True) for t in turns] + [(o, _rng.randrange(4), False) for o in others]
    _rng.shuffle(tiles)
    answer = frozenset(i for i, (_, _, ok) in enumerate(tiles) if ok)
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _lock:
        _purge(now)
        _challenges[token] = (answer, now + CHALLENGE_TTL)
    images = ["data:image/jpeg;base64," + base64.b64encode(render_tile(n, t)).decode() for n, t, _ in tiles]
    return {"type": "images", "token": token, "images": images, "prompt": PROMPT, "expires_in": CHALLENGE_TTL}


# ---------------------------------------------------------------- rompecabezas deslizante
def captcha_type() -> str:
    v = os.environ.get("CAPTCHA_TYPE", "").strip().lower()
    return v if v in TYPES else "aleatorio"


def _mask(variant: int) -> Image.Image:
    """Forma de pieza de puzle: cuadrado con una lengüeta (arriba, derecha, izquierda o abajo)."""
    m = Image.new("L", (PW, PW), 0)
    d = ImageDraw.Draw(m)
    body, tab = {0: ((10, 12, 54, 56), (24, 2, 40, 18)), 1: ((6, 12, 50, 56), (46, 26, 62, 42)),
                 2: ((14, 12, 58, 56), (2, 26, 18, 42)), 3: ((10, 6, 54, 50), (24, 46, 40, 62))}[variant % 4]
    d.rounded_rectangle(body, 6, fill=255)
    d.ellipse(tab, fill=255)
    return m


def _scene(rng: random.Random) -> Image.Image:
    """Fondo con detalle (degradado, formas y figuras giradas): un hueco sobre un fondo liso se detectaría trivialmente."""
    c1 = tuple(rng.randint(30, 200) for _ in range(3))
    c2 = tuple(rng.randint(60, 240) for _ in range(3))
    grad = Image.linear_gradient("L")
    if rng.random() < 0.5:
        grad = grad.transpose(Image.ROTATE_90)
    img = ImageOps.colorize(grad.resize((PUZ_W, PUZ_H)), c1, c2).convert("RGBA")
    over = Image.new("RGBA", (PUZ_W, PUZ_H), (0, 0, 0, 0))
    d = ImageDraw.Draw(over)
    for _ in range(rng.randint(10, 16)):
        x, y, r = rng.randint(0, PUZ_W), rng.randint(0, PUZ_H), rng.randint(14, 48)
        col = tuple(rng.randint(0, 255) for _ in range(3)) + (rng.randint(60, 140),)
        if rng.random() < 0.5:
            d.ellipse((x - r, y - r, x + r, y + r), fill=col)
        else:
            d.polygon([(x + rng.randint(-r, r), y + rng.randint(-r, r)) for _ in range(rng.randint(3, 5))], fill=col)
    img = Image.alpha_composite(img, over)
    names = figures()
    for name in rng.sample(names, min(len(names), rng.randint(4, 6))):
        fig = _hue_shift(_base(name), rng.randint(0, 255)).rotate(rng.uniform(0, 360), resample=Image.BICUBIC, expand=True)
        box = fig.getbbox()
        fig = fig.crop(box) if box else fig
        fig.thumbnail((rng.randint(46, 82),) * 2, Image.LANCZOS)
        img.alpha_composite(fig, (rng.randint(0, max(0, PUZ_W - fig.width)), rng.randint(0, max(0, PUZ_H - fig.height))))
    return img.convert("RGB")


def _new_puzzle() -> dict:
    rng = _rng
    bg = _scene(rng)
    tx = rng.randint(PW + 24, PUZ_W - PW - 6)
    ty = rng.randint(6, PUZ_H - PW - 6)
    variant = rng.randrange(4)
    mask = _mask(variant)
    edge = ImageChops.subtract(mask, mask.filter(ImageFilter.MinFilter(3)))
    region = bg.crop((tx, ty, tx + PW, ty + PW))
    piece = region.convert("RGBA")
    piece.putalpha(mask)
    rim = Image.new("RGBA", (PW, PW), (255, 255, 255, 0))
    rim.putalpha(edge.point(lambda v: int(v * 0.9)))
    piece = Image.alpha_composite(piece, rim)
    # hueco señuelo, con otra forma, lejos del verdadero
    far = [x for x in range(PW + 10, PUZ_W - PW - 4) if abs(x - tx) > PW + 10]
    if far:
        dx, dy = rng.choice(far), rng.randint(6, PUZ_H - PW - 6)
        dmask = _mask(variant + rng.randint(1, 3))
        dreg = bg.crop((dx, dy, dx + PW, dy + PW))
        bg.paste(Image.blend(dreg, Image.new("RGB", (PW, PW), (0, 0, 0)), 0.4), (dx, dy), dmask)
    bg.paste(Image.blend(region, Image.new("RGB", (PW, PW), (0, 0, 0)), 0.58), (tx, ty), mask)
    bg.paste((0, 0, 0), (tx, ty), edge.point(lambda v: int(v * 0.6)))
    noise = Image.effect_noise((PUZ_W, PUZ_H), rng.uniform(6, 12)).convert("RGB")
    bg = ImageChops.add(bg, noise, scale=1.0, offset=-128)
    out = io.BytesIO()
    bg.save(out, "JPEG", quality=85)
    pout = io.BytesIO()
    piece.save(pout, "PNG", optimize=True)
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _lock:
        _purge(now)
        _challenges[token] = (tx, now + CHALLENGE_TTL)
    return {"type": "puzzle", "token": token, "background": "data:image/jpeg;base64," + base64.b64encode(out.getvalue()).decode(),
            "piece": "data:image/png;base64," + base64.b64encode(pout.getvalue()).decode(), "piece_y": ty, "width": PUZ_W, "height": PUZ_H,
            "piece_size": PW, "prompt": PUZZLE_PROMPT, "expires_in": CHALLENGE_TTL}


def _plausible_drag(track, x: int) -> bool:
    """Control básico: el arrastre debe ser una secuencia de posiciones en el tiempo, no un salto instantáneo.
    Un bot decidido puede imitarlo: frena automatismos simples, no es una prueba de que haya un humano."""
    if not isinstance(track, list) or not MIN_SAMPLES <= len(track) <= 400:
        return False
    prev_t, xs = -1, set()
    for item in track:
        if not (isinstance(item, (list, tuple)) and len(item) == 2 and all(type(v) is int for v in item)):
            return False
        t, px = item
        if t < prev_t or not 0 <= t <= MAX_DRAG_MS or not 0 <= px <= PUZ_W:
            return False
        prev_t = t
        xs.add(px)
    duration = track[-1][0] - track[0][0]
    return MIN_DRAG_MS <= duration <= MAX_DRAG_MS and len(xs) >= 4 and abs(track[-1][1] - x) <= 2


def verify_puzzle(token: str, x, track, ip: str = "") -> str | None:
    """Pase si la pieza quedó dentro de la tolerancia y el arrastre es plausible. Un intento por desafío."""
    now = time.time()
    with _lock:
        entry = _challenges.pop(token, None)
    if not entry or entry[1] < now or type(entry[0]) is not int:
        return None
    if type(x) is not int or abs(x - entry[0]) > TOL or not _plausible_drag(track, x):
        return None
    grant = secrets.token_urlsafe(24)
    with _lock:
        _purge(now)
        _passes[grant] = [now + PASS_TTL, PASS_USES, ip]
    return grant


def new_challenge(kind: str | None = None) -> dict:
    kind = kind or captcha_type()
    if kind == "aleatorio":
        kind = _rng.choice(TYPES)
    return _new_puzzle() if kind == "rompecabezas" else _new_images()


def verify(token: str, selected: list[int], ip: str = "") -> str | None:
    """Devuelve un pase si la selección es exacta; None si no. El desafío se consume siempre (un intento por desafío)."""
    now = time.time()
    with _lock:
        entry = _challenges.pop(token, None)
    if not entry or entry[1] < now or not isinstance(entry[0], frozenset):
        return None
    if len(selected) != len(set(selected)) or any(type(i) is not int or not 0 <= i < GRID for i in selected):
        return None
    if frozenset(selected) != entry[0]:
        return None
    grant = secrets.token_urlsafe(24)
    with _lock:
        _purge(now)
        _passes[grant] = [now + PASS_TTL, PASS_USES, ip]
    return grant


def consume_pass(grant: str, ip: str = "") -> bool:
    now = time.time()
    with _lock:
        p = _passes.get(grant or "")
        if not p or p[0] < now or p[1] <= 0 or p[2] != ip:
            return False
        p[1] -= 1
        return True
