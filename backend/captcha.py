"""Captcha local de imágenes (opcional, apagado por defecto: CAPTCHA=on lo activa).

Funcionamiento: se muestran 6 imágenes; 3 son la misma figura (en distintas rotaciones, colores y ruido) y 3 son figuras
distintas. La persona marca las 3 que muestran lo mismo. Todo ocurre en el propio servidor: sin servicios de terceros,
sin internet, sin claves.

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

from PIL import Image, ImageChops, ImageDraw, ImageEnhance

ASSETS = Path(__file__).parent / "captcha_assets"
TILE = 168                  # lado de cada imagen entregada (px)
GRID, TARGETS = 6, 3        # 6 imágenes, 3 correctas
CHALLENGE_TTL = 180         # segundos para resolver un desafío
PASS_TTL = 120              # el pase solo cubre el envío inmediato del archivo tras resolver el captcha
PASS_USES = 1               # un análisis por captcha
MAX_PENDING = 500           # tope de desafíos/pases en memoria (evita agotar memoria pidiendo desafíos)
PROMPT = "Marca las 3 imágenes que muestran la misma figura. Pueden estar giradas o tener otro color."

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


def new_challenge() -> dict:
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
    return {"token": token, "images": images, "prompt": PROMPT, "expires_in": CHALLENGE_TTL}


def verify(token: str, selected: list[int], ip: str = "") -> str | None:
    """Devuelve un pase si la selección es exacta; None si no. El desafío se consume siempre (un intento por desafío)."""
    now = time.time()
    with _lock:
        entry = _challenges.pop(token, None)
    if not entry or entry[1] < now:
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
