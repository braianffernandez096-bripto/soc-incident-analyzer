"""Captcha local de imágenes: figuras, desafíos, verificación, pases y límites."""
import base64
import io
import time

import pytest
from PIL import Image

from backend import captcha


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("CAPTCHA", raising=False)
    monkeypatch.setenv("CAPTCHA_TYPE", "imagenes")          # las pruebas de este bloque son del captcha de imágenes
    captcha.reset()
    yield
    captcha.reset()


def _answer(token):
    return sorted(captcha._challenges[token][0])


def _jpeg(uri):
    assert uri.startswith("data:image/jpeg;base64,")
    return Image.open(io.BytesIO(base64.b64decode(uri.split(",", 1)[1])))


# ---- activación -------------------------------------------------------------------------------------

def test_disabled_by_default():
    assert captcha.enabled() is False


@pytest.mark.parametrize("v", ["on", "ON", "1", "true", "Yes"])
def test_enabled_values(monkeypatch, v):
    monkeypatch.setenv("CAPTCHA", v)
    assert captcha.enabled() is True


@pytest.mark.parametrize("v", ["", "off", "0", "false", "no", "banana"])
def test_not_enabled_values(monkeypatch, v):
    monkeypatch.setenv("CAPTCHA", v)
    assert captcha.enabled() is False


# ---- figuras ----------------------------------------------------------------------------------------

def test_figures_are_shipped_and_valid():
    names = captcha.figures()
    assert len(names) >= 12                       # conjunto grande: memorizarlas no es práctico
    for n in names:
        with Image.open(captcha.ASSETS / f"{n}.png") as im:
            assert im.size == (256, 256) and im.mode == "RGBA"
            assert im.getchannel("A").getbbox() is not None      # no está vacía


def test_figures_are_all_different():
    sigs = set()
    for n in captcha.figures():
        sigs.add(captcha._base(n).tobytes())
    assert len(sigs) == len(captcha.figures())


# ---- desafío ----------------------------------------------------------------------------------------

def test_challenge_shape():
    c = captcha.new_challenge()
    assert len(c["images"]) == 6 and c["expires_in"] == captcha.CHALLENGE_TTL
    assert "answer" not in c and "respuesta" not in str(c).lower() and "selected" not in c     # la respuesta no sale del servidor
    assert len(_answer(c["token"])) == 3
    for uri in c["images"]:
        assert _jpeg(uri).size == (captcha.TILE, captcha.TILE)


def test_correct_tiles_are_not_always_in_the_same_positions():
    seen = set()
    for _ in range(40):
        seen.add(tuple(_answer(captcha.new_challenge()["token"])))
    assert len(seen) >= 8                         # las posiciones correctas se reparten al azar (hay 20 combinaciones)


def test_images_are_different_every_time():
    a, b = captcha.new_challenge(), captcha.new_challenge()
    assert set(a["images"]).isdisjoint(b["images"])
    assert len(set(a["images"])) == 6             # ni siquiera dentro de un desafío hay dos idénticas


def test_target_tiles_use_distinct_orientations(monkeypatch):
    calls = []
    real = captcha.render_tile
    monkeypatch.setattr(captcha, "render_tile", lambda n, t, rng=None: (calls.append((n, t)), real(n, t, rng))[1])
    c = captcha.new_challenge()
    by_fig = {}
    for n, t in calls:
        by_fig.setdefault(n, []).append(t)
    target = next(n for n, ts in by_fig.items() if len(ts) == 3)
    assert len(set(by_fig[target])) == 3          # las 3 versiones de la figura correcta están giradas de forma distinta
    assert sum(1 for ts in by_fig.values() if len(ts) == 1) == 3      # y los 3 señuelos son figuras diferentes
    assert len(_answer(c["token"])) == 3


def test_render_rotates_the_figure():
    """Una figura más ancha que alta ocupa distinto espacio girada 90° que sin girar."""
    import random
    r = random.Random(5)
    flat = Image.open(io.BytesIO(captcha.render_tile("switch", 0, r)))
    turned = Image.open(io.BytesIO(captcha.render_tile("switch", 1, random.Random(5))))
    assert flat.tobytes() != turned.tobytes()


# ---- verificación -----------------------------------------------------------------------------------

def test_correct_answer_gives_pass():
    c = captcha.new_challenge()
    assert captcha.verify(c["token"], _answer(c["token"]), "1.2.3.4")


def test_selection_order_does_not_matter():
    c = captcha.new_challenge()
    assert captcha.verify(c["token"], list(reversed(_answer(c["token"]))))


def test_wrong_answer_is_rejected_and_consumes_the_challenge():
    c = captcha.new_challenge()
    right = _answer(c["token"])
    wrong = [i for i in range(6) if i not in right]
    assert captcha.verify(c["token"], wrong) is None
    assert captcha.verify(c["token"], right) is None       # un intento por desafío: ya no sirve ni acertando


@pytest.mark.parametrize("bad", [lambda r: r[:2], lambda r: r + [next(i for i in range(6) if i not in r)],
                                 lambda r: [r[0], r[0], r[1]], lambda r: [r[0], r[1], 9], lambda r: [r[0], r[1], -1],
                                 lambda r: [r[0], r[1], "x"], lambda r: [r[0], r[1], True], lambda r: [], lambda r: list(range(6))])
def test_malformed_or_partial_selections_fail(bad):
    c = captcha.new_challenge()
    assert captcha.verify(c["token"], bad(_answer(c["token"]))) is None


def test_challenge_is_single_use():
    c = captcha.new_challenge()
    r = _answer(c["token"])
    assert captcha.verify(c["token"], r)
    assert captcha.verify(c["token"], r) is None


def test_unknown_token_fails():
    assert captcha.verify("no-existe", [0, 1, 2]) is None
    assert captcha.verify("", []) is None


def test_expired_challenge_fails():
    c = captcha.new_challenge()
    ans, _ = captcha._challenges[c["token"]]
    captcha._challenges[c["token"]] = (ans, time.time() - 1)
    assert captcha.verify(c["token"], sorted(ans)) is None


# ---- pase -------------------------------------------------------------------------------------------

def _grant(ip="ip"):
    c = captcha.new_challenge()
    return captcha.verify(c["token"], _answer(c["token"]), ip)


def test_pass_is_single_use():
    assert captcha.PASS_USES == 1
    g = _grant()
    assert captcha.consume_pass(g, "ip") is True
    assert captcha.consume_pass(g, "ip") is False


def test_pass_is_short_lived():
    assert captcha.PASS_TTL <= 180      # solo cubre el envío inmediato; no es una sesión


def test_pass_is_bound_to_the_ip():
    g = _grant("10.0.0.1")
    assert captcha.consume_pass(g, "10.0.0.2") is False
    assert captcha.consume_pass(g, "10.0.0.1") is True


def test_pass_expires():
    g = _grant()
    captcha._passes[g][0] = time.time() - 1
    assert captcha.consume_pass(g, "ip") is False


@pytest.mark.parametrize("g", ["", "abc", None])
def test_invalid_pass(g):
    assert captcha.consume_pass(g, "ip") is False


# ---- memoria acotada --------------------------------------------------------------------------------

def test_pending_challenges_are_capped(monkeypatch):
    monkeypatch.setattr(captcha, "MAX_PENDING", 5)
    monkeypatch.setattr(captcha, "render_tile", lambda n, t, rng=None: b"x")
    for _ in range(30):
        captcha.new_challenge()
    assert len(captcha._challenges) <= 5


def test_expired_entries_are_purged():
    c = captcha.new_challenge()
    ans, _ = captcha._challenges[c["token"]]
    captcha._challenges[c["token"]] = (ans, time.time() - 1)
    captcha.new_challenge()
    assert c["token"] not in captcha._challenges


# ======================================================================== rompecabezas deslizante
def _puz():
    return captcha.new_challenge("rompecabezas")


def _tx(c):
    return captcha._challenges[c["token"]][0]


def _track(x, steps=10, ms=60):
    return [[i * ms, round(x * i / steps)] for i in range(steps + 1)]


def _png(uri):
    assert uri.startswith("data:image/png;base64,")
    return Image.open(io.BytesIO(base64.b64decode(uri.split(",", 1)[1])))


def test_puzzle_challenge_shape_and_images():
    c = _puz()
    assert c["type"] == "puzzle" and c["width"] == captcha.PUZ_W and c["height"] == captcha.PUZ_H and c["piece_size"] == captcha.PW
    assert set(c) == {"type", "token", "background", "piece", "piece_y", "width", "height", "piece_size", "prompt", "expires_in"}
    bg, pc = _jpeg(c["background"]), _png(c["piece"])
    assert bg.size == (320, 160) and pc.size == (64, 64) and pc.mode == "RGBA"
    assert 0 <= c["piece_y"] <= captcha.PUZ_H - captcha.PW
    assert isinstance(_tx(c), int) and captcha.PW <= _tx(c) <= captcha.PUZ_W - captcha.PW      # el hueco no está pegado al punto de partida


def test_puzzle_piece_is_a_shape_not_a_square():
    alpha = _png(_puz()["piece"]).getchannel("A")
    solid = sum(alpha.histogram()[201:])
    assert 1500 < solid < 3400          # un cuadrado completo tendría 4096 píxeles opacos


def test_puzzle_hole_is_visible_in_the_background():
    """El hueco está más oscuro que la pieza que lo rellena (si no, no habría nada que encajar)."""
    c = _puz()
    bg, pc = _jpeg(c["background"]).convert("L"), _png(c["piece"])
    tx, ty = _tx(c), c["piece_y"]
    pts = [(x, y) for x in range(captcha.PW) for y in range(captcha.PW) if pc.getchannel("A").getpixel((x, y)) > 250]
    hole = sum(bg.getpixel((tx + x, ty + y)) for x, y in pts) / len(pts)
    piece = sum(pc.convert("L").getpixel((x, y)) for x, y in pts) / len(pts)
    assert hole < piece * 0.8


def test_puzzle_answer_is_not_in_the_response():
    c = _puz()
    assert "answer" not in c and "x" not in c and "target" not in c


def test_puzzle_target_position_varies():
    assert len({_tx(_puz()) for _ in range(25)}) >= 10


def test_puzzle_correct_drop_gives_a_pass():
    c = _puz()
    x = _tx(c)
    assert captcha.verify_puzzle(c["token"], x, _track(x), "ip")


@pytest.mark.parametrize("off", [-captcha.TOL, -3, 0, 3, captcha.TOL])
def test_puzzle_tolerance_accepts_small_offsets(off):
    c = _puz()
    x = _tx(c) + off
    assert captcha.verify_puzzle(c["token"], x, _track(x))


@pytest.mark.parametrize("off", [captcha.TOL + 1, -(captcha.TOL + 1), 40, -60])
def test_puzzle_wrong_position_is_rejected(off):
    c = _puz()
    x = max(0, _tx(c) + off)
    assert captcha.verify_puzzle(c["token"], x, _track(x)) is None


def test_puzzle_challenge_is_single_use_even_after_failure():
    c = _puz()
    x = _tx(c)
    assert captcha.verify_puzzle(c["token"], x + 50, _track(x + 50)) is None
    assert captcha.verify_puzzle(c["token"], x, _track(x)) is None


def test_puzzle_expired_or_unknown_token_fails():
    c = _puz()
    x = _tx(c)
    captcha._challenges[c["token"]] = (x, time.time() - 1)
    assert captcha.verify_puzzle(c["token"], x, _track(x)) is None
    assert captcha.verify_puzzle("no-existe", 100, _track(100)) is None


@pytest.mark.parametrize("bad", [
    lambda x: [], lambda x: _track(x)[:3], lambda x: [[0, x]] * 8,                               # vacío, corto, sin movimiento
    lambda x: [[0, 0], [10, x // 4], [20, x // 2], [30, 3 * x // 4], [40, x]],                  # un «salto» en 40 ms
    lambda x: [[t, px] for t, px in reversed(_track(x))],                                       # tiempo hacia atrás
    lambda x: _track(x)[:-1] + [[600, x - 30]],                                                  # termina lejos de donde dice
    lambda x: [[i * 60, "a"] for i in range(8)], lambda x: [[1, 2, 3]] * 8, lambda x: "no es una lista",
    lambda x: [[i * 60, 9999] for i in range(8)], lambda x: [[-5 + i * 60, i * 10] for i in range(8)],
    lambda x: [[i * 60_000, i * 10] for i in range(8)]])
def test_puzzle_implausible_drags_are_rejected(bad):
    c = _puz()
    x = _tx(c)
    assert captcha.verify_puzzle(c["token"], x, bad(x)) is None


def test_puzzle_wrong_types_are_rejected():
    for x in ("100", 100.0, None, True):
        c = _puz()
        assert captcha.verify_puzzle(c["token"], x, _track(100)) is None


def test_challenge_types_do_not_cross():
    img, puz = captcha.new_challenge("imagenes"), _puz()
    assert captcha.verify(puz["token"], [0, 1, 2]) is None
    assert captcha.verify_puzzle(img["token"], 100, _track(100)) is None


# ---- selección del tipo
def test_type_selection_by_environment(monkeypatch):
    for value, expected in (("imagenes", "images"), ("rompecabezas", "puzzle")):
        monkeypatch.setenv("CAPTCHA_TYPE", value)
        assert {captcha.new_challenge()["type"] for _ in range(6)} == {expected}


def test_random_type_serves_both(monkeypatch):
    monkeypatch.setenv("CAPTCHA_TYPE", "aleatorio")
    monkeypatch.setattr(captcha, "render_tile", lambda n, t, rng=None: b"x")
    assert {captcha.new_challenge()["type"] for _ in range(60)} == {"images", "puzzle"}


@pytest.mark.parametrize("v,expected", [("", "aleatorio"), ("banana", "aleatorio"), ("ROMPECABEZAS", "rompecabezas"), ("  imagenes ", "imagenes")])
def test_type_defaults_to_random(monkeypatch, v, expected):
    monkeypatch.setenv("CAPTCHA_TYPE", v)
    assert captcha.captcha_type() == expected
