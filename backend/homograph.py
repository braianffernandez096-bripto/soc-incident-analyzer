"""Ataques homógrafos: direcciones y dominios que se VEN iguales a otros pero no lo son.

Casos que cubre
- Alfabetos mezclados en una misma palabra: «а» cirílica (U+0430) en vez de «a» latina (U+0061), «о» cirílica, «ο» griega…
- Alfabeto completo que imita letras latinas («аррӏе» escrito solo con letras cirílicas).
- Letras ASCII que se confunden entre sí: «I» mayúscula por «l» minúscula, «0» por «o», «1» por «l», «rn» por «m».
- Caracteres invisibles o de dirección (espacio de ancho cero, RLO).
- Comparación con una dirección esperada: dice EXACTAMENTE qué carácter cambió.

Límite honesto: sin una dirección de referencia no se puede saber cuál es la legítima. Por eso, además de las señales, se
entrega el desglose carácter por carácter (código Unicode, nombre y alfabeto) para que el analista lo compare con el contacto real.
Es una tabla curada de confusables (los casos prácticos), no la base completa de Unicode (UTS #39).
"""
from __future__ import annotations

import re
import unicodedata

MAX_CHARS = 96          # tope de caracteres que se desglosan por dirección

_SCRIPT_ES = {"LATIN": "Latino", "CYRILLIC": "Cirílico", "GREEK": "Griego", "ARMENIAN": "Armenio", "HEBREW": "Hebreo", "ARABIC": "Árabe",
              "CJK": "CJK", "HIRAGANA": "Hiragana", "KATAKANA": "Katakana", "HANGUL": "Hangul", "THAI": "Tailandés", "CHEROKEE": "Cheroqui",
              "DEVANAGARI": "Devanagari", "GEORGIAN": "Georgiano"}

# Letras no latinas que se ven como una letra latina (curado: los casos usados en la práctica).
_CONFUSABLE = {
    # cirílico minúsculas
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q",
    "ԝ": "w", "ӏ": "l",
    # cirílico mayúsculas
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J",
    "Ѕ": "S",
    # griego
    "ο": "o", "ν": "v", "ρ": "p", "υ": "u", "ι": "i", "α": "a", "τ": "t", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # latinas extendidas y otras
    "ı": "i", "ɑ": "a", "ɡ": "g", "ǀ": "l", "ⅼ": "l", "ꓲ": "l", "օ": "o", "ս": "u", "ց": "g", "ո": "n", "հ": "h",
}
_AMBIGUOUS_ASCII = str.maketrans({"I": "l", "1": "l", "|": "l", "O": "o", "0": "o"})
_INVISIBLE = {0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062,
              0x2063, 0x2064, 0x3164, 0xFEFF, 0xFFA0}
_SEP = re.compile(r"[.\-_+@]")


def script_of(ch: str) -> str:
    """Alfabeto de una letra («Común» para cifras y signos)."""
    if not ch.isalpha():
        return "Común"
    name = unicodedata.name(ch, "")
    first = name.split(" ", 1)[0] if name else "?"
    if first in ("FULLWIDTH", "MATHEMATICAL", "SMALL", "CIRCLED", "PARENTHESIZED", "SQUARED"):
        return "Latino (compatibilidad)" if unicodedata.normalize("NFKC", ch).isascii() else first.title()
    return _SCRIPT_ES.get(first, first.title())


def lookalike(ch: str) -> str:
    """Letra latina ASCII a la que se parece un carácter no ASCII ('' si no imita ninguna)."""
    if ch.isascii():
        return ""
    if ch in _CONFUSABLE:
        return _CONFUSABLE[ch]
    n = unicodedata.normalize("NFKC", ch)
    return n if n != ch and n.isascii() and n.isalnum() else ""


def is_invisible(ch: str) -> bool:
    return ord(ch) in _INVISIBLE or (unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\t\r\n")


def lc(s: str) -> str:
    """Minúsculas solo para ASCII (conserva la longitud y no esconde un cambio de alfabeto)."""
    return "".join(c.lower() if c.isascii() else c for c in s)


def skeleton(text: str) -> str:
    """Forma «tal como se ve»: letras de otro alfabeto → su gemela latina; I/1/| → l; O/0 → o; rn → m; vv → w."""
    out = "".join(lookalike(c) or c for c in unicodedata.normalize("NFC", text) if not is_invisible(c))
    return out.translate(_AMBIGUOUS_ASCII).lower().replace("rn", "m").replace("vv", "w")


def breakdown(text: str, flagged: dict[int, str] | None = None) -> tuple[list[dict], bool]:
    """Desglose carácter por carácter. ``flagged``: posición → motivo (se resalta). Devuelve (celdas, truncado)."""
    flagged = flagged or {}
    cells = []
    for i, ch in enumerate(text[:MAX_CHARS]):
        invisible = is_invisible(ch)
        look = lookalike(ch)
        cells.append({
            "pos": i + 1, "ch": "·" if invisible else ch, "code": f"U+{ord(ch):04X}",
            "name": unicodedata.name(ch, "(sin nombre)" if not unicodedata.category(ch).startswith("C") else "(carácter de control)"),
            "script": script_of(ch), "looks_like": look, "flag": flagged.get(i, ""),
        })
    return cells, len(text) > MAX_CHARS


def _tokens(text: str):
    """(posición, palabra) separando por . - _ + @: las mezclas de alfabeto se miran dentro de cada palabra."""
    start = 0
    for m in list(_SEP.finditer(text)) + [None]:
        end = m.start() if m else len(text)
        if end > start:
            yield start, text[start:end]
        start = m.end() if m else end


def decode_host(host: str) -> str:
    """Forma Unicode de un host con etiquetas xn-- (si no se puede decodificar, se deja tal cual)."""
    out = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def ascii_form(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii") if not host.isascii() else ""
    except (UnicodeError, ValueError):
        return ""


def inspect(text: str, kind: str = "address") -> dict:
    """Examina una dirección (``kind='address'``), un dominio (``'host'``) o un nombre visible (``'name'``).

    Devuelve las señales encontradas y, por posición, qué carácter es sospechoso (para resaltarlo en el desglose)."""
    text = text or ""
    flagged: dict[int, str] = {}
    res = {"text": text, "mixed": [], "whole_script": [], "odd_case": [], "digit_swap": [], "invisible": [], "idn": "", "scripts": []}
    scripts: list[str] = []
    for ch in text:
        s = script_of(ch)
        if s != "Común" and s not in scripts:
            scripts.append(s)
    res["scripts"] = scripts
    for i, ch in enumerate(text):
        if is_invisible(ch):
            res["invisible"].append({"pos": i + 1, "code": f"U+{ord(ch):04X}", "name": unicodedata.name(ch, "(control)")})
            flagged[i] = "invisible"
    for start, word in _tokens(text):
        letters = [(start + k, c, script_of(c)) for k, c in enumerate(word) if c.isalpha()]
        sc = {s for _, _, s in letters}
        latin = {"Latino"}          # las formas de compatibilidad (ancho completo, matemáticas) también cuentan como «otro alfabeto»
        non_latin = sc - latin
        if non_latin and (sc & latin):
            chars = [{"pos": pos + 1, "ch": c, "code": f"U+{ord(c):04X}", "name": unicodedata.name(c, "?"), "script": s_, "looks_like": lookalike(c)}
                     for pos, c, s_ in letters if s_ not in latin]
            res["mixed"].append({"word": word, "scripts": sorted(sc), "chars": chars})
            for pos, c, s_ in letters:
                if s_ not in latin:
                    flagged[pos] = "alfabeto"
        elif non_latin and len(letters) >= 3 and all(lookalike(c) for _, c, _ in letters):
            res["whole_script"].append({"word": word, "script": sorted(non_latin)[0], "as": "".join(lookalike(c) for _, c, _ in letters)})
            for pos, _, _ in letters:
                flagged[pos] = "parecido"
    if kind != "name":
        # «I» o «O» mayúsculas dentro de palabras en minúsculas (no existen razones para escribirlas así en una dirección)
        for start, word in _tokens(text):
            for k, c in enumerate(word):
                if c in "IO" and ((k > 0 and word[k - 1].islower()) or (k + 1 < len(word) and word[k + 1].islower())) and word[:1] != c:
                    pos = start + k
                    twin = "l" if c == "I" else "0"
                    res["odd_case"].append({"pos": pos + 1, "ch": c, "looks_like": twin, "word": word})
                    flagged.setdefault(pos, "ambiguo")
                if c in "01" and 0 < k < len(word) - 1 and word[k - 1].isalpha() and word[k + 1].isalpha():
                    pos = start + k
                    res["digit_swap"].append({"pos": pos + 1, "ch": c, "looks_like": "o" if c == "0" else "l", "word": word})
                    flagged.setdefault(pos, "ambiguo")
    if kind == "host" and not text.isascii():
        res["idn"] = ascii_form(text)
    res["flagged"] = flagged
    res["suspicious"] = bool(res["mixed"] or res["whole_script"] or res["odd_case"] or res["digit_swap"] or res["invisible"])
    return res


def spelled(text: str) -> str:
    """«b a n c o . u n i v e r s a I @ …»: cada carácter separado (la distinción entre I y l se ve a simple vista)."""
    return " ".join("·" if is_invisible(c) else c for c in text[:MAX_CHARS]) + (" …" if len(text) > MAX_CHARS else "")


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def compare(found: str, expected: str) -> dict:
    """Compara lo recibido con lo esperado, sin distinguir mayúsculas ASCII (las direcciones no las distinguen).

    ``kind``: igual · parecida (se ve igual, pero es distinta) · casi (1-2 cambios) · distinta."""
    f, e = (found or "").strip(), (expected or "").strip()
    fl, el = lc(f), lc(e)
    if fl == el:
        return {"kind": "igual", "diffs": [], "distance": 0}
    import difflib
    diffs = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, fl, el, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        got, want = f[i1:i2], e[j1:j2]
        diffs.append({"pos": i1 + 1, "op": {"replace": "cambiado", "delete": "sobra", "insert": "falta"}[tag], "found": got, "expected": want,
                      "found_detail": [{"ch": c, "code": f"U+{ord(c):04X}", "name": unicodedata.name(c, "?"), "script": script_of(c)} for c in got][:4],
                      "expected_detail": [{"ch": c, "code": f"U+{ord(c):04X}", "name": unicodedata.name(c, "?"), "script": script_of(c)} for c in want][:4]})
    dist = _lev(fl, el)
    kind = "parecida" if skeleton(f) == skeleton(e) else "casi" if dist <= 2 else "distinta"
    return {"kind": kind, "diffs": diffs[:8], "distance": dist}


def describe_char(c: str) -> str:
    return f"«{c}» (U+{ord(c):04X} {unicodedata.name(c, '?')})"
