"""Dominios parecidos (typosquatting): genera las variantes que un atacante podría registrar para imitar un dominio.

Sirve para vigilar: el analista obtiene una lista de dominios a monitorear o bloquear en el proxy y el DNS. La generación es
**local** (no abre ninguna conexión). Comprobar cuáles están registrados es un paso aparte y opcional que consulta el DNS público
(ver ``dnsdoh``) y solo envía los nombres de dominio de la lista.

La tabla de caracteres confundibles es la misma que usa el análisis de homógrafos de los correos (curada, no toda Unicode).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from . import homograph
from .dnsdoh import DnsDisabled, DnsError, enabled
from .phishing import reg_domain

MAX_VARIANTS = 250
MAX_CHECK = 60                  # tope de dominios por comprobación de registro (cada uno es una consulta DNS)
TLDS = ["com", "net", "org", "co", "io", "info", "biz", "online", "site", "xyz", "top", "app", "com.ar", "ar"]
KEYWORDS = ["login", "secure", "soporte", "support", "verify", "cuenta", "pago", "online", "app"]
BIT_CAP = 20

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
    "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm", "k": "jil", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
ASCII_LOOK = {"l": ["1", "i"], "i": ["l", "1"], "o": ["0"], "0": ["o"], "1": ["l", "i"], "e": ["3"], "s": ["5"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "u": ["v"], "v": ["u"]}
KINDS = {  # clave -> (etiqueta, prioridad: menor = más probable que se use en un ataque real)
    "visual": ("Parecida a simple vista (1/l, 0/o, rn/m…)", 0),
    "homografo": ("Homógrafo Unicode (IDN)", 1),
    "transposicion": ("Letras intercambiadas", 2),
    "omision": ("Letra omitida", 3),
    "teclado": ("Tecla vecina", 4),
    "repeticion": ("Letra repetida", 5),
    "tld": ("Otra terminación", 6),
    "guion": ("Guion agregado", 7),
    "palabra": ("Palabra añadida", 8),
    "bit": ("Un bit cambiado", 9),
}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _lookalike_chars() -> dict[str, list[str]]:
    """Letra latina minúscula -> caracteres cirílicos/griegos minúsculos de la tabla de confundibles que se le parecen."""
    out: dict[str, list[str]] = {}
    for ch, latin in homograph._CONFUSABLE.items():
        if latin.islower() and latin.isascii() and ch.islower() and ord(ch) > 127 and homograph.script_of(ch) in ("Cirílico", "Griego"):
            out.setdefault(latin, []).append(ch)
    return out


def split_domain(domain: str) -> tuple[str, str]:
    """('bancouniversal', 'gob') — etiqueta registrable y sufijo, con la misma heurística de sufijos que el resto de la app."""
    reg = reg_domain(domain)
    label, _, suffix = reg.partition(".")
    return label, suffix


def generate(domain: str, limit: int = MAX_VARIANTS) -> list[dict]:
    """Variantes del dominio (ya validado con ``dnsdoh.clean_domain``), ordenadas de más a menos probables."""
    label, suffix = split_domain(domain)
    original = f"{label}.{suffix}"
    found: dict[str, dict] = {}
    unicode_of: dict[str, str] = {}

    def add(lbl: str, kind: str, note: str, suf: str | None = None) -> None:
        suf = suffix if suf is None else suf
        if not lbl or lbl == label and suf == suffix:
            return
        name = f"{lbl}.{suf}"
        if lbl.isascii():
            if not _LABEL.match(lbl) or name == original:
                return
            ascii_name = name
        else:
            try:
                ascii_name = name.encode("idna").decode("ascii")
            except UnicodeError:
                return
            unicode_of[ascii_name] = name
        if ascii_name not in found and ascii_name != original:
            found[ascii_name] = {"domain": ascii_name, "unicode": unicode_of.get(ascii_name, ""), "kind": kind, "kind_label": KINDS[kind][0], "note": note}

    for i, c in enumerate(label):
        for alt in ASCII_LOOK.get(c, []):
            add(label[:i] + alt + label[i + 1:], "visual", f"«{c}» por «{alt}» en la posición {i + 1}")
    if "rn" in label:
        add(label.replace("rn", "m"), "visual", "«rn» por «m»")
    look = _lookalike_chars()
    for i, c in enumerate(label):
        for alt in look.get(c, [])[:2]:
            add(label[:i] + alt + label[i + 1:], "homografo", f"«{c}» latina (U+{ord(c):04X}) por «{alt}» (U+{ord(alt):04X}, {homograph.script_of(alt)}) en la posición {i + 1}")
    full = "".join(look[c][0] if c in look else c for c in label)
    if full != label and any(c in look for c in label):
        add(full, "homografo", "todas las letras posibles reemplazadas por cirílico/griego (aparenta ser el original)")
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposicion", f"«{label[i]}{label[i + 1]}» invertidas")
    for i, c in enumerate(label):
        add(label[:i] + label[i + 1:], "omision", f"falta «{c}» en la posición {i + 1}")
    for i, c in enumerate(label):
        for alt in KEYBOARD.get(c, "")[:3]:
            add(label[:i] + alt + label[i + 1:], "teclado", f"«{alt}» está junto a «{c}» en el teclado")
    for i, c in enumerate(label):
        add(label[:i] + c + label[i:], "repeticion", f"«{c}» repetida")
    for tld in TLDS:
        if tld != suffix:
            add(label, "tld", f"misma marca con «.{tld}»", tld)
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:], "guion", "guion entre las letras")
    for kw in KEYWORDS:
        add(f"{label}-{kw}", "palabra", f"«{kw}» añadida al final")
        add(f"{kw}-{label}", "palabra", f"«{kw}» añadida al principio")
    bits = 0
    for i, c in enumerate(label):
        for b in range(8):
            flipped = chr(ord(c) ^ (1 << b))
            if flipped.isascii() and (flipped.isalnum() and flipped == flipped.lower()) and flipped != c and bits < BIT_CAP:
                before = len(found)
                add(label[:i] + flipped + label[i + 1:], "bit", f"el bit {b} de «{c}» cambia a «{flipped}» (error de memoria)")
                bits += len(found) - before
    ordered = sorted(found.values(), key=lambda v: KINDS[v["kind"]][1])           # estable: dentro de cada tipo se conserva el orden de generación
    return ordered[:max(1, min(limit, MAX_VARIANTS))]


STATES = {"registrado": "Tiene DNS (registrado)", "libre": "Sin DNS (posiblemente libre)", "sin_datos": "Sin datos", "error": "No se pudo consultar"}


def check_registered(domains: list[str], resolver, max_items: int = MAX_CHECK) -> dict[str, str]:
    """Estado de cada dominio según el DNS: un NS publicado indica que está registrado; NXDOMAIN, que no tiene delegación.

    Es orientativo: un dominio puede estar registrado sin DNS delegado, o reservado sin estar a la venta.
    """
    if not enabled():
        raise DnsDisabled("Las consultas DNS están desactivadas en este servidor (DNS_LOOKUPS=off).")
    names = list(dict.fromkeys(domains))[:max_items]

    def one(name: str) -> tuple[str, str]:
        try:
            r = resolver.query(name, "NS")
        except DnsError:
            return name, "error"
        if r["status"] == 3:
            return name, "libre"
        return name, "registrado" if r["answers"] else "sin_datos"
    with ThreadPoolExecutor(max_workers=8) as ex:
        out = dict(ex.map(one, names))
    if names and all(v == "error" for v in out.values()):
        raise DnsError("No se pudo consultar el DNS (sin conexión o bloqueado). Revisa que el servidor tenga salida a Internet.")
    return out
