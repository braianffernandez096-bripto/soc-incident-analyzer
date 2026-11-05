"""Normalización estática de la ofuscación más habitual en URLs y líneas de comandos.

Nada se ejecuta ni se consulta en la red: son transformaciones de texto con tope de tamaño. El objetivo es que las reglas existentes vean
lo que vería el sistema destino (la IP real de ``http://3232235777``, el ``powershell`` de ``p^o^w^e^r^s^h^e^l^l``). No pretende cubrir toda
la ofuscación posible; la que queda fuera se documenta en docs/VALIDACION.md.
"""
from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from . import psdecode

MAX_URL = 4000
MAX_CMD = 20_000
MAX_PASSES = 40                  # tope de sustituciones de concatenación/replace por comando

# ------------------------------------------------------------------ URLs

_CTRL_RE = re.compile(r"[\x00-\x20\x7f​-‍⁠﻿]")        # los navegadores descartan tab y saltos dentro de la URL
_NUM_ENTITY_RE = re.compile(r"&#(?:x[0-9a-fA-F]+|\d+);?")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PCT_ALNUM_RE = re.compile(r"%(?:3[0-9]|4[1-9a-fA-F]|5[0-9aA]|6[1-9a-fA-F]|7[0-9aA])")     # 0-9, A-Z, a-z codificados sin necesidad
_NUMHOST_PART = re.compile(r"^(?:0x[0-9a-f]*|\d+)$", re.I)
REDIRECT_PARAMS = {"url", "u", "uri", "link", "redirect", "redirect_url", "redirect_uri", "redir", "r", "target", "dest", "destination",
                   "goto", "next", "continue", "return", "returnurl", "return_to", "to", "q", "href"}
# Reescritores legítimos de enlaces corporativos (Safe Links, Proofpoint…): se sigue el destino pero no cuenta como señal.
WRAPPERS = ("safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com", "protect-us.mimecast.com",
            "protection.sophos.com", "linkprotect.cudasvc.com")


def _int_part(p: str) -> int | None:
    try:
        if p.lower().startswith("0x"):
            return int(p[2:] or "0", 16)
        if len(p) > 1 and p.startswith("0"):
            return int(p, 8)
        return int(p, 10)
    except ValueError:
        return None


def numeric_host(host: str) -> tuple[str, str] | None:
    """Si ``host`` es una IPv4 escrita en decimal, hexadecimal, octal o con menos de 4 partes (como las acepta ``inet_aton``), devuelve
    (ip_con_puntos, descripción). Si ya es una IPv4 normal con puntos, devuelve None."""
    h = host.strip("[]").lower().rstrip(".")
    if not h:
        return None
    if ":" in h:                                     # IPv6 con IPv4 incrustada (::ffff:1.2.3.4)
        try:
            v4 = ipaddress.IPv6Address(h).ipv4_mapped
        except ValueError:
            return None
        return (str(v4), "IPv4 dentro de una dirección IPv6") if v4 else None
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or not all(_NUMHOST_PART.match(p) for p in parts):
        return None
    vals = [_int_part(p) for p in parts]
    if any(v is None for v in vals):
        return None
    plain = len(parts) == 4 and all(p.isdigit() and (p == "0" or not p.startswith("0")) for p in parts)
    n = 0
    for v in vals[:-1]:
        if v > 255:
            return None
        n = (n << 8) | v
    last = vals[-1]
    if last >= 256 ** (5 - len(parts)):
        return None
    n = (n << (8 * (5 - len(parts)))) | last
    if n > 0xFFFFFFFF:
        return None
    ip = str(ipaddress.IPv4Address(n))
    if plain and ip == h:
        return None
    kinds = []
    if any(p.lower().startswith("0x") for p in parts):
        kinds.append("hexadecimal")
    if any(len(p) > 1 and p.startswith("0") and not p.lower().startswith("0x") for p in parts):
        kinds.append("octal")
    if len(parts) < 4:
        kinds.append("abreviada" if len(parts) > 1 else "decimal")
    return ip, "IP escrita en formato " + (" y ".join(kinds) or "numérico")


def normalize_url(raw: str) -> dict:
    """Devuelve {clean, url, techniques, ip, redirect}.

    clean: sin caracteres de control, entidades numéricas ni barras invertidas (sirve para ver el esquema real).
    url: además con la codificación porcentual deshecha y la IP numérica convertida a puntos.
    techniques: lista de textos para el analista (vacía si la URL es normal).
    """
    raw = (raw or "")[:MAX_URL]
    tech: list[str] = []
    s = raw
    if _CTRL_RE.search(s.strip()):
        stripped = _CTRL_RE.sub("", s.strip())
        if stripped != s.strip():
            tech.append("caracteres invisibles o saltos dentro de la URL (el navegador los descarta)")
        s = stripped
    else:
        s = s.strip()
    if _NUM_ENTITY_RE.search(s):
        s = html.unescape(s)
        tech.append("entidades HTML numéricas")
    head, sep, tail = s.partition("?")
    if "\\" in head and re.match(r"^\s*[a-z][a-z0-9+.-]*:[/\\]", head, re.I):
        head = head.replace("\\", "/")
        tech.append("barras invertidas en lugar de «/»")
        s = head + sep + tail
    clean = s

    rounds = 0
    cur = s
    while rounds < 3 and _PCT_RE.search(cur):
        nxt = unquote(cur, errors="replace")
        if nxt == cur:
            break
        cur, rounds = nxt, rounds + 1
    if rounds >= 2:
        tech.append(f"codificación porcentual repetida ({rounds} capas)")
    auth_end = re.search(r"[/?#]", clean.split("//", 1)[-1])
    authority = clean.split("//", 1)[-1][:auth_end.start()] if auth_end else clean.split("//", 1)[-1]
    if "//" in clean and _PCT_RE.search(authority):
        tech.append("la parte del servidor (host) está codificada con «%»")
    elif len(_PCT_ALNUM_RE.findall(clean)) >= 3:
        tech.append("letras o números codificados con «%» sin necesidad")
    url = cur

    ip = None
    try:
        p = urlsplit(url if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I) else "//" + url)
        host = (p.hostname or "")
    except ValueError:
        host = ""
        p = None
    if host:
        nh = numeric_host(host)
        if nh:
            ip = nh[0]
            tech.append(f"{nh[1]} ({host} = {ip})")
            url = re.sub(r"\[?" + re.escape(host) + r"\]?", ip, url, count=1, flags=re.I)
    redirect = _redirect_target(p) if p is not None else ""
    return {"clean": clean, "url": url, "techniques": tech, "ip": ip, "redirect": redirect}


def _redirect_target(p) -> str:
    """URL de destino escondida en un parámetro (redirección abierta o enlace envuelto); solo si es otro sitio distinto."""
    try:
        pairs = parse_qsl(p.query or "", keep_blank_values=False)[:20]
    except ValueError:
        return ""
    own = (p.hostname or "").lower()
    for k, v in pairs:
        if k.lower() not in REDIRECT_PARAMS:
            continue
        v = v.strip()
        for _ in range(2):
            if re.match(r"^https?://", v, re.I):
                break
            v = unquote(v)
        m = re.match(r"^https?://[^\s<>\"']{4,1000}", v, re.I)
        if not m:
            continue
        try:
            th = (urlsplit(m.group(0)).hostname or "").lower()
        except ValueError:
            continue
        if th and th != own:
            return m.group(0)
    return ""


def is_wrapper(host: str) -> bool:
    h = (host or "").lower()
    return any(h == w or h.endswith("." + w) for w in WRAPPERS)


# ------------------------------------------------------------------ comandos

TRIGGER_RE = re.compile(r"\^|`|(?i:\[char|frombase64string|\.replace\(|-join)|['\"]\s*\+\s*['\"]|[A-Za-z][\"'][A-Za-z]|(?:[a-z][A-Z]){3}")
KEYWORD_RE = re.compile(r"\b(?:powershell|pwsh|cmd|iex|invoke-expression|certutil|mshta|rundll32|regsvr32|wscript|cscript|bitsadmin|msiexec|"
                        r"downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|net\.webclient|frombase64string|start-bitstransfer|"
                        r"mimikatz|vssadmin|wmic|schtasks|whoami|bcdedit)\b", re.I)
_CONCAT_RE = re.compile(r"""(?P<q>['"])(?P<a>[^'"\n]{0,2000})(?P=q)\s*\+\s*(?P<q2>['"])(?P<b>[^'"\n]{0,2000})(?P=q2)""")
_REPLACE_RE = re.compile(r"""(?P<q>['"])(?P<s>[^'"\n]{1,2000})(?P=q)\s*\.replace\(\s*(['"])(?P<x>[^'"\n]{1,50})\3\s*,\s*(['"])(?P<y>[^'"\n]{0,50})\5\s*\)""", re.I)
_CHAR_RE = re.compile(r"\[char\]\s*\(?\s*(0x[0-9a-f]{1,4}|\d{1,5})\s*\)?", re.I)
_CHARARR_RE = re.compile(r"\[char\[\]\]\s*\(?\s*((?:0x[0-9a-f]{1,4}|\d{1,5})(?:\s*,\s*(?:0x[0-9a-f]{1,4}|\d{1,5}))+)\s*\)?(?:\s*-join\s*(?:''|\"\"))?", re.I)
_STRARR_JOIN_RE = re.compile(r"""\(\s*((?:'[^'\n]*'|"[^"\n]*")(?:\s*,\s*(?:'[^'\n]*'|"[^"\n]*"))+)\s*\)\s*-join\s*(?:''|"")""", re.I)
_B64STR_RE = re.compile(r"""frombase64string\(\s*['"]([A-Za-z0-9+/=]{16,%d})['"]\s*\)""" % psdecode.MAX_B64, re.I)


def _chr(n: int) -> str:
    return chr(n) if 32 <= n < 127 else ""


def command(text: str) -> dict:
    """Quita la ofuscación habitual de una línea de comandos. Devuelve {text, techniques, decoded, changed}.

    Cubre: ``^`` de cmd, backticks de PowerShell, comillas intercaladas (``po"wer"shell``), concatenación (``'Down'+'loadString'``),
    ``.Replace('X','')``, ``[char]72`` y ``[char[]](72,105) -join ''``, ``('a','b') -join ''`` y ``FromBase64String('…')`` fuera de ``-enc``.
    No ejecuta nada; si la ofuscación no se resuelve con estas reglas, el texto queda como estaba.
    """
    res = {"text": text or "", "techniques": [], "decoded": [], "changed": False}
    if not text or not TRIGGER_RE.search(text[:MAX_CMD]):
        return res
    s = text[:MAX_CMD]
    tech: list[str] = []
    n_caret = len(re.findall(r"(?<=\w)\^(?=\w)", s))
    if n_caret >= 3:
        s = re.sub(r"\^(?=[\w])", "", s)
        tech.append("caracteres «^» intercalados (cmd)")
    n_tick = len(re.findall(r"(?<=\w)`(?=\w)", s))
    if n_tick >= 3:
        s = re.sub(r"(?<=\w)`(?=\w)", "", s)
        tech.append("acentos graves «`» intercalados (PowerShell)")
    if len(re.findall(r"(?<=[A-Za-z])[\"'](?=[A-Za-z])", s)) >= 2:
        s2 = re.sub(r"(?<=[A-Za-z])[\"'](?=[A-Za-z])", "", s)
        if s2 != s:
            s = s2
            tech.append("comillas intercaladas dentro de una palabra")
    changed_chars = False
    for rx_, fn in ((_CHARARR_RE, lambda m: "'" + "".join(_chr(int(x, 0)) for x in re.split(r"\s*,\s*", m.group(1))) + "'"),
                    (_CHAR_RE, lambda m: "'" + _chr(int(m.group(1), 0)) + "'")):
        s2 = rx_.sub(fn, s)
        if s2 != s:
            s, changed_chars = s2, True
    if changed_chars:
        tech.append("caracteres construidos con [char]")
    s2 = _STRARR_JOIN_RE.sub(lambda m: "'" + "".join(x.strip().strip("'\"") for x in re.split(r"\s*,\s*", m.group(1))) + "'", s)
    if s2 != s:
        s = s2
        tech.append("texto armado con -join")
    for _ in range(MAX_PASSES):
        s2 = _REPLACE_RE.sub(lambda m: m.group("q") + m.group("s").replace(m.group("x"), m.group("y")) + m.group("q"), s, count=1)
        if s2 == s:
            break
        s = s2
        if "reemplazos con .Replace()" not in tech:
            tech.append("reemplazos con .Replace()")
    joined = False
    for _ in range(MAX_PASSES):
        s2 = _CONCAT_RE.sub(lambda m: m.group("q") + m.group("a") + m.group("b") + m.group("q"), s, count=1)
        if s2 == s:
            break
        s, joined = s2, True
    if joined:
        tech.append("cadenas partidas y concatenadas con «+»")
    decoded: list[str] = []
    for m in _B64STR_RE.finditer(s):
        raw = psdecode._b64(m.group(1))
        if not raw:
            continue
        out = psdecode._inflate(raw)
        t = psdecode._text(out) if out else psdecode._text(raw)
        if t and t.strip() and t.strip() not in decoded and len(decoded) < 3:
            decoded.append(t.strip()[:psdecode.SHOW])
    if decoded:
        tech.append("Base64 decodificado con FromBase64String")
        s = s + " || " + " || ".join(decoded)
    if re.search(r"\b[a-z]*(?:[a-z][A-Z]){3,}[a-zA-Z]*\b", s) and KEYWORD_RE.search(s):
        tech.append("mayúsculas y minúsculas alternadas")
    res.update(text=s, techniques=tech, decoded=decoded, changed=s != text[:MAX_CMD] or bool(tech))
    return res


def reveals(raw: str, result: dict) -> bool:
    """True si la ofuscación escondía una palabra relevante: aparece tras normalizar y no estaba a la vista."""
    if not result["changed"]:
        return False
    seen = {m.lower() for m in KEYWORD_RE.findall(raw or "")}
    return any(m.lower() not in seen for m in KEYWORD_RE.findall(result["text"]))
