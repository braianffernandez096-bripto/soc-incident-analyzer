"""Revisión estática del HTML de un correo o de un adjunto .html: ofuscación, texto oculto, redirecciones y «HTML smuggling».

Solo lee texto: no ejecuta JavaScript. Decodifica los literales que se pueden resolver sin ejecutar (``atob('…')``, ``unescape('%…')``,
``String.fromCharCode(…)``, secuencias ``\\x41``) para sacar las URL que esconden. Lo que dependa de ejecutar el código queda sin ver.
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
from html.parser import HTMLParser
from urllib.parse import unquote

log = logging.getLogger(__name__)
MAX_HTML = 600_000
MAX_DECODE = 20_000
URL_RE = re.compile(r"https?://[^\s'\"<>)\]\\]{4,300}", re.I)
INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f"
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|"
                          r"(?:max-)?height\s*:\s*0(?:px)?\s*;[^\"']*overflow\s*:\s*hidden|text-indent\s*:\s*-\d{3,}", re.I)
META_REFRESH = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*content\s*=\s*[\"']\s*\d+\s*;\s*url\s*=\s*['\"]?([^\"'>\s]+)", re.I)
HREF_NUMENT = re.compile(r"""(?:href|src|action)\s*=\s*["'][^"']*&#(?:x[0-9a-f]+|\d+);""", re.I)
SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.I | re.S)
ATOB_RE = re.compile(r"""\batob\(\s*(['"])([A-Za-z0-9+/=\s]{16,%d})\1\s*\)""" % MAX_DECODE, re.I)
UNESCAPE_RE = re.compile(r"""\bunescape\(\s*(['"])((?:%[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}|[^'"\\]){6,""" + str(MAX_DECODE) + r"""})\1\s*\)""", re.I)
FROMCHAR_RE = re.compile(r"String\s*\.\s*fromCharCode\(\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+)){3,})\s*\)", re.I)
ESC_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){8,}")
BIG_B64_RE = re.compile(r"[A-Za-z0-9+/]{800,}={0,2}")


class _Hidden(HTMLParser):
    """Cuenta los caracteres de texto dentro de elementos ocultos con estilos CSS."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[bool] = []
        self.hidden_chars = 0
        self.invisible = 0
        self.samples: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("br", "img", "meta", "link", "input", "hr"):
            return
        a = {k: (v or "") for k, v in attrs}
        hid = bool(HIDDEN_STYLE.search(a.get("style", ""))) or "hidden" in a and tag not in ("input",)
        self.stack.append(hid or (bool(self.stack) and self.stack[-1]))

    def handle_endtag(self, tag):
        if self.stack and tag not in ("br", "img", "meta", "link", "input", "hr"):
            self.stack.pop()

    def handle_data(self, data):
        # solo cuenta el invisible que PARTE palabras (pa\u200bypal); el relleno en cadena de los boletines (preheader) no
        self.invisible += len(re.findall("(?<=[A-Za-z])[" + INVISIBLE + "]+(?=[A-Za-z])", data))
        if self.stack and self.stack[-1]:
            t = "".join(ch for ch in data if ch.isalnum())
            self.hidden_chars += len(t)
            if t and len(self.samples) < 2:
                self.samples.append(" ".join(data.split())[:60])


def _b64_text(s: str) -> str:
    s = re.sub(r"\s+", "", s)
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return ""
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        t = raw.decode("latin-1")
    return t if sum(c.isprintable() or c in "\r\n\t" for c in t) / max(1, len(t)) > 0.85 else ""


def _js_decoded(script: str) -> list[str]:
    """Textos que el script arma con literales (sin ejecutarlo)."""
    out: list[str] = []
    for m in ATOB_RE.finditer(script):
        t = _b64_text(m.group(2))
        if t:
            out.append(t[:MAX_DECODE])
    for m in UNESCAPE_RE.finditer(script):
        v = m.group(2)
        v = re.sub(r"%u([0-9a-fA-F]{4})", lambda x: chr(int(x.group(1), 16)), v)
        out.append(unquote(v)[:MAX_DECODE])
    for m in FROMCHAR_RE.finditer(script):
        try:
            out.append("".join(chr(int(x, 0)) for x in re.split(r"\s*,\s*", m.group(1)) if 0 < int(x, 0) < 0x110000)[:MAX_DECODE])
        except (ValueError, OverflowError):
            continue
    for m in ESC_RUN_RE.finditer(script):
        try:
            out.append(re.sub(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})", lambda x: chr(int(x.group(1) or x.group(2), 16)), m.group(0))[:MAX_DECODE])
        except ValueError:
            continue
    return out


def scan(html_text: str, where: str = "cuerpo") -> dict:
    """Devuelve {signals, urls, decoded}. ``signals``: dicts con severity, points, title, detail, mitre, key. ``urls``: destinos ocultos."""
    h = (html_text or "")[:MAX_HTML]
    signals: list[dict] = []
    urls: list[str] = []
    decoded: list[str] = []
    if not h.strip():
        return {"signals": signals, "urls": urls, "decoded": decoded}

    def add(sev: str, pts: int, title: str, detail: str, mitre: list[str], key: str) -> None:
        signals.append({"severity": sev, "points": pts, "title": title, "detail": detail, "mitre": mitre, "key": key})

    m = META_REFRESH.search(h)
    if m:
        urls.append(m.group(1)[:500])
        add("Medio", 3, "Redirección automática (meta refresh)", f"El HTML manda al navegador a {m.group(1)[:120]} sin que el usuario haga clic. "
            "Se usa para saltar de una página inocente a la de captura de datos.", ["T1566.002"], "meta")
    if HREF_NUMENT.search(h):
        add("Medio", 3, "Enlace escrito con entidades HTML numéricas", "Un enlace está escrito como «&#104;&#116;…» para que no se lea ni lo detecten filtros simples. "
            "El navegador lo interpreta igual que un enlace normal.", ["T1027", "T1566.002"], "nument")

    hp = _Hidden()
    try:
        hp.feed(h)
        hp.close()
    except Exception:  # noqa: BLE001 - un HTML roto no debe tumbar el análisis
        log.debug("html_parse_error")
    if hp.hidden_chars >= 150:
        add("Bajo", 0, "Texto oculto en el HTML", f"Hay unos {hp.hidden_chars} caracteres de texto invisibles (por ejemplo «{hp.samples[0] if hp.samples else ''}»). "
            "Algunos correos legítimos ocultan un resumen, pero también se usa para meter palabras que despistan a los filtros.", ["T1027"], "hidden")
    if hp.invisible >= 5:
        add("Bajo", 1, "Caracteres invisibles dentro de palabras", f"Hay {hp.invisible} palabras partidas con caracteres de ancho cero. Se usan para evadir filtros por texto.", ["T1027"], "zerowidth")

    scripts = SCRIPT_RE.findall(h)
    blob = "\n".join(scripts)[:MAX_HTML] if scripts else ""
    if blob:
        dec = _js_decoded(blob)
        decoded += dec
        for t in dec:
            for u in URL_RE.findall(t):
                urls.append(u.rstrip(".,;'\")"))
        kinds = []
        if re.search(r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]", blob):
            kinds.append("eval / Function")
        if ATOB_RE.search(blob) or re.search(r"\batob\s*\(", blob):
            kinds.append("atob (Base64)")
        if UNESCAPE_RE.search(blob) or re.search(r"\bunescape\s*\(|decodeURIComponent\s*\(\s*['\"]%", blob):
            kinds.append("unescape / %XX")
        if FROMCHAR_RE.search(blob) or re.search(r"fromCharCode", blob):
            kinds.append("fromCharCode")
        if ESC_RUN_RE.search(blob):
            kinds.append("secuencias \\x / \\u")
        if BIG_B64_RE.search(blob):
            kinds.append("bloque Base64 largo")
        if re.search(r"document\.write\s*\(\s*(?:unescape|atob|String)", blob):
            kinds.append("document.write de texto decodificado")
        smuggle = (re.search(r"new\s+Blob\s*\(", blob) and re.search(r"createObjectURL|msSaveOrOpenBlob|saveAs\s*\(", blob)
                   and (BIG_B64_RE.search(blob) or re.search(r"atob\s*\(|Uint8Array", blob)))
        if smuggle:
            add("Crítico", 7, "Posible HTML smuggling: el HTML arma y descarga un archivo",
                f"El script construye un archivo en el navegador (Blob + descarga) a partir de datos incrustados. Así se entrega malware sin que pase por el filtro de adjuntos ({where}).",
                ["T1027.006", "T1204.002"], "smuggle")
        elif len(kinds) >= 2:
            add("Alto", 5, "JavaScript ofuscado en el HTML", f"El script combina técnicas de ocultación ({', '.join(kinds[:4])}). "
                "El código legítimo de un correo o de un adjunto casi nunca necesita esconder lo que hace.", ["T1027.010", "T1059.007"], "jsobf")
        elif scripts and where == "cuerpo":
            add("Medio", 3, "El correo contiene JavaScript", "Los clientes de correo no ejecutan scripts; incluirlos suele indicar un HTML reutilizado de una página de phishing.", ["T1059.007"], "script")
        if urls and not smuggle and len(kinds) < 2:
            add("Medio", 3, "El script esconde una URL decodificándola", "Una dirección se arma a partir de texto codificado en vez de aparecer escrita.", ["T1027", "T1566.002"], "jsurl")
    return {"signals": signals, "urls": list(dict.fromkeys(urls))[:8], "decoded": [d[:300] for d in decoded[:3]]}
