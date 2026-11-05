"""Decodifica comandos de PowerShell con ``-EncodedCommand`` para mostrar qué ejecutan, sin ejecutar nada.

El contenido es Base64 de texto UTF-16LE. Además se revisa una capa más (el patrón habitual de ``FromBase64String`` + Deflate/GZip) con un
tope de tamaño para que un archivo comprimido malicioso no pueda agotar la memoria. Todo es análisis estático y offline.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib

MAX_B64 = 200_000            # caracteres de Base64 que se aceptan
MAX_OUT = 100_000            # bytes máximos tras descomprimir
SHOW = 1500                  # caracteres que se muestran
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]{4,200}", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{36,}={0,2}")
# -e, -ec, -enc… hasta -EncodedCommand: PowerShell acepta cualquier prefijo de «encodedcommand» que empiece por «e» (y el alias -ec)
FLAG_RE = re.compile(r"(?:^|[\s;&|\"'(])-(e[a-z]*)\s+[\"']?([A-Za-z0-9+/]{16,}={0,2})", re.I)
FULL = "encodedcommand"
INDICATORS = [
    (r"invoke-expression|\biex\b", "ejecuta texto como código (IEX)"),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer", "descarga contenido de Internet"),
    (r"frombase64string", "decodifica otra capa de Base64"),
    (r"deflatestream|gzipstream|decompress", "descomprime un payload"),
    (r"-w(indowstyle)?\s+hidden|-nop\b|-noprofile|-ep\s+bypass|executionpolicy\s+bypass", "oculta la ventana o salta la política de ejecución"),
    (r"amsiutils|amsiinitfailed|amsi\.dll", "intenta desactivar AMSI (antimalware)"),
    (r"add-mppreference|set-mppreference\s+-disable", "modifica las exclusiones o la protección de Defender"),
    (r"reflection\.assembly|virtualalloc|createthread|add-type", "carga código nativo o ensamblados en memoria (inyección)"),
    (r"new-object\s+net\.sockets|tcpclient|\bnc(\.exe)?\s+-e", "abre una conexión de red tipo shell inversa"),
    (r"schtasks|new-scheduledtask|currentversion\\run", "crea persistencia"),
]


def _printable(text: str) -> float:
    return sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text))


def _b64(data: str) -> bytes | None:
    data = data.strip()
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _inflate(raw: bytes) -> bytes | None:
    for wbits in (-15, 31, 15):                     # Deflate crudo, GZip, zlib
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(raw, MAX_OUT)
            if out and not d.unconsumed_tail or len(out) >= MAX_OUT:
                return out
        except zlib.error:
            continue
    return None


def _text(raw: bytes) -> str | None:
    for enc in ("utf-16-le", "utf-8"):
        try:
            t = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if _printable(t) > 0.9:
            return t
    return None


def decode(command: str) -> dict | None:
    """Si ``command`` trae ``-EncodedCommand``, devuelve {decoded, inner, urls, ips, indicators, plausible}; si no, None."""
    if not command:
        return None
    for m in FLAG_RE.finditer(command[:MAX_B64 + 500]):
        flag = m.group(1).lower()
        if not (FULL.startswith(flag) or flag == "ec"):          # «-ec» es un alias aceptado aunque no sea prefijo
            continue
        blob = m.group(2)
        if len(blob) > MAX_B64:
            return {"decoded": "", "inner": "", "urls": [], "ips": [], "indicators": [], "plausible": False, "note": "El comando codificado es demasiado grande para decodificarlo aquí."}
        raw = _b64(blob)
        text = _text(raw) if raw else None
        if text is None:
            return {"decoded": "", "inner": "", "urls": [], "ips": [], "indicators": [], "plausible": False,
                    "note": "El Base64 no se decodifica a texto legible (UTF-16): puede estar truncado o no ser un comando de PowerShell."}
        inner = ""
        for blobm in B64_BLOB_RE.finditer(text):
            rawi = _b64(blobm.group(0))
            if not rawi:
                continue
            out = _inflate(rawi)
            t2 = _text(out) if out else _text(rawi)
            if t2:
                inner = t2
                break
        full = text + "\n" + inner
        low = full.lower()
        ips = [i for i in dict.fromkeys(IPV4_RE.findall(full)) if all(0 <= int(p) <= 255 for p in i.split("."))]
        return {"decoded": text.strip()[:SHOW], "inner": inner.strip()[:SHOW],
                "urls": list(dict.fromkeys(u.rstrip(".,;'\"") for u in URL_RE.findall(full)))[:8], "ips": ips[:8],
                "indicators": [label for pat, label in INDICATORS if re.search(pat, low)], "plausible": True, "note": ""}
    return None


def summary(res: dict) -> str:
    """Frase corta para mostrar al analista."""
    if not res["plausible"]:
        return res["note"]
    bits = res["indicators"][:3]
    return "Decodificado: «" + re.sub(r"\s+", " ", res["decoded"])[:160] + "»" + (f". Hace lo siguiente: {'; '.join(bits)}." if bits else ".")
