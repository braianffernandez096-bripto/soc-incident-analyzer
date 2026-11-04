"""Análisis de correos sospechosos (.eml): encabezados, SPF/DKIM/DMARC, URLs y adjuntos.

Principios
- El .eml es un archivo hostil: se lee solo como texto. No se renderiza el HTML, no se abre ningún enlace, no se
  ejecuta ni se extrae ningún adjunto (de los ZIP solo se lee la lista de nombres) y todo tiene un tope de tamaño.
- Es determinista: cada señal tiene un peso fijo y la criticidad sale de la suma. No hay IA ni consultas de red aquí
  (la reputación es un paso aparte, opcional y confirmado por el analista, en ``intel.py``).
- Las cabeceras de autenticación (Authentication-Results, Received-SPF) las escribe el servidor que recibió el
  correo: sirven si ese servidor es el tuyo. Un remitente puede incluirlas falsas; se informa en «Qué verificar».
- El mapeo a ATT&CK es orientativo.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from io import BytesIO
from urllib.parse import urlparse

log = logging.getLogger("soc.phishing")

MAX_EML_BYTES = 5 * 1024 * 1024
MAX_PARTS = 200
MAX_URLS = 60
MAX_ATTACHMENTS = 25
MAX_ATTACH_SCAN = 2 * 1024 * 1024       # bytes de un adjunto que se examinan (firma y marcadores)
SEV_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]

# Marcas que los atacantes suplantan con frecuencia -> dominios oficiales (dominio registrable).
BRANDS = {
    "paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com"},
    "office365": {"office.com", "office365.com", "microsoft.com", "microsoftonline.com"}, "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"}, "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.es", "amazon.com.mx", "amazon.com.br", "amazonaws.com"}, "netflix": {"netflix.com"},
    "mercadolibre": {"mercadolibre.com", "mercadolibre.com.ar", "mercadolibre.com.mx", "mercadolivre.com.br"}, "mercadopago": {"mercadopago.com", "mercadopago.com.ar"},
    "santander": {"santander.com", "santander.com.ar", "santander.com.mx", "santander.es"}, "bbva": {"bbva.com", "bbva.com.ar", "bbva.mx", "bbva.es"},
    "galicia": {"galicia.com.ar", "bancogalicia.com.ar"}, "afip": {"afip.gob.ar", "arca.gob.ar"}, "arca": {"arca.gob.ar", "afip.gob.ar"},
    "correoargentino": {"correoargentino.com.ar"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"}, "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com"},
    "dropbox": {"dropbox.com"}, "docusign": {"docusign.com", "docusign.net"}, "github": {"github.com"},
}
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.com.ar", "live.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "aol.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "lnkd.in"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "icu", "monster", "buzz", "cam", "sbs", "cyou", "cfd"}
SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "gob", "ac"}          # com.ar, co.uk, gob.mx, org.br…
EXEC_EXT = {"exe", "scr", "com", "pif", "msi", "dll", "cpl", "jar", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "reg", "chm", "iso", "img", "vhd", "application", "gadget"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "xlsb"}
OFFICE_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods"}
DOC_EXT = {"pdf", "txt", "csv"} | OFFICE_EXT
IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "z", "bz2", "xz"}
HTML_EXT = {"html", "htm", "xhtml", "svg", "shtml", "mht", "mhtml"}

URGENCY = re.compile(r"urgente|inmediat|último aviso|ultimo aviso|vence hoy|en las próximas \d+ horas|dentro de las próximas|act now|immediately|final notice|within 24 hours|expires today", re.I)
ENABLE_CONTENT = re.compile(r"habilit\w* (?:el )?(?:contenido|las macros|macros|la edici[oó]n)|activ\w* (?:el )?(?:contenido|las macros|macros)|enable (?:content|macros|editing)", re.I)
CREDENTIALS = re.compile(r"verifica(?:r)? tu (?:cuenta|identidad|contraseña)|confirma(?:r)? tu (?:cuenta|identidad|contraseña)|cuenta (?:suspendida|bloqueada|será (?:suspendida|bloqueada|cerrada))|restablec|actualiza(?:r)? tus datos|inicia(?:r)? sesión|ingresa(?:r)? tu (?:clave|contraseña)|verify your (?:account|identity|password)|confirm your (?:account|password)|account (?:has been )?(?:suspended|locked)|sign in to (?:your|view)|password (?:will )?expire", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
HOP_FROM_RE = re.compile(r"from\s+(?P<from>\S+)", re.I)
BRACKET_IP_RE = re.compile(r"[\[(](?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,39})[\])]", re.I)
CTRL_RE = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")    # control y marcas de dirección (RLO), como escapes: sin caracteres bidi en el código


class EmlError(ValueError):
    """El archivo no se puede leer como un correo."""


# ---------------------------------------------------------------- utilidades

def _clean(value, limit: int = 300) -> str:
    s = CTRL_RE.sub("", str(value or "")).strip()
    s = re.sub(r"\s+", " ", s)
    return s[: limit - 1] + "…" if len(s) > limit else s


def _hdr(msg, name: str) -> str:
    try:
        v = msg.get(name)
        return _clean(v, 500) if v is not None else ""
    except Exception:  # noqa: BLE001 - una cabecera malformada no debe tumbar el análisis
        return ""


def _hdr_all(msg, name: str) -> list[str]:
    try:
        return [_clean(v, 1500) for v in (msg.get_all(name) or [])][:20]
    except Exception:  # noqa: BLE001
        return []


def defang(url: str) -> str:
    """hxxps://sitio[.]com/ruta: se puede copiar y pegar en un informe sin que sea un enlace activo."""
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    m = re.match(r"^(\w+://)([^/?#]+)(.*)$", out)
    return f"{m.group(1)}{m.group(2).replace('.', '[.]')}{m.group(3)}" if m else out.replace(".", "[.]")


def reg_domain(host: str) -> str:
    """Dominio registrable aproximado (sin lista de sufijos públicos): sitio.com, sitio.com.ar."""
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})


def _squash(label: str) -> str:
    return label.lower().translate(_HOMOGLYPH).replace("rn", "m").replace("vv", "w").replace("-", "")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _public_ip(ip: str) -> bool:
    """IP fuera de la red interna. Los rangos de documentación (RFC 5737) cuentan como externos: son los que usan los ejemplos."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global or any(a in n for n in _DOC_NETS if n.version == a.version)


def _addr(raw: str) -> tuple[str, str]:
    name, addr = parseaddr(raw or "")
    return _clean(name, 150), _clean(addr, 200).lower()


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _brand_in(text: str) -> str:
    t = re.sub(r"[^a-z0-9]", "", text.lower())
    return next((b for b in BRANDS if b in t), "")


class _Sig:
    """Acumula señales; cada una con severidad, puntos y la categoría donde se muestra."""

    def __init__(self) -> None:
        self.items: list[dict] = []
        self._seen: set[tuple] = set()

    def add(self, cat: str, sev: str, pts: int, title: str, detail: str, mitre: list[str] | None = None, key=None) -> None:
        k = (cat, title, key)
        if k in self._seen:
            return
        self._seen.add(k)
        self.items.append({"category": cat, "severity": sev, "points": pts, "title": title, "detail": detail, "mitre": mitre or []})


# ---------------------------------------------------------------- cuerpo y enlaces

class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []          # (href, texto visible)
        self.forms: list[str] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "br":
            self.text.append("\n")
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self._href, self._buf = a["href"].strip(), []
        elif tag == "form" and a.get("action"):
            self.forms.append(a["action"].strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())))
            self._href = None
        if tag in ("a", "p", "div", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "table", "ul", "ol") and not self._skip:
            self.text.append("\n")             # sin separador, el texto de dos bloques seguidos se pegaría y formaría URL falsas

    def handle_startendtag(self, tag, attrs):
        if tag == "br":
            self.text.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _decode(part) -> str:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:  # noqa: BLE001
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload[:MAX_EML_BYTES].decode(charset, errors="replace")
    except LookupError:
        return payload[:MAX_EML_BYTES].decode("utf-8", errors="replace")


# ---------------------------------------------------------------- autenticación y recorrido

def _auth(msg) -> dict:
    res = {"spf": "", "dkim": "", "dmarc": "", "spf_domain": "", "dkim_domain": "", "dmarc_from": "", "raw": []}
    for h in _hdr_all(msg, "Authentication-Results"):
        res["raw"].append(h)
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", h, re.I)
            if m and not res[mech]:
                res[mech] = m.group(1).lower()
        m = re.search(r"smtp\.mailfrom=([^\s;]+)", h, re.I)
        if m and not res["spf_domain"]:
            res["spf_domain"] = _domain_of(m.group(1).lower()) or m.group(1).lower()
        m = re.search(r"header\.d=([^\s;]+)", h, re.I)
        if m and not res["dkim_domain"]:
            res["dkim_domain"] = m.group(1).lower()
        m = re.search(r"header\.from=([^\s;]+)", h, re.I)
        if m and not res["dmarc_from"]:
            res["dmarc_from"] = m.group(1).lower()
    for h in _hdr_all(msg, "Received-SPF"):
        res["raw"].append(h)
        m = re.match(r"\s*(\w+)", h)
        if m and not res["spf"]:
            res["spf"] = m.group(1).lower()
    res["raw"] = res["raw"][:6]
    return res


def _hops(msg) -> list[dict]:
    """Cadena Received del más reciente al más antiguo; la última es el primer salto (origen)."""
    hops = []
    for raw in _hdr_all(msg, "Received")[:15]:
        m = HOP_FROM_RE.search(raw)
        by = re.search(r"\bby\s+(\S+)", raw, re.I)
        ips = [x.group("ip") for x in BRACKET_IP_RE.finditer(raw) if _is_ip(x.group("ip"))]
        when = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
        hops.append({"from": _clean(m.group("from"), 120) if m else "", "by": _clean(by.group(1), 120) if by else "",
                     "ip": ips[0] if ips else "", "public": bool(ips and _public_ip(ips[0])), "when": _clean(when, 60)})
    return hops


# ---------------------------------------------------------------- adjuntos

def _sniff(data: bytes) -> str:
    h = data[:16]
    if h[:2] == b"MZ":
        return "exe"
    if h[:4] == b"\x7fELF":
        return "elf"
    if h[:4] == b"%PDF":
        return "pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if h[:5] == b"{\\rtf":
        return "rtf"
    if h[:3] == b"\xff\xd8\xff":
        return "jpg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:4] == b"GIF8":
        return "gif"
    if h[:4] == b"Rar!":
        return "rar"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    return ""


def _attachment(part, sig: _Sig) -> dict:
    name = _clean(part.get_filename() or "", 200) or "(sin nombre)"
    try:
        data = part.get_payload(decode=True) or b""
    except Exception:  # noqa: BLE001
        data = b""
    ctype = (part.get_content_type() or "").lower()
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    stem_ext = name.rsplit(".", 2)[-2].lower() if name.count(".") >= 2 else ""
    magic = _sniff(data[:MAX_ATTACH_SCAN])
    sha = hashlib.sha256(data).hexdigest()
    info = {"filename": name, "content_type": ctype, "size": len(data), "sha256": sha, "ext": ext, "magic": magic, "notes": [], "risk": "Bajo"}
    notes: list[str] = []

    def flag(sev: str, pts: int, title: str, detail: str, mitre: list[str]) -> None:
        notes.append(title)
        info["risk"] = min((info["risk"], sev), key=SEV_ORDER.index)
        sig.add("Adjunto", sev, pts, f"{title} ({name})", detail, mitre, key=sha)

    double = stem_ext in DOC_EXT | IMAGE_EXT and ext in EXEC_EXT | {"html", "htm"}
    if magic in ("exe", "elf") and ext not in EXEC_EXT:
        flag("Crítico", 10, "Ejecutable disfrazado", f"El contenido es un programa ejecutable ({'Windows PE' if magic == 'exe' else 'ELF'}) pero el nombre dice «.{ext or '?'}».", ["T1036.007", "T1566.001", "T1204.002"])
    if double:
        flag("Alto", 8, "Doble extensión", f"«{name}» parece un documento o imagen pero termina en «.{ext}», que se ejecuta al abrirlo.", ["T1036.007", "T1566.001", "T1204.002"])
    elif ext in EXEC_EXT:
        flag("Alto", 6, "Adjunto ejecutable o script", f"Los adjuntos «.{ext}» pueden ejecutar código y los filtros de correo normalmente los bloquean.", ["T1566.001", "T1204.002"])
    if ext in MACRO_EXT:
        flag("Medio", 4, "Documento con macros habilitadas", f"El formato «.{ext}» admite macros VBA, una vía habitual de ejecución.", ["T1566.001", "T1204.002"])
    if ext in HTML_EXT:
        flag("Medio", 3, "Adjunto HTML/SVG", "Un archivo HTML adjunto puede mostrar un formulario falso de inicio de sesión sin pasar por filtros de URL.", ["T1566.001"])
    if ext in ARCHIVE_EXT or magic in ("zip", "rar", "7z") and ext not in OFFICE_EXT | MACRO_EXT:
        notes.append("Archivo comprimido")
        info["risk"] = min((info["risk"], "Medio"), key=SEV_ORDER.index)
        sig.add("Adjunto", "Medio", 1, f"Archivo comprimido ({name})", "Los comprimidos se usan para ocultar contenido de los filtros; hay que revisar qué contiene.", ["T1566.001"], key=sha)
    if magic == "zip" and data:
        try:
            with zipfile.ZipFile(BytesIO(data[:MAX_ATTACH_SCAN])) as z:        # solo la lista de nombres, nada se descomprime
                infos = z.infolist()[:500]
                names = [i.filename for i in infos]
                if any(i.flag_bits & 0x1 for i in infos):
                    flag("Alto", 5, "Comprimido protegido con contraseña", "El contenido cifrado no puede ser inspeccionado por el antivirus del correo.", ["T1566.001", "T1027.013"])
                inner = [n for n in names if n.rsplit(".", 1)[-1].lower() in EXEC_EXT]
                if inner:
                    flag("Alto", 6, "El comprimido contiene ejecutables o scripts", f"Dentro hay {', '.join(_clean(n, 60) for n in inner[:3])}.", ["T1566.001", "T1204.002"])
                if ext not in MACRO_EXT and any(n.lower().endswith("vbaproject.bin") for n in names):
                    flag("Medio", 4, "Documento Office con macros VBA", "El paquete contiene vbaProject.bin: tiene macros aunque el nombre no lo diga.", ["T1566.001", "T1204.002"])
                if any(n.lower().startswith(("word/embeddings/", "xl/embeddings/")) for n in names):
                    flag("Medio", 3, "Documento Office con objetos incrustados", "Los objetos incrustados pueden ejecutar programas al hacer clic.", ["T1566.001", "T1204.002"])
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError, OSError):
            pass
    if magic == "ole" and (b"_VBA_PROJECT" in data[:MAX_ATTACH_SCAN] or b"Macros" in data[:MAX_ATTACH_SCAN]):
        flag("Medio", 4, "Documento Office antiguo con posibles macros", "El archivo OLE contiene marcadores de proyecto VBA.", ["T1566.001", "T1204.002"])
    if magic == "pdf" and re.search(rb"/(JavaScript|JS|Launch|OpenAction)\b", data[:MAX_ATTACH_SCAN]):
        flag("Medio", 3, "PDF con contenido activo", "El PDF incluye acciones al abrir o JavaScript, poco habituales en un documento común.", ["T1566.001", "T1204.002"])
    if ext in IMAGE_EXT and magic and magic not in ("jpg", "png", "gif") and magic not in ("exe", "elf"):
        flag("Medio", 3, "Tipo de archivo no coincide con la extensión", f"El nombre dice imagen y el contenido parece «{magic}».", ["T1036.008"])
    if ext == "pdf" and data and magic not in ("pdf", "exe", "elf"):
        flag("Medio", 3, "El PDF no es un PDF", f"El nombre dice «.pdf» pero el contenido no empieza como un PDF ({magic or 'desconocido'}).", ["T1036.008"])
    info["notes"] = notes
    return info


# ---------------------------------------------------------------- análisis principal

def _check_url(url: str, text: str, sig: _Sig, from_domains: set[str], location: str) -> dict:
    raw = url.strip()
    info = {"url": raw[:300], "defanged": defang(raw[:300]), "host": "", "domain": "", "text": _clean(text, 120), "flags": [], "location": location}
    scheme = urlparse(raw).scheme.lower() if ":" in raw else ""
    if scheme in ("javascript", "data", "vbscript", "file"):
        info["flags"].append("Esquema peligroso")
        sig.add("URL", "Alto", 5, f"Enlace con esquema «{scheme}:»", "El enlace ejecuta código o abre datos en vez de ir a un sitio web.", ["T1566.002", "T1204.001"], key=scheme)
        return info
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower().strip(".")
    except ValueError:
        return info
    if not host:
        return info
    dom = reg_domain(host) if not _is_ip(host) else host
    info.update(host=host, domain=dom)
    mitre = ["T1566.002", "T1204.001"]
    if _is_ip(host):
        info["flags"].append("IP en vez de dominio")
        sig.add("URL", "Alto", 4, "Enlace a una dirección IP", f"El enlace va directo a {host}: los sitios legítimos usan un nombre de dominio.", mitre, key=host)
    if p.username is not None or "@" in (p.netloc or ""):
        info["flags"].append("Usuario en la URL")
        sig.add("URL", "Alto", 4, "URL con «@»: el destino real no es el que parece", f"Todo lo anterior a «@» es un usuario; el sitio real es {host}.", mitre, key=host)
    if host.startswith("xn--") or ".xn--" in host:
        info["flags"].append("Punycode")
        sig.add("URL", "Medio", 3, "Dominio con punycode (xn--)", f"{host} puede mezclar caracteres de otros alfabetos para parecerse a otro dominio.", mitre, key=host)
    if dom in SHORTENERS:
        info["flags"].append("Acortador")
        sig.add("URL", "Medio", 2, "Enlace acortado", f"{dom} oculta el destino final; hay que expandirlo en un entorno seguro.", mitre, key=dom)
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS and not _is_ip(host):
        info["flags"].append(f"TLD .{tld}")
        sig.add("URL", "Medio", 2, f"Dominio con TLD de alto riesgo (.{tld})", f"{host}: este TLD se usa con frecuencia en campañas de phishing (orientativo).", mitre, key=dom)
    if p.scheme == "http":
        info["flags"].append("Sin HTTPS")
        sig.add("URL", "Bajo", 1, "Enlace sin HTTPS", "El sitio no cifra la conexión.", mitre, key=dom)
    if not _is_ip(host):
        labels = host.split(".")
        brand_hit = next((b for b in BRANDS if b in re.sub(r"[^a-z0-9]", "", ".".join(labels[:-1])) and dom not in BRANDS[b]), "")
        if brand_hit:
            info["flags"].append(f"Suplanta {brand_hit}")
            sig.add("URL", "Alto", 5, f"Dominio que imita a {brand_hit}", f"{host} contiene «{brand_hit}» pero su dominio real es {dom}, que no es de esa empresa.", ["T1566.002", "T1684.001"], key=dom)
        else:
            label = dom.split(".")[0]
            for b, official in BRANDS.items():
                if dom in official or len(b) < 5:
                    continue
                if _squash(label) == b or (0 < _lev(label.replace("-", ""), b) <= 1 and abs(len(label) - len(b)) <= 1):
                    info["flags"].append(f"Parecido a {b}")
                    sig.add("URL", "Alto", 5, f"Dominio casi idéntico a {b}", f"{dom} se parece a «{b}» con letras cambiadas (typosquatting).", ["T1566.002", "T1684.001"], key=dom)
                    break
        if len(labels) - len(dom.split(".")) >= 3:
            info["flags"].append("Muchos subdominios")
            sig.add("URL", "Bajo", 1, "Subdominios en exceso", f"{host} tiene muchos niveles, útil para disimular el dominio real.", mitre, key=dom)
    shown = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower()) if text else None
    if shown and not _is_ip(host) and reg_domain(shown.group(1)) != dom:
        info["flags"].append("Texto engañoso")
        sig.add("URL", "Alto", 5, "El texto del enlace muestra otro dominio", f"Dice «{shown.group(1)}» pero apunta a {host}.", mitre, key=(shown.group(1), host))
    return info


def analyze_eml(data: bytes, filename: str = "correo.eml") -> dict:
    if len(data) > MAX_EML_BYTES:
        raise EmlError("El correo supera el límite de 5 MB.")
    head = data[:8192].decode("utf-8", errors="ignore")
    if not re.search(r"^(?:From|Received|Subject|Message-ID|MIME-Version|Date|To|Return-Path|Authentication-Results):", head, re.I | re.M):
        raise EmlError("El archivo no parece un correo en formato .eml (no se encontraron encabezados como From, Subject o Received).")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # noqa: BLE001
        raise EmlError("No se pudo leer el correo: el formato de los encabezados es inválido.") from exc

    sig = _Sig()
    from_raw, reply_raw, rpath_raw = _hdr(msg, "From"), _hdr(msg, "Reply-To"), _hdr(msg, "Return-Path")
    from_name, from_addr = _addr(from_raw)
    _, reply_addr = _addr(reply_raw)
    _, rpath_addr = _addr(rpath_raw)
    from_dom, reply_dom, rpath_dom = _domain_of(from_addr), _domain_of(reply_addr), _domain_of(rpath_addr)
    subject = _hdr(msg, "Subject")
    headers = {"from": from_raw, "from_name": from_name, "from_addr": from_addr, "reply_to": reply_raw, "return_path": rpath_raw,
               "to": _hdr(msg, "To"), "date": _hdr(msg, "Date"), "message_id": _hdr(msg, "Message-ID"), "subject": subject,
               "x_mailer": _hdr(msg, "X-Mailer") or _hdr(msg, "User-Agent")}

    # ---- remitente y suplantación -------------------------------------------------
    if not from_addr:
        sig.add("Encabezados", "Medio", 3, "Sin remitente válido", "El encabezado From no tiene una dirección legible.")
    if reply_dom and from_dom and reg_domain(reply_dom) != reg_domain(from_dom):
        sig.add("Encabezados", "Alto", 3, "Reply-To de otro dominio", f"Las respuestas van a {reply_addr}, no a {from_dom}: típico para desviar la conversación.", ["T1566"])
    if rpath_dom and from_dom and reg_domain(rpath_dom) != reg_domain(from_dom):
        sig.add("Encabezados", "Bajo", 1, "Return-Path de otro dominio", f"El remitente del sobre ({rpath_addr}) no coincide con el visible ({from_addr}); es normal en envíos masivos legítimos.")
    shown_email = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_name)
    if shown_email and shown_email.group(0).lower() != from_addr:
        sig.add("Encabezados", "Alto", 4, "El nombre visible muestra otra dirección", f"Dice «{shown_email.group(0)}» pero el correo real es {from_addr}.", ["T1684.001"])
    brand = _brand_in(from_name)
    if brand and from_dom and reg_domain(from_dom) not in BRANDS[brand]:
        sig.add("Encabezados", "Alto", 4, f"Se hace pasar por {brand}", f"El nombre visible menciona «{brand}» pero el dominio real es {from_dom}.", ["T1684.001", "T1566"])
    elif from_dom in FREE_MAIL and re.search(r"soporte|support|seguridad|security|banco|bank|admin|servicio|cobranza|facturaci|rrhh|recursos humanos|helpdesk|it\b", from_name, re.I):
        sig.add("Encabezados", "Medio", 2, "Cuenta gratuita con nombre de área oficial", f"«{from_name}» escribe desde {from_dom}: una empresa real usaría su propio dominio.", ["T1684.001"])
    mid = headers["message_id"]
    if mid and from_dom and "@" in mid and reg_domain(re.sub(r"[<>]", "", mid).rsplit("@", 1)[-1].lower()) != reg_domain(from_dom) and from_dom not in FREE_MAIL:
        sig.add("Encabezados", "Bajo", 1, "Message-ID de otro dominio", "El identificador del mensaje no fue generado por el dominio del remitente (puede ser un servicio de envío).")
    try:
        when = parsedate_to_datetime(headers["date"]) if headers["date"] else None
        if when and when.tzinfo and when > datetime.now(timezone.utc):
            sig.add("Encabezados", "Bajo", 1, "Fecha en el futuro", "El encabezado Date está adelantado respecto a la fecha actual.")
    except (TypeError, ValueError):
        pass

    # ---- autenticación ------------------------------------------------------------
    auth = _auth(msg)
    favorable: list[str] = []
    if not (auth["spf"] or auth["dkim"] or auth["dmarc"]):
        sig.add("Autenticación", "Bajo", 1, "Sin resultados de SPF/DKIM/DMARC", "El .eml no trae Authentication-Results ni Received-SPF (pudo exportarse sin ellos); no se puede confirmar el origen.")
    for mech, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        v = auth[mech]
        if v in ("fail", "permerror") and mech != "dkim":
            sig.add("Autenticación", "Alto", 4 if mech == "dmarc" else 3, f"{label} falló ({v})", f"El servidor que recibió el correo marcó {label}={v}: el remitente no está autorizado a enviar por ese dominio." if mech == "spf" else f"DMARC={v}: ni SPF ni DKIM se alinean con el dominio visible.", ["T1566"])
        elif v == "softfail":
            sig.add("Autenticación", "Medio", 2, "SPF softfail", "El dominio indica que probablemente no debería enviar desde esa IP, pero no lo rechaza.", ["T1566"])
        elif mech == "dkim" and v in ("fail", "permerror"):
            sig.add("Autenticación", "Medio", 2, f"DKIM falló ({v})", "La firma del correo no es válida: pudo ser modificado o no es del dominio que dice.", ["T1566"])
        elif v in ("none", "neutral", "temperror") and mech == "dmarc":
            sig.add("Autenticación", "Bajo", 1, f"DMARC sin política efectiva ({v})", "El dominio visible no protege con DMARC.")
        elif v == "pass":
            favorable.append(f"{label} = pass")
    if auth["spf"] == "pass" and auth["spf_domain"] and from_dom and reg_domain(auth["spf_domain"]) != reg_domain(from_dom):
        sig.add("Autenticación", "Medio", 2, "SPF pasa pero no se alinea", f"SPF validó el dominio {auth['spf_domain']}, distinto del visible ({from_dom}): el «pass» no prueba que sea quien dice.", ["T1566"])
    if auth["dkim"] == "pass" and auth["dkim_domain"] and from_dom and reg_domain(auth["dkim_domain"]) != reg_domain(from_dom):
        sig.add("Autenticación", "Medio", 2, "DKIM pasa pero no se alinea", f"La firma es de {auth['dkim_domain']}, no de {from_dom}.", ["T1566"])

    # ---- recorrido ----------------------------------------------------------------
    hops = _hops(msg)
    origin = next((h for h in reversed(hops) if h["public"]), None)

    # ---- cuerpo, enlaces y adjuntos -------------------------------------------------
    urls: list[dict] = []
    seen_urls: set[str] = set()
    attachments: list[dict] = []
    body_text: list[str] = []
    html_forms: list[str] = []
    shown_text: set[str] = set()          # texto visible de los enlaces: no se repite como URL suelta
    n_parts = 0
    for part in msg.walk():
        n_parts += 1
        if n_parts > MAX_PARTS:
            break
        ctype = part.get_content_type()
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        if part.get_filename() or disp == "attachment" or ctype == "message/rfc822":
            if len(attachments) < MAX_ATTACHMENTS:
                attachments.append(_attachment(part, sig))
            continue
        if ctype == "text/html":
            lp = _LinkParser()
            try:
                lp.feed(_decode(part))
                lp.close()
            except Exception:  # noqa: BLE001 - un HTML roto no debe tumbar el análisis: se sigue con lo que se alcanzó a leer
                log.debug("html_parse_error")
            body_text.append("\n".join(" ".join(x.split()) for x in "".join(lp.text).split("\n") if x.strip()))
            shown_text |= {t for _, t in lp.links if t}
            html_forms += lp.forms
            for href, txt in lp.links:
                if href and href not in seen_urls and len(urls) < MAX_URLS and not href.lower().startswith(("mailto:", "tel:", "#", "cid:")):
                    seen_urls.add(href)
                    urls.append(_check_url(href, txt, sig, {from_dom}, "enlace en HTML"))
        elif ctype == "text/plain":
            body_text.append(_decode(part))
    plain = "\n".join(body_text)
    for m in URL_RE.finditer(plain):
        u = m.group(0).rstrip(".,;:!?")
        if u not in seen_urls and u not in shown_text and len(urls) < MAX_URLS:
            seen_urls.add(u)
            urls.append(_check_url(u, "", sig, {from_dom}, "texto del cuerpo"))
    for f in html_forms[:5]:
        if f.lower().startswith(("http", "//")):
            sig.add("URL", "Alto", 3, "Formulario que envía datos a un sitio externo", f"El HTML incluye un formulario cuyo destino es {_clean(defang(f), 120)}: puede recolectar credenciales.", ["T1566.002", "T1598.003"], key=f)
    if URGENCY.search(plain + " " + subject):
        sig.add("Contenido", "Bajo", 1, "Lenguaje de urgencia", "El mensaje presiona para actuar rápido, un recurso habitual de la ingeniería social.", ["T1566"])
    if CREDENTIALS.search(plain + " " + subject):
        sig.add("Contenido", "Medio", 2, "Pide verificar la cuenta o iniciar sesión", "El texto solicita credenciales o datos de la cuenta.", ["T1566.002", "T1598.003"])
    if ENABLE_CONTENT.search(plain + " " + subject):
        sig.add("Contenido", "Medio", 3, "Pide habilitar contenido o macros", "Habilitar el contenido de un documento recibido por correo es la forma de activar sus macros.", ["T1566.001", "T1204.002"])
    if attachments and re.search(r"adjunto|attached|attachment|factura|invoice|comprobante|pago|payment", plain + " " + subject, re.I) and any(a["risk"] != "Bajo" for a in attachments):
        sig.add("Contenido", "Bajo", 1, "El texto empuja a abrir el adjunto", "Factura, pago o comprobante: pretextos frecuentes para que el usuario abra el archivo.", ["T1566.001"])
    if not urls and not attachments and not plain.strip():
        sig.add("Contenido", "Bajo", 0, "Correo sin cuerpo legible", "No se pudo extraer texto, enlaces ni adjuntos.")

    # ---- veredicto ----------------------------------------------------------------
    cat_cap = {"URL": 10, "Adjunto": 14, "Autenticación": 8, "Encabezados": 8, "Contenido": 5}
    score, per = 0, {}
    for s in sorted(sig.items, key=lambda x: -x["points"]):
        room = cat_cap.get(s["category"], 6) - per.get(s["category"], 0)
        add = max(0, min(s["points"], room))
        per[s["category"]] = per.get(s["category"], 0) + add
        score += add
    has_crit = any(s["severity"] == "Crítico" for s in sig.items)
    severity = "Crítico" if has_crit or score >= 12 else "Alto" if score >= 6 else "Medio" if score >= 3 else "Bajo"
    verdict = {"Crítico": "Phishing / malware muy probable", "Alto": "Probable phishing", "Medio": "Sospechoso", "Bajo": "Sin señales relevantes"}[severity]
    sig.items.sort(key=lambda x: (SEV_ORDER.index(x["severity"]), -x["points"]))

    mitre: list[str] = []
    for s in sig.items:
        for t in s["mitre"]:
            if t not in mitre:
                mitre.append(t)
    if severity == "Bajo":
        mitre = []

    # ---- IoC, qué verificar y acciones ----------------------------------------------
    iocs: list[dict] = []

    def ioc(kind: str, value: str, note: str) -> None:
        if value and not any(i["type"] == kind and i["value"] == value for i in iocs):
            iocs.append({"type": kind, "value": value, "note": note})

    if from_addr:
        ioc("Correo", from_addr, "Remitente visible")
    if reply_addr and reply_addr != from_addr:
        ioc("Correo", reply_addr, "Reply-To")
    if origin:
        ioc("IP", origin["ip"], "Primer salto público del recorrido (origen probable)")
    for u in urls:
        if u["flags"] and u["url"].lower().startswith(("http://", "https://")):
            ioc("URL/URI", u["url"], "Enlace con señales: " + ", ".join(u["flags"]))
    for a in attachments:
        if a["size"]:
            ioc("SHA256", a["sha256"], f"Adjunto {a['filename']}")

    if severity == "Bajo":
        iocs = []
    verify: list[str] = []
    if severity != "Bajo":
        verify.append("Confirmar con el supuesto remitente, por otro canal (llamada o chat interno), que envió este correo. No respondas al mismo mensaje.")
    if auth["raw"]:
        verify.append("Comprobar los resultados de SPF/DKIM/DMARC en tu propio servidor de correo: estas cabeceras las escribe quien recibe el mensaje y un remitente puede incluirlas falsas.")
    if any(u["flags"] for u in urls):
        verify.append("Buscar en el proxy y en los logs de DNS si alguien visitó los dominios sospechosos y desde qué equipo. Si hubo clic, tratar la cuenta como comprometida.")
        verify.append("Expandir acortadores y analizar las URL en un entorno aislado (sandbox de URL), nunca abrirlas desde un equipo corporativo.")
    if any(a["risk"] != "Bajo" for a in attachments):
        verify.append("Consultar el hash SHA-256 de los adjuntos en VirusTotal y, si no hay datos, detonarlos en una sandbox. No abrirlos en un equipo real.")
        verify.append("Revisar en el EDR si el adjunto se ejecutó (proceso hijo de Outlook u Office, conexiones salientes tras abrirlo).")
    if severity != "Bajo":
        verify.append("Buscar el mismo asunto, remitente o hash en otros buzones para saber cuántos usuarios lo recibieron.")
    if not verify:
        verify.append("Sin señales relevantes: si el usuario aún sospecha, confirma por otro canal antes de actuar.")
    actions: list[str] = []
    if severity in ("Crítico", "Alto"):
        actions += ["Retirar el correo de todos los buzones (purga en el gateway) y bloquear el remitente y los dominios de las URL.",
                    "Si algún usuario hizo clic o abrió el adjunto: aislar el equipo, restablecer su contraseña, cerrar sesiones y revisar reglas de reenvío del buzón.",
                    "Escalar a un analista de nivel superior si el adjunto se ejecutó o hay credenciales entregadas."]
    elif severity == "Medio":
        actions += ["Marcar el mensaje como sospechoso, avisar al usuario que no interactúe y revisar si otros lo recibieron."]
    else:
        actions += ["Sin acción de contención; documentar el análisis y cerrar el reporte."]

    return {
        "filename": _clean(filename, 120), "size": len(data), "headers": headers, "auth": {k: v for k, v in auth.items() if k != "raw"},
        "auth_raw": auth["raw"], "hops": hops, "origin_ip": origin["ip"] if origin else "", "urls": urls, "attachments": attachments,
        "signals": sig.items, "favorable": favorable, "score": score, "severity": severity, "verdict": verdict, "mitre": mitre,
        "iocs": iocs, "verify": verify, "actions": actions,
        "truncated": n_parts > MAX_PARTS or len(urls) >= MAX_URLS,
        "limitations": ["Análisis estático: no se abrieron enlaces ni se ejecutaron adjuntos.",
                        "Los pesos de las señales son orientativos; el veredicto es una ayuda para el triage, no una prueba.",
                        "El mapeo a ATT&CK es orientativo."],
    }


def analyze_many(files: list[tuple[str, bytes]]) -> dict:
    items: list[dict] = []
    errors: list[dict] = []
    for name, data in files:
        try:
            r = analyze_eml(data, name)
            r["id"] = f"MAIL-{len(items) + 1:02d}"
            items.append(r)
        except EmlError as exc:
            errors.append({"filename": _clean(name, 120), "error": str(exc)})
    items.sort(key=lambda i: (SEV_ORDER.index(i["severity"]), -i["score"]))
    for n, i in enumerate(items, 1):
        i["id"] = f"MAIL-{n:02d}"
    return {"items": items, "errors": errors}


def all_iocs(items: list[dict]) -> list[dict]:
    """IoC de todos los correos, con el formato que consume intel.py (type, value)."""
    out, seen = [], set()
    for i in items:
        for x in i["iocs"]:
            if x["type"] in ("IP", "URL/URI", "SHA256") and (x["type"], x["value"]) not in seen:
                seen.add((x["type"], x["value"]))
                out.append({"type": x["type"], "value": x["value"]})
        dom = i["headers"].get("from_addr", "").rsplit("@", 1)[-1]
        if dom and ("URL/URI", f"https://{dom}/") not in seen and i["severity"] != "Bajo":
            seen.add(("URL/URI", f"https://{dom}/"))
            out.append({"type": "URL/URI", "value": f"https://{dom}/"})
    return out
