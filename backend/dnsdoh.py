"""Consultas DNS por HTTPS (DoH) para el evaluador de dominios y la comprobación de dominios parecidos.

Principios de diseño
- Es **opcional y explícito**: nada de lo que hace el análisis de un correo abre una conexión. Solo se consulta cuando el
  analista pulsa «Evaluar» o «Comprobar registro», y solo sale **el nombre de dominio** (nunca el correo, sus enlaces ni sus adjuntos).
- Los servidores son fijos (Cloudflare y, si falla, Google): nada de la petición elige el destino, así que no hay SSRF.
- No hay dependencias nuevas: se usa ``httpx``, que el proyecto ya tiene. No se envían cookies ni claves.
- Se limita el tamaño de la respuesta, no se siguen redirecciones y hay una caché corta para no repetir consultas.
- ``DNS_LOOKUPS=off`` desactiva por completo estas consultas (por ejemplo en una red sin salida a Internet).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import time

import httpx

log = logging.getLogger("soc.dns")

PROVIDERS = [("Cloudflare", "https://cloudflare-dns.com/dns-query"), ("Google", "https://dns.google/resolve")]
TIMEOUT = 5.0
MAX_BODY = 64 * 1024
CACHE_TTL = 300
CACHE_MAX = 500
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class DnsError(RuntimeError):
    """No se pudo consultar ningún servidor DNS (sin red, bloqueado o respuesta inválida)."""


class DnsDisabled(DnsError):
    """El operador desactivó las consultas DNS con DNS_LOOKUPS=off."""


def enabled() -> bool:
    return os.environ.get("DNS_LOOKUPS", "on").strip().lower() not in ("off", "0", "no", "false")


def clean_domain(text: str) -> str:
    """Devuelve el dominio en minúsculas y en forma ASCII (punycode) o lanza ValueError con un mensaje para el usuario.

    Acepta «dominio.com», «https://dominio.com/ruta» y «usuario@dominio.com». Rechaza IP, nombres sin punto y nombres
    internos: aquí solo se evalúan dominios públicos.
    """
    t = (text or "").strip().lower()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = t.rsplit("@", 1)[-1].split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip(".")
    if not t:
        raise ValueError("Escribe un dominio, por ejemplo empresa.com.ar.")
    try:
        ipaddress.ip_address(t)
        raise ValueError("Escribe un nombre de dominio, no una dirección IP.")
    except ValueError as exc:
        if "dirección IP" in str(exc):
            raise
    try:
        ascii_name = t.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("El dominio contiene caracteres que no se pueden convertir (IDN inválido).") from exc
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or len(labels) < 2 or not all(LABEL_RE.match(x) for x in labels):
        raise ValueError("No parece un dominio válido (usa letras, números y guiones; por ejemplo empresa.com.ar).")
    if labels[-1] in {"local", "lan", "internal", "corp", "home", "localdomain", "localhost", "intranet", "test", "invalid", "example"}:
        raise ValueError("Es un dominio interno o reservado: solo se evalúan dominios públicos.")
    if labels[-1].isdigit():
        raise ValueError("El último tramo del dominio no puede ser numérico.")
    return ascii_name


def _txt_value(data: str) -> str:
    """Los TXT largos llegan partidos en cadenas de hasta 255 caracteres: se unen (así los entiende SPF/DKIM)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts).replace('\\"', '"').replace("\\\\", "\\") if parts else data.strip('"')


class DohResolver:
    """Resolvedor DoH mínimo. ``http`` permite inyectar un cliente simulado en las pruebas (nada sale a Internet)."""

    def __init__(self, http: httpx.Client | None = None, providers=None) -> None:
        self._http = http
        self._own = http is None
        self.providers = providers or PROVIDERS
        self._cache: dict[tuple[str, str], tuple[float, dict]] = {}
        self._lock = threading.Lock()
        self.queries = 0

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=TIMEOUT, follow_redirects=False, headers={"user-agent": "soc-incident-analyzer"})
        return self._http

    def close(self) -> None:
        if self._own and self._http is not None:
            self._http.close()
            self._http = None

    def query(self, name: str, rtype: str = "TXT") -> dict:
        """{status, answers, provider}. status: 0 = existe, 3 = NXDOMAIN, 2 = fallo del servidor. ``answers`` son cadenas de texto."""
        if not enabled():
            raise DnsDisabled("Las consultas DNS están desactivadas en este servidor (DNS_LOOKUPS=off).")
        key = (name.lower(), rtype)
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < CACHE_TTL:
                return hit[1]
        want = TYPES[rtype]
        last: Exception | None = None
        for label, url in self.providers:
            try:
                with self._client().stream("GET", url, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"}) as r:
                    if r.status_code != 200:
                        raise DnsError(f"{label} respondió {r.status_code}")
                    body = b""
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY:
                            raise DnsError(f"{label} devolvió una respuesta demasiado grande")
                data = json.loads(body)
                if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
                    raise DnsError(f"{label} devolvió una respuesta inesperada")
                answers = []
                for a in data.get("Answer") or []:
                    if isinstance(a, dict) and a.get("type") == want and isinstance(a.get("data"), str):
                        answers.append(_txt_value(a["data"]) if rtype == "TXT" else a["data"].strip().rstrip("."))
                res = {"status": data["Status"], "answers": answers[:50], "provider": label}
                with self._lock:
                    self.queries += 1
                    if len(self._cache) >= CACHE_MAX:
                        self._cache.clear()
                    self._cache[key] = (now, res)
                return res
            except (httpx.HTTPError, DnsError, ValueError) as exc:
                last = exc
                log.warning("doh_failed provider=%s type=%s error=%s", label, rtype, type(exc).__name__)
        raise DnsError("No se pudo consultar el DNS (sin conexión o bloqueado). Revisa que el servidor tenga salida a Internet.") from last
