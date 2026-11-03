"""Enriquecimiento con inteligencia de amenazas: VirusTotal y AbuseIPDB.

Principios de diseño
- Es **opcional y explícito**: solo se consulta cuando el analista lo pide y tras ver exactamente qué se enviará.
- **Solo salen indicadores públicos**: IP enrutables en Internet y dominios. Nunca IP internas, cuentas, nombres de
  equipo, comandos ni contenido de los logs. Los rangos de documentación (RFC 5737) se omiten salvo que se pida
  expresamente (útil solo para probar la conexión).
- **No cambia la criticidad**: la reputación es contexto para el analista; el motor de reglas sigue decidiendo.
- Las claves se reciben por variable de entorno o por cabecera, viven solo en memoria durante la consulta y nunca se
  registran ni se devuelven al navegador.
- Respeta los límites de los planes gratuitos (VirusTotal: 4 consultas/min; AbuseIPDB: 1.000/día) y se detiene con
  un mensaje claro si el servicio rechaza la clave o agota la cuota.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import quote, urlparse

import httpx

from . import detection as D

log = logging.getLogger("soc.intel")

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 15.0
MAX_INDICATORS = int(os.environ.get("INTEL_MAX_INDICATORS", "25"))        # tope por consulta
VT_INTERVAL = float(os.environ.get("INTEL_VT_INTERVAL", "15.5"))         # s entre consultas (4/min en el plan gratuito)
ABUSE_INTERVAL = float(os.environ.get("INTEL_ABUSE_INTERVAL", "0.3"))
ABUSE_MAX_AGE_DAYS = 90

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
PRIVATE_TLDS = {"local", "lan", "internal", "corp", "home", "localdomain", "localhost", "intranet", "example", "test", "invalid"}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


# ---------------------------------------------------------------- qué se puede enviar

def classify_ip(value: str) -> tuple[bool, str]:
    """(consultable, motivo). Solo las IP globalmente enrutables son consultables."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False, "no es una IP válida"
    if any(addr in n for n in DOC_NETS if n.version == addr.version):
        return False, "rango de documentación (RFC 5737), sin reputación pública"
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return False, "IP interna o privada"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified or not addr.is_global:
        return False, "IP no enrutable en Internet"
    return True, ""


def classify_domain(value: str) -> tuple[bool, str]:
    v = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(v):
        return False, "no es un dominio público válido"
    if v.rsplit(".", 1)[-1] in PRIVATE_TLDS:
        return False, "dominio reservado o interno"
    return True, ""


def _candidates(iocs: list[dict]) -> list[tuple[str, str]]:
    """(tipo, valor) a partir de los IoC del análisis: IP y dominios de URL con esquema http(s)."""
    seen, out = set(), []

    def add(kind: str, value: str) -> None:
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append((kind, value))

    for i in iocs:
        t, v = i.get("type"), str(i.get("value") or "")
        if t == "IP":
            ip = D.ip_of(v) or v.strip()
            if ip:
                add("ip", ip)
        elif t == "URL/URI" and re.match(r"^https?://", v, re.I):
            try:
                host = (urlparse(v).hostname or "").strip()
            except ValueError:
                continue
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
                add("ip", host)
            except ValueError:
                add("domain", host.lower())
    return out


def build_plan(iocs: list[dict], include_reserved: bool = False) -> dict:
    """Qué se consultaría y qué se omite (con el motivo). No hace ninguna llamada de red."""
    queries, skipped = [], []
    for kind, value in _candidates(iocs):
        ok, reason = classify_ip(value) if kind == "ip" else classify_domain(value)
        is_doc = kind == "ip" and not ok and reason.startswith("rango de documentación")
        if ok or (include_reserved and is_doc):
            queries.append({"kind": kind, "value": value, "reserved": is_doc})
        else:
            skipped.append({"kind": kind, "value": value, "reason": reason})
    truncated = max(0, len(queries) - MAX_INDICATORS)
    return {"queries": queries[:MAX_INDICATORS], "skipped": skipped, "truncated": truncated,
            "max_indicators": MAX_INDICATORS, "reserved_available": sum(1 for s in skipped if s["reason"].startswith("rango de documentación"))}


# ---------------------------------------------------------------- proveedores

class ProviderStop(Exception):
    """El proveedor rechazó la clave o agotó la cuota: no tiene sentido seguir consultándolo."""


def _ts(epoch) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return ""


def _vt(http: httpx.Client, key: str, kind: str, value: str, sleep: Callable[[float], None]) -> dict:
    path = "ip_addresses" if kind == "ip" else "domains"
    gui = "ip-address" if kind == "ip" else "domain"
    url = f"{VT_BASE}/{path}/{quote(value, safe='')}"
    link = f"https://www.virustotal.com/gui/{gui}/{quote(value, safe='')}"
    for attempt in (1, 2):
        r = http.get(url, headers={"x-apikey": key, "accept": "application/json"})
        if r.status_code == 429 and attempt == 1:       # límite por minuto: una espera y un reintento
            sleep(60)
            continue
        break
    if r.status_code in (401, 403):
        raise ProviderStop("VirusTotal rechazó la clave (revisa que sea válida y esté activa).")
    if r.status_code == 429:
        raise ProviderStop("VirusTotal alcanzó su límite de consultas (plan gratuito: 4 por minuto y 500 por día).")
    if r.status_code == 404:
        return {"status": "not_found", "link": link, "detail": "VirusTotal no tiene información sobre este indicador."}
    if r.status_code != 200:
        return {"status": "error", "link": link, "detail": f"VirusTotal respondió HTTP {r.status_code}."}
    attrs = (r.json().get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    out = {"status": "ok", "link": link, "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
           "harmless": int(stats.get("harmless", 0)), "total": total, "reputation": attrs.get("reputation"),
           "last_analysis": _ts(attrs.get("last_analysis_date"))}
    if kind == "ip":
        out.update(country=attrs.get("country") or "", owner=attrs.get("as_owner") or "", asn=attrs.get("asn"))
    else:
        out.update(registrar=attrs.get("registrar") or "", created=_ts(attrs.get("creation_date")),
                   categories=sorted({str(v) for v in (attrs.get("categories") or {}).values()})[:4])
    return out


def _abuse(http: httpx.Client, key: str, value: str) -> dict:
    link = f"https://www.abuseipdb.com/check/{quote(value, safe='')}"
    r = http.get(f"{ABUSE_BASE}/check", params={"ipAddress": value, "maxAgeInDays": ABUSE_MAX_AGE_DAYS},
                 headers={"Key": key, "Accept": "application/json"})
    if r.status_code in (401, 403):
        raise ProviderStop("AbuseIPDB rechazó la clave (revisa que sea válida).")
    if r.status_code == 429:
        raise ProviderStop("AbuseIPDB alcanzó su límite diario de consultas (plan gratuito: 1.000 por día).")
    if r.status_code == 422:
        return {"status": "error", "link": link, "detail": "AbuseIPDB no aceptó la IP."}
    if r.status_code != 200:
        return {"status": "error", "link": link, "detail": f"AbuseIPDB respondió HTTP {r.status_code}."}
    d = r.json().get("data") or {}
    return {"status": "ok", "link": link, "score": int(d.get("abuseConfidenceScore") or 0),
            "reports": int(d.get("totalReports") or 0), "users": int(d.get("numDistinctUsers") or 0),
            "country": d.get("countryCode") or "", "isp": d.get("isp") or "", "usage": d.get("usageType") or "",
            "tor": bool(d.get("isTor")), "whitelisted": bool(d.get("isWhitelisted")),
            "last_reported": (d.get("lastReportedAt") or "")[:10], "window_days": ABUSE_MAX_AGE_DAYS}


# ---------------------------------------------------------------- veredicto

def verdict(vt: dict | None, abuse: dict | None) -> str:
    """Resumen orientativo. Umbrales: malicioso si VT>=3 motores o AbuseIPDB>=75; sospechoso si VT>=1 o AbuseIPDB>=25."""
    vt_ok = bool(vt) and vt.get("status") == "ok"
    ab_ok = bool(abuse) and abuse.get("status") == "ok"
    if not vt_ok and not ab_ok:
        return "Sin datos"
    mal = vt["malicious"] if vt_ok else 0
    sus = vt["suspicious"] if vt_ok else 0
    score = abuse["score"] if ab_ok else 0
    if mal >= 3 or score >= 75:
        return "Malicioso"
    if mal >= 1 or sus >= 1 or score >= 25:
        return "Sospechoso"
    return "Sin reportes"


# ---------------------------------------------------------------- ejecución

def available_providers(vt_key: str | None, abuse_key: str | None) -> list[str]:
    return [n for n, k in (("virustotal", vt_key), ("abuseipdb", abuse_key)) if k]


def lookup(queries: list[dict], vt_key: str | None, abuse_key: str | None, *, http: httpx.Client | None = None,
           sleep: Callable[[float], None] = time.sleep, on_progress: Callable[[dict], None] | None = None) -> dict:
    """Consulta cada indicador en los proveedores con clave. Devuelve resultados y avisos; nunca lanza por errores de red."""
    own = http is None
    http = http or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    results: list[dict] = []
    notices: list[str] = []
    stopped: set[str] = set()
    last_call = {"virustotal": 0.0, "abuseipdb": 0.0}

    def pace(provider: str, interval: float) -> None:
        wait = interval - (time.monotonic() - last_call[provider])
        if last_call[provider] and wait > 0:
            sleep(wait)
        last_call[provider] = time.monotonic()

    def run(provider: str, fn) -> dict:
        try:
            return fn()
        except ProviderStop as exc:
            stopped.add(provider)
            notices.append(str(exc))
            return {"status": "stopped", "detail": str(exc)}
        except httpx.HTTPError as exc:
            log.warning("intel_http_error provider=%s type=%s", provider, type(exc).__name__)   # sin URL ni cabeceras (llevan la clave)
            return {"status": "error", "detail": f"No se pudo contactar con el servicio ({type(exc).__name__})."}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("intel_bad_response provider=%s type=%s", provider, type(exc).__name__)
            return {"status": "error", "detail": "Respuesta inesperada del servicio."}

    try:
        for n, q in enumerate(queries, 1):
            kind, value = q["kind"], q["value"]
            row: dict = {"indicator": value, "kind": kind, "reserved": bool(q.get("reserved")), "vt": None, "abuse": None}
            if vt_key and "virustotal" not in stopped:
                pace("virustotal", VT_INTERVAL)
                row["vt"] = run("virustotal", lambda: _vt(http, vt_key, kind, value, sleep))
            if abuse_key and kind == "ip" and "abuseipdb" not in stopped:
                pace("abuseipdb", ABUSE_INTERVAL)
                row["abuse"] = run("abuseipdb", lambda: _abuse(http, abuse_key, value))
            row["verdict"] = verdict(row["vt"], row["abuse"])
            results.append(row)
            if on_progress:
                on_progress({"done": n, "total": len(queries), "results": list(results), "notices": list(dict.fromkeys(notices))})
            providers = [p for p, k in (("virustotal", vt_key), ("abuseipdb", abuse_key)) if k]
            if providers and all(p in stopped for p in providers):
                break
    finally:
        if own:
            http.close()
    return {"results": results, "notices": list(dict.fromkeys(notices)),
            "queried_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
