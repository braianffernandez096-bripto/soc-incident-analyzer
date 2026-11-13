"""Feed JSON propio de indicadores (opcional, apagado por defecto): un archivo o una URL tuya cuyos indicadores se cruzan **en local**.

Sirve para tener inteligencia de amenazas sin depender de MISP, o además de MISP, y es fácil de versionar y compartir. Ningún evento sale de tu red: si el feed
es una URL, solo se descarga el archivo completo.

Configuración (variables de entorno):
- ``FEED_PATH``: ruta del archivo JSON (en Docker, móntalo dentro del contenedor). Se vuelve a leer solo si cambia.
- ``FEED_URL``: alternativa, URL ``http(s)`` del JSON. Se descarga cada ``FEED_REFRESH_HOURS`` (6) en segundo plano; si falla se usa la última copia.
- ``FEED_TTL_DAYS``: vida de un indicador desde su fecha (``fecha``/``added``/``last_seen``). 0 = no vencen por tiempo. Un ``expira``/``expires`` explícito manda sobre el TTL.

Formato: una lista de objetos, o ``{"indicators": [...]}`` / ``{"indicadores": [...]}``. Cada objeto:
``valor`` (``value``), opcionales ``tipo`` (``type``: ip, dominio, hash; se deduce si falta), ``descripcion`` (``description``), ``fuente`` (``source``),
``fecha`` (``added``, ``last_seen``) y ``expira`` (``expires``, ``valid_until``), con fechas ``AAAA-MM-DD``.
Un indicador **sin fecha ni expira no vence nunca** (se indica en «Límites» y en la guía).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger("soc.feed")

MAX_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 200_000
HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
TOKEN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?", re.I)
_VAL, _TYPE, _DESC, _SRC = ("valor", "value", "indicator"), ("tipo", "type"), ("descripcion", "description", "descripción"), ("fuente", "source")
_DATE, _EXP = ("fecha", "added", "last_seen", "first_seen"), ("expira", "expires", "valid_until")


def _first(item: dict, keys) -> str:
    for k in keys:
        v = item.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip():
            return str(v).strip()
    return ""


def _date(text: str) -> date | None:
    try:
        return date.fromisoformat(text[:10]) if text else None
    except ValueError:
        return None


def normalize(value: str) -> tuple[str, str]:
    """(valor canónico, tipo) o ('', '') si no es una IP, un hash ni un dominio."""
    v = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(v)), "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return v, "hash"
    if DOMAIN_RE.match(v):
        return v, "dominio"
    return "", ""


def parse(raw: bytes | str | list | dict, ttl_days: int = 0) -> tuple[dict[str, dict], dict]:
    """Interpreta el feed. Devuelve ({valor: entrada}, resumen). Las entradas rotas se cuentan y se ignoran, nunca rompen la carga."""
    data = raw if isinstance(raw, (list, dict)) else json.loads(raw)
    items = data if isinstance(data, list) else next((data[k] for k in ("indicators", "indicadores") if isinstance(data.get(k), list)), None)
    if items is None:
        raise ValueError("El JSON debe ser una lista de indicadores o un objeto con «indicators»/«indicadores».")
    out: dict[str, dict] = {}
    skipped = 0
    for it in items[:MAX_ENTRIES]:
        if not isinstance(it, dict):
            skipped += 1
            continue
        val, kind = normalize(_first(it, _VAL))
        if not val:
            skipped += 1
            continue
        declared = _first(it, _TYPE).lower()
        if declared in ("domain", "hostname"):
            declared = "dominio"
        if declared in ("ip-dst", "ip-src", "ipv4", "ipv6"):
            declared = "ip"
        if declared in ("md5", "sha1", "sha256"):
            declared = "hash"
        if declared and declared != kind:
            skipped += 1                          # el tipo declarado no coincide con el valor: mejor ignorarlo que arriesgar un cruce erróneo
            continue
        added, exp = _date(_first(it, _DATE)), _date(_first(it, _EXP))
        expires = exp or (added + timedelta(days=ttl_days) if added and ttl_days > 0 else None)
        out[val] = {"tipo": kind, "descripcion": _first(it, _DESC)[:200], "fuente": _first(it, _SRC)[:60],
                    "fecha": added.isoformat() if added else "", "expira": expires.isoformat() if expires else ""}
    return out, {"total": len(items), "validos": len(out), "ignorados": skipped}


def is_active(entry: dict, today: date | None = None) -> bool:
    today = today or datetime.now(timezone.utc).date()
    exp = _date(entry.get("expira", ""))
    return exp is None or today <= exp


class Feed:
    def __init__(self, path: str = "", url: str = "", *, ttl_days: int = 0, refresh_hours: float = 6.0, cache_dir: str | Path | None = None):
        self.path, self.url, self.ttl, self.refresh_hours = path, url, ttl_days, refresh_hours
        self.cache = Path(cache_dir or os.environ.get("CONTEXT_DIR", "context_cache")) / "feed.json"
        self.entries: dict[str, dict] = {}
        self.summary: dict = {}
        self.error = ""
        self._mtime = 0.0
        self._loaded_at = 0.0
        self._refreshing = False
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "Feed | None":
        path, url = os.environ.get("FEED_PATH", "").strip(), os.environ.get("FEED_URL", "").strip()
        if not path and not (url and re.match(r"^https?://", url, re.I)):
            return None
        def num(name, default, cast):
            try:
                return cast(os.environ.get(name, "").strip() or default)
            except ValueError:
                return default
        return cls(path, url, ttl_days=max(0, min(3650, num("FEED_TTL_DAYS", 0, int))), refresh_hours=max(0.1, num("FEED_REFRESH_HOURS", 6.0, float)))

    # -- carga
    def _source_file(self) -> Path | None:
        if self.path:
            return Path(self.path)
        return self.cache if self.cache.exists() else None

    def load(self) -> bool:
        src = self._source_file()
        if src is None:
            return False
        try:
            st = src.stat()
            if st.st_size > MAX_BYTES:
                raise ValueError("archivo demasiado grande")
            entries, summary = parse(src.read_bytes(), self.ttl)
        except (OSError, ValueError, RecursionError) as exc:
            self.error = f"{type(exc).__name__}"
            log.warning("feed_load_failed type=%s", type(exc).__name__)
            return False
        self.entries, self.summary, self.error, self._mtime, self._loaded_at = entries, summary, "", st.st_mtime, time.time()
        return True

    def refresh_url(self, http: httpx.Client | None = None) -> bool:
        if not self.url:
            return False
        own = http is None
        http = http or httpx.Client(timeout=30.0, follow_redirects=True)
        try:
            with http.stream("GET", self.url) as r:
                if r.status_code != 200:
                    raise ValueError(f"HTTP {r.status_code}")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise ValueError("archivo demasiado grande")
            parse(bytes(buf), self.ttl)                       # se valida antes de guardar: un archivo roto no pisa el bueno
            self.cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache.with_suffix(".tmp")
            tmp.write_bytes(bytes(buf))
            tmp.replace(self.cache)
            return self.load()
        except (httpx.HTTPError, ValueError, OSError, RecursionError) as exc:
            self.error = type(exc).__name__
            log.warning("feed_refresh_failed type=%s", type(exc).__name__)
            return False
        finally:
            if own:
                http.close()

    def ensure(self) -> None:
        """Mantiene el feed al día sin bloquear el análisis: archivo local (relee si cambió) o URL (descarga en segundo plano)."""
        with self._lock:
            if self.path:
                try:
                    if Path(self.path).stat().st_mtime != self._mtime:
                        self.load()
                except OSError:
                    self.error = "FileNotFoundError"
                return
            if not self._loaded_at:
                self.load()
            stale = (time.time() - self._loaded_at) > self.refresh_hours * 3600
            if (stale or not self.entries) and not self._refreshing:
                self._refreshing = True
                threading.Thread(target=self._bg, daemon=True).start()

    def _bg(self) -> None:
        try:
            self.refresh_url()
        finally:
            self._refreshing = False

    # -- consulta
    @property
    def ready(self) -> bool:
        return bool(self.entries)

    def domains(self) -> set[str]:
        return {v for v, e in self.entries.items() if e["tipo"] == "dominio"}

    def lookup(self, values, today: date | None = None) -> dict[str, dict]:
        out = {}
        for v in values:
            e = self.entries.get(v)
            if e and is_active(e, today):
                out[v] = e
        return out

    def status(self) -> dict:
        today = datetime.now(timezone.utc).date()
        activos = sum(1 for e in self.entries.values() if is_active(e, today))
        return {"configured": True, "source": "archivo" if self.path else "url", "ttl_days": self.ttl, "indicators": len(self.entries),
                "active": activos, "expired": len(self.entries) - activos, "ignored": self.summary.get("ignorados", 0), "error": self.error}


_FEED: Feed | None = None
_LOADED = False


def get_feed() -> Feed | None:
    global _FEED, _LOADED
    if not _LOADED:
        _FEED, _LOADED = Feed.from_env(), True
    if _FEED is not None:
        _FEED.ensure()
    return _FEED


def set_feed(feed: Feed | None) -> None:
    """Para pruebas."""
    global _FEED, _LOADED
    _FEED, _LOADED = feed, True
