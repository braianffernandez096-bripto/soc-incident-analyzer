"""Consulta a **tu propia** instancia de MISP (opcional, apagado por defecto).

MISP es la plataforma de inteligencia de amenazas que corre en tu red: ahí ya puedes tener feeds (Feodo Tracker, etc.) y tus propios indicadores.
Aquí solo se le pregunta, por la API REST (``POST /attributes/restSearch``), si alguna IP, dominio o hash visto en los eventos figura como indicador.
Nada sale a Internet: la consulta va a la URL que tú configuras.

Variables: ``MISP_URL`` (p. ej. ``https://192.168.64.20``) y ``MISP_KEY`` (clave de API de un usuario con permisos de lectura; va en el ``.env`` del servidor,
nunca en el chat ni en el repositorio). Opcionales: ``MISP_CACHE_SECONDS`` (600) para cuánto se recuerda una respuesta, ``MISP_VERIFY=0`` si el certificado es autofirmado (laboratorio), ``MISP_CA`` (ruta de una CA propia),
``MISP_ONLY_IDS=0`` para incluir también atributos no marcados «to_ids», ``MISP_INCLUDE_PRIVATE=1`` para consultar también IP privadas.

Se usa ``enforceWarninglist`` para que MISP descarte valores de listas de advertencia (DNS públicos, rangos conocidos…) y se reduzcan los falsos positivos.
Un fallo de red o de clave nunca tumba el análisis: se registra (sin la clave) y la regla simplemente no dispara.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import time

import httpx

log = logging.getLogger("soc.misp")

TIMEOUT = 10.0
MAX_VALUES = 50
CACHE_OK, CACHE_ERR = 600.0, 60.0
HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", re.I)


def _truthy(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    return default if not v else v in ("1", "true", "yes", "on")


class MispClient:
    def __init__(self, url: str, key: str, *, verify: bool | str = True, only_ids: bool = True, include_private: bool = False,
                 http: httpx.Client | None = None, clock=time.monotonic, cache_seconds: float = CACHE_OK):
        self.url, self._key = url.rstrip("/"), key
        self.cache_ok = cache_seconds
        self.only_ids, self.include_private = only_ids, include_private
        self._http = http or httpx.Client(timeout=TIMEOUT, verify=verify, follow_redirects=False, trust_env=False)
        self._cache: dict[str, tuple[float, list[dict]]] = {}
        self._lock = threading.Lock()
        self._clock = clock

    @classmethod
    def from_env(cls) -> "MispClient | None":
        url, key = os.environ.get("MISP_URL", "").strip(), os.environ.get("MISP_KEY", "").strip()
        if not url or not key or not re.match(r"^https?://", url, re.I):
            return None
        ca = os.environ.get("MISP_CA", "").strip()
        verify: bool | str = ca if ca else _truthy("MISP_VERIFY", True)
        if verify is False:
            log.warning("tls_verify_disabled service=misp: solo para laboratorio; en producción usa MISP_CA con la CA de tu MISP")
        try:
            cache = max(0.0, min(86400.0, float(os.environ.get("MISP_CACHE_SECONDS", "").strip() or CACHE_OK)))
        except ValueError:
            cache = CACHE_OK
        return cls(url, key, verify=verify, only_ids=_truthy("MISP_ONLY_IDS", True), include_private=_truthy("MISP_INCLUDE_PRIVATE", False),
                   cache_seconds=cache)

    # -- qué se puede preguntar
    def queryable(self, value: str) -> bool:
        v = (value or "").strip()
        if HASH_RE.match(v):
            return True
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return False
        if a.is_unspecified or a.is_multicast or a.is_loopback:
            return False
        return self.include_private or not (a.is_private and not self._is_doc(a))

    @staticmethod
    def _is_doc(a) -> bool:
        # los rangos de documentación (RFC 5737) cuentan como «privados» para Python, pero son los que se usan para probar con un IoC de demostración
        return any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24") if a.version == 4)

    # -- consulta
    def search(self, values: list[str]) -> dict[str, list[dict]]:
        """{valor: [coincidencias]}. Solo aparecen los valores con coincidencia. Nunca lanza."""
        wanted = list(dict.fromkeys(v.strip().lower() for v in values if self.queryable(v)))[:MAX_VALUES]
        now = self._clock()
        out: dict[str, list[dict]] = {}
        todo: list[str] = []
        with self._lock:
            for v in wanted:
                hit = self._cache.get(v)
                if hit and now - hit[0] < (self.cache_ok if hit[1] is not None else CACHE_ERR):
                    if hit[1]:
                        out[v] = hit[1]
                else:
                    todo.append(v)
        if not todo:
            return out
        try:
            found = self._restsearch(todo)
            ok = True
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("misp_failed type=%s", type(exc).__name__)       # sin URL ni cabeceras (llevan la clave)
            found, ok = {}, False
        with self._lock:
            for v in todo:
                self._cache[v] = (now, found.get(v, [])) if ok else (now, None)       # None = error: se reintenta en CACHE_ERR segundos
            if len(self._cache) > 2000:
                self._cache.pop(next(iter(self._cache)))
        out.update(found)
        return out

    def _restsearch(self, values: list[str]) -> dict[str, list[dict]]:
        body = {"returnFormat": "json", "value": values, "limit": 200, "enforceWarninglist": True, "includeEventTags": False}
        if self.only_ids:
            body["to_ids"] = 1
        r = self._http.post(f"{self.url}/attributes/restSearch", json=body,
                            headers={"Authorization": self._key, "Accept": "application/json", "Content-Type": "application/json"})
        if r.status_code in (401, 403):
            raise ValueError("clave rechazada")
        if r.status_code != 200:
            raise ValueError(f"HTTP {r.status_code}")
        attrs = (r.json().get("response") or {}).get("Attribute") or []
        res: dict[str, list[dict]] = {}
        for a in attrs:
            if not isinstance(a, dict):
                continue
            val = str(a.get("value") or "").strip().lower()
            if val not in values:
                continue       # p. ej. un atributo compuesto «ip|puerto»: no es una coincidencia exacta
            ev = a.get("Event") if isinstance(a.get("Event"), dict) else {}
            item = {"event_id": str(a.get("event_id") or ev.get("id") or "")[:20], "event": str(ev.get("info") or "")[:160],
                    "type": str(a.get("type") or "")[:30], "category": str(a.get("category") or "")[:40],
                    "ids": bool(a.get("to_ids")), "comment": str(a.get("comment") or "")[:160]}
            lst = res.setdefault(val, [])
            if all(x["event_id"] != item["event_id"] for x in lst):
                lst.append(item)
        return res


_CLIENT: MispClient | None = None
_LOADED = False


def get_client() -> MispClient | None:
    global _CLIENT, _LOADED
    if not _LOADED:
        _CLIENT, _LOADED = MispClient.from_env(), True
    return _CLIENT


def set_client(client: MispClient | None) -> None:
    """Para pruebas."""
    global _CLIENT, _LOADED
    _CLIENT, _LOADED = client, True
