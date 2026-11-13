"""Contexto de vulnerabilidades: catálogo CISA KEV (explotadas activamente) y puntaje EPSS (probabilidad de explotación).

Opcional y apagado por defecto (``CONTEXT_ENABLED=1``). Principios:
- **Nada sale de tu red por tus CVE.** Se descargan dos archivos públicos completos (KEV y EPSS) y el cruce se hace en local.
  No se envía ningún CVE, equipo ni log a un tercero.
- Los archivos se guardan en ``CONTEXT_DIR`` (por defecto ``./context_cache``) y se refrescan solos tras ``CONTEXT_REFRESH_HOURS`` (24 h).
  Si la descarga falla se usa la copia anterior y el análisis sigue; sin datos, las reglas de contexto simplemente no disparan.
- Es contexto para priorizar. No reemplaza a CVSS ni al criterio del analista, y un CVE ausente de KEV no significa que sea seguro.

Fuentes: CISA KEV (``known_exploited_vulnerabilities.json``) y EPSS de FIRST (``epss_scores-current.csv.gz``, columnas ``cve,epss,percentile``).
Las URL se pueden cambiar con ``CONTEXT_KEV_URL`` y ``CONTEXT_EPSS_URL``. Prueba manual: ``python -m backend.context --refresh``.
"""
from __future__ import annotations

import gzip
import io
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

import httpx

log = logging.getLogger("soc.context")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_RE = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.I)
MAX_DOWNLOAD = 60 * 1024 * 1024          # el CSV de EPSS pesa ~5 MB comprimido; un tope evita descargas absurdas
TIMEOUT = 60.0


def enabled() -> bool:
    return os.environ.get("CONTEXT_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text or "")))


# ---------------------------------------------------------------- lectura de los archivos

def parse_kev(raw: bytes | str | dict) -> tuple[dict[str, dict], str]:
    """KEV -> ({CVE: datos}, versión del catálogo). Tolera campos ausentes; ignora entradas sin un CVE válido."""
    data = raw if isinstance(raw, dict) else json.loads(raw)
    out: dict[str, dict] = {}
    for v in data.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not CVE_RE.fullmatch(cve):
            continue
        out[cve] = {
            "name": str(v.get("vulnerabilityName") or "")[:200], "vendor": str(v.get("vendorProject") or "")[:80],
            "product": str(v.get("product") or "")[:80], "added": str(v.get("dateAdded") or "")[:10],
            "due": str(v.get("dueDate") or "")[:10], "action": str(v.get("requiredAction") or "")[:300],
            "ransomware": str(v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        }
    return out, str(data.get("catalogVersion") or "")


def parse_epss(raw: bytes | str) -> tuple[dict[str, tuple[float, float]], str]:
    """EPSS (CSV, con o sin gzip) -> ({CVE: (epss, percentil)}, fecha del modelo). Salta comentarios (#…) y filas rotas."""
    if isinstance(raw, bytes):
        raw = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
        text = raw.decode("utf-8", "replace")
    else:
        text = raw
    out: dict[str, tuple[float, float]] = {}
    date = ""
    for line in io.StringIO(text):
        line = line.strip()
        if line.startswith("#"):
            m = re.search(r"score_date:(\S+?)(?:,|$)", line)
            if m:
                date = m.group(1)[:10]
            continue
        parts = line.split(",")
        if len(parts) < 3 or not CVE_RE.fullmatch(parts[0].strip()):
            continue                                   # encabezado o fila rota
        try:
            e, p = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        if 0.0 <= e <= 1.0 and 0.0 <= p <= 1.0:
            out[parts[0].strip().upper()] = (e, p)
    return out, date


# ---------------------------------------------------------------- almacén

class Store:
    def __init__(self, directory: str | Path | None = None, *, refresh_hours: float = 24.0):
        self.dir = Path(directory or os.environ.get("CONTEXT_DIR", "context_cache"))
        self.refresh_hours = refresh_hours
        self.kev: dict[str, dict] = {}
        self.epss: dict[str, tuple[float, float]] = {}
        self.kev_version = ""
        self.epss_date = ""
        self.loaded_at = 0.0
        self.error = ""
        self._lock = threading.Lock()
        self._refreshing = False

    # -- carga / descarga
    def load(self) -> bool:
        """Lee los archivos ya guardados. True si hay al menos uno."""
        ok = False
        try:
            kev, ver = parse_kev((self.dir / "kev.json").read_bytes())
            self.kev, self.kev_version, ok = kev, ver, True
        except (OSError, ValueError):
            pass
        try:
            ep, date = parse_epss((self.dir / "epss.csv.gz").read_bytes())
            self.epss, self.epss_date, ok = ep, date, True
        except (OSError, ValueError, EOFError):
            pass
        if ok:
            self.loaded_at = time.time()
        return ok

    def _fetch(self, http: httpx.Client, url: str) -> bytes:
        with http.stream("GET", url) as r:
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_DOWNLOAD:
                    raise ValueError("archivo demasiado grande")
            return bytes(buf)

    def refresh(self, http: httpx.Client | None = None) -> dict:
        """Descarga KEV y EPSS (cada uno por separado: si uno falla se conserva el anterior). Devuelve el resultado por fuente."""
        own = http is None
        http = http or httpx.Client(timeout=TIMEOUT, follow_redirects=True, trust_env=True)
        res: dict[str, str] = {}
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            for name, url, fname, parse in (
                ("kev", os.environ.get("CONTEXT_KEV_URL", KEV_URL), "kev.json", parse_kev),
                ("epss", os.environ.get("CONTEXT_EPSS_URL", EPSS_URL), "epss.csv.gz", parse_epss),
            ):
                try:
                    body = self._fetch(http, url)
                    data, meta = parse(body)              # se valida antes de guardar: un archivo roto no pisa el bueno
                    if not data:
                        raise ValueError("sin registros reconocibles")
                    tmp = self.dir / (fname + ".tmp")
                    tmp.write_bytes(body)
                    tmp.replace(self.dir / fname)
                    if name == "kev":
                        self.kev, self.kev_version = data, meta
                    else:
                        self.epss, self.epss_date = data, meta
                    res[name] = f"ok ({len(data)} registros)"
                except (httpx.HTTPError, ValueError, OSError, EOFError) as exc:
                    log.warning("context_refresh_failed source=%s error=%s", name, type(exc).__name__)
                    res[name] = f"error: {type(exc).__name__}"
            self.loaded_at = time.time() if (self.kev or self.epss) else self.loaded_at
            self.error = "" if all(v.startswith("ok") for v in res.values()) else "; ".join(f"{k}: {v}" for k, v in res.items() if not v.startswith("ok"))
        finally:
            if own:
                http.close()
        return res

    def ensure(self) -> None:
        """Carga lo guardado y, si está vencido o falta, refresca en segundo plano (no bloquea el análisis)."""
        with self._lock:
            if not self.loaded_at:
                self.load()
            stale = (time.time() - self._age_ref()) > self.refresh_hours * 3600
            if (stale or not (self.kev or self.epss)) and not self._refreshing:
                self._refreshing = True
                threading.Thread(target=self._bg, daemon=True).start()

    def _age_ref(self) -> float:
        try:
            return max((self.dir / n).stat().st_mtime for n in ("kev.json", "epss.csv.gz") if (self.dir / n).exists())
        except ValueError:
            return 0.0

    def _bg(self) -> None:
        try:
            self.refresh()
        finally:
            self._refreshing = False

    # -- consulta
    @property
    def ready(self) -> bool:
        return bool(self.kev or self.epss)

    def lookup(self, cve: str) -> dict | None:
        cve = cve.upper()
        k, e = self.kev.get(cve), self.epss.get(cve)
        if k is None and e is None:
            return None
        return {"cve": cve, "kev": k, "epss": e[0] if e else None, "percentile": e[1] if e else None}

    def status(self) -> dict:
        return {"enabled": enabled(), "kev_entries": len(self.kev), "kev_version": self.kev_version, "epss_entries": len(self.epss),
                "epss_date": self.epss_date, "error": self.error, "ready": self.ready}


_STORE: Store | None = None


def get_store() -> Store | None:
    """El almacén global, o None si el contexto está apagado."""
    global _STORE
    if not enabled():
        return None
    if _STORE is None:
        _STORE = Store(refresh_hours=float(os.environ.get("CONTEXT_REFRESH_HOURS", "24") or 24))
    _STORE.ensure()
    return _STORE


def set_store(store: Store | None) -> None:
    """Para pruebas."""
    global _STORE
    _STORE = store


if __name__ == "__main__":      # python -m backend.context --refresh  (comprueba descarga y formato desde tu red)
    import sys
    logging.basicConfig(level=logging.INFO)
    s = Store()
    if "--refresh" in sys.argv:
        print(s.refresh())
    else:
        s.load()
    print(s.status())
    if "CVE-2021-44228" in (s.kev or s.epss):
        print(s.lookup("CVE-2021-44228"))
