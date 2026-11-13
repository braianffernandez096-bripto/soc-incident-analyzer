"""Contexto de un hallazgo desde el Indexer de Wazuh (opcional, apagado por defecto).

Muestra, bajo un hallazgo, lo que Wazuh guardó del mismo equipo o IP en una ventana de tiempo alrededor del hallazgo, para tener más contexto que las
alertas que llegaron al analizador. Solo lectura: el analizador **consulta**, no escribe nada en el Indexer.

Variables: ``WAZUH_INDEXER_URL`` (p. ej. ``https://single-node-wazuh.indexer-1:9200`` dentro de la red de Wazuh), ``WAZUH_INDEXER_USER`` y
``WAZUH_INDEXER_PASSWORD`` (un usuario de **solo lectura**; la contraseña va en el ``.env`` del servidor, nunca en el chat ni en el repositorio).
Opcionales: ``WAZUH_INDEXER_VERIFY=0`` (certificado autofirmado, lo habitual en un laboratorio) o ``WAZUH_INDEXER_CA``; ``WAZUH_INDEXER_WINDOW_MIN``
(minutos antes y después, 5); ``WAZUH_INDEXER_MAX`` (filas máximas, 100); ``WAZUH_INDEXER_ARCHIVES=off`` para no mirar el índice de archivos.

Qué hay en el Indexer: siempre el índice de **alertas** (``wazuh-alerts-*``). Los **eventos crudos** (``wazuh-archives-*``) existen solo si activaste el archivado
(``<logall_json>yes</logall_json>`` en el manager y archivos habilitados en Filebeat); si no existe, se consulta igual y simplemente no aparecen.
La consulta la arma el servidor a partir del hallazgo (equipo, IP, horas): el navegador nunca envía una consulta propia.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import timedelta

import httpx
import pandas as pd

log = logging.getLogger("soc.indexer")

TIMEOUT = 15.0
SOURCE = ["@timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "decoder.name", "location", "full_log",
          "data.srcip", "data.dstip", "data.srcuser", "data.dstuser", "data.vulnerability.cve",
          "data.win.system.eventID", "data.win.system.computer", "data.win.eventdata.ipAddress", "data.win.eventdata.targetUserName",
          "data.win.eventdata.subjectUserName", "data.win.eventdata.commandLine", "data.win.eventdata.image", "data.win.eventdata.parentImage",
          "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"]
IP_FIELDS = ["data.srcip", "data.dstip", "data.win.eventdata.ipAddress", "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"]
_SAFE = re.compile(r"[^\w.\-:@ ]")


class IndexerError(Exception):
    """Fallo al consultar el Indexer. El mensaje es apto para mostrar (no lleva credenciales ni la URL)."""


def configured() -> bool:
    return bool(os.environ.get("WAZUH_INDEXER_URL", "").strip().lower().startswith(("http://", "https://"))
                and os.environ.get("WAZUH_INDEXER_USER", "").strip() and os.environ.get("WAZUH_INDEXER_PASSWORD", ""))


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        v = default
    return max(lo, min(hi, v))


def _verify():
    ca = os.environ.get("WAZUH_INDEXER_CA", "").strip()
    if ca:
        return ca
    return os.environ.get("WAZUH_INDEXER_VERIFY", "").strip().lower() not in ("0", "false", "no", "off")


def _host_variants(host: str) -> list[str]:
    short = host.split(".")[0]
    return list(dict.fromkeys(x for x in (host, short, short.lower(), short.upper(), host.lower()) if x))


def build_query(finding: dict, window_min: int, size: int, archives: bool) -> tuple[str, dict]:
    """(índices, cuerpo) a partir del hallazgo. Nada del navegador entra en la consulta."""
    t0 = pd.Timestamp(finding["time_start"], tz="UTC") - timedelta(minutes=window_min)
    t1 = pd.Timestamp(finding["time_end"], tz="UTC") + timedelta(minutes=window_min)
    should = []
    hosts = [h for h in (finding.get("hosts") or [])[:10] if h]
    if hosts:
        should.append({"terms": {"agent.name": [v for h in hosts for v in _host_variants(h)]}})
    ips = [i for i in (finding.get("ips") or [])[:10] if i]
    if ips:
        should += [{"terms": {f: ips}} for f in IP_FIELDS]
    if not should:
        raise IndexerError("El hallazgo no tiene equipo ni IP para buscar en Wazuh.")
    body = {"size": size, "track_total_hits": True, "sort": [{"@timestamp": "asc"}], "_source": SOURCE,
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": t0.isoformat(), "lte": t1.isoformat()}}}],
                               "should": should, "minimum_should_match": 1}}}
    return ("wazuh-alerts-*,wazuh-archives-*" if archives else "wazuh-alerts-*"), body


def _g(src: dict, path: str) -> str:
    cur = src
    for k in path.split("."):
        cur = cur.get(k) if isinstance(cur, dict) else None
        if cur is None:
            return ""
    return str(cur)


def _clean(text: str, n: int) -> str:
    return re.sub(r"\s+", " ", text).strip()[:n]


_ESC = re.compile(r'\\(["\\])')


def _unescape(text: str) -> str:
    """Wazuh guarda las rutas y comillas de Windows con una barra de escape de más (\\\\ por \\ y \\" por "): se deshace para leer el comando tal como se escribió."""
    return _ESC.sub(r"\1", text or "")


def normalize_hit(hit: dict) -> dict:
    s = hit.get("_source") or {}
    detail = _g(s, "data.win.eventdata.commandLine") or _g(s, "data.win.eventdata.image") or _clean(_g(s, "full_log"), 300)
    return {"time": _g(s, "@timestamp"), "raw": str(hit.get("_index", "")).startswith("wazuh-archives"),
            "host": _g(s, "agent.name"), "rule": _g(s, "rule.id"), "level": _g(s, "rule.level"),
            "description": _clean(_unescape(_g(s, "rule.description")), 200),
            "ip": _g(s, "data.srcip") or _g(s, "data.win.eventdata.ipAddress") or _g(s, "data.win.eventdata.sourceIp"),
            "user": _g(s, "data.srcuser") or _g(s, "data.dstuser") or _g(s, "data.win.eventdata.targetUserName") or _g(s, "data.win.eventdata.subjectUserName"),
            "event_id": _g(s, "data.win.system.eventID"), "detail": _clean(_unescape(detail), 300)}


def context_for(finding: dict, http: httpx.Client | None = None) -> dict:
    window, size = _int("WAZUH_INDEXER_WINDOW_MIN", 5, 1, 60), _int("WAZUH_INDEXER_MAX", 100, 10, 500)
    archives = os.environ.get("WAZUH_INDEXER_ARCHIVES", "").strip().lower() not in ("off", "0", "false", "no")
    index, body = build_query(finding, window, size, archives)
    own = http is None
    http = http or httpx.Client(timeout=TIMEOUT, verify=_verify(), follow_redirects=False, trust_env=False)
    url = os.environ["WAZUH_INDEXER_URL"].strip().rstrip("/")
    try:
        r = http.post(f"{url}/{index}/_search", params={"ignore_unavailable": "true", "allow_no_indices": "true"}, json=body,
                      auth=(os.environ["WAZUH_INDEXER_USER"].strip(), os.environ["WAZUH_INDEXER_PASSWORD"]))
    except httpx.HTTPError as exc:
        log.warning("indexer_failed type=%s", type(exc).__name__)
        raise IndexerError("No se pudo conectar con el Indexer de Wazuh (revisa la URL, la red y el certificado: WAZUH_INDEXER_VERIFY).") from exc
    finally:
        if own:
            http.close()
    if r.status_code in (401, 403):
        raise IndexerError("El Indexer rechazó el usuario o la contraseña, o el usuario no puede leer los índices de Wazuh.")
    if r.status_code != 200:
        log.warning("indexer_status code=%s", r.status_code)
        raise IndexerError(f"El Indexer respondió con un error (HTTP {r.status_code}).")
    try:
        data = r.json()
        hits = data["hits"]["hits"]
        total = data["hits"]["total"]
        total = total["value"] if isinstance(total, dict) else int(total)
    except (ValueError, KeyError, TypeError) as exc:
        raise IndexerError("Respuesta inesperada del Indexer.") from exc
    events = [normalize_hit(h) for h in hits if isinstance(h, dict)]
    return {"events": events, "total": total, "shown": len(events), "window_min": window,
            "raw_events": any(e["raw"] for e in events), "archives_enabled": archives,
            "from": body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"], "to": body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"]}
