"""Contexto de un hallazgo desde el Indexer de Wazuh (opcional, apagado por defecto).

Muestra, bajo un hallazgo, lo que Wazuh guardó del mismo equipo o IP en una ventana de tiempo alrededor del hallazgo, para tener más contexto que las
alertas que llegaron al analizador. Solo lectura: el analizador **consulta**, no escribe nada en el Indexer.

Variables: ``WAZUH_INDEXER_URL`` (p. ej. ``https://single-node-wazuh.indexer-1:9200`` dentro de la red de Wazuh), ``WAZUH_INDEXER_USER`` y
``WAZUH_INDEXER_PASSWORD`` (un usuario de **solo lectura**; la contraseña va en el ``.env`` del servidor, nunca en el chat ni en el repositorio).
Opcionales: ``WAZUH_INDEXER_VERIFY=0`` (certificado autofirmado, lo habitual en un laboratorio) o ``WAZUH_INDEXER_CA``; ``WAZUH_INDEXER_WINDOW_MIN``
(minutos antes y después, 5); ``WAZUH_INDEXER_MAX`` (alertas máximas, 100); ``WAZUH_INDEXER_ARCHIVES=off`` para no mirar el índice de archivos;
``WAZUH_INDEXER_RAW_WINDOW_SEC`` (segundos antes y después para los eventos crudos, 90) y ``WAZUH_INDEXER_RAW_MAX`` (eventos crudos máximos, 50).

Qué hay en el Indexer: siempre el índice de **alertas** (``wazuh-alerts-*``). Los **eventos crudos** (``wazuh-archives-*``) existen solo si activaste el archivado
(``<logall_json>yes</logall_json>`` en el manager y archivos habilitados en Filebeat); si no existe, se consulta igual y simplemente no aparecen.
Alertas y eventos crudos se consultan por separado: así un volumen grande de crudos nunca desplaza a las alertas, los crudos usan una ventana más corta
y se ordenan por relevancia (misma IP o cuenta primero), y solo se muestran los que **no** generaron alerta (los demás ya están en la lista de alertas).
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
          "data.win.system.eventID", "data.win.system.providerName", "data.win.system.message", "data.win.system.computer", "data.win.eventdata.ipAddress", "data.win.eventdata.targetUserName",
          "data.win.eventdata.subjectUserName", "data.win.eventdata.commandLine", "data.win.eventdata.image", "data.win.eventdata.parentImage",
          "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"]
IP_FIELDS = ["data.srcip", "data.dstip", "data.win.eventdata.ipAddress", "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"]
USER_FIELDS = ["data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName"]
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


_TLS_WARNED = False


def _warn_tls() -> None:
    global _TLS_WARNED
    if not _TLS_WARNED:
        _TLS_WARNED = True
        log.warning("tls_verify_disabled service=wazuh_indexer: solo para laboratorio; en producción usa WAZUH_INDEXER_CA con la CA de tu Indexer")


def _verify():
    ca = os.environ.get("WAZUH_INDEXER_CA", "").strip()
    if ca:
        return ca
    ok = os.environ.get("WAZUH_INDEXER_VERIFY", "").strip().lower() not in ("0", "false", "no", "off")
    if not ok:
        _warn_tls()
    return ok


def _host_variants(host: str) -> list[str]:
    short = host.split(".")[0]
    return list(dict.fromkeys(x for x in (host, short, short.lower(), short.upper(), host.lower()) if x))


def _range(finding: dict, seconds: int) -> dict:
    t0 = pd.Timestamp(finding["time_start"], tz="UTC") - timedelta(seconds=seconds)
    t1 = pd.Timestamp(finding["time_end"], tz="UTC") + timedelta(seconds=seconds)
    return {"range": {"@timestamp": {"gte": t0.isoformat(), "lte": t1.isoformat()}}}


def _clauses(finding: dict) -> list[dict]:
    should = []
    hosts = [h for h in (finding.get("hosts") or [])[:10] if h]
    if hosts:
        should.append({"terms": {"agent.name": [v for h in hosts for v in _host_variants(h)]}})
    ips = [i for i in (finding.get("ips") or [])[:10] if i]
    if ips:
        should += [{"terms": {f: ips, "boost": 5}} for f in IP_FIELDS]
    users = [u for u in (finding.get("users") or [])[:10] if u]
    if users:
        should += [{"terms": {f: users, "boost": 5}} for f in USER_FIELDS]
    if not (hosts or ips):
        raise IndexerError("El hallazgo no tiene equipo ni IP para buscar en Wazuh.")
    return should


def build_query(finding: dict, window_min: int, size: int, raw: bool = False, raw_window_sec: int = 90) -> tuple[str, dict]:
    """(índice, cuerpo) a partir del hallazgo. Nada del navegador entra en la consulta.

    ``raw=False``: alertas (``wazuh-alerts-*``) en ±``window_min`` minutos, en orden cronológico.
    ``raw=True``: eventos crudos (``wazuh-archives-*``) en ±``raw_window_sec`` segundos que **no** generaron alerta (sin ``rule.id``),
    los más relevantes primero (misma IP o cuenta), para que un volumen alto de eventos no tape lo importante.
    """
    should = _clauses(finding)
    if not raw:
        body = {"size": size, "track_total_hits": True, "sort": [{"@timestamp": "asc"}], "_source": SOURCE,
                "query": {"bool": {"filter": [_range(finding, window_min * 60)], "should": should, "minimum_should_match": 1}}}
        return "wazuh-alerts-*", body
    body = {"size": size, "track_total_hits": True, "sort": [{"_score": "desc"}, {"@timestamp": "asc"}], "_source": SOURCE,
            "query": {"bool": {"filter": [_range(finding, raw_window_sec)], "must_not": [{"exists": {"field": "rule.id"}}],
                               "should": should, "minimum_should_match": 1}}}
    return "wazuh-archives-*", body


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
    raw = str(hit.get("_index", "")).startswith("wazuh-archives")
    eid = _g(s, "data.win.system.eventID")
    detail = _g(s, "data.win.eventdata.commandLine") or _g(s, "data.win.eventdata.image")
    desc = _g(s, "rule.description")
    if raw and not detail:
        msg = _g(s, "data.win.system.message")
        detail = (f"{msg}" if msg else "") or (_g(s, "full_log") if not _g(s, "full_log").lstrip().startswith("{") else "")
    if not detail:
        detail = _g(s, "full_log") if not _g(s, "full_log").lstrip().startswith("{") else ""
    if raw and not desc:
        prov = _g(s, "data.win.system.providerName").replace("Microsoft-Windows-", "")
        desc = f"Windows {eid}" + (f" ({prov})" if prov else "") if eid else (_g(s, "decoder.name") or _g(s, "location"))
    return {"time": _g(s, "@timestamp"), "raw": raw,
            "host": _g(s, "agent.name"), "rule": _g(s, "rule.id"), "level": _g(s, "rule.level"),
            "description": _clean(_unescape(desc), 200),
            "ip": _g(s, "data.srcip") or _g(s, "data.win.eventdata.ipAddress") or _g(s, "data.win.eventdata.sourceIp"),
            "user": _g(s, "data.srcuser") or _g(s, "data.dstuser") or _g(s, "data.win.eventdata.targetUserName") or _g(s, "data.win.eventdata.subjectUserName"),
            "event_id": eid, "detail": _clean(_unescape(detail), 300)}


def _search(http: httpx.Client, url: str, index: str, body: dict) -> tuple[list[dict], int]:
    try:
        r = http.post(f"{url}/{index}/_search", params={"ignore_unavailable": "true", "allow_no_indices": "true"}, json=body,
                      auth=(os.environ["WAZUH_INDEXER_USER"].strip(), os.environ["WAZUH_INDEXER_PASSWORD"]))
    except httpx.HTTPError as exc:
        log.warning("indexer_failed type=%s", type(exc).__name__)
        raise IndexerError("No se pudo conectar con el Indexer de Wazuh (revisa la URL, la red y el certificado: WAZUH_INDEXER_VERIFY).") from exc
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
    return [h for h in hits if isinstance(h, dict)], total


def context_for(finding: dict, http: httpx.Client | None = None) -> dict:
    window, size = _int("WAZUH_INDEXER_WINDOW_MIN", 5, 1, 60), _int("WAZUH_INDEXER_MAX", 100, 10, 500)
    raw_window, raw_size = _int("WAZUH_INDEXER_RAW_WINDOW_SEC", 90, 10, 3600), _int("WAZUH_INDEXER_RAW_MAX", 50, 0, 500)
    archives = os.environ.get("WAZUH_INDEXER_ARCHIVES", "").strip().lower() not in ("off", "0", "false", "no") and raw_size > 0
    index, body = build_query(finding, window, size)
    own = http is None
    http = http or httpx.Client(timeout=TIMEOUT, verify=_verify(), follow_redirects=False, trust_env=False)
    url = os.environ["WAZUH_INDEXER_URL"].strip().rstrip("/")
    try:
        hits, alerts_total = _search(http, url, index, body)
        raw_hits, raw_total = [], 0
        if archives:
            try:
                rindex, rbody = build_query(finding, window, raw_size, raw=True, raw_window_sec=raw_window)
                raw_hits, raw_total = _search(http, url, rindex, rbody)
            except IndexerError as exc:       # los crudos son un extra: si fallan, las alertas se muestran igual
                log.warning("indexer_raw_skipped")
                raw_hits, raw_total = [], 0
    finally:
        if own:
            http.close()
    events = sorted((normalize_hit(h) for h in hits + raw_hits), key=lambda e: e["time"])
    return {"events": events, "total": alerts_total + raw_total, "shown": len(events), "alerts_total": alerts_total, "raw_total": raw_total,
            "alerts_shown": len(hits), "raw_shown": len(raw_hits), "window_min": window, "raw_window_sec": raw_window,
            "raw_events": bool(raw_hits), "archives_enabled": archives,
            "from": body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"], "to": body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"]}
