"""Medición de falsos positivos con actividad legítima de un laboratorio con Wazuh.

Lee del Indexer los eventos de uno o más agentes en un rango de horas, los pasa por el mismo camino que una alerta en vivo (traductor de
Wazuh y motor de reglas) e informa cuánto ruido genera la app sobre actividad que se sabe legítima: hallazgos por cada 1.000 eventos, por
regla, criticidad y confianza. Procedimiento completo: docs/MEDIR_FALSOS_POSITIVOS.md.

Se ejecuta dentro del contenedor del analizador, que ya tiene la conexión al Indexer configurada (``WAZUH_INDEXER_URL``, ``_USER``,
``_PASSWORD``, ``_VERIFY`` o ``_CA``): no pide contraseñas y **no guarda los eventos**, solo imprime la medición.

    docker exec soc-incident-analyzer-analyzer-1 python -m backend.medicion_fp --agente WIN-A --agente WIN-B \\
        --desde 2026-11-16T09:00-03:00 --hasta 2026-11-17T09:00-03:00

Además informa qué tipos de evento llegaron (Sysmon, 4688 con línea de comandos, 5145…). Si falta alguno que depende de la configuración
de auditoría, las reglas que lo usan no pudieron medirse y se dice: un «cero falsos positivos» sin esos eventos no probaría nada.

No consulta servicios externos: durante la medición MISP queda apagado (los datos del laboratorio no salen del servidor), así que
``ctx_misp`` no forma parte de la medición. El contexto local (CISA KEV/EPSS en caché y el feed propio) sí se usa.
Las horas se muestran en la zona horaria de ``--desde``.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import json
import os
import sys

import httpx
import pandas as pd

from . import misp
from . import wazuh
from . import wazuh_indexer as wi
from .analysis import analyze

INDICES = {"archives": "wazuh-archives-*", "alertas": "wazuh-alerts-*"}
MAX_EVENTS = 100_000          # el mismo tope que un archivo cargado a mano (parser.MAX_ROWS)
PAGE = 2_000
OBSERVATIONS = {"siem_underclass", "dq_account_lookalike", "dq_host_alias", "dq_logsource"}
# Tipos de evento de los que dependen las reglas más propensas a ruido: (nombre, reglas, tipo).
# «auditoria»: solo llegan si Windows y el agente están configurados para enviarlos (si faltan, esas reglas NO se midieron).
# «actividad»: llegan cuando ocurre la acción (en 0 puede ser simplemente que en ese rango no pasó).
COVERAGE = {
    "sysmon_1": ("Creación de procesos de Sysmon (evento 1)", "comandos, WMI, PowerShell remoto, DCOM", "auditoria"),
    "4688_cmd": ("Creación de procesos 4688 con línea de comandos", "comandos, WMI, PowerShell remoto, DCOM (si no hay Sysmon)", "auditoria"),
    "5145": ("Acceso a recursos compartidos (5145)", "control remoto de servicios y copia por C$/ADMIN$", "auditoria"),
    "4624": ("Inicios de sesión (4624)", "inicios externos, DCOM, servicio remoto", "actividad"),
    "4625": ("Inicios de sesión fallidos (4625)", "fuerza bruta", "actividad"),
    "7045_4697": ("Servicios instalados (7045/4697)", "persistencia y servicio remoto", "actividad"),
    "4698": ("Tareas programadas creadas (4698)", "persistencia", "actividad"),
    "sysmon_13": ("Cambios de registro de Sysmon (evento 13)", "claves Run y apagado de defensas", "auditoria"),
}
EXAMPLE_KEYS = ("ejemplos", "procesos", "binarios", "archivos", "imagenes", "comandos_ejemplo")


class MedicionError(Exception):
    """Error apto para mostrar (sin credenciales ni URL)."""


def _ts(value: str) -> pd.Timestamp:
    try:
        t = pd.Timestamp(value)
    except (TypeError, ValueError) as exc:
        raise MedicionError(f"Fecha no válida: {value!r}. Usa el formato 2026-11-16T09:00-03:00.") from exc
    return t.tz_localize("UTC") if t.tzinfo is None else t.tz_convert("UTC")


def build_query(agents: list[str], t0: pd.Timestamp, t1: pd.Timestamp) -> dict:
    variants = [v for a in agents for v in wi._host_variants(a)]
    return {"size": PAGE, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [{"terms": {"agent.name": variants}},
                                          {"range": {"@timestamp": {"gte": t0.isoformat(), "lt": t1.isoformat()}}}]}}}


def fetch(agents: list[str], t0: pd.Timestamp, t1: pd.Timestamp, index: str = INDICES["archives"], max_events: int = MAX_EVENTS,
          http: httpx.Client | None = None) -> tuple[list[dict], bool]:
    """Eventos del rango con la API de scroll. Devuelve (documentos, recortado)."""
    if not wi.configured():
        raise MedicionError("Falta la conexión al Indexer (WAZUH_INDEXER_URL, WAZUH_INDEXER_USER y WAZUH_INDEXER_PASSWORD en el .env).")
    url = os.environ["WAZUH_INDEXER_URL"].strip().rstrip("/")
    auth = (os.environ["WAZUH_INDEXER_USER"].strip(), os.environ["WAZUH_INDEXER_PASSWORD"])
    http = http or httpx.Client(timeout=60.0, verify=wi._verify(), follow_redirects=False, trust_env=False)
    docs: list[dict] = []
    scroll_id = None
    try:
        r = http.post(f"{url}/{index}/_search", params={"scroll": "2m", "ignore_unavailable": "true", "allow_no_indices": "true"},
                      json=build_query(agents, t0, t1), auth=auth)
        while True:
            if r.status_code in (401, 403):
                raise MedicionError("El Indexer rechazó el usuario, o el usuario no puede leer ese índice.")
            if r.status_code != 200:
                raise MedicionError(f"El Indexer respondió con un error (HTTP {r.status_code}).")
            data = r.json()
            scroll_id = data.get("_scroll_id") or scroll_id
            hits = data.get("hits", {}).get("hits", [])
            for h in hits:
                if isinstance(h, dict) and isinstance(h.get("_source"), dict):
                    docs.append({**h["_source"], "_doc_id": h.get("_id", "")})
            if not hits or len(docs) >= max_events or not scroll_id:
                break
            r = http.post(f"{url}/_search/scroll", json={"scroll": "2m", "scroll_id": scroll_id}, auth=auth)
    except httpx.HTTPError as exc:
        raise MedicionError("No se pudo conectar con el Indexer de Wazuh (revisa la URL, la red y el certificado).") from exc
    except ValueError as exc:
        raise MedicionError("Respuesta inesperada del Indexer.") from exc
    finally:
        if scroll_id:
            try:
                http.request("DELETE", f"{url}/_search/scroll", json={"scroll_id": [scroll_id]}, auth=auth)
            except httpx.HTTPError:
                pass
    return docs[:max_events], len(docs) >= max_events


def prepare(docs: list[dict]) -> list[dict]:
    """Los eventos de archives no traen regla (no generaron alerta): se les da una regla neutra.

    El identificador es siempre el del Indexer (``_id``), que es único. El campo ``id`` de Wazuh no sirve en archives: se repite entre
    eventos distintos, y con identificadores repetidos la evidencia de un hallazgo arrastra eventos ajenos (medición de tareas de
    administración, docs/VALIDACION.md 3.1)."""
    out = []
    for d in docs:
        d = dict(d)
        did = str(d.pop("_doc_id", "") or "")
        if did:
            d["id"] = did
        if not isinstance(d.get("rule"), dict):
            d["rule"] = {"id": "0", "level": 0, "description": "Evento sin alerta (archives)"}
        out.append(d)
    return out


def repeated_ids(docs: list[dict]) -> int:
    """Cuántos eventos traen un ``id`` de Wazuh que ya usó otro evento (solo informativo: se analiza con el ``_id`` del Indexer)."""
    seen, rep = set(), 0
    for d in docs:
        i = str(d.get("id") or "")
        if i:
            rep += i in seen
            seen.add(i)
    return rep


def _coverage(df: pd.DataFrame) -> dict:
    src = df.get("Log_Source", pd.Series("", index=df.index)).astype(str).str.lower()
    eid = df.get("Event_ID", pd.Series("", index=df.index)).astype(str)
    desc = df.get("Event_Description", pd.Series("", index=df.index)).astype(str)
    sysmon = src.str.contains("sysmon")
    return {
        "sysmon_1": int((sysmon & (eid == "1")).sum()),
        "4688_cmd": int(((eid == "4688") & desc.str.contains(r"(?:Process\s*)?Command\s*Line\s*:\s*\S", case=False, regex=True)).sum()),
        "5145": int((eid == "5145").sum()),
        "4624": int((eid == "4624").sum()),
        "4625": int((eid == "4625").sum()),
        "7045_4697": int(eid.isin(["7045", "4697"]).sum()),
        "4698": int((eid == "4698").sum()),
        "sysmon_13": int((sysmon & (eid == "13")).sum()),
    }


@contextlib.contextmanager
def _without_external_lookups():
    """MISP apagado mientras se mide: los datos del laboratorio no salen del servidor."""
    previous = misp.get_client()
    misp.set_client(None)
    try:
        yield
    finally:
        misp.set_client(previous)


def _local_time(value: str, tz) -> str:
    """Hora del hallazgo (UTC, como la guardan las alertas de Wazuh) en la zona horaria de la medición."""
    try:
        t = pd.Timestamp(value)
        t = t.tz_localize("UTC") if t.tzinfo is None else t
        return t.tz_convert(tz).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def _examples(metrics: dict) -> list[str]:
    """Hasta tres ejemplos, cada uno en una sola línea (un mensaje de Windows trae saltos de línea)."""
    for k in EXAMPLE_KEYS:
        v = (metrics or {}).get(k)
        if isinstance(v, (list, tuple)) and v:
            return [" ".join(str(x).split())[:160] for x in v[:3]]
    return []


def _process_rows(df: pd.DataFrame, ids: list[str]) -> list[dict]:
    """Campos de proceso de la evidencia (programa, padre e identificadores), para revisar por qué una cadena se exime o no.
    No incluye cuentas ni líneas de comandos completas."""
    from . import detection as D
    out = []
    for r in df[df["Log_ID"].isin(ids) & df["Event_ID"].isin(["1", "4688"])].itertuples():
        t = r.Event_Description or ""
        image, parent, _ = D._proc(r)
        out.append({"evento": r.Event_ID, "programa": image[-90:], "padre": parent[-90:],
                    "guid": D._field(t, "ProcessGuid"), "guid_padre": D._field(t, "ParentProcessGuid"),
                    "pid": D._field(t, r"New\s*Process\s*I[Dd]") or D._field(t, "NewProcessId") or D._field(t, "ProcessId"),
                    "pid_padre": D._field(t, r"Creator\s*Process\s*I[Dd]") or D._field(t, "ParentProcessId")
                    or (D._field(t, "ProcessId") if r.Event_ID == "4688" else "")})
    return out[:12]


def measure(docs: list[dict], label: str = "", tz="UTC", processes: bool = False) -> dict:
    """La medición sobre eventos que se saben legítimos: todo hallazgo es, por definición, un falso positivo a revisar."""
    rows, st = wazuh.normalize_alerts(prepare(docs))
    out = {"etiqueta": label, "eventos_leidos": len(docs), "ids_repetidos": repeated_ids(docs), "eventos_interpretados": len(rows), "traductor": {k: st[k] for k in ("windows", "linux_auth", "otro", "descartadas")},
           "cobertura": {}, "hallazgos": 0, "observaciones": 0, "por_1000_eventos": 0.0, "por_regla": {}, "criticidad": {}, "confianza": {}, "detalle": []}
    if not rows:
        return out
    df, meta = wazuh.rows_to_frame(rows)
    out["cobertura"] = _coverage(df)
    with _without_external_lookups():
        fs = analyze(df, meta)["findings"]
    real = [f for f in fs if f["rule"] not in OBSERVATIONS]
    out["hallazgos"], out["observaciones"] = len(real), len(fs) - len(real)
    out["por_1000_eventos"] = round(1000 * len(real) / len(rows), 3)
    per = collections.defaultdict(lambda: {"n": 0, "criticidad": collections.Counter(), "confianza": collections.Counter()})
    for f in real:
        p = per[f["rule"]]
        p["n"] += 1
        p["criticidad"][f["severity"]] += 1
        p["confianza"][f["confidence"]] += 1
    out["por_regla"] = {k: {"n": v["n"], "criticidad": dict(v["criticidad"]), "confianza": dict(v["confianza"])}
                        for k, v in sorted(per.items(), key=lambda x: -x[1]["n"])}
    out["criticidad"] = dict(collections.Counter(f["severity"] for f in real))
    out["confianza"] = dict(collections.Counter(f["confidence"] for f in real))
    out["zona_horaria"] = str(tz)
    out["detalle"] = [{"regla": f["rule"], "criticidad": f["severity"], "confianza": f["confidence"], "titulo": f["title"],
                       "inicio": _local_time(f["time_start"], tz), "eventos": len(f["evidence_ids"]), "ejemplos": _examples(f.get("metrics")),
                       "a_favor": f["confidence_for"], "en_contra": f["confidence_against"],
                       **({"procesos": _process_rows(df, f["evidence_ids"])} if processes else {})}
                      for f in real]
    return out


def as_text(m: dict, detail: bool = True) -> str:
    L = [f"Medición de falsos positivos{(' · ' + m['etiqueta']) if m['etiqueta'] else ''}",
         f"Eventos leídos: {m['eventos_leidos']:,} · interpretados: {m['eventos_interpretados']:,} · descartados: {m['traductor']['descartadas']:,}".replace(",", "."),
         f"Hallazgos (sin observaciones de calidad de datos): {m['hallazgos']} · por cada 1.000 eventos: {m['por_1000_eventos']}"]
    if m.get("ids_repetidos"):
        L.append(f"Eventos con el «id» de Wazuh repetido: {m['ids_repetidos']:,} (se analizan con el identificador único del Indexer)".replace(",", "."))
    if not m["eventos_leidos"]:
        L += ["", "No se leyó ningún evento. Revisa:",
              "  - el nombre del agente: tiene que ser exacto (lista: docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l);",
              "  - el rango de horas y su zona horaria (por ejemplo, -03:00);",
              "  - que el índice exista: con --indice archives hace falta el archivado activo en Wazuh; prueba también --indice alertas."]
    if m["cobertura"]:
        L += ["", "Tipos de evento recibidos:"]
        for k, (name, rules, kind) in COVERAGE.items():
            n = m["cobertura"].get(k, 0)
            if n:
                L.append(f"  ✔ {name}: {n}")
            elif kind == "auditoria":
                L.append(f"  ✘ {name}: 0  → requisito sin cumplir (ver la guía): NO se midieron {rules}")
            else:
                L.append(f"  · {name}: 0  → no ocurrió en este rango ({rules})")
    if m["por_regla"]:
        L += ["", "Por regla (criticidad · confianza):"]
        for r, v in m["por_regla"].items():
            sev = ", ".join(f"{k} {n}" for k, n in v["criticidad"].items())
            conf = ", ".join(f"{k} {n}" for k, n in v["confianza"].items())
            L.append(f"  {r}: {v['n']}  ({sev} · confianza {conf})")
    if detail and m["detalle"]:
        L += ["", f"Detalle (horas en {m.get('zona_horaria', 'UTC')}; en actividad legítima, todo hallazgo es un falso positivo):"]
        for d in m["detalle"]:
            L.append(f"  - [{d['criticidad']} · confianza {d['confianza']}] {d['regla']}: {d['titulo']} ({d['inicio']}, {d['eventos']} eventos)")
            for x in d.get("ejemplos", []):
                L.append(f"      ejemplo: {x}")
            for x in d["en_contra"]:
                L.append(f"      en contra: {x}")
            for p in d.get("procesos", []):
                ids = f"guid {p['guid']} ← {p['guid_padre']}" if p["guid"] or p["guid_padre"] else f"pid {p['pid']} ← {p['pid_padre']}"
                L.append(f"      proceso [{p['evento']}]: {p['programa']}  ← padre: {p['padre']}  ({ids})")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m backend.medicion_fp", description=__doc__.split("\n\n")[0])
    ap.add_argument("--agente", action="append", required=True, help="nombre del agente de Wazuh (repetible)")
    ap.add_argument("--desde", required=True, help="inicio, p. ej. 2026-11-16T09:00-03:00 (sin zona horaria se toma como UTC)")
    ap.add_argument("--hasta", required=True, help="fin, mismo formato")
    ap.add_argument("--indice", choices=sorted(INDICES), default="archives", help="archives (todos los eventos, por defecto) o alertas")
    ap.add_argument("--max-eventos", type=int, default=MAX_EVENTS)
    ap.add_argument("--etiqueta", default="", help="nombre de la medición, p. ej. «jornada normal» o «tareas de administración»")
    ap.add_argument("--json", action="store_true", help="salida en JSON")
    ap.add_argument("--sin-detalle", action="store_true", help="no listar cada hallazgo (solo los totales)")
    ap.add_argument("--procesos", action="store_true", help="mostrar el árbol de procesos de la evidencia (programa, padre e identificadores)")
    a = ap.parse_args(argv)
    try:
        t0, t1 = _ts(a.desde), _ts(a.hasta)
        if t1 <= t0:
            raise MedicionError("«--hasta» debe ser posterior a «--desde».")
        docs, cut = fetch(a.agente, t0, t1, INDICES[a.indice], max(1, min(a.max_eventos, MAX_EVENTS)))
    except MedicionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    m = measure(docs, a.etiqueta, tz=pd.Timestamp(a.desde).tzinfo or "UTC", processes=a.procesos)
    m["rango_utc"] = [t0.isoformat(), t1.isoformat()]
    m["agentes"] = a.agente
    m["recortado"] = cut
    if a.json:
        if a.sin_detalle:
            m.pop("detalle")
        print(json.dumps(m, ensure_ascii=False, indent=1))
    else:
        print(as_text(m, detail=not a.sin_detalle))
        if cut:
            print(f"\nAviso: se alcanzó el tope de {MAX_EVENTS:,} eventos; acorta el rango para medirlo entero.".replace(",", "."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
