"""Orquesta el parser, las reglas y la correlación, y arma las estadísticas del dashboard."""
from __future__ import annotations

import logging
from collections import Counter, defaultdict

import pandas as pd

from . import attack
from . import detection as D
from .siemqueries import ALL_SUPPORTED as SIEM_SUPPORTED

log = logging.getLogger("soc.analysis")

IOC_TYPE_ORDER = ["IP", "Cuenta", "Host", "Servicio/Tarea", "Ruta/archivo", "URL/URI", "Comando"]
NOT_BASELINE_SKIP = {"dq_host_alias", "dq_logsource", "dq_account_lookalike", "siem_underclass"}


def _profile(df: pd.DataFrame, meta: dict) -> dict:
    t0, t1 = df["Timestamp"].min(), df["Timestamp"].max()
    ext_ips = sorted({i for i in df["Source_IP"] if D.is_external(i)})
    ext_ips += sorted({D.ip_of(x) for x in df["Destination"] if D.is_external(x)} - set(ext_ips))
    blank_dest = int((df["Destination"] == "").sum())
    per_user_ips = df[df["Source_IP"] != ""].groupby("User")["Source_IP"].nunique()
    return {
        "rows": int(len(df)),
        "time_start": D.fts(t0), "time_end": D.fts(t1),
        "duration": D.fmt_dur((t1 - t0).total_seconds()),
        "hosts": int(df["Hostname"].nunique()), "users": int(df[~df["User"].isin(["", "-"])]["User"].nunique()),
        "event_ids": dict(Counter(df["Event_ID"]).most_common()),
        "siem_severity": dict(Counter(df["Severity"])),
        "log_sources": dict(Counter(df["Log_Source"])),
        "external_ips": ext_ips,
        "blank_destination_pct": round(blank_dest / len(df) * 100, 1),
        "users_with_many_source_ips": int((per_user_ips >= 5).sum()),
        "load": meta,
    }


def _limitations(df: pd.DataFrame, profile: dict) -> list[str]:
    tz_note = (
        "Las marcas de tiempo del export traían zona horaria (u hora epoch); se convirtieron a UTC para unificarlas."
        if profile["load"].get("timezone_converted")
        else "Las marcas de tiempo del export no indican zona horaria; se usaron tal como vienen."
    )
    out = [
        tz_note,
        f"El export cubre solo {profile['duration']} de un único día ({profile['time_start'][:10]}). No hay línea base histórica, por lo que no "
        "se evaluó 'horario inusual' ni desvíos respecto del comportamiento normal de cada usuario.",
        "Las rutas, hashes de archivos, nombres de proceso padre y tipo de inicio de sesión solo están cuando el SIEM los incluyó en "
        "Event_Description o Process_CommandLine. No se inventaron campos ausentes.",
        "Los rangos 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 son rangos de documentación (RFC 5737); se trataron como externos "
        "porque no pertenecen a las redes privadas del cliente. No se hizo reputación ni geolocalización (no hay inteligencia de amenazas en el export).",
    ]
    if profile["blank_destination_pct"] > 5:
        out.append(f"El campo Destination está vacío en el {profile['blank_destination_pct']} % de los eventos, lo que limita el análisis de flujos.")
    if profile["users_with_many_source_ips"]:
        out.append(f"{profile['users_with_many_source_ips']} cuentas aparecen con 5 o más IP internas distintas en eventos rutinarios; "
                   "por eso las IP internas no se usaron como señal de anomalía.")
    out.append("El movimiento lateral solo se infiere cuando el log declara explícitamente el host de origen (source=...); "
               "no se reconstruyen saltos por simple coincidencia de cuentas.")
    out.append("No se puede determinar, solo con este export, si las cuentas internas involucradas fueron comprometidas o usadas "
               "indebidamente por su titular; ese punto requiere investigación adicional.")
    if profile["load"].get("json_in_sheet"):
        out.append("El archivo era un JSON guardado línea por línea en una hoja de cálculo; se reconstruyó y solo se usó la lista de eventos."
                   + (" Faltaban líneas en el original (había comas sobrantes), así que otros apartados del JSON, como incidentes "
                      "o hallazgos previos, pueden estar incompletos y no se tuvieron en cuenta." if profile["load"].get("json_repaired") else ""))
    return out


def _aggregate_iocs(findings: list[D.Finding], df: pd.DataFrame) -> list[dict]:
    agg: dict[tuple, dict] = {}
    for f in findings:
        extra = []
        if not f.rule.startswith("dq_"):  # las cuentas que actúan en un hallazgo son indicadores
            extra = [{"type": "Cuenta", "value": u, "note": "Cuenta involucrada en actividad sospechosa"} for u in f.actor_users]
        for i in f.iocs + extra:
            key = (i["type"], i["value"])
            a = agg.setdefault(key, {"type": i["type"], "value": i["value"], "notes": [], "finding_ids": [],
                                     "first_seen": f.time_start, "last_seen": f.time_end, "severity": "Bajo"})
            if i["note"] and i["note"] not in a["notes"]:
                a["notes"].append(i["note"])
            a["finding_ids"].append(f.id)
            a["first_seen"] = min(a["first_seen"], f.time_start)
            a["last_seen"] = max(a["last_seen"], f.time_end)
            a["severity"] = D.max_sev([a["severity"], f.severity])
    out = []
    for a in agg.values():
        v = a["value"]
        if a["type"] == "IP":
            a["events"] = int(((df["Source_IP"] == v) | df["Destination"].str.contains(v, regex=False)).sum())
        elif a["type"] == "Cuenta":
            a["events"] = int((df["User"] == v).sum())
        elif a["type"] == "Host":
            a["events"] = int((df["Hostname"] == v).sum())
        a["finding_ids"] = list(dict.fromkeys(a["finding_ids"]))
        out.append(a)
    out.sort(key=lambda a: (IOC_TYPE_ORDER.index(a["type"]) if a["type"] in IOC_TYPE_ORDER else 99,
                            -D.SEV_ORDER[a["severity"]], a["value"]))
    return out


def _stats(df: pd.DataFrame, findings: list[D.Finding], incidents: list[dict]) -> tuple[dict, dict]:
    flag_map: dict[str, list[str]] = defaultdict(list)
    row_sev: dict[str, str] = {}
    for f in findings:
        if f.rule in NOT_BASELINE_SKIP:
            continue
        for e in f.evidence_ids:
            flag_map[e].append(f.id)
            row_sev[e] = D.max_sev([row_sev.get(e, "Bajo"), f.severity])
    # los hallazgos de calidad también se mapean (para filtrar), sin afectar el gráfico
    for f in findings:
        if f.rule in NOT_BASELINE_SKIP:
            for e in f.evidence_ids:
                if f.id not in flag_map[e]:
                    flag_map[e].append(f.id)

    sev_counts = Counter(f.severity for f in findings)
    inc_counts = Counter(i["severity"] for i in incidents)
    cat_counts = Counter(f.category for f in findings)
    tac_counts = Counter(f.tactic for f in findings)

    d = df.copy()
    d["_bucket"] = d["Timestamp"].dt.floor("10min")
    d["_flag_sev"] = d["Log_ID"].map(row_sev)
    idx = pd.date_range(d["_bucket"].min(), d["_bucket"].max(), freq="10min")
    timeline = []
    for b in idx:
        g = d[d["_bucket"] == b]
        timeline.append({
            "t": b.strftime("%H:%M"), "total": int(len(g)),
            "normal": int(g["_flag_sev"].isna().sum()),
            **{s: int((g["_flag_sev"] == s).sum()) for s in ("Crítico", "Alto", "Medio", "Bajo")},
        })

    ip_counts = Counter(i for i in df["Source_IP"] if i)
    flagged_ids = set(row_sev)
    top_ips = []
    for ip, n in ip_counts.most_common():
        fl = int(df[(df["Source_IP"] == ip) & df["Log_ID"].isin(flagged_ids)].shape[0])
        top_ips.append({"ip": ip, "events": n, "flagged": fl, "external": D.is_external(ip)})
    ext_first = [x for x in top_ips if x["external"]]
    top_ips = (ext_first + [x for x in top_ips if not x["external"]])[:10]

    siem_flagged = Counter(df[df["Log_ID"].isin(flagged_ids)]["Severity"])
    stats = {
        "findings_total": len(findings), "incidents_total": len(incidents),
        "flagged_events": len(flagged_ids),
        "findings_by_severity": {s: sev_counts.get(s, 0) for s in ("Crítico", "Alto", "Medio", "Bajo")},
        "incidents_by_severity": {s: inc_counts.get(s, 0) for s in ("Crítico", "Alto", "Medio", "Bajo")},
        "findings_by_category": {c: cat_counts.get(c, 0) for c in D.CATEGORIES},
        "findings_by_tactic": {t: tac_counts[t] for t in D.TACTIC_ORDER if tac_counts.get(t)},
        "timeline": timeline, "top_ips": top_ips,
        "siem_severity_of_flagged": dict(siem_flagged),
    }
    return stats, dict(flag_map)


def analyze(df: pd.DataFrame, meta: dict) -> dict:
    st = D.State(df)
    failed_rules: list[str] = []
    for key, desc, fn in D.RULES:
        try:
            fn(st)
        except Exception:   # una regla defectuosa no debe tumbar todo el análisis, pero se declara
            log.exception("rule_failed rule=%s", key)
            failed_rules.append(desc)
    D.prune_uncorroborated(st)
    incidents, others = D.correlate(st)

    n = 1
    ordered: list[D.Finding] = []
    for inc in incidents:
        for f in inc["_findings"]:
            f.id = f"F-{n:03d}"
            n += 1
            inc["finding_ids"].append(f.id)
            ordered.append(f)
    for f in sorted(others, key=lambda f: (-D.SEV_ORDER[f.severity], f.time_start)):
        f.id = f"F-{n:03d}"
        n += 1
        ordered.append(f)

    hypotheses = D.build_hypotheses(incidents)
    for inc in incidents:
        inc.pop("_findings")
        # observaciones sueltas (p. ej. cuentas de nombre parecido) que tocan a un actor del incidente
        inc["observation_ids"] = [f.id for f in others if f.rule == "dq_account_lookalike"
                                  and set(f.actor_users) & set(inc["actor_users"])]

    profile = _profile(df, meta)
    stats, flag_map = _stats(df, ordered, incidents)
    iocs = _aggregate_iocs([f for f in ordered if f.rule not in ("siem_underclass",)], df)

    rule_catalog = []
    for key, desc, _fn in D.RULES:
        if key == "cmd":
            hits = sum(v for k, v in st.rule_hits.items() if k.startswith("cmd_"))
        elif key == "dataquality":
            hits = sum(v for k, v in st.rule_hits.items() if k.startswith("dq_"))
        else:
            hits = st.rule_hits.get(key, 0)
        rule_catalog.append({"key": key, "description": desc, "hits": hits})

    return {
        "profile": profile,
        "findings": [f.to_dict() for f in ordered],
        "incidents": incidents,
        "hypotheses": hypotheses,
        "iocs": iocs,
        "stats": stats,
        "attack": attack.build_matrix(ordered),
        "siem_rules": sorted(SIEM_SUPPORTED),
        "flag_map": flag_map,
        "limitations": _limitations(df, profile) + [
            f"La regla «{d}» no pudo ejecutarse con este archivo; sus detecciones pueden faltar." for d in failed_rules],
        "rules": rule_catalog,
        "config": D.CONFIG,
    }


def rows_for(df: pd.DataFrame, ids: list[str], flag_map: dict | None = None, cmd_len: int | None = None) -> list[dict]:
    """Filas del Excel (por Log_ID) listas para JSON, respetando el orden pedido."""
    sub = df[df["Log_ID"].isin(ids)].set_index("Log_ID")
    out = []
    for i in ids:
        if i not in sub.index:
            continue
        r = sub.loc[i]
        if isinstance(r, pd.DataFrame):
            r = r.iloc[0]
        row = {c: ("" if pd.isna(r[c]) else r[c]) for c in sub.columns}
        row["Log_ID"] = i
        row["Timestamp"] = D.fts(r["Timestamp"])
        if cmd_len:
            row["Process_CommandLine"] = D.trunc(row["Process_CommandLine"], cmd_len)
        if flag_map is not None:
            row["findings"] = flag_map.get(i, [])
        out.append(row)
    return out
