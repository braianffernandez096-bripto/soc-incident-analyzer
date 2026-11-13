"""Reglas de contexto externo (opcionales): vulnerabilidades explotadas (CISA KEV / EPSS) e indicadores de tu MISP.

Solo disparan si el contexto está activado y tiene datos; con todo apagado (el valor por defecto) no producen hallazgos y el motor se comporta igual que antes.
Como el resto del motor, fijan la criticidad con umbrales explícitos; la IA solo redacta.

- ``ctx_cve``: un CVE que aparece en los eventos (p. ej. alertas de vulnerabilidades de Wazuh) y figura en KEV, o tiene un EPSS alto.
- ``ctx_misp``: una IP o hash de los eventos que existe como indicador en tu MISP.
- ``ctx_feed``: una IP, un hash o un dominio de los eventos que figura (y no venció) en tu feed JSON de indicadores.
"""
from __future__ import annotations

import re

import pandas as pd

from . import context as C
from . import feed as F
from . import misp as M
from .detection import CONFIG, State, _ioc, _mk, fmt_dec, ip_of

CONFIG.update({"epss_high": 0.7, "epss_medium": 0.1})

_SOLVED = re.compile(r"estado:\s*(solved|resolved|fixed|resuelt\w*)", re.I)
_PKG = re.compile(r"paquete:\s*([^\n]{1,100})", re.I)
_HASH = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b", re.I)


def rule_cve_context(st: State) -> None:
    store = C.get_store()
    if store is None or not store.ready:
        return
    d = st.df
    text = d["Event_Description"] + " " + d["Process_CommandLine"]
    hit = text.str.contains(C.CVE_RE, na=False)
    if not hit.any():
        return
    by_cve: dict[str, list[int]] = {}
    for idx in d.index[hit]:
        if _SOLVED.search(d.at[idx, "Event_Description"]):
            continue                                # vulnerabilidad ya corregida
        for cve in C.extract_cves(text.at[idx]):
            by_cve.setdefault(cve, []).append(idx)
    for cve, idxs in by_cve.items():
        info = store.lookup(cve)
        if not info:
            continue
        kev, epss = info["kev"], info["epss"]
        if kev:
            sev = "Crítico" if kev["ransomware"] else "Alto"
        elif epss is not None and epss >= CONFIG["epss_high"]:
            sev = "Alto"
        elif epss is not None and epss >= CONFIG["epss_medium"]:
            sev = "Medio"
        else:
            continue
        rows = d.loc[idxs]
        hosts = list(dict.fromkeys(h for h in rows["Hostname"] if h))
        pkgs = list(dict.fromkeys(m.group(1).strip() for t in rows["Event_Description"] for m in [_PKG.search(t)] if m))[:5]
        reasons = []
        if kev:
            reasons.append(f"{cve} figura en el catálogo CISA KEV (explotación activa confirmada), agregado el {kev['added'] or 's/d'}"
                           + (f"; plazo de remediación de CISA: {kev['due']}" if kev["due"] else "") + ".")
            if kev["ransomware"]:
                reasons.append("CISA indica uso conocido en campañas de ransomware.")
        if epss is not None:
            reasons.append(f"EPSS {fmt_dec(epss * 100, 1)} %: probabilidad estimada de explotación en los próximos 30 días "
                           f"(percentil {fmt_dec(info['percentile'] * 100, 0)}).")
        where = f"en {', '.join(hosts[:4])}" if hosts else "en el entorno"
        title = (f"{cve} explotada activamente (CISA KEV) {where}" if kev
                 else f"{cve} con alta probabilidad de explotación (EPSS {fmt_dec(epss * 100, 0)} %) {where}")
        expl = (f"Se detectó la vulnerabilidad {cve}" + (f" ({kev['vendor']} {kev['product']})".replace("  ", " ") if kev and (kev["vendor"] or kev["product"]) else "")
                + f" {where}" + (f", paquete(s): {'; '.join(pkgs)}" if pkgs else "") + ". "
                + ("CISA la tiene catalogada como explotada en ataques reales, por lo que conviene priorizar su corrección sobre otras con puntaje CVSS similar. "
                   if kev else "No está en KEV, pero el modelo EPSS estima una probabilidad alta de explotación. ")
                + "Es contexto para priorizar: confirma que el equipo realmente expone el componente afectado y aplica el parche del fabricante.")
        _mk(st, "ctx_cve", title, "Otras anomalías", "Acceso inicial", [], sev, reasons, expl, rows,
            metrics={"cve": cve, "kev": bool(kev), "ransomware": bool(kev and kev["ransomware"]), "epss": epss, "percentile": info["percentile"],
                     "plazo_cisa": kev["due"] if kev else "", "equipos": len(hosts), "paquetes": pkgs}, iocs=[], hosts=hosts)


def rule_misp(st: State) -> None:
    client = M.get_client()
    if client is None:
        return
    d = st.df
    where: dict[str, list[int]] = {}

    def add(val: str, idx: int) -> None:
        v = val.strip().lower()
        if v and client.queryable(v):
            where.setdefault(v, []).append(idx)

    for col in ("Source_IP", "Destination"):
        for idx, v in d[col].items():
            ip = ip_of(str(v))
            if ip:
                add(ip, idx)
    text = d["Event_Description"] + " " + d["Process_CommandLine"]
    for idx in d.index[text.str.contains(_HASH, na=False)]:
        for h in _HASH.findall(text.at[idx]):
            add(h, idx)
    if not where:
        return
    found = client.search(list(where))
    for val, events in found.items():
        rows = d.loc[list(dict.fromkeys(where.get(val, [])))]
        if rows.empty:
            continue
        is_ip = bool(ip_of(val))
        names = "; ".join(f"#{e['event_id']} {e['event']}".strip() for e in events[:3])
        reasons = [f"{'La IP' if is_ip else 'El hash'} {val} figura como indicador en tu MISP ({len(events)} evento(s): {names})."]
        _mk(st, "ctx_misp", f"Indicador conocido en MISP: {val}", "Otras anomalías", "Comando y control" if is_ip else "Ejecución", [], "Alto", reasons,
            f"{'La IP' if is_ip else 'El hash'} {val} aparece en los eventos y coincide con un indicador cargado en tu instancia de MISP "
            f"({names}). Revisa en MISP el contexto del evento (campaña, confianza, fecha) antes de actuar: una coincidencia indica que el dato "
            f"fue reportado como malicioso, no prueba por sí sola que el equipo esté comprometido.",
            rows, actor_ips=[val] if is_ip else [],
            metrics={"valor": val, "eventos_misp": [e["event_id"] for e in events], "descripciones": [e["event"] for e in events[:5]]},
            iocs=[_ioc("IP" if is_ip else "Hash", val, "Coincide con MISP")])


def rule_feed(st: State) -> None:
    feed = F.get_feed()
    if feed is None or not feed.ready:
        return
    d = st.df
    where: dict[str, list[int]] = {}

    def add(val: str, idx: int) -> None:
        where.setdefault(val, []).append(idx)

    for col in ("Source_IP", "Destination"):
        for idx, v in d[col].items():
            ip = ip_of(str(v))
            if ip:
                norm, kind = F.normalize(ip)
                if kind == "ip":
                    add(norm, idx)
    text = (d["Event_Description"] + " " + d["Process_CommandLine"] + " " + d["Destination"]).str.lower()
    for idx in d.index[text.str.contains(_HASH, na=False)]:
        for h in _HASH.findall(text.at[idx]):
            add(h, idx)
    doms = feed.domains()
    if doms:
        for idx, t in text.items():
            for tok in F.TOKEN_RE.findall(t):
                labels = tok.rstrip(".").split(".")
                for i in range(len(labels) - 1):                      # «a.b.evil.com» coincide con «evil.com» (sin cruzar el sufijo público)
                    cand = ".".join(labels[i:])
                    if cand in doms:
                        add(cand, idx)
                        break
    if not where:
        return
    active = feed.lookup(list(where))
    for val, e in active.items():
        rows = d.loc[list(dict.fromkeys(where[val]))]
        kind = e["tipo"]
        label = {"ip": "La IP", "hash": "El hash", "dominio": "El dominio"}[kind]
        extra = " · ".join(x for x in (e["descripcion"], f"fuente: {e['fuente']}" if e["fuente"] else "",
                                       f"vigente hasta {e['expira']}" if e["expira"] else "sin vencimiento") if x)
        _mk(st, "ctx_feed", f"Indicador conocido en tu feed: {val}", "Otras anomalías", "Ejecución" if kind == "hash" else "Comando y control", [], "Alto",
            [f"{label} {val} figura en tu feed de indicadores ({extra})."],
            f"{label} {val} aparece en los eventos y coincide con un indicador de tu feed ({extra}). Revisa el contexto del indicador (campaña, fecha, "
            f"confianza) antes de actuar: la coincidencia indica que alguien lo reportó como malicioso, no prueba por sí sola que el equipo esté comprometido.",
            rows, actor_ips=[val] if kind == "ip" else [],
            metrics={"valor": val, "tipo": kind, "fuente": e["fuente"], "fecha": e["fecha"], "expira": e["expira"], "descripcion": e["descripcion"]},
            iocs=[_ioc({"ip": "IP", "hash": "Hash", "dominio": "Dominio"}[kind], val, "Coincide con tu feed")])


RULES = [
    ("ctx_cve", "Contexto (opcional): CVE presente en los eventos y listado en CISA KEV o con EPSS alto", rule_cve_context),
    ("ctx_misp", "Contexto (opcional): IP o hash de los eventos que existe como indicador en tu MISP", rule_misp),
    ("ctx_feed", "Contexto (opcional): IP, hash o dominio de los eventos que figura (y no venció) en tu feed JSON de indicadores", rule_feed),
]
