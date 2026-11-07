"""Informe HTML descargable: un único archivo que se abre sin conexión (CSS, JS y anime.js dentro del propio archivo).

Mismo contenido que el PDF (resumen, incidentes con evidencia y plan de acción, IoC, reputación, triaje y decisiones del analista, correos
sospechosos), con gráficos SVG y animaciones suaves. Las animaciones son un extra: sin JavaScript, o con «reducir movimiento» activado, el
informe se ve completo y estático.

Seguridad (el archivo se genera con datos de logs que pueden ser hostiles):
- TODO dato que viene del archivo analizado, de la IA o del correo pasa por ``e()`` (html.escape con comillas) antes de entrar al HTML; nunca se arma
  marcado con datos sin escapar y no hay atributos ``style`` ni manejadores ``on…`` generados.
- El propio informe lleva una Content-Security-Policy que solo permite su script y su hoja de estilo (por hash) y nada de red:
  aunque algo se escapara mal, el navegador no ejecutaría código ni cargaría recursos externos.
"""
from __future__ import annotations

import base64
import hashlib
import html
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from . import attack
from . import detection as D
from .analysis import rows_for
from .report import _u

ASSETS = Path(__file__).resolve().parent / "assets"
SEV_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]
SEV_CLASS = {"Crítico": "crit", "Alto": "alto", "Medio": "medio", "Bajo": "bajo"}
EVIDENCE_MAX = 40
FOOTER = "Confidencial · Uso exclusivo del cliente · Generado automáticamente a partir de los logs del SIEM"


def e(v) -> str:
    """Único punto de escape de datos hacia HTML."""
    return html.escape(str(v if v is not None else ""), quote=True)


def _sev(s: str) -> str:
    return SEV_CLASS.get(s, "bajo")


def pill(sev: str) -> str:
    return f'<span class="pill {_sev(sev)}">{e(sev)}</span>'


def paras(text: str) -> str:
    parts = [x.strip() for x in re.split(r"\n\s*\n", str(text or "")) if x.strip()]
    return "".join(f"<p>{e(x)}</p>" for x in parts)


def ul(items) -> str:
    items = [i for i in (items or []) if str(i).strip()]
    return "<ul class=\"l\">" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items else "<p class=\"note\">—</p>"


def _cls(i: int, mono: set[int], nowrap: set[int] | None) -> str:
    c = [x for x, on in (("mono", i in mono), ("nw", i in (nowrap or set()))) if on]
    return f' class="{" ".join(c)}"' if c else ""


def table(head: list[str], rows: list[list[str]], mono: set[int] | None = None, body_id: str = "", scroll: bool = False, row_attrs: list[str] | None = None,
          nowrap: set[int] | None = None) -> str:
    """`rows` ya trae el HTML de cada celda (escapado por quien lo arma)."""
    mono = mono or set()
    th = "".join(f"<th scope=\"col\">{e(h)}</th>" for h in head)
    trs = []
    for n, r in enumerate(rows):
        tds = "".join(f"<td{_cls(i, mono, nowrap)}>{c}</td>" for i, c in enumerate(r))
        trs.append(f"<tr{(' ' + row_attrs[n]) if row_attrs else ''}>{tds}</tr>")
    bid = f' id="{body_id}"' if body_id else ""
    return f'<div class="tablewrap{" scroll" if scroll else ""}"><table><thead><tr>{th}</tr></thead><tbody{bid}>{"".join(trs)}</tbody></table></div>'


# ------------------------------------------------------------------------------------------------ gráficos
def donut(stats: dict) -> str:
    sev = stats["findings_by_severity"]
    total = sum(sev.values())
    r, circ = 54.0, 2 * 3.141592653589793 * 54.0
    segs, cum = [], 0.0
    for s in SEV_ORDER:
        n = sev.get(s, 0)
        if not n or not total:
            continue
        ln = circ * n / total
        segs.append(f'<circle class="seg f-{_sev(s)}" cx="80" cy="80" r="{r:g}" data-c="{circ:.2f}" data-dash="{ln:.2f} {circ - ln:.2f}" '
                    f'stroke-dasharray="{ln:.2f} {circ - ln:.2f}" stroke-dashoffset="{-cum:.2f}"><title>{e(s)}: {n}</title></circle>')
        cum += ln
    label = ", ".join(f"{sev.get(s, 0)} {s.lower()}" for s in SEV_ORDER)
    svg = (f'<svg viewBox="0 0 160 160" width="180" height="180" role="img" aria-label="Hallazgos por criticidad: {e(label)}">'
           f'<circle class="track" cx="80" cy="80" r="{r:g}"/><g transform="rotate(-90 80 80)">{"".join(segs)}</g>'
           f'<text class="tx-c" x="80" y="82" text-anchor="middle" font-size="26">{total}</text>'
           f'<text x="80" y="100" text-anchor="middle">hallazgos</text></svg>')
    legend = "".join(f'<li><span class="sw {_sev(s)}"></span>{e(s)}: <b>{sev.get(s, 0)}</b></li>' for s in SEV_ORDER)
    return (f'<div class="chart"><h3>Hallazgos por criticidad</h3>{svg}<ul class="legend">{legend}</ul></div>')


def timeline_chart(stats: dict) -> str:
    tl = stats["timeline"]
    if not tl:
        return ""
    W, Hh, left, bottom, top = 620, 190, 34, 28, 10
    plot_h = Hh - bottom - top
    mx = max([b["total"] for b in tl] + [1])
    bw = (W - left - 8) / len(tl)
    step = max(1, -(-len(tl) // 8))
    base = top + plot_h
    out = [f'<svg viewBox="0 0 {W} {Hh}" role="img" aria-label="Eventos por ventana de 10 minutos, separados por criticidad">']
    for frac in (0, .5, 1):
        y = base - plot_h * frac
        out.append(f'<line class="axis" x1="{left}" x2="{W - 4}" y1="{y:.1f}" y2="{y:.1f}"/><text x="{left - 5}" y="{y + 4:.1f}" text-anchor="end">{round(mx * frac)}</text>')
    for i, b in enumerate(tl):
        x = left + i * bw + bw * 0.12
        w = max(bw * 0.76, 1.5)
        y_cur = base
        for key, cls in (("normal", "norm"), ("Bajo", "bajo"), ("Medio", "medio"), ("Alto", "alto"), ("Crítico", "crit")):
            n = b.get(key, 0)
            if not n:
                continue
            h = plot_h * n / mx
            y_cur -= h
            out.append(f'<rect class="bar f-{cls}" x="{x:.1f}" y="{y_cur:.1f}" width="{w:.1f}" height="{h:.1f}" data-base="{y_cur + h:.1f}">'
                       f'<title>{e(b["t"])} · {e("eventos normales" if key == "normal" else key)}: {n}</title></rect>')
        if i % step == 0:
            out.append(f'<text x="{x + w / 2:.1f}" y="{Hh - 10}" text-anchor="middle">{e(b["t"])}</text>')
    out.append("</svg>")
    legend = '<ul class="legend"><li><span class="sw norm"></span>Eventos sin marcar</li>' + "".join(
        f'<li><span class="sw {_sev(s)}"></span>{e(s)}</li>' for s in SEV_ORDER) + "</ul>"
    return f'<div class="chart" id="timeline"><h3>Eventos por ventana de 10 minutos</h3>{"".join(out)}{legend}</div>'


# ------------------------------------------------------------------------------------------------ bloques
def evidence_html(df: pd.DataFrame, ids: list[str]) -> str:
    rows = rows_for(df, ids)
    shown = rows[:EVIDENCE_MAX]
    body = []
    for r in shown:
        txt = r["Process_CommandLine"] or r["Event_Description"]
        body.append([e(r["Log_ID"]), e(r["Timestamp"][11:]), e(r["Hostname"]), e(D.short_user(r["User"]) or "-"), e(r["Source_IP"] or "-"),
                     e(f"{r['Event_ID']} · {D.trunc(txt, 220)}"), e(r["Severity"])])
    out = table(["Log_ID", "Hora", "Host", "Usuario", "IP origen", "Evento / comando", "SIEM"], body, mono={0, 4, 5}, scroll=True)
    if len(rows) > len(shown):
        out += f'<p class="note">Se muestran {len(shown)} de {len(rows)} eventos. IDs completos: {e(", ".join(r["Log_ID"] for r in rows))}</p>'
    return out


def triage_html(t: dict | None) -> str:
    if not t or (t["source"] != "ia" and not t.get("decision")):
        return ""
    out = []
    if t["source"] == "ia":
        out.append(f'<div class="box"><b>Triaje asistido por IA:</b> {e(t["recommendation"])} (confianza {e(t["confidence"])}).'
                   f' {e(" ".join(t["reasons"][:3]))} <i>Cambiaría de opinión si:</i> {e(t["would_change_if"])}</div>')
    if t.get("conflicto") and t.get("ia_sugirio"):
        out.append(f'<div class="box warn"><b>Conflicto:</b> la IA sugirió «{e(t["ia_sugirio"]["recommendation"])}», pero se mantiene la recomendación del motor '
                   'porque la severidad es alta; la decisión es del analista.</div>')
    d = t.get("decision")
    if d:
        out.append(f'<div class="box"><b>Decisión del analista:</b> {e(d["decision"])}' + (f' — {e(d["note"])}' if d.get("note") else "")
                   + f' <span class="note">· {e(d["at"])}</span></div>')
    return "".join(out)


def finding_html(f: dict, fa: dict, df: pd.DataFrame, ai_mode: bool, opened: bool = False) -> str:
    mitre = f" · MITRE ATT&amp;CK (orientativo): {e(', '.join(attack.label(t) for t in f['mitre']))}" if f["mitre"] else ""
    ap = fa["action_plan"]
    plan = "".join(f"<div><h5>{t}</h5>{ul(ap.get(k, []))}</div>" for t, k in (("Investigar", "investigate"), ("Contener", "contain"), ("Remediar", "remediate")))
    note = ('<p class="note">Nota: el texto de este hallazgo proviene de las reglas del motor (la IA no devolvió un análisis verificable para él).</p>'
            if ai_mode and fa.get("source") == "determinista" else "")
    return (f'<details class="fnd"{" open" if opened else ""}><summary>{pill(f["severity"])}<span class="idtag">{e(f["id"])}</span> {e(f["title"])}</summary><div class="dbody">'
            f'<p class="note">{e(f["category"])} · {e(f["tactic"])}{mitre} · {e(f["time_start"][11:])}–{e(f["time_end"][11:])} · {e(D.pl(len(f["evidence_ids"]), "evento", "eventos"))}</p>'
            f'<h4>Criticidad y justificación</h4>{paras(fa["severity_justification"] or " ".join(f["reasons"]))}'
            f'<h4>Explicación técnica</h4>{paras(fa["technical_explanation"])}'
            f'<h4>Evidencias en los logs</h4>{evidence_html(df, f["evidence_ids"])}'
            f'<h4>Posible impacto en la organización</h4>{paras(fa["impact"])}'
            f'<h4>Plan de acción</h4><div class="plan">{plan}</div>{note}</div></details>')


def _ev_short(ids: list[str]) -> str:
    return ", ".join(ids[:4]) + (f" … (+{len(ids) - 4})" if len(ids) > 4 else "")


def incident_html(inc: dict, g: dict, by_id: dict, ai: dict, df: pd.DataFrame, ai_mode: bool, tri: dict | None, first: bool) -> str:
    meta = [f"<b>Ventana:</b> {e(inc['time_start'])} a {e(inc['time_end'][11:])}", f"<b>Hosts:</b> {e(', '.join(inc['hosts']))}"]
    if inc["external_ips"]:
        meta.append(f"<b>IP externas:</b> {e(', '.join(inc['external_ips']))}")
    if inc["actor_users"]:
        meta.append(f"<b>Cuentas:</b> {e(', '.join(D.short_user(u) for u in inc['actor_users']))}")
    kc = ""
    steps = g.get("kill_chain", [])
    if steps:
        li = "".join(f'<li><span class="t">{e(s["time"])}</span> {e(s["step"])}<br><span class="mono note">{e(_ev_short(s["evidence_ids"]))}</span></li>' for s in steps)
        kc = f"<h4>Cronología</h4><ol class=\"kc\">{li}</ol>"
    conf = (f'<p class="note"><b>Confianza de la agrupación:</b> {e(g["confidence"])}. {e(g.get("confidence_reason", ""))}</p>' if g.get("confidence") else "")
    fnds = "".join(finding_html(by_id[fid], ai["findings"][fid], df, ai_mode) for fid in inc["finding_ids"])
    rel = "".join(f'<p class="note">Observación relacionada: {e(oid)} — {e(by_id[oid]["title"])} (ver sección 5).</p>' for oid in inc.get("observation_ids", []))
    return (f'<details class="inc reveal" id="{e(inc["id"])}"{" open" if first else ""}><summary>{pill(inc["severity"])}<span class="idtag">{e(inc["id"])}</span> '
            f'{e(g.get("title") or inc["title"])}</summary><div class="dbody"><p class="note">{" · ".join(meta)}</p>{paras(g.get("narrative", ""))}'
            f'{triage_html(tri)}{conf}{kc}<h4>Hallazgos</h4>{fnds}{rel}</div></details>')


def _vt_text(vt) -> str:
    if not vt:
        return "No consultado"
    st = vt.get("status")
    if st == "not_found":
        return "Sin información"
    if st != "ok":
        return "No disponible"
    txt = f"{vt['malicious']} de {vt['total']} motores lo marcan malicioso" if vt["total"] else "Sin análisis"
    return txt + (f"; {vt['suspicious']} sospechoso" if vt.get("suspicious") else "")


def _abuse_text(ab) -> str:
    if not ab:
        return "No consultado"
    if ab.get("status") != "ok":
        return "No disponible"
    return f"Puntaje {ab['score']} %, {ab['reports']} reportes en {ab['window_days']} días" + ("; nodo Tor" if ab.get("tor") else "")


def intel_html(intel: dict) -> str:
    provs = " y ".join({"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB"}.get(p, str(p)) for p in intel.get("providers", []))
    rows = []
    for r in intel.get("results", []):
        vt, ab = r.get("vt") or {}, r.get("abuse") or {}
        who = " / ".join(x for x in [ab.get("country") or vt.get("country"), ab.get("isp") or vt.get("owner") or vt.get("registrar")] if x)
        label = e(D.trunc(r["indicator"], 60)) + ("<br><i>IP de documentación (consulta de prueba)</i>" if r.get("reserved") else "")
        rows.append([label, e(r.get("verdict", "")), e(_vt_text(r.get("vt"))), e(_abuse_text(r.get("abuse"))), e(D.trunc(who, 80))])
    notes = "".join(f'<p class="note">Aviso: {e(n)}</p>' for n in intel.get("notices", []))
    return (f'<h3>Reputación de indicadores externos</h3><p>Consulta realizada el {e(intel.get("queried_at") or "dato no disponible")} con {e(provs)}. '
            'Es información de contexto: no modifica la criticidad de los hallazgos, que la fija el motor de reglas. Una IP sin reportes no prueba que sea legítima.</p>'
            + table(["Indicador", "Resumen", "VirusTotal", "AbuseIPDB", "País / propietario"], rows, mono={0}) + notes)


def ioc_html(analysis: dict, intel: dict | None) -> str:
    rows, attrs = [], []
    for i in analysis["iocs"]:
        ctx = "; ".join(i["notes"][:2]) + (f" ({D.pl(i['events'], 'evento', 'eventos')} en el export)" if i.get("events") is not None else "")
        rows.append([e(i["type"]), e(D.trunc(i["value"], 120)), pill(i["severity"]), e(i["first_seen"][11:]), e(ctx), e(", ".join(i["finding_ids"][:4]))])
        attrs.append(f'data-s="{e(i["severity"])}" data-t="{e((i["type"] + " " + i["value"] + " " + ctx).lower())}"')
    opts = "".join(f'<option value="{e(s)}">{e(s)}</option>' for s in SEV_ORDER)
    intro = ("Indicadores extraídos de las evidencias. El export no contiene hashes de archivos ni reputación de IP; "
             + ("la reputación de los indicadores externos se consultó aparte (ver más abajo)." if intel else "esos datos deben obtenerse en el endpoint o con inteligencia de amenazas."))
    out = (f'<p>{intro}</p><div class="filters noprint"><input id="ioc-q" type="search" placeholder="Filtrar por valor, tipo o contexto" aria-label="Filtrar indicadores">'
           f'<select id="ioc-sev" aria-label="Filtrar por criticidad"><option value="">Todas las criticidades</option>{opts}</select>'
           f'<span class="note" id="ioc-count" aria-live="polite">{len(rows)} de {len(rows)} indicadores</span></div>'
           + table(["Tipo", "Valor", "Crit.", "Primera vez", "Contexto", "Hallazgos"], rows, mono={1}, body_id="ioc-body", row_attrs=attrs))
    if intel and intel.get("results"):
        out += intel_html(intel)
    return out


# ------------------------------------------------------------------------------------------------ correos sospechosos
def _tbl_pairs(pairs: list[tuple[str, str]]) -> str:
    return '<div class="tablewrap"><table><tbody>' + "".join(f"<tr><th scope=\"row\">{e(k)}</th><td class=\"mono\">{e(v)}</td></tr>" for k, v in pairs) + "</tbody></table></div>"


def _delay_txt(sec) -> str:
    if sec is None:
        return "—"
    a = abs(int(sec))
    t = f"{a // 3600} h {a % 3600 // 60} min" if a >= 3600 else f"{a // 60} min {a % 60} s" if a >= 60 else f"{a} s"
    return ("-" if sec < 0 else "+") + t


def phishing_html(items: list[dict], number: str = "9", intel: dict | None = None) -> str:
    rows = [[f"<b>{e(i['id'])}</b>", pill(i["severity"]), e(_u(D.trunc(i["headers"]["subject"] or "(sin asunto)", 90))),
             e(_u(D.trunc(i["headers"]["from_addr"] or i["headers"]["from"], 60))), e(i["verdict"])] for i in items]
    out = [f'<section class="sec glass reveal" id="sec-{number}"><h2>{number}. Análisis de correos sospechosos</h2>'
           '<p>Análisis estático de los archivos .eml: no se abrieron enlaces ni se ejecutaron adjuntos. Las URL se muestran «defangeadas» (hxxp, [.]) para que no sean enlaces activos. '
           'La criticidad la fijan reglas con pesos fijos y es una ayuda para el triage, no una prueba.</p>',
           table(["ID", "Criticidad", "Asunto", "Remitente", "Veredicto"], rows)]
    for i in items:
        h, a = i["headers"], i["auth"]
        facts = [("De", _u(h["from"])), ("Reply-To", _u(h["reply_to"]) or "—"), ("Return-Path", _u(h["return_path"]) or "—"), ("Para", _u(h["to"]) or "—"), ("Fecha", h["date"] or "—"),
                 ("SPF / DKIM / DMARC", f"{a.get('spf') or 'sin dato'} / {a.get('dkim') or 'sin dato'} / {a.get('dmarc') or 'sin dato'}"),
                 ("Origen probable (IP)", i["origin_ip"] or "no determinado")]
        b = [f'<p class="note">Veredicto: {e(i["verdict"])} · puntaje {e(i["score"])} · ' + (f'origen {e(i["source"])}' if i.get("source") else f'archivo {e(_u(i["filename"]))}') + "</p>"]
        if i.get("headers_only"):
            b.append('<p class="note">Solo se analizaron las cabeceras: sin el cuerpo no se evaluaron enlaces ni adjuntos.</p>')
        b.append(_tbl_pairs([(k, D.trunc(v, 200)) for k, v in facts]))
        if i["signals"]:
            b.append("<h4>Señales detectadas</h4>" + table(["Cat.", "Crit.", "Señal", "Detalle"], [[e(x["category"]), pill(x["severity"]), e(_u(D.trunc(x["title"], 110))), e(_u(D.trunc(x["detail"], 300)))] for x in i["signals"]]))
        hops = i.get("hops") or []
        if hops:
            lab = {"hora_anterior": "hora anterior", "retraso_largo": "retraso largo", "sin_fecha": "sin fecha"}
            b.append("<h4>Recorrido del correo (horas en UTC)</h4>" + table(["#", "Desde → hacia", "IP", "Hora (UTC)", "Retraso", "Aviso"], [
                [e(x["n"]), e(_u(D.trunc(f"{x['from'] or '?'} → {x['by'] or '?'}", 90))), e(x["ip"] or "—"), e(x["ts"] or "—"), e(_delay_txt(x["delay_s"])),
                 e(", ".join(lab.get(f, f) for f in x["flags"]) or "—")] for x in hops[:30]], mono={2, 3}))
        r = i.get("dns_review")
        if r:
            st = {"ok": "OK", "warn": "Revisar", "fail": "Diferencia", "info": "Info"}
            b.append(f"<h4>Verificación en DNS de {e(r['domain'])} (el {e(r['checked_at'])})</h4><p class=\"note\">Nota del dominio {e(r['grade'])} ({e(r['score'])}/100).</p>"
                     + table(["Resultado", "Comprobación", "Detalle"], [[e(st.get(c["status"], c["status"])), e(_u(D.trunc(c["title"], 90))), e(_u(D.trunc(c["detail"], 380)))] for c in r["checks"]])
                     + f'<p class="note">{e(" ".join(r["limitations"]))}</p>')
        bd = i.get("score_breakdown")
        if bd and bd["categories"]:
            rr = []
            for c in bd["categories"]:
                for k, x in enumerate(c["signals"]):
                    cat = c["category"] + (f" (tope {c['cap']}" + (f", {c['raw']}→{c['applied']})" if c["capped"] else ")") if k == 0 else "")
                    rr.append([e(cat), e(_u(D.trunc(x["title"], 100))), pill(x["severity"]), e(f"+{x['points']}"), e(x["applied"])])
            b.append(f"<h4>Cómo se calculó el puntaje: {e(bd['total'])} puntos → {e(bd['severity'])}</h4><p>{e(bd['why'])}</p>"
                     + table(["Categoría", "Señal", "Crit.", "Puntos", "Contó"], rr)
                     + f'<p class="note">Criticidad: {e(" · ".join(t["severity"] + ": " + t["rule"] for t in bd["thresholds"]))}.</p>')
        g = i.get("homograph") or {}
        if g.get("entries"):
            hb = ["<h4>Verificación de caracteres (homógrafos)</h4><p class=\"note\">Cada carácter con su código Unicode: una «I» mayúscula y una «l» minúscula, o la «a» latina (U+0061) y la «a» cirílica (U+0430), se ven iguales pero no lo son.</p>"]
            for en in g["entries"]:
                hb.append(f'<p><b>{e(en["label"])}:</b> <span class="mono">{e(_u(en["value"]))}</span>' + (" (sospechoso)" if en["suspicious"] else "") + "</p>")
                hb.append(f'<p class="note">Letra por letra: <span class="mono">{e(_u(en["spelled"]))}</span></p>')
                flagged = [c for c in en["chars"] if c["flag"]]
                if flagged:
                    hb.append(table(["Pos.", "Código", "Nombre", "Alfabeto", "Parece"], [[e(c["pos"]), e(c["code"]), e(c["name"]), e(c["script"]), e(c["looks_like"] or "—")] for c in flagged[:8]], mono={1}))
            b.append("".join(hb))
        if i["favorable"]:
            b.append(f'<p class="note">A favor: {e(_u(", ".join(i["favorable"])))}</p>')
        if i["urls"]:
            b.append("<h4>Enlaces</h4>" + table(["URL (defangeada)", "Señales"], [
                [e(_u(D.trunc(u["defanged"], 140))) + (f"<br><i>Interpretada como: {e(_u(D.trunc(u['normalized'], 110)))}</i>" if u.get("normalized") else ""), e(", ".join(u["flags"]) or "—")] for u in i["urls"][:15]], mono={0}))
        if i["attachments"]:
            b.append("<h4>Adjuntos</h4>" + table(["Archivo", "Tamaño", "SHA-256", "Notas"], [
                [e(_u(D.trunc(x["filename"], 60))), e(f"{x['size']:,} B".replace(",", ".")), e(x["sha256"]), e(_u("; ".join(x["notes"]) or "—"))] for x in i["attachments"]], mono={2}))
        b.append("<h4>Qué verificar</h4>" + ul(i["verify"]) + "<h4>Acciones sugeridas</h4>" + ul(i["actions"]))
        if i["mitre"]:
            b.append(f'<p class="note">MITRE ATT&amp;CK (orientativo): {e(", ".join(f"{t} {attack.technique_name(t)}" for t in i["mitre"]))}</p>')
        out.append(f'<details class="inc"><summary>{pill(i["severity"])}<span class="idtag">{e(i["id"])}</span> {e(_u(D.trunc(h["subject"] or i["filename"], 100)))}</summary><div class="dbody">{"".join(b)}</div></details>')
    if intel and intel.get("results"):
        out.append(intel_html(intel))
    out.append("</section>")
    return "".join(out)


# ------------------------------------------------------------------------------------------------ documento
def _asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def build_html(analysis: dict, ai: dict, df: pd.DataFrame, meta: dict, intel: dict | None = None, phishing: list[dict] | None = None,
               triage: dict | None = None) -> bytes:
    client = meta.get("client") or "Cliente"
    analyst = meta.get("analyst") or "Analista SOC"
    filename = meta.get("filename") or "export_siem.xlsx"
    p, st = analysis["profile"], analysis["stats"]
    incidents, findings = analysis["incidents"], analysis["findings"]
    by_id = {f["id"]: f for f in findings}
    ai_mode = ai.get("mode") == "ia"
    sev = st["findings_by_severity"]
    tri_by = {t["incident_id"]: t for t in (triage or {}).get("items", [])}
    today = datetime.now().strftime("%d/%m/%Y")

    kpis = "".join(f'<div class="kpi {c}"><div class="n">{e(v)}</div><div class="l">{e(k)}</div></div>' for k, v, c in (
        ("Eventos", D.fmt_int(p["rows"]), ""), ("Incidentes", len(incidents), ""), ("Hallazgos", st["findings_total"], ""),
        ("Críticos", sev["Crítico"], "crit"), ("Altos", sev["Alto"], "alto"), ("IoC", len(analysis["iocs"]), "")))
    how = (f"La explicación técnica y el plan de acción fueron redactados con asistencia de IA ({e(ai.get('model'))}) y verificados contra el archivo de logs: se descartan las citas o direcciones que no existan en los datos."
           if ai_mode else "La redacción corresponde al modo determinista (sin IA).")
    hero = (f'<header class="hero glass reveal"><div class="k">Investigación de incidentes de seguridad</div><h1>Informe técnico de análisis de logs del SIEM</h1>'
            f'<div class="meta"><span><b>Cliente:</b> {e(client)}</span><span><b>Analista:</b> {e(analyst)}</span><span><b>Fecha del informe:</b> {today}</span>'
            f'<span><b>Fuente:</b> {e(filename)} · {e(D.fmt_int(p["rows"]))} eventos · {e(p["time_start"])} a {e(p["time_end"])}</span></div>'
            f'<div class="kpis">{kpis}</div><p class="note">Este informe fue generado por SOC Incident Analyzer. Los hallazgos y su criticidad se determinan con reglas aplicadas directamente sobre los registros '
            f'y cada conclusión cita los Log_ID que la sustentan. {how}</p></header>')

    inc_rows = [[f"<b>{e(i['id'])}</b>", pill(i["severity"]), f'<a href="#{e(i["id"])}">{e(ai["incidents"].get(i["id"], {}).get("title") or i["title"])}</a>',
                 e(f"{i['time_start'][11:16]}–{i['time_end'][11:16]}"), e(", ".join(i["hosts"])), e(len(i["finding_ids"]))] for i in incidents]
    s1 = (f'<section class="sec glass reveal" id="sec-1"><h2>1. Resumen ejecutivo</h2>{paras(ai["executive_summary"])}'
          + table(["ID", "Criticidad", "Incidente", "Ventana", "Hosts", "Hall."], inc_rows, nowrap={0, 3})
          + f'<div class="grid2">{donut(st)}{timeline_chart(st)}</div></section>')

    fired = [r for r in analysis["rules"] if r["hits"]]
    host_txt = D.pl(p["hosts"], "host", "hosts") if p["hosts"] else "sin dato de host"
    s2 = ('<section class="sec glass reveal" id="sec-2"><h2>2. Alcance y metodología</h2>'
          f'<p>Se analizó el export del SIEM «{e(filename)}» ({e(D.fmt_int(p["rows"]))} eventos, {e(host_txt)}, {e(D.pl(p["users"], "cuenta", "cuentas"))}, '
          f'{e(p["time_start"])} a {e(p["time_end"])}, {e(p["duration"])}). El análisis combina tres pasos:</p>'
          + ul(["Detección determinista: reglas explícitas sobre los campos del archivo (fuerza bruta, inicios de sesión sospechosos, escalamiento, comandos y procesos, movimiento lateral, exfiltración, persistencia, ataques web y anomalías de calidad de datos). Cada hallazgo conserva sus Log_ID.",
                "Correlación: los hallazgos se agrupan en incidentes si comparten un actor (IP externa o cuenta). Compartir solo un host o un recurso NO fusiona incidentes; esos casos se reportan como hipótesis de baja confianza.",
                ("Redacción asistida por IA: explicación técnica, impacto y plan de acción redactados a partir de la evidencia; la criticidad la fija el motor y un validador descarta Log_ID o IP inexistentes."
                 if ai_mode else "Redacción determinista a partir de plantillas y de los datos de cada hallazgo.")])
          + f'<p class="note">Se evaluaron {len(analysis["rules"])} reglas; en este archivo generaron hallazgos {len(fired)}. Solo se listan esas.</p>'
          + table(["Regla", "Descripción", "Hallazgos"], [[f"<b>{e(r['key'])}</b>", e(r["description"]), e(r["hits"])] for r in fired], mono={0}) + "</section>")

    hyp = ""
    if analysis["hypotheses"]:
        hyp = table(["ID", "Hipótesis (no confirmada)", "Confianza"], [[e(h["id"]), e(h["statement"] + " " + h["basis"]), e(h["confidence"])] for h in analysis["hypotheses"]])
    s3 = f'<section class="sec glass reveal" id="sec-3"><h2>3. Relación entre incidentes</h2>{paras(ai["cross_incident_assessment"])}{hyp}</section>'

    incs = "".join(incident_html(inc, ai["incidents"].get(inc["id"], {}), by_id, ai, df, ai_mode, tri_by.get(inc["id"]), n == 0) for n, inc in enumerate(incidents))
    s4 = ('<section class="sec glass" id="sec-4"><h2>4. Incidentes y hallazgos</h2><div class="filters noprint"><button class="btn" id="expand" type="button">Expandir todo</button>'
          f'<button class="btn" id="collapse" type="button">Contraer todo</button></div>{incs}</section>')

    obs = [f for f in findings if f["incident_id"] is None]
    s5 = ""
    if obs:
        s5 = ('<section class="sec glass reveal" id="sec-5"><h2>5. Observaciones generales (SIEM y calidad de datos)</h2>'
              "<p>Hallazgos que no forman parte de una cadena de ataque concreta pero afectan la capacidad de detección o la fiabilidad de los datos.</p>"
              + "".join(finding_html(f, ai["findings"][f["id"]], df, ai_mode) for f in obs) + "</section>")

    s6 = f'<section class="sec glass reveal" id="sec-6"><h2>6. Indicadores de compromiso (IoC)</h2>{ioc_html(analysis, intel)}</section>'

    order = {"Inmediata": 0, "Corto plazo": 1, "Mediano plazo": 2}
    acts = [[f"<b>{e(a['priority'])}</b>", e(a["action"]), e(", ".join(a["incident_ids"]))] for a in sorted(ai["prioritized_actions"], key=lambda a: order.get(a["priority"], 9))]
    s7 = f'<section class="sec glass reveal" id="sec-7"><h2>7. Plan de acción priorizado</h2>{table(["Prioridad", "Acción", "Incidentes"], acts)}</section>'
    s8 = f'<section class="sec glass reveal" id="sec-8"><h2>8. Recomendaciones generales de seguridad</h2>{ul(ai["general_recommendations"])}</section>'
    s9 = phishing_html(phishing, "9") if phishing else ""

    links = [("sec-1", "Resumen"), ("sec-2", "Metodología"), ("sec-3", "Relación"), ("sec-4", "Incidentes")] + ([("sec-5", "Observaciones")] if obs else []) + [
        ("sec-6", "IoC"), ("sec-7", "Plan"), ("sec-8", "Recomendaciones")] + ([("sec-9", "Correos")] if phishing else [])
    nav = ('<nav class="bar noprint" aria-label="Secciones"><div class="glass">' + "".join(f'<a href="#{i}">{l}</a>' for i, l in links)
           + '<span class="sp"></span><button class="btn" id="theme" type="button" aria-label="Cambiar entre tema claro y oscuro">Tema</button>'
           '<button class="btn" id="print" type="button">Imprimir / PDF</button></div></nav>')

    return _wrap(f"Informe técnico de investigación de incidente — {client}", nav, f"{hero}{s1}{s2}{s3}{s4}{s5}{s6}{s7}{s8}{s9}", FOOTER)


def _wrap(title: str, nav: str, main_html: str, footer: str) -> bytes:
    """Documento completo: CSS y JS (con anime.js) dentro del archivo y una CSP propia por hash, sin red."""
    css = _asset("report.css")
    script = _asset("anime.min.js").replace("</script", "<\\/script") + "\n" + _asset("report.js")
    h_css = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode()
    h_js = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
    csp = (f"default-src 'none'; style-src 'sha256-{h_css}'; script-src 'sha256-{h_js}'; img-src data:; base-uri 'none'; form-action 'none'")
    doc = (f'<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta http-equiv="Content-Security-Policy" content="{csp}"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex">'
           f'<meta name="generator" content="SOC Incident Analyzer"><title>{e(title)}</title>'
           f'<style>{css}</style></head><body><div class="blob b1"></div><div class="blob b2"></div><div class="wrap">{nav}<main>{main_html}</main>'
           f'<footer>{e(footer)}</footer></div><script>{script}</script></body></html>')
    return doc.encode("utf-8")


PHISHING_FOOTER = "Confidencial · Uso exclusivo del cliente · Análisis estático generado automáticamente a partir de archivos .eml"


def build_phishing_html(items: list[dict], meta: dict, intel: dict | None = None) -> bytes:
    """Informe HTML del análisis de correos sospechosos (mismo contenido que el PDF de phishing), en un único archivo sin conexión."""
    client = meta.get("client") or "Cliente"
    analyst = meta.get("analyst") or "Analista SOC"
    today = datetime.now().strftime("%d/%m/%Y")
    sev = {k: sum(1 for i in items if i["severity"] == k) for k in SEV_ORDER}
    kpis = "".join(f'<div class="kpi {c}"><div class="n">{e(v)}</div><div class="l">{e(k)}</div></div>' for k, v, c in (
        ("Correos", len(items), ""), ("Críticos", sev["Crítico"], "crit"), ("Altos", sev["Alto"], "alto"), ("Medios", sev["Medio"], "medio"), ("Bajos", sev["Bajo"], "bajo")))
    hero = (f'<header class="hero glass reveal"><div class="k">Análisis de correos sospechosos</div><h1>Informe de análisis de phishing</h1>'
            f'<div class="meta"><span><b>Cliente:</b> {e(client)}</span><span><b>Analista:</b> {e(analyst)}</span><span><b>Fecha del informe:</b> {today}</span>'
            f'<span><b>Correos analizados:</b> {e(len(items))}</span></div><div class="kpis">{kpis}</div>'
            '<p class="note">Análisis estático de archivos .eml: no se abrieron enlaces ni se ejecutaron adjuntos. La criticidad la fijan reglas con pesos fijos y es una ayuda '
            'para el triage, no una prueba.</p></header>')
    nav = ('<nav class="bar noprint" aria-label="Secciones"><div class="glass"><a href="#sec-1">Correos</a>'
           '<span class="sp"></span><button class="btn" id="theme" type="button" aria-label="Cambiar entre tema claro y oscuro">Tema</button>'
           '<button class="btn" id="print" type="button">Imprimir / PDF</button></div></nav>')
    return _wrap(f"Informe de análisis de correos sospechosos — {client}", nav, hero + phishing_html(items, "1", intel), PHISHING_FOOTER)
