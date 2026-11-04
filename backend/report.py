"""Generación del informe técnico en PDF (reportlab)."""
from __future__ import annotations

import io
import re
from datetime import datetime
# `escape` only sanitises text for ReportLab markup; this module never parses XML (hence the bandit exemption).
from xml.sax.saxutils import escape  # nosec B406

import pandas as pd
from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

from . import attack
from . import detection as D
from .analysis import rows_for

NAVY = colors.HexColor("#0f172a")
NAVY2 = colors.HexColor("#1e293b")
ORANGE = colors.HexColor("#ff7a45")
GREY = colors.HexColor("#64748b")
LIGHT = colors.HexColor("#f1f5f9")
LINE = colors.HexColor("#cbd5e1")
SEV_COLOR = {"Crítico": colors.HexColor("#dc2626"), "Alto": colors.HexColor("#ea580c"),
             "Medio": colors.HexColor("#ca8a04"), "Bajo": colors.HexColor("#2f8f63")}
SEV_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]

W, H = A4
MARGIN = 18 * mm
CONTENT_W = W - 2 * MARGIN


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=colors.HexColor("#1e293b"), alignment=TA_LEFT)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5),
        "tiny": ParagraphStyle("tiny", parent=base, fontSize=7, leading=9, textColor=GREY),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.6, leading=9.6),
        "cellb": ParagraphStyle("cellb", parent=base, fontSize=7.6, leading=9.6, fontName="Helvetica-Bold"),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=NAVY, spaceBefore=4, spaceAfter=7),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10.2, leading=13, textColor=NAVY, spaceBefore=7, spaceAfter=2, keepWithNext=1),
        "label": ParagraphStyle("label", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=ORANGE, spaceBefore=6, spaceAfter=1, keepWithNext=1),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=10, bulletIndent=0, spaceAfter=1.5),
        "bullet_s": ParagraphStyle("bullet_s", parent=base, fontSize=8.3, leading=11, leftIndent=8, bulletIndent=0, spaceAfter=1.5),
        "cover_t": ParagraphStyle("cover_t", parent=base, fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=colors.white),
        "cover_k": ParagraphStyle("cover_k", parent=base, fontName="Helvetica-Bold", fontSize=9, textColor=ORANGE, leading=12),
        "cover_s": ParagraphStyle("cover_s", parent=base, fontSize=11, leading=15, textColor=colors.HexColor("#cbd5e1")),
    }


S = _styles()


def P(text: str, style: str = "base") -> Paragraph:
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), S[style])


def PR(markup: str, style: str = "base") -> Paragraph:
    """Paragraph con marcado propio (los datos dinámicos deben ir ya escapados)."""
    return Paragraph(markup, S[style])


def bullets(items: list[str], style: str = "bullet") -> list:
    return [Paragraph(escape(str(i)), S[style], bulletText="•") for i in items if str(i).strip()]


def sev_badge(sev: str, w: float = 17 * mm) -> Table:
    t = Table([[Paragraph(f'<font color="white"><b>{sev.upper()}</b></font>', ParagraphStyle("b", parent=S["base"], fontSize=7.2, leading=9, alignment=1))]],
              colWidths=[w], rowHeights=[5.2 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR[sev]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return t


def heading_badge(title: str, sev: str, style: str = "h2", pre: str = "") -> Table:
    t = Table([[sev_badge(sev), Paragraph((f"<font color='#ff7a45'>{escape(pre)}</font> " if pre else "") + escape(title), S[style])]],
              colWidths=[19 * mm, CONTENT_W - 19 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    t.keepWithNext = 1   # un título nunca queda solo al final de la página
    return t


def table(rows: list[list], widths: list[float], header: bool = True, zebra: bool = True, font: int = 0) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 3.5), ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
          ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
          ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE)]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    if zebra:
        st += [("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, LIGHT])]
    t.setStyle(TableStyle(st))
    return t


def hcell(text: str) -> Paragraph:
    return Paragraph(f'<font color="white"><b>{escape(text)}</b></font>', S["cell"])


# --------------------------------------------------------------------------
# gráficos
# --------------------------------------------------------------------------
def chart_severity(stats: dict) -> Drawing:
    d = Drawing(CONTENT_W * 0.46, 120)
    d.add(String(0, 108, "Hallazgos por criticidad", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    ch = HorizontalBarChart()
    ch.x, ch.y, ch.width, ch.height = 42, 6, CONTENT_W * 0.46 - 60, 90
    vals = [stats["findings_by_severity"][s] for s in reversed(SEV_ORDER)]
    ch.data = [vals]
    ch.categoryAxis.categoryNames = list(reversed(SEV_ORDER))
    ch.categoryAxis.labels.fontName = "Helvetica"
    ch.categoryAxis.labels.fontSize = 8
    ch.valueAxis.valueMin = 0
    ch.valueAxis.valueMax = max(vals + [1]) + 1
    ch.valueAxis.valueStep = 1 if max(vals + [1]) < 12 else 2
    ch.valueAxis.labels.fontSize = 7
    ch.bars.strokeColor = None
    ch.barWidth = 9
    for i, s in enumerate(reversed(SEV_ORDER)):
        ch.bars[(0, i)].fillColor = SEV_COLOR[s]
    ch.barLabelFormat = "%d"
    ch.barLabels.fontSize = 7.5
    ch.barLabels.nudge = 7
    d.add(ch)
    return d


def chart_timeline(stats: dict) -> Drawing:
    tl = stats["timeline"]
    width = CONTENT_W * 0.52
    d = Drawing(width, 120)
    d.add(String(0, 108, "Eventos por ventana de 10 min (actividad marcada vs resto)", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 22, 18, width - 28, 80
    flagged = [sum(b[s] for s in SEV_ORDER) for b in tl]
    normal = [b["normal"] for b in tl]
    ch.data = [normal, flagged]
    ch.categoryAxis.categoryNames = [b["t"] if i % 6 == 0 else "" for i, b in enumerate(tl)]
    ch.categoryAxis.labels.fontSize = 6.5
    ch.categoryAxis.labels.angle = 0
    ch.valueAxis.labels.fontSize = 6.5
    ch.valueAxis.valueMin = 0
    ch.bars[0].fillColor = colors.HexColor("#94a3b8")
    ch.bars[1].fillColor = SEV_COLOR["Crítico"]
    ch.bars.strokeColor = None
    ch.groupSpacing = 1
    ch.barSpacing = 0
    ch.categoryAxis.style = "stacked"
    ch.categoryAxis.visibleTicks = False
    d.add(ch)
    return d


# --------------------------------------------------------------------------
# bloques
# --------------------------------------------------------------------------
def evidence_table(df: pd.DataFrame, ids: list[str]) -> list:
    rows = rows_for(df, ids)
    fixed = [17 * mm, 13 * mm, 21 * mm, 17 * mm, 20 * mm]
    cw = fixed + [CONTENT_W - sum(fixed) - 20 * mm, 20 * mm]
    head = [hcell(h) for h in ("Log_ID", "Hora", "Host", "Usuario", "IP origen", "Evento / comando", "SIEM")]
    shown = rows if len(rows) <= 14 else rows[:9] + rows[-2:]
    data = [head]
    for r in shown:
        txt = r["Process_CommandLine"] or r["Event_Description"]
        txt = f"{r['Event_ID']} · {D.trunc(txt, 95)}"
        data.append([Paragraph(escape(r["Log_ID"]), S["cellb"]), Paragraph(escape(r["Timestamp"][11:]), S["cell"]),
                     Paragraph(escape(r["Hostname"]), S["cell"]), Paragraph(escape(D.short_user(r["User"]) or "-"), S["cell"]),
                     Paragraph(escape(r["Source_IP"] or "-"), S["cell"]), Paragraph(escape(txt), S["cell"]),
                     Paragraph(escape(r["Severity"]), S["cell"])])
    out = [table(data, cw)]
    if len(rows) > len(shown):
        out.append(P(f"Se muestran {len(shown)} de {len(rows)} eventos (primeros 9 y últimos 2). Rango completo: {rows[0]['Log_ID']} a {rows[-1]['Log_ID']}. "
                     "IDs completos: " + ", ".join(r["Log_ID"] for r in rows), "tiny"))
    return out


def finding_block(f: dict, fa: dict, df: pd.DataFrame, ai_mode: bool) -> list:
    items = [Spacer(1, 8), heading_badge(f"{f['title']}", f["severity"], "h3", pre=f["id"]),
             PR(f"<font color='#64748b'>{escape(f['category'])} · {escape(f['tactic'])}"
                + (f" · MITRE ATT&amp;CK (orientativo): {escape(', '.join(attack.label(t) for t in f['mitre']))}" if f["mitre"] else "")
                + f" · {escape(f['time_start'][11:])}–{escape(f['time_end'][11:])} · {D.pl(len(f['evidence_ids']), 'evento', 'eventos')}</font>", "small"),
             P("CRITICIDAD Y JUSTIFICACIÓN", "label"), P(fa["severity_justification"] or " ".join(f["reasons"])),
             P("EXPLICACIÓN TÉCNICA", "label"), P(fa["technical_explanation"]),
             P("EVIDENCIAS EN LOS LOGS", "label"), *evidence_table(df, f["evidence_ids"]),
             P("POSIBLE IMPACTO EN LA ORGANIZACIÓN", "label"), P(fa["impact"])]
    ap = fa["action_plan"]
    cols = []
    for title, key in (("Investigar", "investigate"), ("Contener", "contain"), ("Remediar", "remediate")):
        cell = [Paragraph(f"<b>{title}</b>", S["cellb"])] + (bullets(ap.get(key, []), "bullet_s") or [P("—", "small")])
        cols.append(cell)
    plan = Table([cols], colWidths=[CONTENT_W / 3] * 3)
    plan.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.4, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.25, LINE),
                              ("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
    items += [P("PLAN DE ACCIÓN", "label"), plan]
    if ai_mode and fa.get("source") == "determinista":
        items.append(P("Nota: el texto de este hallazgo proviene de las reglas del motor (la IA no devolvió un análisis verificable para él).", "tiny"))
    items.append(Spacer(1, 7))
    return items


def _vt_text(vt: dict | None) -> str:
    if not vt:
        return "No consultado"
    st = vt.get("status")
    if st == "not_found":
        return "Sin información"
    if st != "ok":
        return "No disponible"
    txt = f"{vt['malicious']} de {vt['total']} motores lo marcan malicioso" if vt["total"] else "Sin análisis"
    if vt.get("suspicious"):
        txt += f"; {vt['suspicious']} sospechoso"
    return txt


def _abuse_text(ab: dict | None) -> str:
    if not ab:
        return "No consultado"
    if ab.get("status") != "ok":
        return "No disponible"
    txt = f"Puntaje {ab['score']} %, {ab['reports']} reportes en {ab['window_days']} días"
    if ab.get("tor"):
        txt += "; nodo Tor"
    return txt


def intel_section(intel: dict) -> list:
    """Tabla de reputación de indicadores (VirusTotal / AbuseIPDB). Informativa: no altera ninguna criticidad."""
    out: list = [Spacer(1, 6), P("Reputación de indicadores externos", "h2"),
                 P(f"Consulta realizada el {intel.get('queried_at') or 'dato no disponible'} con "
                   f"{' y '.join({'virustotal': 'VirusTotal', 'abuseipdb': 'AbuseIPDB'}[p] for p in intel.get('providers', []))}. "
                   "Es información de contexto: no modifica la criticidad de los hallazgos, que la fija el motor de reglas. "
                   "Una IP sin reportes no prueba que sea legítima.")]
    rows = [[hcell("Indicador"), hcell("Resumen"), hcell("VirusTotal"), hcell("AbuseIPDB"), hcell("País / propietario")]]
    for r in intel.get("results", []):
        vt, ab = r.get("vt") or {}, r.get("abuse") or {}
        who = " / ".join(x for x in [ab.get("country") or vt.get("country"), ab.get("isp") or vt.get("owner") or vt.get("registrar")] if x)
        label = escape(D.trunc(r["indicator"], 40)) + ("<br/><i>IP de documentación (consulta de prueba)</i>" if r.get("reserved") else "")
        rows.append([Paragraph(label, S["cellb"]), Paragraph(escape(r.get("verdict", "")), S["cell"]),
                     Paragraph(escape(_vt_text(r.get("vt"))), S["cell"]), Paragraph(escape(_abuse_text(r.get("abuse"))), S["cell"]),
                     Paragraph(escape(D.trunc(who, 60)), S["cell"])])
    out.append(table(rows, [34 * mm, 20 * mm, 40 * mm, 40 * mm, CONTENT_W - 134 * mm]))
    for n in intel.get("notices", []):
        out.append(P(f"Aviso: {n}", "small"))
    return out


def _on_page(canvas, doc, meta):
    canvas.saveState()
    if doc.page > 1:
        canvas.setFillColor(NAVY)
        canvas.rect(0, H - 11 * mm, W, 11 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(MARGIN, H - 7 * mm, meta.get("header") or "INFORME TÉCNICO DE INVESTIGACIÓN DE INCIDENTE")
        canvas.setFillColor(ORANGE)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(W - MARGIN, H - 7 * mm, f"{meta['client']}")
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(MARGIN, 9 * mm, meta.get("footer") or "Confidencial · Uso exclusivo del cliente · Generado automáticamente a partir de los logs del SIEM")
    canvas.drawRightString(W - MARGIN, 9 * mm, f"Página {doc.page}")
    canvas.restoreState()


# --------------------------------------------------------------------------
# documento
# --------------------------------------------------------------------------
def phishing_section(items: list[dict], number: str = "", intel: dict | None = None) -> list:
    """Sección con el análisis de correos sospechosos. Enlaces siempre «defangeados»; nada de lo que viene del correo se interpreta como marcado."""
    pre = f"{number}. " if number else ""
    out: list = [P(f"{pre}Análisis de correos sospechosos", "h1"),
                 P("Análisis estático de los archivos .eml: no se abrieron enlaces ni se ejecutaron adjuntos. Las URL se muestran «defangeadas» "
                   "(hxxp, [.]) para que no sean enlaces activos. La criticidad la fijan reglas con pesos fijos y es una ayuda para el triage, no una prueba.")]
    rows = [[hcell("ID"), hcell("Criticidad"), hcell("Asunto"), hcell("Remitente"), hcell("Veredicto")]]
    for i in items:
        rows.append([Paragraph(f"<b>{i['id']}</b>", S["cell"]), Paragraph(i["severity"], S["cell"]), Paragraph(escape(D.trunc(i["headers"]["subject"] or "(sin asunto)", 70)), S["cell"]),
                     Paragraph(escape(D.trunc(i["headers"]["from_addr"] or i["headers"]["from"], 50)), S["cell"]), Paragraph(escape(i["verdict"]), S["cell"])])
    out += [Spacer(1, 4), table(rows, [16 * mm, 18 * mm, CONTENT_W - 16 * mm - 18 * mm - 45 * mm - 40 * mm, 45 * mm, 40 * mm])]
    for i in items:
        h, a = i["headers"], i["auth"]
        out.append(CondPageBreak(70 * mm))
        out.append(heading_badge(D.trunc(h["subject"] or i["filename"], 80), i["severity"], "h2", i["id"]))
        out.append(P(f"Veredicto: {i['verdict']} · puntaje {i['score']} · archivo {i['filename']}", "small"))
        facts = [("De", h["from"]), ("Reply-To", h["reply_to"] or "—"), ("Return-Path", h["return_path"] or "—"), ("Para", h["to"] or "—"), ("Fecha", h["date"] or "—"),
                 ("SPF / DKIM / DMARC", f"{a.get('spf') or 'sin dato'} / {a.get('dkim') or 'sin dato'} / {a.get('dmarc') or 'sin dato'}"),
                 ("Origen probable (IP)", i["origin_ip"] or "no determinado")]
        out += [Spacer(1, 3), table([[Paragraph(f"<b>{escape(k)}</b>", S["cell"]), Paragraph(escape(D.trunc(v, 160)), S["cell"])] for k, v in facts], [34 * mm, CONTENT_W - 34 * mm], header=False)]
        if i["signals"]:
            out.append(P("Señales detectadas", "label"))
            sr = [[hcell("Cat."), hcell("Crit."), hcell("Señal"), hcell("Detalle")]]
            for x in i["signals"]:
                sr.append([Paragraph(escape(x["category"]), S["cell"]), Paragraph(x["severity"], S["cell"]), Paragraph(escape(D.trunc(x["title"], 90)), S["cellb"]), Paragraph(escape(D.trunc(x["detail"], 220)), S["cell"])])
            out.append(table(sr, [24 * mm, 15 * mm, 55 * mm, CONTENT_W - 94 * mm]))
        if i["favorable"]:
            out.append(P("A favor: " + ", ".join(i["favorable"]), "small"))
        if i["urls"]:
            out.append(P("Enlaces", "label"))
            ur = [[hcell("URL (defangeada)"), hcell("Señales")]]
            for u in i["urls"][:15]:
                ur.append([Paragraph(escape(D.trunc(u["defanged"], 110)), S["cell"]), Paragraph(escape(", ".join(u["flags"]) or "—"), S["cell"])])
            out.append(table(ur, [CONTENT_W - 60 * mm, 60 * mm]))
        if i["attachments"]:
            out.append(P("Adjuntos", "label"))
            ar_ = [[hcell("Archivo"), hcell("Tamaño"), hcell("SHA-256"), hcell("Notas")]]
            for x in i["attachments"]:
                ar_.append([Paragraph(escape(D.trunc(x["filename"], 50)), S["cellb"]), Paragraph(f"{x['size']:,} B".replace(",", "."), S["cell"]),
                            Paragraph(escape(x["sha256"]), S["tiny"]), Paragraph(escape("; ".join(x["notes"]) or "—"), S["cell"])])
            out.append(table(ar_, [38 * mm, 18 * mm, CONTENT_W - 38 * mm - 18 * mm - 40 * mm, 40 * mm]))
        out.append(P("Qué verificar", "label"))
        out += bullets(i["verify"], "bullet_s")
        out.append(P("Acciones sugeridas", "label"))
        out += bullets(i["actions"], "bullet_s")
        if i["mitre"]:
            out.append(P("MITRE ATT&CK (orientativo): " + ", ".join(f"{t} {attack.technique_name(t)}" for t in i["mitre"]), "small"))
    if intel and intel.get("results"):
        out += intel_section(intel)
    return out


def build_phishing_pdf(items: list[dict], meta: dict, intel: dict | None = None) -> bytes:
    meta = {"client": meta.get("client") or "Cliente", "analyst": meta.get("analyst") or "Analista SOC", "header": "INFORME DE ANÁLISIS DE CORREOS SOSPECHOSOS",
            "footer": "Confidencial · Uso exclusivo del cliente · Análisis estático generado automáticamente a partir de archivos .eml"}
    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=18 * mm, bottomMargin=16 * mm,
                          title="Informe de análisis de correos sospechosos", author=meta["analyst"], subject="Análisis de phishing")
    frame = Frame(MARGIN, 16 * mm, CONTENT_W, H - 34 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=lambda c, d: _on_page(c, d, meta))])
    sev = {k: sum(1 for i in items if i["severity"] == k) for k in SEV_ORDER}
    cover = Table([[Paragraph("ANÁLISIS DE CORREOS SOSPECHOSOS", S["cover_k"])], [Spacer(1, 4 * mm)],
                   [Paragraph("Informe de análisis de phishing", S["cover_t"])], [Spacer(1, 5 * mm)],
                   [Paragraph(escape(f"Cliente: {meta['client']}"), S["cover_s"])], [Paragraph(escape(f"Analista: {meta['analyst']}"), S["cover_s"])],
                   [Paragraph(f"Fecha del informe: {datetime.now().strftime('%d/%m/%Y')}", S["cover_s"])],
                   [Paragraph(f"{len(items)} correo(s) analizado(s) · {sev['Crítico']} críticos · {sev['Alto']} altos · {sev['Medio']} medios", S["cover_s"])]], colWidths=[CONTENT_W])
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 10 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 10 * mm),
                               ("TOPPADDING", (0, 0), (0, 0), 14 * mm), ("BOTTOMPADDING", (0, -1), (-1, -1), 14 * mm), ("TOPPADDING", (0, 1), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -2), 1)]))
    story: list = [Spacer(1, 12 * mm), cover, PageBreak()] + phishing_section(items, "", intel)
    doc.build(story)
    return buf.getvalue()


def build_pdf(analysis: dict, ai: dict, df: pd.DataFrame, meta: dict, intel: dict | None = None, phishing: list[dict] | None = None) -> bytes:
    meta = {"client": meta.get("client") or "Cliente", "analyst": meta.get("analyst") or "Analista SOC",
            "filename": meta.get("filename") or "export_siem.xlsx"}
    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=18 * mm, bottomMargin=16 * mm,
                          title="Informe técnico de investigación de incidente", author=meta["analyst"],
                          subject="Investigación de incidentes de seguridad a partir de logs de SIEM")
    frame = Frame(MARGIN, 16 * mm, CONTENT_W, H - 34 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=lambda c, d: _on_page(c, d, meta))])

    p, st = analysis["profile"], analysis["stats"]
    incidents, findings = analysis["incidents"], analysis["findings"]
    by_id = {f["id"]: f for f in findings}
    ai_mode = ai.get("mode") == "ia"
    sev = st["findings_by_severity"]
    story: list = []

    # ---- portada ----------------------------------------------------------
    cover = Table([[Paragraph("INVESTIGACIÓN DE INCIDENTES DE SEGURIDAD", S["cover_k"])],
                   [Spacer(1, 4 * mm)],
                   [Paragraph("Informe técnico de análisis de logs del SIEM", S["cover_t"])],
                   [Spacer(1, 5 * mm)],
                   [Paragraph(escape(f"Cliente: {meta['client']}"), S["cover_s"])],
                   [Paragraph(escape(f"Analista: {meta['analyst']}"), S["cover_s"])],
                   [Paragraph(f"Fecha del informe: {datetime.now().strftime('%d/%m/%Y')}", S["cover_s"])],
                   [Paragraph(escape(f"Fuente: {meta['filename']} · {D.fmt_int(p['rows'])} eventos · {p['time_start']} a {p['time_end']}"), S["cover_s"])]],
                  colWidths=[CONTENT_W], rowHeights=None)
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 10 * mm),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 10 * mm), ("TOPPADDING", (0, 0), (0, 0), 14 * mm),
                               ("BOTTOMPADDING", (0, -1), (-1, -1), 14 * mm), ("TOPPADDING", (0, 1), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -2), 1)]))
    story += [Spacer(1, 12 * mm), cover, Spacer(1, 10 * mm)]

    kp = [[Paragraph(f"<font size=20 color='#0f172a'><b>{v}</b></font><br/><font size=8 color='#64748b'>{escape(k)}</font>", S["base"])
           for k, v in (("Eventos", D.fmt_int(p["rows"])), ("Incidentes", str(len(incidents))), ("Hallazgos", str(st["findings_total"])),
                        ("Críticos", str(sev["Crítico"])), ("Altos", str(sev["Alto"])), ("IoC", str(len(analysis["iocs"]))))]]
    kt = Table(kp, colWidths=[CONTENT_W / 6] * 6)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.25, LINE), ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [kt, Spacer(1, 6 * mm)]
    story.append(P("Este informe fue generado por la aplicación SOC Incident Analyzer. Los hallazgos y su criticidad se determinan con reglas "
                   "aplicadas directamente sobre los registros y cada conclusión cita los Log_ID que la sustentan. "
                   + ("La explicación técnica y el plan de acción fueron redactados con asistencia de IA (" + str(ai.get("model")) + ") y verificados "
                      "contra el archivo de logs: se descartan las citas o direcciones que no existan en los datos." if ai_mode
                      else "La redacción corresponde al modo determinista (sin IA)."), "small"))
    story.append(PageBreak())

    # ---- 1. resumen ejecutivo -----------------------------------------------
    story.append(P("1. Resumen ejecutivo", "h1"))
    for para in [x.strip() for x in re.split(r"\n\s*\n", ai["executive_summary"]) if x.strip()]:   # párrafos separados por línea en blanco
        story.append(P(para))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 4))
    cw = [14 * mm, 17 * mm, CONTENT_W - 14 * mm - 17 * mm - 27 * mm - 28 * mm - 13 * mm, 27 * mm, 28 * mm, 13 * mm]
    rows = [[hcell("ID"), hcell("Criticidad"), hcell("Incidente"), hcell("Ventana"), hcell("Hosts"), hcell("Hall.")]]
    for i in incidents:
        title = ai["incidents"].get(i["id"], {}).get("title") or i["title"]
        rows.append([Paragraph(f"<b>{i['id']}</b>", S["cell"]),
                     Paragraph(f"<font color='{SEV_COLOR[i['severity']].hexval().replace('0x', '#')}'><b>{i['severity']}</b></font>", S["cell"]),
                     Paragraph(escape(title), S["cell"]), Paragraph(f"{i['time_start'][11:16]}–{i['time_end'][11:16]}", S["cell"]),
                     Paragraph(escape(", ".join(i["hosts"])), S["cell"]), Paragraph(str(len(i["finding_ids"])), S["cell"])])
    story += [table(rows, cw), Spacer(1, 6)]
    charts = Table([[chart_severity(st), chart_timeline(st)]], colWidths=[CONTENT_W * 0.47, CONTENT_W * 0.53])
    charts.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [charts, Spacer(1, 4)]

    # ---- 2. alcance y metodología -------------------------------------------
    story.append(P("2. Alcance y metodología", "h1"))
    story.append(P(f"Se analizó el export del SIEM «{meta['filename']}» ({D.fmt_int(p['rows'])} eventos, {p['hosts']} hosts, {p['users']} cuentas, "
                   f"{p['time_start']} a {p['time_end']}, {p['duration']}). El análisis combina tres pasos:"))
    story += bullets([
        "Detección determinista: reglas explícitas sobre los campos del archivo (fuerza bruta, inicios de sesión sospechosos, escalamiento, comandos y "
        "procesos, movimiento lateral, exfiltración, persistencia, ataques web y anomalías de calidad de datos). Cada hallazgo conserva sus Log_ID.",
        "Correlación: los hallazgos se agrupan en incidentes si comparten un actor (IP externa o cuenta). Compartir solo un host o un recurso NO fusiona incidentes; "
        "esos casos se reportan como hipótesis de baja confianza.",
        ("Redacción asistida por IA: explicación técnica, impacto y plan de acción redactados a partir de la evidencia; la criticidad la fija el motor y "
         "un validador descarta Log_ID o IP inexistentes." if ai_mode else "Redacción determinista a partir de plantillas y de los datos de cada hallazgo."),
    ])
    rr = [[hcell("Regla"), hcell("Descripción"), hcell("Hallazgos")]]
    for r in analysis["rules"]:
        rr.append([Paragraph(escape(r["key"]), S["cellb"]), Paragraph(escape(r["description"]), S["cell"]), Paragraph(str(r["hits"]), S["cell"])])
    story += [Spacer(1, 4), table(rr, [30 * mm, CONTENT_W - 30 * mm - 18 * mm, 18 * mm])]

    # ---- 3. relación entre incidentes ----------------------------------------
    story.append(P("3. Relación entre incidentes", "h1"))
    story.append(P(ai["cross_incident_assessment"]))
    if analysis["hypotheses"]:
        hr = [[hcell("ID"), hcell("Hipótesis (no confirmada)"), hcell("Confianza")]]
        for h in analysis["hypotheses"]:
            hr.append([Paragraph(h["id"], S["cellb"]), Paragraph(escape(h["statement"] + " " + h["basis"]), S["cell"]), Paragraph(h["confidence"], S["cell"])])
        story += [Spacer(1, 4), table(hr, [14 * mm, CONTENT_W - 14 * mm - 18 * mm, 18 * mm])]

    # ---- 4. incidentes y hallazgos -------------------------------------------
    story.append(PageBreak())
    story.append(P("4. Incidentes y hallazgos", "h1"))
    for inc in incidents:
        g = ai["incidents"].get(inc["id"], {})
        story.append(CondPageBreak(60 * mm))
        story.append(heading_badge(g.get("title") or inc["title"], inc["severity"], "h2", pre=inc["id"]))
        meta_line = (f"{inc['time_start']} a {inc['time_end'][11:]} · Hosts: {', '.join(inc['hosts'])}"
                     + (f" · IP externas: {', '.join(inc['external_ips'])}" if inc["external_ips"] else "")
                     + (f" · Cuentas: {', '.join(D.short_user(u) for u in inc['actor_users'])}" if inc["actor_users"] else ""))
        story += [P(meta_line, "small"), Spacer(1, 3), P(g.get("narrative", ""))]
        if g.get("confidence"):
            story.append(PR(f"<b>Confianza de la agrupación:</b> {escape(g['confidence'])}. {escape(g.get('confidence_reason', ''))}", "small"))
        kc = [[hcell("Hora"), hcell("Paso"), hcell("Evidencia")]]
        for s in g.get("kill_chain", []):
            ev = s["evidence_ids"]
            kc.append([Paragraph(escape(s["time"]), S["cell"]), Paragraph(escape(s["step"]), S["cell"]),
                       Paragraph(escape(", ".join(ev[:4]) + (f" … (+{len(ev) - 4})" if len(ev) > 4 else "")), S["cell"])])
        if len(kc) > 1:
            story += [P("CRONOLOGÍA", "label"), table(kc, [16 * mm, CONTENT_W - 16 * mm - 52 * mm, 52 * mm])]
        for fid in inc["finding_ids"]:
            story.append(CondPageBreak(70 * mm))
            story += finding_block(by_id[fid], ai["findings"][fid], df, ai_mode)
        for oid in inc.get("observation_ids", []):
            story.append(P(f"Observación relacionada: {oid} — {by_id[oid]['title']} (ver sección 5).", "small"))
        story.append(Spacer(1, 6))

    # ---- 5. observaciones -----------------------------------------------------
    obs = [f for f in findings if f["incident_id"] is None]
    if obs:
        story.append(PageBreak())
        story.append(P("5. Observaciones generales (SIEM y calidad de datos)", "h1"))
        story.append(P("Hallazgos que no forman parte de una cadena de ataque concreta pero afectan la capacidad de detección o la fiabilidad de los datos."))
        for f in obs:
            story.append(CondPageBreak(60 * mm))
            story += finding_block(f, ai["findings"][f["id"]], df, ai_mode)

    # ---- 6. IoC ---------------------------------------------------------------
    story.append(PageBreak())
    story.append(P("6. Indicadores de compromiso (IoC)", "h1"))
    story.append(P("Indicadores extraídos de las evidencias. El export no contiene hashes de archivos ni reputación de IP; esos datos deben obtenerse en el endpoint o con inteligencia de amenazas."
                   if not intel else "Indicadores extraídos de las evidencias. El export no contiene hashes de archivos ni reputación de IP; la reputación de los indicadores externos se consultó aparte (ver más abajo)."))
    ir = [[hcell("Tipo"), hcell("Valor"), hcell("Crit."), hcell("Primera vez"), hcell("Contexto"), hcell("Hallazgos")]]
    for i in analysis["iocs"]:
        ctx = "; ".join(i["notes"][:2]) + (f" ({D.pl(i['events'], 'evento', 'eventos')} en el export)" if i.get("events") is not None else "")
        ir.append([Paragraph(escape(i["type"]), S["cell"]), Paragraph(escape(D.trunc(i["value"], 90)), S["cellb"]), Paragraph(i["severity"], S["cell"]),
                   Paragraph(i["first_seen"][11:], S["cell"]), Paragraph(escape(ctx), S["cell"]), Paragraph(escape(", ".join(i["finding_ids"][:4])), S["cell"])])
    story.append(table(ir, [24 * mm, 48 * mm, 13 * mm, 15 * mm, CONTENT_W - 24 * mm - 48 * mm - 13 * mm - 15 * mm - 22 * mm, 22 * mm]))
    if intel and intel.get("results"):
        story += intel_section(intel)

    # ---- 7. plan de acción ----------------------------------------------------
    story.append(P("7. Plan de acción priorizado", "h1"))
    ar = [[hcell("Prioridad"), hcell("Acción"), hcell("Incidentes")]]
    order = {"Inmediata": 0, "Corto plazo": 1, "Mediano plazo": 2}
    for a in sorted(ai["prioritized_actions"], key=lambda a: order.get(a["priority"], 9)):
        ar.append([Paragraph(f"<b>{a['priority']}</b>", S["cell"]), Paragraph(escape(a["action"]), S["cell"]), Paragraph(escape(", ".join(a["incident_ids"])), S["cell"])])
    story.append(table(ar, [22 * mm, CONTENT_W - 22 * mm - 24 * mm, 24 * mm]))

    story.append(P("8. Recomendaciones generales de seguridad", "h1"))
    story += bullets(ai["general_recommendations"])

    if phishing:
        story.append(PageBreak())
        story += phishing_section(phishing, "9")

    doc.build(story)
    return buf.getvalue()
