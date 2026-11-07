"""Informe HTML descargable: contenido igual al del PDF, archivo único sin recursos externos y datos hostiles siempre escapados."""
import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import ai as ai_mod
from backend import main, phishing as phishing_mod
from backend import report_html as RH
from backend import triage as T
from backend.analysis import analyze
from backend.parser import load_events
from tests.integration.test_ai import _fake_model

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
MAILS = ROOT / "sample_data" / "correos"
META = {"client": "ACME S.A.", "analyst": "Braian", "filename": "export.xlsx"}
BAD = '<img src=x onerror=alert(1)><script>alert("xss")</script>"\'><svg onload=alert(2)>'


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


class Scan(HTMLParser):
    """Recorre el HTML generado: qué etiquetas y atributos hay realmente (un dato mal escapado aparecería aquí como etiqueta o atributo extra)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.scripts, self.styles, self._in = [], [], [], [], None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]
        self._in = tag if tag in ("script", "style") else None

    def handle_endtag(self, tag):
        self._in = None

    def handle_data(self, data):
        if self._in == "script":
            self.scripts.append(data)
        elif self._in == "style":
            self.styles.append(data)


def scan(doc: bytes) -> Scan:
    s = Scan()
    s.feed(doc.decode("utf-8"))
    return s


def build(ctx, **kw):
    df, a = ctx
    return RH.build_html(a, kw.pop("ai", None) or ai_mod.build_deterministic(a), df, META, **kw)


# ------------------------------------------------------------------ contenido
def test_contains_the_same_sections_as_the_pdf(ctx):
    df, a = ctx
    doc = build(ctx).decode()
    for n, title in ((1, "Resumen ejecutivo"), (2, "Alcance y metodología"), (3, "Relación entre incidentes"), (4, "Incidentes y hallazgos"),
                     (6, "Indicadores de compromiso"), (7, "Plan de acción priorizado"), (8, "Recomendaciones generales")):
        assert f"{n}. {title}" in doc
    for inc in a["incidents"]:
        assert f'id="{inc["id"]}"' in doc
    for f in a["findings"]:
        assert f'<span class="idtag">{f["id"]}</span>' in doc
    assert "ACME S.A." in doc and "Braian" in doc and "export.xlsx" in doc
    assert "Eventos por ventana de 10 minutos" in doc and "Hallazgos por criticidad" in doc
    assert doc.count("<circle class=\"seg") == sum(1 for v in a["stats"]["findings_by_severity"].values() if v)


def test_every_evidence_id_cited_by_a_finding_is_in_the_report(ctx):
    df, a = ctx
    doc = build(ctx).decode()
    for f in a["findings"]:
        for ev in f["evidence_ids"][:RH.EVIDENCE_MAX]:
            assert ev in doc


def test_ai_mode_text_and_model_are_shown(ctx):
    df, a = ctx
    ai = ai_mod.generate(a, df, None, model="modelo-x", call=lambda tool, text, mt: _fake_model(tool, text, mt), provider="openai", workers=1)
    doc = build(ctx, ai=ai).decode()
    assert "modelo-x" in doc and "asistencia de IA" in doc


def test_triage_and_analyst_decisions_are_included(ctx):
    df, a = ctx
    inc = a["incidents"][0]
    tri = T.view(a, T.deterministic(a), {inc["id"]: {"decision": "Escalado", "note": "Se escaló a L2 por la cuenta admin", "by": "Braian", "at": "2026-11-07 01:00 · UTC-03:00"}})
    items = [{**i, "source": "ia", "reasons": ["La secuencia de eventos coincide con un ataque real"], "would_change_if": "Que el dueño lo confirme"} if n == 1 else i
             for n, i in enumerate(tri["items"])]
    doc = build(ctx, triage={**tri, "items": items}).decode()
    assert "Decisión del analista:</b> Escalado" in doc and "Se escaló a L2 por la cuenta admin" in doc
    assert "Triaje asistido por IA:</b>" in doc


def test_without_triage_nothing_is_invented(ctx):
    doc = build(ctx).decode()
    assert "Decisión del analista" not in doc and "Triaje asistido por IA" not in doc


def test_phishing_section_is_included_when_there_are_emails(ctx):
    items = phishing_mod.analyze_many([(p.name, p.read_bytes()) for p in sorted(MAILS.glob("*.eml"))[:3]])["items"]
    doc = build(ctx, phishing=items).decode()
    assert "9. Análisis de correos sospechosos" in doc and items[0]["id"] in doc and 'href="#sec-9"' in doc
    assert "9. Análisis de correos" not in build(ctx).decode()


def test_reputation_table_when_queried(ctx):
    intel = {"queried_at": "2026-11-07", "providers": ["abuseipdb"], "notices": ["aviso <b>x</b>"],
             "results": [{"indicator": "203.0.113.74", "verdict": "Sospechosa", "abuse": {"status": "ok", "score": 90, "reports": 5, "window_days": 90, "country": "AR"}}]}
    doc = build(ctx, intel=intel).decode()
    assert "Reputación de indicadores externos" in doc and "Puntaje 90 %" in doc and "aviso &lt;b&gt;x&lt;/b&gt;" in doc


# ------------------------------------------------------------------ archivo único y sin red
def test_single_file_without_external_resources(ctx):
    doc = build(ctx)
    s = scan(doc)
    assert s.tags.count("script") == 1 and s.tags.count("style") == 1
    assert not {"link", "iframe", "object", "embed", "form", "base"} & set(s.tags)
    for tag, k, v in s.attrs:
        assert not k.startswith("on"), (tag, k)                       # ningún manejador de eventos en el marcado
        assert k != "style", (tag, k)                                  # ni estilos en línea (la CSP no los permite)
        if k in ("src", "href", "action", "data"):
            assert (v or "").startswith("#"), (tag, k, v)             # solo anclas internas
    text = doc.decode()
    assert not re.search(r"@import|url\(", s.styles[0])
    assert "fetch(" not in (RH.ASSETS / "report.js").read_text() and "XMLHttpRequest" not in (RH.ASSETS / "report.js").read_text()   # el informe no hace ninguna consulta de red
    assert not re.search(r"(src|href)=[\"']https?:", text)


def test_content_security_policy_matches_the_actual_script_and_style(ctx):
    doc = build(ctx)
    s = scan(doc)
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', doc.decode()).group(1)
    h = lambda t: base64.b64encode(hashlib.sha256(t.encode("utf-8")).digest()).decode()   # noqa: E731
    assert f"script-src 'sha256-{h(s.scripts[0])}'" in csp and f"style-src 'sha256-{h(s.styles[0])}'" in csp
    assert "default-src 'none'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp and "http" not in csp


def test_anime_is_embedded_unmodified_with_its_license_note():
    assert (RH.ASSETS / "anime.min.js").read_text().lstrip().startswith("/*\n * anime.js v3.2.2")
    assert "Julian Garnier" in (RH.ASSETS / "ANIME-LICENSE.md").read_text()


def test_animations_are_optional(ctx):
    js = (RH.ASSETS / "report.js").read_text()
    css = (RH.ASSETS / "report.css").read_text()
    assert "prefers-reduced-motion" in js and "prefers-reduced-motion" in css       # respeta «reducir movimiento»
    assert "html.anim .reveal" in css and "@media print" in css                       # el contenido solo se oculta si el JS lo anima, y se imprime completo


# ------------------------------------------------------------------ datos hostiles
def _hostile_ctx():
    df, meta = load_events(str(SAMPLE))
    df = df.copy()
    for col in ("Hostname", "User", "Event_Description", "Process_CommandLine", "Log_Source", "Result"):
        if col in df:
            df[col] = df[col].astype(str).map(lambda v: (BAD + v)[:400])
    return df, analyze(df, meta)


def test_hostile_logs_never_become_markup():
    df, a = _hostile_ctx()
    doc = RH.build_html(a, ai_mod.build_deterministic(a), df, META)
    s = scan(doc)
    assert s.tags.count("script") == 1 and "img" not in s.tags and "svg" in s.tags and s.tags.count("svg") == 2     # solo los dos gráficos propios
    assert not [x for x in s.attrs if x[1].startswith("on") or x[1] == "style"]
    text = doc.decode()
    assert "<img src=x" not in text and "<script>alert" not in text and "<svg onload" not in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text                                                                # sí aparece, pero como texto


def test_hostile_report_fields_are_escaped(ctx):
    df, a = ctx
    ai = ai_mod.build_deterministic(a)
    ai["executive_summary"] = BAD
    ai["cross_incident_assessment"] = BAD
    ai["general_recommendations"] = [BAD]
    ai["prioritized_actions"] = [{"priority": "Inmediata", "action": BAD, "incident_ids": [BAD]}]
    for g in ai["incidents"].values():
        g["title"], g["narrative"] = BAD, BAD
    for fa in ai["findings"].values():
        fa["technical_explanation"] = fa["impact"] = BAD
    dec = {a["incidents"][0]["id"]: {"decision": "Escalado", "note": BAD, "by": BAD, "at": BAD}}
    tri = T.view(a, T.deterministic(a), dec)
    doc = RH.build_html(a, ai, df, {"client": BAD, "analyst": BAD, "filename": BAD}, triage=tri,
                        intel={"queried_at": BAD, "providers": [BAD], "notices": [BAD], "results": [{"indicator": BAD, "verdict": BAD}]})
    s = scan(doc)
    assert s.tags.count("script") == 1 and "img" not in s.tags and not [x for x in s.attrs if x[1].startswith("on") or x[1] == "style"]
    assert "<title>" in doc.decode() and BAD not in doc.decode()
    csp = re.search(r'content="(default-src[^"]+)"', doc.decode()).group(1)
    assert "script-src 'sha256-" in csp


def test_closing_script_tag_in_data_cannot_break_out(ctx):
    df, a = ctx
    ai = ai_mod.build_deterministic(a)
    ai["executive_summary"] = "</script><script>alert(1)</script></style><style>*{display:none}</style>"
    s = scan(RH.build_html(a, ai, df, META))
    assert s.tags.count("script") == 1 and s.tags.count("style") == 1


def test_hostile_phishing_fields_are_escaped(ctx):
    raw = (b"From: =?utf-8?q?Soporte?= <a@b.example>\r\nTo: x@y.example\r\nSubject: " + BAD.encode() + b"\r\nMessage-ID: <1@x>\r\nDate: Mon, 02 Nov 2026 09:00:00 +0000\r\n"
           b"Content-Type: text/html\r\n\r\n<a href=\"http://evil.example/\">" + BAD.encode() + b"</a>\r\n")
    items = phishing_mod.analyze_many([("hostil.eml", raw)])["items"]
    doc = build(ctx, phishing=items)
    s = scan(doc)
    assert s.tags.count("script") == 1 and "img" not in s.tags and not [x for x in s.attrs if x[1].startswith("on")]
    assert not [x for x in s.attrs if x[0] == "a" and x[1] == "href" and not x[2].startswith("#")]      # los enlaces del correo nunca son enlaces activos


# ------------------------------------------------------------------ API
@pytest.fixture
def api(monkeypatch):
    monkeypatch.setitem(main.RATE_LIMITS, "/api/ai", (1000, 60))
    c = TestClient(main.app)
    sid = c.post("/api/upload", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/octet-stream")}).json()["session_id"]
    return c, sid


def test_endpoint_returns_a_downloadable_html(api):
    c, sid = api
    r = c.post(f"/api/sessions/{sid}/report.html", data={"client": "Cliente <b>X</b>", "analyst": "Ana"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert 'attachment; filename="informe_incidentes_seguridad.html"' in r.headers["content-disposition"]
    assert r.content.startswith(b"<!doctype html>") and "Cliente &lt;b&gt;X&lt;/b&gt;" in r.text
    assert r.headers["x-content-type-options"] == "nosniff"


def test_names_do_not_travel_in_the_url(api):
    c, sid = api
    assert c.get(f"/api/sessions/{sid}/report.html?client=X").status_code in (404, 405)        # solo POST: los nombres van en el cuerpo
    assert c.post("/api/sessions/no-existe/report.html").status_code == 404


def test_report_includes_triage_decisions_made_in_the_session(api):
    c, sid = api
    inc = main.SESSIONS[sid].analysis["incidents"][0]["id"]
    assert c.post(f"/api/sessions/{sid}/triage/{inc}/decision", data={"decision": "Descartado", "note": "Pentest autorizado", "tz": "180"}).status_code == 200
    assert "Pentest autorizado" in c.post(f"/api/sessions/{sid}/report.html").text
