"""Informe HTML del análisis de phishing: mismo contenido que el PDF de phishing, un solo archivo sin red y con todo dato escapado."""
import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main, phishing as phishing_mod
from backend import report_html as RH

ROOT = Path(__file__).resolve().parents[2]
MAILS = ROOT / "sample_data" / "correos"
META = {"client": "ACME S.A.", "analyst": "Braian"}
BAD = '<img src=x onerror=alert(1)><script>alert("xss")</script>"\'><svg onload=alert(2)>'


class Scan(HTMLParser):
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


@pytest.fixture(scope="module")
def items():
    return phishing_mod.analyze_many([(p.name, p.read_bytes()) for p in sorted(MAILS.glob("*.eml"))[:4]])["items"]


def test_has_cover_summary_and_every_email(items):
    doc = RH.build_phishing_html(items, META).decode()
    assert "Informe de análisis de phishing" in doc and "ACME S.A." in doc and "Braian" in doc
    assert "Análisis de correos sospechosos" in doc and "no se abrieron enlaces ni se ejecutaron adjuntos" in doc
    for i in items:
        assert f"<b>{i['id']}</b>" in doc and RH.e(i["verdict"]) in doc
    assert RH.PHISHING_FOOTER in doc and "Informe técnico de investigación" not in doc          # no se mezcla con el informe de logs


def test_single_file_without_external_resources_and_matching_csp(items):
    doc = RH.build_phishing_html(items, META)
    s = scan(doc)
    assert s.tags.count("script") == 1 and s.tags.count("style") == 1
    assert not {"link", "iframe", "object", "embed", "form", "base"} & set(s.tags)
    for tag, k, v in s.attrs:
        assert not k.startswith("on") and k != "style", (tag, k)
        if k in ("src", "href", "action", "data"):
            assert (v or "").startswith("#"), (tag, k, v)
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', doc.decode()).group(1)
    h = lambda t: base64.b64encode(hashlib.sha256(t.encode("utf-8")).digest()).decode()   # noqa: E731
    assert f"script-src 'sha256-{h(s.scripts[0])}'" in csp and f"style-src 'sha256-{h(s.styles[0])}'" in csp
    assert "default-src 'none'" in csp and "'unsafe-inline'" not in csp and "http" not in csp


def test_reputation_table_is_included_only_when_queried(items):
    assert "Reputación de indicadores externos" not in RH.build_phishing_html(items, META).decode()
    intel = {"queried_at": "2026-11-07", "providers": ["abuseipdb"], "notices": ["aviso <b>x</b>"],
             "results": [{"indicator": "203.0.113.74", "verdict": "Sospechosa", "abuse": {"status": "ok", "score": 90, "reports": 5, "window_days": 90, "country": "AR"}}]}
    doc = RH.build_phishing_html(items, META, intel).decode()
    assert "Reputación de indicadores externos" in doc and "Puntaje 90 %" in doc and "aviso &lt;b&gt;x&lt;/b&gt;" in doc


def test_hostile_fields_never_become_markup():
    raw = (b"From: =?utf-8?q?Soporte?= <a@b.example>\r\nTo: x@y.example\r\nSubject: " + BAD.encode() + b"\r\nMessage-ID: <1@x>\r\nDate: Mon, 02 Nov 2026 09:00:00 +0000\r\n"
           b"Content-Type: text/html\r\n\r\n<a href=\"http://evil.example/\">" + BAD.encode() + b"</a>\r\n")
    its = phishing_mod.analyze_many([("hostil.eml", raw)])["items"]
    doc = RH.build_phishing_html(its, {"client": BAD, "analyst": BAD})
    s = scan(doc)
    assert s.tags.count("script") == 1 and "img" not in s.tags and "svg" not in s.tags
    assert not [x for x in s.attrs if x[1].startswith("on")]
    assert not [x for x in s.attrs if x[0] == "a" and x[1] == "href" and not x[2].startswith("#")]      # los enlaces del correo nunca son activos
    assert "<img src=x" not in doc.decode() and "<script>alert" not in doc.decode()


# ------------------------------------------------------------------ API
@pytest.fixture
def api():
    c = TestClient(main.app)
    pid = c.post("/api/phishing/sample").json()["phishing_id"]
    return c, pid


def test_endpoint_returns_a_downloadable_html(api):
    c, pid = api
    r = c.post(f"/api/phishing/{pid}/report.html", data={"client": "Cliente <b>X</b>", "analyst": "Ana"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert 'attachment; filename="informe_phishing.html"' in r.headers["content-disposition"]
    assert r.content.startswith(b"<!doctype html>") and "Cliente &lt;b&gt;X&lt;/b&gt;" in r.text and "<b>X</b>" not in r.text
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "MAIL-01" in r.text


def test_names_do_not_travel_in_the_url_and_unknown_id_is_404(api):
    c, pid = api
    assert c.get(f"/api/phishing/{pid}/report.html?client=X").status_code in (404, 405)
    assert c.post("/api/phishing/no-existe/report.html").status_code == 404


def test_pdf_still_works_next_to_the_html(api):
    c, pid = api
    r = c.post(f"/api/phishing/{pid}/report.pdf", data={"client": "A", "analyst": "B"})
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
