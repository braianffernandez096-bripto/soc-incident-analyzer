"""API de herramientas de dominio y cabeceras pegadas (DNS simulado: nada sale a Internet)."""
import pytest
from fastapi.testclient import TestClient

from backend import dnsdoh, main
from backend.main import app

client = TestClient(app)


class Fake:
    def __init__(self, data=None, nx=(), fail=False):
        self.data, self.nx, self.fail, self.closed = data or {}, set(nx), fail, False
        self.queries = 0

    def query(self, name, rtype="TXT"):
        if self.fail:
            raise dnsdoh.DnsError("sin conexión")
        self.queries += 1
        if name in self.nx:
            return {"status": 3, "answers": [], "provider": "Fake"}
        return {"status": 0, "answers": list(self.data.get((name, rtype), [])), "provider": "Fake"}

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _limpio(monkeypatch):
    monkeypatch.delenv("CAPTCHA", raising=False)
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("DNS_LOOKUPS", raising=False)
    main._hits.clear()


def _use(monkeypatch, fake):
    monkeypatch.setattr(main, "_new_resolver", lambda: fake)
    return fake


GOOD = {("empresa.com", "TXT"): ["v=spf1 -all"], ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@empresa.com"]}


def test_grade_ok(monkeypatch):
    f = _use(monkeypatch, Fake(GOOD))
    r = client.post("/api/domain/grade", data={"domain": "https://Empresa.com/x"})
    assert r.status_code == 200 and r.json()["domain"] == "empresa.com" and r.json()["grade"] in "ABCDF" and f.closed


def test_grade_errors(monkeypatch):
    assert client.post("/api/domain/grade", data={"domain": "1.2.3.4"}).status_code == 400
    assert client.post("/api/domain/grade", data={"domain": "x.local"}).status_code == 400
    assert client.post("/api/domain/grade").status_code == 422
    _use(monkeypatch, Fake(nx={"nada.com"}))
    assert client.post("/api/domain/grade", data={"domain": "nada.com"}).status_code == 404
    _use(monkeypatch, Fake(fail=True))
    assert client.post("/api/domain/grade", data={"domain": "empresa.com"}).status_code == 502


def test_grade_disabled(monkeypatch):
    monkeypatch.setenv("DNS_LOOKUPS", "off")
    r = client.post("/api/domain/grade", data={"domain": "empresa.com"})
    assert r.status_code == 503 and "DNS_LOOKUPS" in r.json()["detail"]


def test_grade_requires_captcha_and_validates_first(monkeypatch):
    monkeypatch.setenv("CAPTCHA", "on")
    _use(monkeypatch, Fake(GOOD))
    assert client.post("/api/domain/grade", data={"domain": "empresa.com"}).status_code == 403
    assert client.post("/api/domain/grade", data={"domain": "1.2.3.4"}).status_code == 400
    monkeypatch.setattr(main.captcha_mod, "consume_pass", lambda *a: True)
    assert client.post("/api/domain/grade", data={"domain": "empresa.com"}).status_code == 200


def test_grade_rate_limited(monkeypatch):
    _use(monkeypatch, Fake(GOOD))
    codes = [client.post("/api/domain/grade", data={"domain": "empresa.com"}).status_code for _ in range(8)]
    assert codes[:6] == [200] * 6 and 429 in codes[6:]


def test_lookalikes_local_needs_no_dns_nor_captcha(monkeypatch):
    monkeypatch.setenv("CAPTCHA", "on")
    monkeypatch.setattr(main, "_new_resolver", lambda: pytest.fail("no debe consultar el DNS"))
    r = client.post("/api/domain/lookalikes", data={"domain": "banco.com.ar"})
    j = r.json()
    assert r.status_code == 200 and j["domain"] == "banco.com.ar" and j["total"] == len(j["variants"]) > 30 and j["checked"] == 0
    assert all(v["state"] == "" for v in j["variants"]) and j["limitations"]


def test_lookalikes_check(monkeypatch):
    f = _use(monkeypatch, Fake({("banc0.com", "NS"): ["ns.x.com"]}, nx={"bnco.com"}))
    j = client.post("/api/domain/lookalikes", data={"domain": "banco.com", "check": "true"}).json()
    by = {v["domain"]: v for v in j["variants"]}
    assert by["banc0.com"]["state"] == "registrado" and by["bnco.com"]["state"] == "libre" and by["banc0.com"]["state_label"]
    assert j["checked"] == 60 == f.queries and f.closed


def test_lookalikes_check_needs_captcha_and_handles_errors(monkeypatch):
    monkeypatch.setenv("CAPTCHA", "on")
    _use(monkeypatch, Fake())
    assert client.post("/api/domain/lookalikes", data={"domain": "banco.com", "check": "true"}).status_code == 403
    monkeypatch.delenv("CAPTCHA")
    _use(monkeypatch, Fake(fail=True))
    assert client.post("/api/domain/lookalikes", data={"domain": "banco.com", "check": "true"}).status_code == 502
    monkeypatch.setenv("DNS_LOOKUPS", "off")
    assert client.post("/api/domain/lookalikes", data={"domain": "banco.com", "check": "true"}).status_code == 503
    assert client.post("/api/domain/lookalikes", data={"domain": "banco"}).status_code == 400


# ---------------------------------------------------------------- cabeceras pegadas
HDR = ("Received: from mail.evil.test (mail.evil.test [203.0.113.9]) by mx.empresa.com with ESMTPS; Mon, 5 Oct 2026 10:00:00 +0000\r\n"
       "From: Soporte <soporte@banco-seguro.test>\r\nTo: victima@empresa.com\r\nSubject: Verifique su cuenta\r\nDate: Mon, 5 Oct 2026 09:59:00 +0000\r\n"
       "Authentication-Results: mx.empresa.com; spf=fail smtp.mailfrom=banco-seguro.test; dkim=none; dmarc=fail\r\n")


def test_pasted_headers_only():
    r = client.post("/api/phishing", data={"headers_text": HDR})
    assert r.status_code == 200
    m = r.json()["items"][0]
    assert m["source"] == "cabeceras pegadas" and m["headers_only"] and m["route"]["count"] == 1 and m["score_breakdown"]["total"] == m["score"]


def test_pasted_headers_with_eml_counts_toward_limit():
    eml = ("a.eml", b"From: a@b.test\r\nSubject: x\r\n\r\ncuerpo", "message/rfc822")
    r = client.post("/api/phishing", data={"headers_text": HDR}, files=[("files", eml)])
    assert r.status_code == 200 and len(r.json()["items"]) == 2
    r = client.post("/api/phishing", data={"headers_text": HDR}, files=[("files", eml)] * 5)
    assert r.status_code == 400


def test_pasted_headers_rejections():
    assert client.post("/api/phishing", data={}).status_code in (400, 422)
    assert client.post("/api/phishing", data={"headers_text": "esto no son cabeceras"}).status_code == 422
    assert client.post("/api/phishing", data={"headers_text": "   "}).status_code in (400, 422)


# ---------------------------------------------------------------- verificación del remitente de un correo
def _mail_session():
    r = client.post("/api/phishing/sample")
    assert r.status_code == 200, r.text
    return r.json()


def test_sender_dns_review_flow(monkeypatch):
    res = _mail_session()
    pid, items = res["phishing_id"], res["items"]
    idx = next(i for i, m in enumerate(items) if m["headers"]["from_addr"] and "@" in m["headers"]["from_addr"])
    dom = items[idx]["headers"]["from_addr"].rsplit("@", 1)[-1].lower()
    f = _use(monkeypatch, Fake({(dom, "TXT"): ["v=spf1 -all"], ("_dmarc." + dom, "TXT"): ["v=DMARC1; p=reject"]}))
    r = client.post(f"/api/phishing/{pid}/items/{idx}/dns")
    assert r.status_code == 200 and r.json()["domain"] == dom and r.json()["checks"] and f.closed
    pdf = client.post(f"/api/phishing/{pid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_sender_dns_review_errors(monkeypatch):
    res = _mail_session()
    pid = res["phishing_id"]
    assert client.post(f"/api/phishing/{pid}/items/999/dns").status_code == 404
    assert client.post("/api/phishing/nope/items/0/dns").status_code == 404
    _use(monkeypatch, Fake(fail=True))
    assert client.post(f"/api/phishing/{pid}/items/0/dns").status_code == 502


def test_sender_dns_review_respects_the_dns_switch(monkeypatch):
    res = _mail_session()
    monkeypatch.setenv("DNS_LOOKUPS", "off")
    monkeypatch.setattr(main, "_new_resolver", lambda: dnsdoh.DohResolver(http=None))
    assert client.post(f"/api/phishing/{res['phishing_id']}/items/0/dns").status_code == 503
