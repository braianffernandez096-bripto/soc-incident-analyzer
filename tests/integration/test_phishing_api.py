"""API de phishing: subida de .eml, límites, reputación (transporte simulado: nada sale a Internet) y PDF."""
import io
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from backend import intel, main
from backend.main import app

client = TestClient(app)
DIR = Path(__file__).parents[2] / "sample_data" / "correos"
FACTURA = (DIR / "01_factura_adjunto_pdf_exe.eml").read_bytes()
LEGIT = (DIR / "05_legitimo_interno.eml").read_bytes()


def up(*files, **data):
    return client.post("/api/phishing", files=[("files", (n, d, "message/rfc822")) for n, d in files], data=data)


@pytest.fixture(autouse=True)
def _limpio(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    main._hits.clear()


def _fake(monkeypatch, handler):
    monkeypatch.setattr(main, "_new_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(intel, "VT_INTERVAL", 0)
    monkeypatch.setattr(intel, "ABUSE_INTERVAL", 0)


def _wait(pid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        j = client.get(f"/api/phishing/{pid}/intel").json()["job"]
        if j and j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("la consulta no terminó")


def test_upload_returns_items_sorted_with_mitre_names():
    r = up(("legit.eml", LEGIT), ("factura.eml", FACTURA))
    assert r.status_code == 200
    d = r.json()
    assert [i["severity"] for i in d["items"]] == ["Crítico", "Bajo"] and d["items"][0]["id"] == "MAIL-01"
    info = d["items"][0]["mitre_info"]["T1036.007"]
    assert info["name"] == "Double File Extension" and info["url"] == "https://attack.mitre.org/techniques/T1036/007/"


def test_sample_endpoint_uses_the_fixed_folder():
    r = client.post("/api/phishing/sample")
    assert r.status_code == 200 and len(r.json()["items"]) == 5


@pytest.mark.parametrize("name,data,code", [
    ("nota.txt", b"hola", 400), ("correo.msg", b"x", 400), ("../../etc/passwd.eml", b"no soy un correo", 422), ("vacio.eml", b"", 422)])
def test_bad_uploads_are_refused(name, data, code):
    assert up((name, data)).status_code == code


def test_too_many_files_and_too_large_file():
    assert up(*[(f"{i}.eml", LEGIT) for i in range(6)]).status_code == 400
    big = b"From: a@b.example\n\n" + b"x" * (5 * 1024 * 1024 + 10)
    assert up(("grande.eml", big)).status_code == 413


def test_one_bad_file_does_not_discard_the_good_ones():
    d = up(("ok.eml", FACTURA), ("mal.eml", b"basura")).json()
    assert len(d["items"]) == 1 and d["errors"][0]["filename"] == "mal.eml"


def test_unknown_id_is_404_and_session_limit_is_enforced():
    assert client.get("/api/phishing/nope/intel").status_code == 404
    assert client.post("/api/phishing/nope/report.pdf").status_code == 404
    for _ in range(main.MAX_SESSIONS + 3):
        up(("f.eml", LEGIT))
    assert len(main.PHISH) <= main.MAX_SESSIONS


def test_upload_is_rate_limited_like_the_log_upload():
    codes = [up(("f.eml", LEGIT)).status_code for _ in range(main.RATE_LIMITS["/api/upload"][0] + 2)]
    assert codes[-1] == 429


# ---------------------------------------------------------------- reputación
def test_plan_sends_only_public_domains_ips_and_hashes_never_urls_or_addresses():
    pid = up(("a.eml", FACTURA), ("b.eml", (DIR / "02_enlace_enganoso_microsoft.eml").read_bytes())).json()["phishing_id"]
    d = client.get(f"/api/phishing/{pid}/intel?include_reserved=true").json()
    kinds = {q["kind"] for q in d["plan"]["queries"]}
    assert kinds <= {"ip", "domain", "hash"} and "hash" in kinds
    assert all(re.fullmatch(r"[A-Za-z0-9.\-]+", q["value"]) for q in d["plan"]["queries"])     # sin «@», «/», «:» ni rutas


def test_documentation_ranges_and_internal_names_are_not_sent_by_default():
    pid = up(("a.eml", FACTURA)).json()["phishing_id"]
    plan = client.get(f"/api/phishing/{pid}/intel").json()["plan"]
    assert all(q["kind"] == "hash" for q in plan["queries"])        # IP de documentación y dominios .example se omiten
    assert any("documentación" in s["reason"] or "reservado" in s["reason"] for s in plan["skipped"])


def test_intel_requires_keys_and_runs_with_a_simulated_transport(monkeypatch):
    pid = up(("a.eml", FACTURA)).json()["phishing_id"]
    assert client.post(f"/api/phishing/{pid}/intel").status_code == 400
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 50}, "meaningful_name": "setup.exe",
                                                                  "type_description": "Win32 EXE"}}})
    _fake(monkeypatch, handler)
    r = client.post(f"/api/phishing/{pid}/intel", headers={"X-VT-Key": "vt-SECRET-1"})
    assert r.status_code == 200
    job = _wait(pid)
    assert job["status"] == "done" and job["results"][0]["kind"] == "hash" and job["results"][0]["verdict"] == "Malicioso"
    assert seen and all("/files/" in u for u in seen) and "vt-SECRET-1" not in str(job)


def test_pdf_for_emails_and_pdf_of_logs_with_the_phishing_section():
    pid = up(("a.eml", FACTURA), ("b.eml", LEGIT)).json()["phishing_id"]
    r = client.post(f"/api/phishing/{pid}/report.pdf", data={"client": "ACME", "analyst": "Braian"})
    assert r.status_code == 200 and r.content[:4] == b"%PDF"
    text = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    assert "Qué verificar" in text and "ACME" in text and "MAIL-01" in text
    sid = client.post("/api/sample").json()["session_id"]
    plain = client.post(f"/api/sessions/{sid}/report.pdf").content
    assert client.post(f"/api/sessions/{sid}/phishing", data={"pid": pid}).status_code == 200
    with_ph = client.post(f"/api/sessions/{sid}/report.pdf").content
    t = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(with_ph)).pages)
    assert "Análisis de correos sospechosos" in t and len(with_ph) > len(plain)
    assert "Análisis de correos sospechosos" not in " ".join(p.extract_text() for p in PdfReader(io.BytesIO(plain)).pages)


def test_uploading_with_a_log_session_links_the_emails():
    sid = client.post("/api/sample").json()["session_id"]
    pid = up(("a.eml", FACTURA), sid=sid).json()["phishing_id"]
    assert main.SESSIONS[sid].phish_id == pid


def test_phishing_routes_need_the_access_token_when_one_is_set(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", "x" * 20)
    assert up(("a.eml", FACTURA)).status_code == 401
    assert client.post("/api/phishing/sample").status_code == 401
    ok = client.post("/api/phishing", files=[("files", ("a.eml", FACTURA, "message/rfc822"))], headers={"Authorization": "Bearer " + "x" * 20})
    assert ok.status_code == 200
