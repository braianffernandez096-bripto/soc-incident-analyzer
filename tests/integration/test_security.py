"""Security behaviour of the API: access token, headers, hostile uploads, session ids, log hygiene."""
import io
import logging
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.main import app

client = TestClient(app, raise_server_exceptions=False)
DATA = Path(__file__).resolve().parents[2] / "sample_data"
CSV = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv").read_bytes()
XLSX = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx").read_bytes()
TOKEN = "correct-horse-battery-staple-9"
OPEN_PATHS = {"/api/health", "/api/auth/status", "/api/wazuh/alerts"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    main._hits.clear()
    yield
    main._hits.clear()


def _upload(data=CSV, name="x.csv", headers=None):
    return client.post("/api/upload", files={"file": (name, data, "application/octet-stream")}, headers=headers or {})


def _xlsx_with(extra: dict[str, bytes]) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(XLSX))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for i in src.infolist():
            z.writestr(i.filename, src.read(i.filename))
        for n, b in extra.items():
            z.writestr(n, b)
    return out.getvalue()


# ---- hardening defaults -----------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_docs_are_disabled_by_default(path):
    assert client.get(path).status_code == 404


def test_security_headers_are_present_on_every_kind_of_response():
    for path in ("/", "/api/health", "/api/sessions/nope", "/does-not-exist"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["cross-origin-resource-policy"] == "same-origin"
        assert "camera=()" in h["permissions-policy"]
        assert "script-src 'self'" in h["content-security-policy"]


def test_hsts_only_over_https():
    assert "strict-transport-security" not in client.get("/api/health").headers
    assert "max-age" in client.get("/api/health", headers={"X-Forwarded-Proto": "https"}).headers["strict-transport-security"]


def test_no_cors_headers_for_foreign_origins():
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_session_ids_have_at_least_128_bits():
    sid = _upload().json()["session_id"]
    assert len(sid) >= 22          # token_urlsafe(16) -> 22 chars


def test_outbound_http_libraries_do_not_log_urls_at_info():
    for name in ("httpx", "httpcore", "anthropic"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING


# ---- hostile uploads ---------------------------------------------------------------------------------

def test_executable_renamed_to_xlsx_is_refused_with_a_human_message():
    r = _upload(b"MZ\x90\x00\x03" + b"\x00" * 100, "factura.xlsx")
    assert r.status_code == 422 and "ejecutable de Windows" in r.json()["detail"] and "Traceback" not in r.text


def test_executable_renamed_to_csv_is_refused():
    assert _upload(b"\x7fELF" + b"\x00" * 100, "logs.csv").status_code == 422


def test_rejections_are_logged_without_the_file_content(caplog):
    caplog.set_level(logging.WARNING)
    _upload(b"MZ\x90\x00SECRETPAYLOAD" + b"\x00" * 50, "x.xlsx")
    assert "upload_rejected" in caplog.text and "SECRETPAYLOAD" not in caplog.text


def test_xml_entity_declaration_inside_xlsx_is_refused():
    bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><x>&lol;</x>'
    r = _upload(_xlsx_with({"xl/extra.xml": bomb}), "x.xlsx")
    assert r.status_code == 422 and "DOCTYPE/ENTITY" in r.json()["detail"]


def test_macro_enabled_workbook_is_analysed_but_flagged_in_the_report_limits():
    r = _upload(_xlsx_with({"xl/vbaProject.bin": b"\x00\x01"}), "libro.xlsm")
    assert r.status_code == 200
    assert any("macros VBA" in x for x in r.json()["analysis"]["limitations"])


def test_formula_injection_cells_are_flagged_but_the_file_is_analysed():
    header, first, *rest = CSV.decode("utf-8").splitlines()
    cols = first.split(",")
    cols[header.split(",").index("User")] = '"=HYPERLINK(""http://evil.example"",""clic"")"'      # whole cell starts with "="
    bad = "\n".join([header, ",".join(cols), *rest]).encode("utf-8")
    r = _upload(bad)
    assert r.status_code == 200
    assert any("inyección de fórmulas" in x for x in r.json()["analysis"]["limitations"])


def test_clean_sample_has_no_security_warnings():
    lims = _upload().json()["analysis"]["limitations"]
    assert not any(x.startswith("Seguridad del archivo") for x in lims)


def test_hostile_file_names_cannot_traverse_or_inject():
    r = _upload(CSV, "../../etc/<img src=x onerror=alert(1)>.csv")
    assert r.status_code == 200 and "/" not in r.json()["filename"]


# ---- optional access token ---------------------------------------------------------------------------

def test_without_a_token_the_api_stays_open():
    assert client.get("/api/auth/status").json() == {"required": False}
    assert client.get("/api/sessions/nope").status_code == 404           # reaches the route, not blocked
    assert _upload().status_code == 200


def test_with_a_token_status_reports_required(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.get("/api/auth/status").json() == {"required": True}


def _api_routes():
    seen = set()
    for r in app.routes:
        path = getattr(r, "path", "")
        if path.startswith("/api/") and path not in OPEN_PATHS:
            for m in getattr(r, "methods", set()) - {"HEAD", "OPTIONS"}:
                seen.add((m, path))
    return sorted(seen)


def test_every_protected_route_answers_401_without_a_token(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    routes = _api_routes()
    assert len(routes) >= 8                                      # guard: the route discovery really found the API
    for method, path in routes:
        main._hits.clear()
        url = path.replace("{sid}", "x").replace("{pid}", "x").replace("{fid}", "F-001")
        r = client.request(method, url)
        assert r.status_code == 401, (method, path, r.status_code)
        assert r.headers["www-authenticate"] == "Bearer" and "x-frame-options" in r.headers


@pytest.mark.parametrize("auth", ["", "Bearer", "Bearer wrong", f"Basic {TOKEN}", f"bearer{TOKEN}", f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Token {TOKEN}"])
def test_wrong_credentials_are_refused(monkeypatch, auth):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.get("/api/auth/check", headers={"Authorization": auth} if auth else {}).status_code == 401


def test_correct_token_unlocks_the_whole_flow(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    h = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/api/auth/check", headers=h).json() == {"ok": True}
    sid = _upload(headers=h).json()["session_id"]
    assert client.get(f"/api/sessions/{sid}", headers=h).status_code == 200
    assert client.get(f"/api/sessions/{sid}/report.pdf", headers=h).content.startswith(b"%PDF")
    assert client.get(f"/api/sessions/{sid}").status_code == 401          # same session, no token


def test_open_paths_and_static_ui_do_not_need_the_token(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 200 and client.get("/app.js").status_code == 200


def test_brute_force_gets_429_but_the_real_token_keeps_working(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    codes = [client.get("/api/auth/check", headers={"Authorization": f"Bearer guess{i}"}).status_code for i in range(14)]
    assert codes[:10] == [401] * 10 and 429 in codes[10:]
    assert client.get("/api/auth/check", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_the_token_never_appears_in_logs_or_responses(monkeypatch, caplog):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    caplog.set_level(logging.DEBUG)
    bad = client.get("/api/auth/check", headers={"Authorization": "Bearer SUPPLIED-GUESS-123"})
    ok = client.get("/api/auth/check", headers={"Authorization": f"Bearer {TOKEN}"})
    assert TOKEN not in caplog.text and "SUPPLIED-GUESS-123" not in caplog.text
    assert TOKEN not in bad.text + ok.text and TOKEN not in str(dict(bad.headers)) + str(dict(ok.headers))


def test_a_short_token_logs_a_warning_at_import_time(monkeypatch):
    import importlib
    monkeypatch.setenv("APP_ACCESS_TOKEN", "short")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("logging.Logger.warning", lambda self, msg, *a, **k: hits.append(msg % a if a else msg))
        hits: list[str] = []
        importlib.reload(main)
    assert any("access_token_weak" in h for h in hits)
    importlib.reload(main)                         # restore module state for the rest of the suite


# ---- report download: personal names must not travel in the URL ---------------------------------------------

def test_pdf_post_sets_the_names_and_returns_a_pdf():
    import io
    from pypdf import PdfReader
    sid = _upload().json()["session_id"]
    r = client.post(f"/api/sessions/{sid}/report.pdf", data={"client": "Cliente Prueba SA", "analyst": "Ana Analista"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")
    text = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    assert "Cliente Prueba SA" in text and "Ana Analista" in text


def test_pdf_post_with_hostile_names_does_not_break_the_report():
    sid = _upload().json()["session_id"]
    r = client.post(f"/api/sessions/{sid}/report.pdf", data={"client": "</para><b>X&", "analyst": "<script>alert(1)</script>"})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_pdf_post_on_an_unknown_session_is_404():
    assert client.post("/api/sessions/nope/report.pdf", data={"client": "a"}).status_code == 404


def test_legacy_pdf_get_still_works():
    sid = _upload().json()["session_id"]
    assert client.get(f"/api/sessions/{sid}/report.pdf").content.startswith(b"%PDF")


def test_the_ui_never_puts_names_in_the_report_url():
    js = (Path(__file__).resolve().parents[2] / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "report.pdf?" not in js and "client=${" not in js


def test_names_do_not_reach_the_access_log_when_using_post(caplog):
    caplog.set_level(logging.DEBUG)
    sid = _upload().json()["session_id"]
    client.post(f"/api/sessions/{sid}/report.pdf", data={"client": "NOMBRE-SECRETO-CLIENTE", "analyst": "NOMBRE-SECRETO-ANALISTA"})
    assert "NOMBRE-SECRETO" not in caplog.text
