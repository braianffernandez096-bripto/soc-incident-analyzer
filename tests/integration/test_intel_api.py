"""API de reputación: ciclo de vida, validaciones y privacidad. Transporte simulado: no sale nada a Internet."""
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import intel, main
from backend.main import app

client = TestClient(app)

PUBLIC_CSV = ("Log_ID,Timestamp,Hostname,Event_ID,User,Source_IP\n"
              + "".join(f"E{i},2026-10-23 08:00:{i:02d},SRV1,4625,admin,8.8.8.8\n" for i in range(12))
              + "E99,2026-10-23 08:01:00,SRV1,4624,admin,8.8.8.8\nE98,2026-10-23 08:02:00,SRV1,4625,bob,10.0.0.5\n").encode()
VT_KEY, AB_KEY = "vt-SECRET-111", "ab-SECRET-222"


def _session(data=PUBLIC_CSV, name="x.csv"):
    r = client.post("/api/upload", files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _fake(monkeypatch, handler):
    monkeypatch.setattr(main, "_new_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(intel, "VT_INTERVAL", 0)
    monkeypatch.setattr(intel, "ABUSE_INTERVAL", 0)


def _ok(req):
    if "virustotal" in req.url.host:
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "harmless": 60}, "country": "US", "as_owner": "ACME"}}})
    return httpx.Response(200, json={"data": {"abuseConfidenceScore": 80, "totalReports": 9, "countryCode": "NL", "isp": "Host"}})


def _wait(sid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        j = client.get(f"/api/sessions/{sid}/intel").json()["job"]
        if j and j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("la consulta no terminó")


@pytest.fixture(autouse=True)
def _sin_claves(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    main._hits.clear()


def test_estado_inicial_muestra_el_plan_sin_tocar_la_red(monkeypatch):
    def prohibido(req):
        raise AssertionError("no debe haber red en un GET")
    _fake(monkeypatch, prohibido)
    d = client.get(f"/api/sessions/{_session()}/intel").json()
    assert d["configured"] == {"virustotal": False, "abuseipdb": False} and d["job"] is None
    assert [q["value"] for q in d["plan"]["queries"]] == ["8.8.8.8"]


def test_sin_claves_da_400_con_mensaje_claro():
    r = client.post(f"/api/sessions/{_session()}/intel")
    assert r.status_code == 400 and "VT_API_KEY" in r.json()["detail"]


def test_sin_indicadores_publicos_da_400(monkeypatch):
    sid = _session(PUBLIC_CSV.replace(b"8.8.8.8", b"203.0.113.9"))
    r = client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY})
    assert r.status_code == 400 and "indicadores públicos" in r.json()["detail"]


def test_flujo_completo_con_claves_por_cabecera(monkeypatch):
    _fake(monkeypatch, _ok)
    sid = _session()
    r = client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY, "X-AbuseIPDB-Key": AB_KEY})
    assert r.status_code == 200 and r.json()["job"]["total"] == 1
    j = _wait(sid)
    assert j["status"] == "done" and j["results"][0]["indicator"] == "8.8.8.8" and j["results"][0]["verdict"] == "Malicioso"
    todo = client.get(f"/api/sessions/{sid}/intel").text + r.text
    assert VT_KEY not in todo and AB_KEY not in todo                    # las claves no vuelven al navegador


def test_claves_del_entorno_se_marcan_configuradas_y_no_se_devuelven(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", VT_KEY)
    _fake(monkeypatch, _ok)
    sid = _session()
    d = client.get(f"/api/sessions/{sid}/intel")
    assert d.json()["configured"] == {"virustotal": True, "abuseipdb": False} and VT_KEY not in d.text
    assert client.post(f"/api/sessions/{sid}/intel").status_code == 200
    assert _wait(sid)["status"] == "done"


def test_solo_ip_publicas_llegan_al_proveedor(monkeypatch):
    vistos = []
    _fake(monkeypatch, lambda req: (vistos.append(str(req.url)), _ok(req))[1])
    sid = _session()
    client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY, "X-AbuseIPDB-Key": AB_KEY})
    _wait(sid)
    assert vistos and all("8.8.8.8" in u for u in vistos)
    assert not any(x in u for u in vistos for x in ("10.0.0.5", "admin", "bob", "SRV1"))


def test_rango_de_documentacion_solo_con_include_reserved(monkeypatch):
    _fake(monkeypatch, _ok)
    sid = _session(PUBLIC_CSV.replace(b"8.8.8.8", b"203.0.113.9"))
    assert client.get(f"/api/sessions/{sid}/intel").json()["plan"]["reserved_available"] == 1
    r = client.post(f"/api/sessions/{sid}/intel?include_reserved=true", headers={"X-VT-Key": VT_KEY})
    assert r.status_code == 200
    j = _wait(sid)
    assert j["results"][0]["reserved"] is True


def test_clave_invalida_termina_con_aviso(monkeypatch):
    _fake(monkeypatch, lambda req: httpx.Response(401))
    sid = _session()
    client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": "mala"})
    j = _wait(sid)
    assert j["status"] == "done" and "rechazó la clave" in j["notices"][0]


def test_409_si_ya_hay_una_consulta_en_curso(monkeypatch):
    import threading
    gate = threading.Event()

    def lento(req):
        gate.wait(3)
        return _ok(req)

    _fake(monkeypatch, lento)
    sid = _session()
    assert client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY}).status_code == 200
    assert client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY}).status_code == 409
    gate.set()
    _wait(sid)


def test_sesion_inexistente_404():
    assert client.get("/api/sessions/nope/intel").status_code == 404
    assert client.post("/api/sessions/nope/intel", headers={"X-VT-Key": VT_KEY}).status_code == 404


def test_limite_de_peticiones_429(monkeypatch):
    monkeypatch.setitem(main.RATE_LIMITS, "/api/intel", (2, 60))
    sid = _session()
    codes = [client.post(f"/api/sessions/{sid}/intel").status_code for _ in range(4)]
    assert 429 in codes


def test_el_pdf_incluye_reputacion_cuando_se_consulto(monkeypatch):
    import io
    from pypdf import PdfReader
    _fake(monkeypatch, _ok)
    sid = _session()
    client.post(f"/api/sessions/{sid}/intel", headers={"X-VT-Key": VT_KEY, "X-AbuseIPDB-Key": AB_KEY})
    _wait(sid)
    pdf = client.get(f"/api/sessions/{sid}/report.pdf")
    assert pdf.status_code == 200
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    flat = " ".join(text.split())
    assert "Reputación de indicadores externos" in flat and "Malicioso" in flat and "criticidad" in flat
    assert VT_KEY not in text and AB_KEY not in text


def test_el_pdf_sin_consulta_no_incluye_la_seccion():
    import io
    from pypdf import PdfReader
    sid = _session()
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(client.get(f"/api/sessions/{sid}/report.pdf").content)).pages)
    assert "Reputación de indicadores externos" not in text
