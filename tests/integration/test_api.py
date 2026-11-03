"""Pruebas de la API: entradas hostiles y regresiones (sin red ni API key reales)."""
import io
from pathlib import Path

import openpyxl
import pytest
from fastapi.testclient import TestClient

from backend.analysis import analyze
from backend.main import app
from backend.parser import load_events

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
HEADER = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP"]
client = TestClient(app)


def _upload_sample(**data):
    return client.post("/api/upload", data=data, files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/octet-stream")})


def _xlsx(rows, header=HEADER) -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(header)
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_upload_rechaza_extension_que_no_es_excel():
    r = client.post("/api/upload", files={"file": ("a.exe", b"MZ", "application/octet-stream")})
    assert r.status_code == 400


def test_upload_rechaza_archivo_corrupto_con_mensaje_humano():
    r = client.post("/api/upload", files={"file": ("a.xlsx", b"no soy excel", "application/octet-stream")})
    assert r.status_code == 422 and "Traceback" not in r.text


def test_sesion_inexistente_da_404():
    assert client.get("/api/sessions/no-existe").status_code == 404


def test_export_sin_eventos_4672_no_rompe_el_analisis():
    """Regresión: groupby sobre un DataFrame vacío lanzaba KeyError y devolvía HTTP 500."""
    data = _xlsx([[f"EVT-{i}", "2026-10-23 08:00:00", "H1", "4625", "u", "1.2.3.4"] for i in range(5)])
    r = client.post("/api/upload", files={"file": ("x.xlsx", data, "application/octet-stream")})
    assert r.status_code == 200, r.text


def test_markup_hostil_en_celdas_y_portada_no_rompe_el_pdf():
    df, meta = load_events(str(SAMPLE))
    r = _upload_sample(client="<b></font>X", analyst="<script>")
    sid = r.json()["session_id"]
    pdf = client.get(f"/api/sessions/{sid}/report.pdf", params={"client": "</para><b>", "analyst": "&<>"})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_ia_sin_clave_da_400_y_no_filtra_detalles(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sid = _upload_sample().json()["session_id"]
    r = client.post(f"/api/sessions/{sid}/ai")
    assert r.status_code == 400 and "sk-ant" not in r.text


def test_estatico_no_permite_salir_del_directorio_frontend():
    assert client.get("/%2e%2e/backend/main.py").status_code in (400, 404)
    assert client.get("/../.env").status_code in (400, 404)


def test_health_responde_sin_exponer_la_clave(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secreta")
    r = client.get("/api/health")
    assert r.status_code == 200 and "secreta" not in r.text


def test_respuestas_incluyen_cabeceras_de_seguridad():
    r = client.get("/api/health")
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert "script-src 'self'" in r.headers["content-security-policy"] and "unsafe-inline" not in r.headers["content-security-policy"].split("style-src")[0]


def test_rate_limit_devuelve_429(monkeypatch):
    from backend import main
    monkeypatch.setitem(main.RATE_LIMITS, "/api/upload", (2, 60))
    main._hits.clear()
    codes = [client.post("/api/upload", files={"file": ("a.exe", b"x", "application/octet-stream")}).status_code for _ in range(3)]
    assert codes == [400, 400, 429]
    main._hits.clear()


def test_upload_mayor_al_limite_devuelve_413(monkeypatch):
    from backend import main
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 1024)
    r = client.post("/api/upload", files={"file": ("a.xlsx", b"x" * 5000, "application/octet-stream")})
    assert r.status_code == 413
