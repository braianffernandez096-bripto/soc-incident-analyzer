"""Smoke test E2E: arranca el servidor real y recorre carga -> análisis -> PDF."""
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--log-level", "warning"], cwd=ROOT)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            pytest.fail("el servidor no arrancó")
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_servidor_arranca_y_sirve_el_frontend(server):
    assert urllib.request.urlopen(server + "/api/health").status == 200
    html = urllib.request.urlopen(server + "/").read().decode()
    assert "SOC Incident Analyzer" in html and "theme-init.js" in html


def test_flujo_completo_ejemplo_a_pdf(server):
    import json
    sample = ROOT / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    boundary = "----soctest"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{sample.name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + sample.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(server + "/api/upload", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    sid = json.load(urllib.request.urlopen(req))["session_id"]
    pdf = urllib.request.urlopen(f"{server}/api/sessions/{sid}/report.pdf").read()
    assert pdf.startswith(b"%PDF") and len(pdf) > 20_000
