"""E2E de navegador (Playwright + Chromium) contra el servidor real: lo que ve y hace una persona.

Se saltan solos si Playwright o Chromium no están instalados (pip install playwright && playwright install chromium).
"""
import socket
import subprocess
import sys
import time
import urllib.request
from email.message import EmailMessage
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect
WAIT = 20_000                                                          # ms: el servidor de CI es más lento que un equipo local
ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
MAILS = ROOT / "sample_data" / "correos"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--log-level", "warning"], cwd=ROOT)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            pytest.fail("el servidor no arrancó")
        yield f"http://127.0.0.1:{port}/"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001 - sin Chromium instalado no hay e2e de navegador
            pytest.skip(f"Chromium no disponible: {str(exc)[:80]}")
        yield b
        b.close()


@pytest.fixture
def page(browser, server):
    ctx = browser.new_context(accept_downloads=True)
    pg = ctx.new_page()
    pg.problems = []                                                  # errores de JS y violaciones de CSP: ninguno debe aparecer
    pg.on("pageerror", lambda e: pg.problems.append(str(e)))
    pg.on("console", lambda m: pg.problems.append(m.text) if m.type == "error" else None)
    pg.set_default_timeout(WAIT)
    pg.goto(server)
    yield pg
    ctx.close()


def _upload_logs(pg, path: Path):
    pg.set_input_files("#file", str(path))
    pg.get_by_role("button", name="Analizar archivo").click()
    pg.wait_for_url("**#/dashboard")


def test_logs_flow_dashboard_and_findings(page):
    _upload_logs(page, SAMPLE)
    main = page.locator("#main")
    expect(main).to_contain_text("715 eventos")
    expect(main).to_contain_text("INC-001")
    expect(main).to_contain_text("INC-006")
    expect(page.get_by_text("Incidentes distintos").first).to_be_visible()
    page.get_by_role("link", name="Hallazgos").first.click()
    expect(page.get_by_text("25 de 25 hallazgos")).to_be_visible()
    page.get_by_role("button", name="Crítico (10)").click()
    expect(page.get_by_text("10 de 25 hallazgos")).to_be_visible()
    assert page.problems == []


def test_sample_button_and_pdf_download(page):
    page.get_by_role("button", name="Probar con datos de ejemplo").click()
    page.wait_for_url("**#/dashboard")
    page.get_by_role("link", name="Ir al informe").click()
    with page.expect_download() as d:
        page.get_by_role("button", name="PDF").click()
    assert Path(d.value.path()).read_bytes()[:5] == b"%PDF-"
    assert page.problems == []


def test_hostile_log_content_is_shown_as_text_and_never_executed(page, tmp_path):
    """Un log con HTML/JS en sus campos se muestra como texto: no se ejecuta (XSS almacenado vía el export del SIEM)."""
    bad = "<img src=x onerror=window.__pwned=1><script>window.__pwned=1</script>"
    rows = ["Log_ID,Timestamp,Hostname,Event_ID,User,Source_IP,Destination,Log_Source,Event_Description,Process_CommandLine,Result,Severity"]
    for i in range(12):
        rows.append(f'EVT-{i:05d},2026-11-02 09:00:{i:02d},WS-01,4625,"CORP\\{bad}",203.0.113.50,DC-01,Security,"failed logon {bad}",,Failure,Informational')
    f = tmp_path / "hostil.csv"
    f.write_text("\n".join(rows), "utf-8")
    _upload_logs(page, f)
    seen = ""
    for route in ("incidents", "findings", "logs", "iocs", "report"):
        page.evaluate(f"location.hash = '#/{route}'")
        page.wait_for_timeout(600)
        seen += page.locator("#main").inner_text()
    assert page.evaluate("window.__pwned") is None
    assert page.locator("#main img[src='x'], #main script").count() == 0
    assert "onerror" in seen                                           # el texto hostil se ve, literal


def test_phishing_flow_critical_and_legit(page):
    page.get_by_role("link", name="Phishing").click()
    page.set_input_files("#pfile", [str(MAILS / "01_factura_adjunto_pdf_exe.eml"), str(MAILS / "05_legitimo_interno.eml")])
    page.get_by_role("button", name="Analizar correos").click()
    main = page.locator("#main")
    expect(main).to_contain_text("Haz clic en una fila para ver su detalle")   # solo existe en la pantalla de resultados
    expect(main).to_contain_text("Phishing / malware muy probable")
    expect(main).to_contain_text("Sin señales relevantes")
    assert page.problems == []


def test_phishing_detects_obfuscated_link_in_html(page, tmp_path):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "Soporte <soporte@banco-seguro.example>", "victima@corp.example", "Verifica tu cuenta"
    m.set_content("Verifica tu cuenta.")
    m.add_alternative('<html><body><a href="&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;login-banco.example/verificar">Verificar mi cuenta</a></body></html>', subtype="html")
    f = tmp_path / "ofuscado.eml"
    f.write_bytes(bytes(m))
    page.get_by_role("link", name="Phishing").click()
    page.set_input_files("#pfile", str(f))
    page.get_by_role("button", name="Analizar correos").click()
    main = page.locator("#main")
    expect(main).to_contain_text("Haz clic en una fila para ver su detalle")
    expect(main).to_contain_text("entidades HTML numéricas")
    assert page.problems == []


def test_report_offers_local_ai_and_explains_when_ollama_is_missing(page):
    page.get_by_role("button", name="Probar con datos de ejemplo").click()
    page.wait_for_url("**#/dashboard")
    page.get_by_role("link", name="Ir al informe").click()
    expect(page.get_by_text("Redacción con IA")).to_be_visible()
    assert page.locator("#keyBox").is_visible() and page.locator("#olBox").is_hidden()
    page.select_option("#prov", "ollama")
    expect(page.locator("#olBox")).to_be_visible()
    expect(page.locator("#olInfo")).to_contain_text("Ollama")                 # sin Ollama en el servidor de prueba: avisa cómo seguir
    assert page.locator("#keyBox").is_hidden()
    page.select_option("#prov", "anthropic")
    expect(page.locator("#keyBox")).to_be_visible()
    assert page.problems == []
