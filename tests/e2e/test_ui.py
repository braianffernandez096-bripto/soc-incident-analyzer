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


def test_html_report_downloads_and_opens_offline_without_errors(page, tmp_path):
    """El informe HTML se descarga, se abre desde un archivo (sin servidor) y su propia política de seguridad no bloquea nada de lo suyo."""
    page.get_by_role("button", name="Probar con datos de ejemplo").click()
    page.wait_for_url("**#/dashboard")
    page.get_by_role("link", name="Ir al informe").click()
    with page.expect_download() as d:
        page.get_by_role("button", name="Descargar informe HTML").click()
    path = tmp_path / "informe.html"
    d.value.save_as(path)
    assert d.value.suggested_filename == "informe_incidentes_seguridad.html" and path.read_bytes().startswith(b"<!doctype html>")
    rep = page.context.new_page()
    problems = []
    rep.on("console", lambda m: problems.append(m.text) if m.type in ("error", "warning") else None)
    rep.on("pageerror", lambda e: problems.append(str(e)))
    rep.on("request", lambda r: problems.append("red: " + r.url) if not r.url.startswith(("file:", "data:")) else None)
    rep.goto(path.as_uri())
    expect(rep.get_by_role("heading", name="1. Resumen ejecutivo")).to_be_visible()
    rep.wait_for_timeout(1500)
    assert rep.evaluate("[...document.querySelectorAll('.kpi .n')].map(n => n.textContent)")[0] == "715"            # la animación termina en el valor real
    before = rep.evaluate("getComputedStyle(document.body).backgroundImage")
    rep.get_by_role("button", name="Cambiar entre tema claro y oscuro").click()
    assert rep.evaluate("document.documentElement.getAttribute('data-theme')") in ("dark", "light")
    rep.fill("#ioc-q", "203.0.113")
    assert rep.locator("#ioc-body tr:not(.hidden-row)").count() < rep.locator("#ioc-body tr").count()
    rep.get_by_role("button", name="Contraer todo").click()
    assert rep.locator("details[open]").count() == 0
    rep.get_by_role("button", name="Expandir todo").click()
    assert rep.locator("details:not([open])").count() == 0
    assert problems == [] and before
    rep.close()
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


def test_triage_recommendation_and_analyst_decision(page):
    """Triaje: cada incidente muestra la recomendación del motor y el analista puede registrar su decisión con una nota (texto hostil incluido)."""
    _upload_logs(page, SAMPLE)
    page.get_by_role("link", name="Incidentes").first.click()
    main = page.locator("#main")
    expect(main).to_contain_text("Triaje asistido por IA")
    expect(main.locator(".tri-chip").first).to_have_text("Escalar")
    box = main.locator(".tri").first
    box.locator("textarea").fill("<img src=x onerror=window.__pwned=1> Se abrió ticket")
    box.get_by_role("button", name="Escalado").click()
    expect(main.locator(".tri").first).to_contain_text("Decisión: Escalado")
    expect(main).to_contain_text("Decididos: 1 de")
    assert page.evaluate("window.__pwned") is None
    assert page.locator("#main .tri img").count() == 0
    assert page.problems == []


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
    for prov, name in (("openai", "OpenAI"), ("gemini", "Gemini")):
        page.select_option("#prov", prov)
        expect(page.locator(f"#repCl-{prov}")).to_be_visible()
        expect(page.locator(f"#repCl-{prov}")).to_contain_text(name)
        assert page.locator("#keyBox").is_hidden() and page.locator("#olBox").is_hidden()
    page.select_option("#prov", "anthropic")
    assert page.locator("#repCl-openai").is_hidden() and page.locator("#repCl-gemini").is_hidden()
    assert page.problems == []


def _open_sample(page):
    page.get_by_role("button", name="Probar con datos de ejemplo").click()
    page.wait_for_url("**#/dashboard")


def test_nav_tabs_are_bold(page):
    _open_sample(page)
    weights = page.evaluate("[...document.querySelectorAll('#nav a')].map(a => +getComputedStyle(a).fontWeight)")
    assert len(weights) == 7 and all(w >= 700 for w in weights)
    expect(page.locator("#nav")).to_contain_text("Informe")                  # en negrita sigue entrando completo
    assert page.problems == []


def test_dashboard_donut_filters_and_drawer_opens_incident(page):
    _open_sample(page)
    page.wait_for_timeout(2800)                                                # termina la animación de entrada
    assert page.evaluate("typeof anime") == "function"
    assert page.locator("#dTot").text_content() == "25"
    page.locator(".sevchip[data-s='Crítico']").click()
    assert page.locator("#dTot").text_content() == "10"
    expect(page.locator("#sevGo")).to_be_visible()
    assert page.locator("[data-card].off").count() >= 1                       # los casos sin críticos se atenúan
    page.locator(".sevchip[data-s='Crítico']").click()                         # segundo clic: quita el filtro
    assert page.locator("#dTot").text_content() == "25" and page.locator("[data-card].off").count() == 0
    page.locator("[data-card='INC-002']").click()
    expect(page.locator("#drawer.open")).to_contain_text("INC-002")
    expect(page.locator("#drawer .fnd").first).to_be_visible()
    page.locator("#drGo").click()
    page.wait_for_url("**#/incidents")
    expect(page.locator("#INC-002")).to_be_visible()
    assert page.problems == []


def test_dashboard_timeline_cursor_and_lane_click(page):
    _open_sample(page)
    page.wait_for_timeout(2800)
    page.locator(".swim svg").hover(position={"x": 500, "y": 80})
    assert page.locator(".cursor span").text_content()[2] == ":"
    page.locator(".swim .lane-bg").first.click()
    expect(page.locator("#drawer.open")).to_be_visible()
    page.locator(".swim .seg").first.click()
    page.wait_for_url("**#/findings")
    assert page.problems == []


def test_dashboard_without_motion_has_everything_visible_at_once(browser, server):
    ctx = browser.new_context(reduced_motion="reduce")
    pg = ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.set_default_timeout(WAIT)
    pg.goto(server)
    _open_sample(pg)
    pg.mouse.move(0, 0)                                                        # sin el puntero sobre una tarjeta (atenuaría los carriles)
    ops = pg.evaluate("[...document.querySelectorAll('[data-card], .kpi, .swim .lane')].map(e => getComputedStyle(e).opacity)")
    assert ops and set(ops) == {"1"}
    assert pg.locator("[data-card]").count() == 6 and errs == []
    ctx.close()


def test_landing_and_phishing_share_glass_style_and_animate_in(page):
    page.wait_for_timeout(1500)                                                # termina la entrada escalonada
    assert page.locator(".view.glassv .landing").count() == 1
    assert set(page.evaluate("[...document.querySelectorAll('.landing > *')].map(e => getComputedStyle(e).opacity)")) == {"1"}
    assert "aur-on" not in (page.evaluate("document.body.className") or "")      # el inicio muestra el radar, sin aurora
    page.get_by_role("link", name="Phishing").click()
    assert "aur-on" not in (page.evaluate("document.body.className") or "")
    page.locator("#psample").click()
    expect(page.locator("body.aur-on")).to_have_count(1)
    expect(page.locator(".view.glassv")).to_contain_text("Correos sospechosos")
    page.get_by_role("link", name="Evaluar dominio").click()
    expect(page.locator(".view.glassv .ph-tabs")).to_be_visible()
    weights = page.evaluate("[...document.querySelectorAll('.ph-tabs a')].map(a => +getComputedStyle(a).fontWeight)")
    assert weights and all(w >= 700 for w in weights)
    assert page.problems == []


def test_landing_without_motion_is_complete_at_once(browser, server):
    ctx = browser.new_context(reduced_motion="reduce")
    pg = ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(server)
    pg.wait_for_selector(".landing")                                           # espera a que la app dibuje el inicio
    ops = pg.evaluate("[...document.querySelectorAll('.landing > *')].map(e => getComputedStyle(e).opacity)")
    assert ops and set(ops) == {"1"} and errs == []
    ctx.close()


def test_every_analysis_view_uses_glass_and_full_screen_aurora(page):
    _open_sample(page)
    vp = page.viewport_size
    for i in range(7):
        page.locator("#nav a").nth(i).click()
        page.wait_for_timeout(300)
        expect(page.locator(".view.glassv")).to_have_count(1)
        expect(page.locator("body.aur-on")).to_have_count(1)
        box = page.locator("#aurora").bounding_box()
        assert box["width"] >= vp["width"] - 1 and box["height"] >= vp["height"] - 1     # cubre toda la ventana, no un recuadro
    assert page.problems == []


def test_filter_chip_pressed_stays_legible_on_findings(page):
    _open_sample(page)
    page.locator("#nav a").nth(2).click()
    chip = page.get_by_role("button", name="Crítico (10)")
    chip.click()
    fg, bg = page.evaluate("""() => { const c = [...document.querySelectorAll('.chip[aria-pressed=true]')][0], s = getComputedStyle(c); return [s.color, s.backgroundColor]; }""")
    assert fg != bg
    assert page.problems == []


def test_light_theme_is_comfortable_not_pure_white_and_high_contrast(browser, server):
    ctx = browser.new_context(color_scheme="light")
    pg = ctx.new_page()
    pg.goto(server)
    res = pg.evaluate("""() => {
      const cs = getComputedStyle(document.documentElement), hex = (n) => cs.getPropertyValue(n).trim();
      const lum = (h) => { const v = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((c) => c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4); return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2]; };
      const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
      return { bg: hex('--bg'), panel: hex('--panel'), muted: ratio(hex('--muted'), hex('--bg')), ink: ratio(hex('--ink'), hex('--bg')) };
    }""")
    assert res["bg"].lower() != "#ffffff" and res["panel"].lower() != "#ffffff"        # sin blanco puro (cansa la vista)
    assert res["muted"] >= 4.5 and res["ink"] >= 7                                      # contraste accesible (WCAG AA / AAA)
    ctx.close()
