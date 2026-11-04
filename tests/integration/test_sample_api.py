"""Datos de ejemplo y estructura de la interfaz: el botón de ejemplo usa un archivo fijo del servidor, no uno elegido por el cliente."""
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main
from backend.main import app

client = TestClient(app)
FRONT = Path(__file__).resolve().parents[2] / "frontend"


def test_sample_runs_the_bundled_export():
    r = client.post("/api/sample", data={"client": "Cliente de prueba", "analyst": "Ana"})
    assert r.status_code == 200
    j = r.json()
    assert j["filename"] == main.SAMPLE_FILE.name and j["client"] == "Cliente de prueba" and j["analyst"] == "Ana"
    assert j["analysis"]["profile"]["rows"] == 715 and len(j["analysis"]["incidents"]) == 6
    assert client.get(f"/api/sessions/{j['session_id']}").status_code == 200


def test_sample_ignores_any_file_or_path_sent_by_the_client():
    r = client.post("/api/sample", data={"file": "../../etc/passwd", "path": "/etc/passwd"}, files={"f": ("x.csv", b"a,b\n1,2\n")})
    assert r.status_code == 200 and r.json()["filename"] == main.SAMPLE_FILE.name


def test_sample_without_the_bundled_file_is_a_clean_404(monkeypatch):
    monkeypatch.setattr(main, "SAMPLE_FILE", Path("/nonexistent/ejemplo.csv"))
    r = client.post("/api/sample")
    assert r.status_code == 404 and "ejemplo" in r.json()["detail"]


def test_sample_is_rate_limited_like_upload():
    main._hits.clear()
    codes = [client.post("/api/sample").status_code for _ in range(main.RATE_LIMITS["/api/upload"][0] + 2)]
    main._hits.clear()
    assert codes[-1] == 429 and codes[0] == 200


def test_ui_has_the_sample_button_and_one_settings_menu():
    html, js = (FRONT / "index.html").read_text(encoding="utf-8"), (FRONT / "app.js").read_text(encoding="utf-8")
    assert 'id="settingsBtn"' in html and 'aria-haspopup="true"' in html and 'role="menu"' in html
    assert html.index('id="settingsMenu"') < html.index('id="themeBtn"') < html.index('id="motionBtn"')      # both options live inside the menu
    assert 'id="sample"' in js and "/api/sample" in js and "Probar con datos de ejemplo" in js


def test_ui_pluralises_counts():
    js = (FRONT / "app.js").read_text(encoding="utf-8")
    assert "const plural =" in js and "hallazgo(s)" not in js


def test_landing_is_short_and_the_details_live_in_the_help_dialog():
    js = (FRONT / "app.js").read_text(encoding="utf-8")
    landing = js[js.index("function landing()"):js.index("function bindLanding()")]
    assert "hasta 25 MB" in landing and "Columnas esperadas" not in landing and "Elastic ECS" not in landing
    how = js[js.index("const showHow"):js.index("function initChrome()")]
    assert "Columnas esperadas" in how and "Timestamp" in how and "Event_ID" in how and "ECS" in how
    assert '$("#helpBtn").onclick = showHow' in js and '$("#fmtHelp").onclick = showHow' in js
