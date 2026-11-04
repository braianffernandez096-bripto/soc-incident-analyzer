"""ATT&CK en la API: la matriz viaja en el análisis y la capa de Navigator se descarga sin enviar nada fuera."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)
SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv"


def _upload():
    r = client.post("/api/upload", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "text/csv")})
    assert r.status_code == 200, r.text
    return r.json()


def test_analysis_carries_the_attack_matrix_for_the_sample():
    a = _upload()["analysis"]["attack"]
    assert a["version"] and a["tactics"] and a["techniques_total"] >= 10 and a["unknown"] == []
    for f in _upload()["analysis"]["findings"]:
        for t in f["mitre"]:
            assert t in a["techniques"] and a["techniques"][t]["url"].startswith("https://attack.mitre.org/techniques/")


def test_every_matrix_cell_points_to_real_findings():
    res = _upload()
    ids = {f["id"] for f in res["analysis"]["findings"]}
    for tac in res["analysis"]["attack"]["tactics"]:
        for c in tac["techniques"]:
            assert c["finding_ids"] and set(c["finding_ids"]) <= ids and c["count"] == len(c["finding_ids"])


def test_navigator_layer_download():
    sid = _upload()["session_id"]
    r = client.get(f"/api/sessions/{sid}/attack-layer.json")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert 'filename="attack_navigator_layer.json"' in r.headers["content-disposition"]
    layer = json.loads(r.text)
    assert layer["domain"] == "enterprise-attack" and layer["techniques"] and layer["versions"]["layer"]
    assert SAMPLE.name in layer["name"]


def test_layer_does_not_leak_finding_titles_hosts_or_ips():
    sid = _upload()["session_id"]
    body = client.get(f"/api/sessions/{sid}/attack-layer.json").text
    res = client.get(f"/api/sessions/{sid}").json()["analysis"]
    for f in res["findings"][:20]:
        assert f["title"] not in body
    assert "Source_IP" not in body


def test_unknown_session_is_404():
    assert client.get("/api/sessions/nope/attack-layer.json").status_code == 404


def test_ui_declares_the_attack_view_and_only_links_to_mitre():
    js = (Path(__file__).resolve().parents[2] / "frontend" / "app.js").read_text(encoding="utf-8")
    assert '["attack", "ATT&CK"]' in js and "attack-layer.json" in js
    assert 'noopener noreferrer' in js and "attack\\.mitre\\.org" in js           # links validated against the MITRE domain
