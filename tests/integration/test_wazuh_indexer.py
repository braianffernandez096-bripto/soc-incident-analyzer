"""Contexto de un hallazgo desde el Indexer de Wazuh."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import main, wazuh_indexer as WI

FINDING = {"time_start": "2026-11-13 14:00:05", "time_end": "2026-11-13 14:01:00", "hosts": ["DESKTOP-2C8LOKA.corp.local"], "ips": ["203.0.113.50"]}
HITS = {"hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
    {"_index": "wazuh-alerts-4.x-2026.11.13", "_source": {"@timestamp": "2026-11-13T14:00:06.100Z", "agent": {"name": "DESKTOP-2C8LOKA"},
                                                         "rule": {"id": "60122", "level": 5, "description": "Logon failure - unknown user"},
                                                         "data": {"win": {"system": {"eventID": "4625"}, "eventdata": {"ipAddress": "203.0.113.50", "targetUserName": "admin"}}}}},
    {"_index": "wazuh-archives-4.x-2026.11.13", "_source": {"@timestamp": "2026-11-13T14:00:07Z", "agent": {"name": "DESKTOP-2C8LOKA"},
                                                            "full_log": "linea   cruda\ncon espacios", "location": "journald"}}]}}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://idx.lab:9200/")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "ro")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "SECRETA")
    for k in ("WAZUH_INDEXER_ARCHIVES", "WAZUH_INDEXER_WINDOW_MIN", "WAZUH_INDEXER_MAX"):
        monkeypatch.delenv(k, raising=False)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_no_configurado(monkeypatch):
    for k in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    assert not WI.configured()
    monkeypatch.setenv("WAZUH_INDEXER_URL", "ftp://x")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "u")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "p")
    assert not WI.configured()


def test_consulta_armada_por_el_servidor(env):
    seen = {}

    def h(req):
        seen["url"], seen["body"], seen["auth"] = str(req.url), json.loads(req.content), req.headers["authorization"]
        return httpx.Response(200, json=HITS)
    r = WI.context_for(FINDING, client(h))
    assert seen["url"].startswith("https://idx.lab:9200/wazuh-alerts-*,wazuh-archives-*/_search?") and "ignore_unavailable=true" in seen["url"]
    q = seen["body"]["query"]["bool"]
    assert q["filter"][0]["range"]["@timestamp"] == {"gte": "2026-11-13T13:55:05+00:00", "lte": "2026-11-13T14:06:00+00:00"}     # ±5 min
    terms = [t["terms"] for t in q["should"]]
    assert {"agent.name": ["DESKTOP-2C8LOKA.corp.local", "DESKTOP-2C8LOKA", "desktop-2c8loka", "DESKTOP-2C8LOKA.corp.local".lower()]} in terms \
        or any("DESKTOP-2C8LOKA" in t.get("agent.name", []) for t in terms)
    assert {"data.srcip": ["203.0.113.50"]} in terms and seen["body"]["size"] == 100 and seen["auth"].startswith("Basic ")
    assert r["total"] == 2 and r["shown"] == 2 and r["raw_events"] and r["archives_enabled"]
    a, b = r["events"]
    assert a["rule"] == "60122" and a["level"] == "5" and a["user"] == "admin" and a["ip"] == "203.0.113.50" and a["event_id"] == "4625" and not a["raw"]
    assert b["raw"] and b["detail"] == "linea cruda con espacios"


def test_archivos_apagado_y_ventana(env, monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_ARCHIVES", "off")
    monkeypatch.setenv("WAZUH_INDEXER_WINDOW_MIN", "10")
    seen = {}

    def h(req):
        seen["url"], seen["body"] = str(req.url), json.loads(req.content)
        return httpx.Response(200, json={"hits": {"total": 0, "hits": []}})
    r = WI.context_for(FINDING, client(h))
    assert "wazuh-archives" not in seen["url"] and seen["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"].startswith("2026-11-13T13:50")
    assert r["events"] == [] and r["total"] == 0 and not r["archives_enabled"]


def test_errores_sin_filtrar_credenciales(env, caplog):
    for code in (401, 500):
        with pytest.raises(WI.IndexerError) as e:
            WI.context_for(FINDING, client(lambda r, c=code: httpx.Response(c)))
        assert "SECRETA" not in str(e.value) and "idx.lab" not in str(e.value)

    def boom(req):
        raise httpx.ConnectError("sin red")
    with pytest.raises(WI.IndexerError):
        WI.context_for(FINDING, client(boom))
    with pytest.raises(WI.IndexerError):
        WI.context_for(FINDING, client(lambda r: httpx.Response(200, json={"otra": 1})))
    with pytest.raises(WI.IndexerError):
        WI.context_for({**FINDING, "hosts": [], "ips": []}, client(lambda r: httpx.Response(200, json=HITS)))
    assert "SECRETA" not in caplog.text


def test_endpoint_y_aviso_en_el_analisis(env, monkeypatch):
    c = TestClient(main.app)
    s = c.post("/api/sample").json()
    sid = s["session_id"] if "session_id" in s else s["sid"]
    assert c.get(f"/api/sessions/{sid}").json()["analysis"]["wazuh_context"] is True
    fid = c.get(f"/api/sessions/{sid}").json()["analysis"]["findings"][0]["id"]
    monkeypatch.setattr(WI, "context_for", lambda f, http=None: {"events": [], "total": 0, "shown": 0, "window_min": 5, "raw_events": False, "archives_enabled": True, "from": "", "to": ""})
    assert c.get(f"/api/sessions/{sid}/findings/{fid}/wazuh-context").status_code == 200
    assert c.get(f"/api/sessions/{sid}/findings/F-999/wazuh-context").status_code == 404

    def fail(f, http=None):
        raise WI.IndexerError("mensaje seguro")
    monkeypatch.setattr(WI, "context_for", fail)
    r = c.get(f"/api/sessions/{sid}/findings/{fid}/wazuh-context")
    assert r.status_code == 502 and "mensaje seguro" in r.text and "SECRETA" not in r.text


def test_endpoint_cerrado_si_no_esta_configurado(monkeypatch):
    for k in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    c = TestClient(main.app)
    s = c.post("/api/sample").json()
    sid = s["session_id"] if "session_id" in s else s["sid"]
    assert c.get(f"/api/sessions/{sid}").json()["analysis"]["wazuh_context"] is False
    assert c.get(f"/api/sessions/{sid}/findings/F-001/wazuh-context").status_code == 404


def test_detalle_sin_barras_de_escape():
    hit = {"_index": "wazuh-alerts-4.x", "_source": {"@timestamp": "2026-11-13T17:52:02Z", "agent": {"name": "H"}, "rule": {"id": "92037", "level": 3, "description": "x"},
           "data": {"win": {"eventdata": {"commandLine": '\\"C:\\\\Windows\\\\system32\\\\net.exe\\" use \\\\\\\\localhost\\\\c$ /user:falso'}}}}}
    assert WI.normalize_hit(hit)["detail"] == '"C:\\Windows\\system32\\net.exe" use \\\\localhost\\c$ /user:falso'


def test_descripcion_de_la_regla_sin_barras_de_escape():
    hit = {"_index": "wazuh-alerts-4.x", "_source": {"@timestamp": "2026-11-13T17:52:02Z", "agent": {"name": "H"},
           "rule": {"id": "92037", "level": 3, "description": "started by C:\\\\Windows\\\\System32\\\\powershell.exe"}}}
    assert WI.normalize_hit(hit)["description"] == "started by C:\\Windows\\System32\\powershell.exe"
