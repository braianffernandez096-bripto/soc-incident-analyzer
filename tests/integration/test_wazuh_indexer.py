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


ALERTS = {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [HITS["hits"]["hits"][0]]}}
RAW = {"hits": {"total": {"value": 640, "relation": "eq"}, "hits": [
    {"_index": "wazuh-archives-4.x-2026.11.13", "_source": {"@timestamp": "2026-11-13T14:00:04Z", "agent": {"name": "DESKTOP-2C8LOKA"}, "full_log": "{\"win\":{}}",
                                                            "data": {"win": {"system": {"eventID": "4624", "providerName": "Microsoft-Windows-Security-Auditing", "message": "An account was successfully logged on."},
                                                                             "eventdata": {"targetUserName": "Braian", "ipAddress": "127.0.0.1"}}}}},
    {"_index": "wazuh-archives-4.x-2026.11.13", "_source": {"@timestamp": "2026-11-13T14:00:07Z", "agent": {"name": "DESKTOP-2C8LOKA"}, "full_log": "linea   cruda\ncon espacios", "location": "journald"}}]}}


def router(seen):
    def h(req):
        index = str(req.url).split("/_search")[0].rsplit("/", 1)[-1]
        seen[index] = {"url": str(req.url), "body": json.loads(req.content), "auth": req.headers["authorization"]}
        return httpx.Response(200, json=ALERTS if index == "wazuh-alerts-*" else RAW)
    return h


def test_alertas_y_crudos_se_consultan_por_separado(env):
    seen = {}
    f = {**FINDING, "users": ["usuariofalso"]}
    r = WI.context_for(f, client(router(seen)))
    a, w = seen["wazuh-alerts-*"], seen["wazuh-archives-*"]
    assert "ignore_unavailable=true" in a["url"] and a["auth"].startswith("Basic ")
    qa, qw = a["body"]["query"]["bool"], w["body"]["query"]["bool"]
    assert qa["filter"][0]["range"]["@timestamp"] == {"gte": "2026-11-13T13:55:05+00:00", "lte": "2026-11-13T14:06:00+00:00"}       # ±5 min
    assert qw["filter"][0]["range"]["@timestamp"] == {"gte": "2026-11-13T13:58:35+00:00", "lte": "2026-11-13T14:02:30+00:00"}       # ±90 s
    assert a["body"]["size"] == 100 and w["body"]["size"] == 50 and a["body"]["sort"] == [{"@timestamp": "asc"}]
    assert qw["must_not"] == [{"exists": {"field": "rule.id"}}] and "must_not" not in qa          # los crudos excluyen lo que ya es alerta
    assert w["body"]["sort"][0] == {"_score": "desc"}
    terms = [t["terms"] for t in qw["should"]]
    assert any("DESKTOP-2C8LOKA" in t.get("agent.name", []) for t in terms)
    assert any(t.get("data.srcip") == ["203.0.113.50"] and t["boost"] == 5 for t in terms)
    assert any("data.win.eventdata.targetUserName" in t and t["boost"] == 5 for t in terms)
    assert r["alerts_total"] == 1 and r["raw_total"] == 640 and r["alerts_shown"] == 1 and r["raw_shown"] == 2 and r["shown"] == 3 and r["total"] == 641
    assert r["raw_events"] and r["archives_enabled"] and r["raw_window_sec"] == 90
    times = [e["time"] for e in r["events"]]
    assert times == sorted(times)                                                                 # mezcladas en orden cronológico
    al, c1, c2 = r["events"][1], r["events"][0], r["events"][2]
    assert al["rule"] == "60122" and al["user"] == "admin" and al["ip"] == "203.0.113.50" and al["event_id"] == "4625" and not al["raw"]
    assert c1["raw"] and c1["description"] == "Windows 4624 (Security-Auditing)" and c1["detail"] == "An account was successfully logged on." and c1["user"] == "Braian"
    assert c2["raw"] and c2["detail"] == "linea cruda con espacios" and c2["description"] == "journald"


def test_crudos_no_muestran_json(env):
    hit = {"_index": "wazuh-archives-4.x", "_source": {"@timestamp": "2026-11-13T14:00:04Z", "agent": {"name": "H"}, "full_log": '{"win":{"system":{}}}'}}
    assert WI.normalize_hit(hit)["detail"] == ""


def test_archivos_apagado_y_ventanas(env, monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_ARCHIVES", "off")
    monkeypatch.setenv("WAZUH_INDEXER_WINDOW_MIN", "10")
    seen = {}
    r = WI.context_for(FINDING, client(router(seen)))
    assert list(seen) == ["wazuh-alerts-*"] and seen["wazuh-alerts-*"]["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"].startswith("2026-11-13T13:50")
    assert not r["archives_enabled"] and r["raw_shown"] == 0
    monkeypatch.setenv("WAZUH_INDEXER_ARCHIVES", "")
    monkeypatch.setenv("WAZUH_INDEXER_RAW_MAX", "0")
    seen.clear()
    WI.context_for(FINDING, client(router(seen)))
    assert list(seen) == ["wazuh-alerts-*"]


def test_si_fallan_los_crudos_se_muestran_las_alertas(env):
    def h(req):
        if "wazuh-archives" in str(req.url):
            return httpx.Response(403)
        return httpx.Response(200, json=ALERTS)
    r = WI.context_for(FINDING, client(h))
    assert r["alerts_shown"] == 1 and r["raw_shown"] == 0 and not r["raw_events"]


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
