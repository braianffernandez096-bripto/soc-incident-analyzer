"""Modo demo de Wazuh: la historia de ejemplo se detecta con el motor real, avisa sin filtrar datos y no abre nada que la ingesta real mantiene cerrado."""
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend import main, notify, wazuh, wazuh_demo, wazuh_live

TOKEN = "x" * 24
NOW = datetime(2026, 11, 15, 15, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def demo(monkeypatch):
    monkeypatch.delenv("WAZUH_INGEST", raising=False)
    monkeypatch.delenv("WAZUH_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setenv("WAZUH_DEMO", "on")
    monkeypatch.setenv("WAZUH_AUTOCYCLE", "off")
    sent = []
    monkeypatch.setattr(main, "_LIVE", wazuh_live.LiveState(
        notifier=notify.TelegramNotifier("t", "1", post=lambda u, p: sent.append(p) or True), label=wazuh_demo.LABEL))
    main.SESSIONS.clear()
    main._hits.clear()
    c = TestClient(main.app)
    c.sent = sent
    return c


def test_las_alertas_se_entienden_todas_y_son_ficticias():
    etapas = wazuh_demo.stages(NOW, "t")
    assert len(etapas) == 5
    alerts = [a for _, lote in etapas for a in lote]
    rows, st = wazuh.normalize_alerts(alerts)
    assert st["descartadas"] == 0 and len(rows) == len(alerts) == 12 + 1 + 2 + 1 + 8
    assert len({r["Log_ID"] for r in rows}) == len(rows)
    ips = {r["Source_IP"] for r in rows if r["Source_IP"]}
    assert ips == {"203.0.113.50", "198.51.100.9"}                  # rangos de documentación (RFC 5737): no apuntan a nadie real
    assert all(r["Timestamp"] <= "2026-11-15T15:00:10" for r in rows)   # nada en el futuro lejano


def test_ids_distintos_en_cada_ejecucion():
    a = {x["id"] for _, l in wazuh_demo.stages(NOW, "a") for x in l}
    b = {x["id"] for _, l in wazuh_demo.stages(NOW, "b") for x in l}
    assert not (a & b)


def test_la_historia_completa_dispara_las_reglas_esperadas(demo):
    live = main._live()
    assert wazuh_demo.replay(live, main._live_cycle, 0, sleep=lambda s: None, now=lambda: NOW) == 5
    df, meta, analysis = live.latest
    rules = {f["rule"] for f in analysis["findings"]}
    assert {"brute_force", "external_logon", "privilege", "cred_lsass", "persist_run"} <= rules


def test_el_aviso_sube_de_severidad_con_las_etapas_y_lleva_la_marca_demo(demo):
    live = main._live()
    wazuh_demo.replay(live, main._live_cycle, 0, sleep=lambda s: None, now=lambda: NOW)
    assert demo.sent, "debe avisar al menos una vez"
    assert all(p["text"].startswith("🧪 DEMO") for p in demo.sent)
    todo = "\n".join(p["text"] for p in demo.sent).lower()
    for secreto in ("203.0.113.50", "admin", "lsass", "ws-01", "svchelper"):      # la privacidad por defecto del aviso también rige en la demo
        assert secreto not in todo
    assert any("Crítico" in p["text"] for p in demo.sent)


def test_el_panel_se_abre_sin_clave_en_demo_y_dice_que_es_demo(demo):
    wazuh_demo.replay(main._live(), main._live_cycle, 0, sleep=lambda s: None, now=lambda: NOW)
    st = demo.get("/api/wazuh/status").json()
    assert st["enabled"] and st["demo"] is True and st["needs_token"] is False and st["rows"] == 24
    res = demo.get("/api/wazuh/session")
    assert res.status_code == 200
    body = res.json()
    assert body["filename"] == "Alertas de Wazuh (demo)"
    assert any("MODO DEMO" in x for x in body["analysis"]["limitations"])
    assert body["analysis"]["wazuh_context"] is False               # nunca se ofrece el Indexer sobre datos inventados
    sid = body["session_id"]
    assert demo.get(f"/api/sessions/{sid}/triage").status_code == 200
    assert demo.post(f"/api/sessions/{sid}/report.html", data={"client": "", "analyst": ""}).status_code == 200


def test_en_demo_no_existe_el_endpoint_de_ingesta(demo):
    for hdr in ({}, {"X-Wazuh-Token": ""}, {"X-Wazuh-Token": TOKEN}):
        assert demo.post("/api/wazuh/alerts", json={"id": "x"}, headers=hdr).status_code == 404       # sin clave vacía que «coincida»
    assert demo.get("/api/wazuh/status").json()["rows"] == 0


def test_la_demo_no_se_activa_si_hay_ingesta_real(demo, monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST", "on")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", TOKEN)
    assert wazuh_live.demo() is False and wazuh_live.ingest_usable() is True
    monkeypatch.setattr(main, "_LIVE", wazuh_live.LiveState())
    assert demo.get("/api/wazuh/session").status_code == 403         # real y sin APP_ACCESS_TOKEN: sigue cerrado, como siempre
    assert demo.get("/api/wazuh/status").json()["demo"] is False


def test_apagado_por_defecto(monkeypatch):
    monkeypatch.delenv("WAZUH_DEMO", raising=False)
    monkeypatch.delenv("WAZUH_INGEST", raising=False)
    assert wazuh_live.demo() is False and wazuh_live.usable() is False
    assert TestClient(main.app).get("/api/wazuh/status").json() == {"enabled": False}


@pytest.mark.parametrize("val,esperado", [("", 20), ("5", 5), ("0", 1), ("9999", 300), ("abc", 20)])
def test_intervalo_acotado(monkeypatch, val, esperado):
    monkeypatch.setenv("WAZUH_DEMO_SECONDS", val)
    assert wazuh_demo.interval() == esperado


def test_un_ciclo_que_falla_no_frena_la_historia(demo):
    llamadas = []

    def mal():
        llamadas.append(1)
        raise RuntimeError("boom")

    assert wazuh_demo.replay(main._live(), mal, 0, sleep=lambda s: None, now=lambda: NOW) == 5
    assert len(llamadas) == 5


def test_las_pausas_entre_etapas_son_las_configuradas(demo):
    pausas = []
    wazuh_demo.replay(main._live(), lambda: True, 7, sleep=pausas.append, now=lambda: NOW)
    assert pausas == [7, 7, 7, 7]
