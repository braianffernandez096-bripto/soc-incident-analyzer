"""Feed JSON propio de indicadores con vencimiento (TTL)."""
import json
import os
from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import analysis, feed, main, misp, notify, wazuh

TODAY = date(2026, 11, 13)
HASH = "a" * 64


def items():
    return [
        {"valor": "203.0.113.50", "tipo": "ip", "descripcion": "C2 conocido", "fuente": "lab", "fecha": "2026-11-01"},
        {"value": "EVIL.example.com.", "type": "domain", "description": "Phishing", "added": "2026-06-01"},
        {"valor": HASH, "tipo": "hash", "fecha": "2026-11-10", "expira": "2026-12-31"},
        {"valor": "198.51.100.7"},                                        # sin fecha: no vence
        {"valor": "no es nada"},                                          # inválido
        {"valor": "203.0.113.99", "tipo": "dominio"},                     # el tipo no coincide con el valor
        "basura",
    ]


def test_parse_formatos_y_normalizacion():
    e, res = feed.parse(items())
    assert set(e) == {"203.0.113.50", "evil.example.com", HASH, "198.51.100.7"} and res == {"total": 7, "validos": 4, "ignorados": 3}
    assert feed.parse({"indicadores": items()[:1]})[0].keys() == {"203.0.113.50"}
    assert feed.parse(json.dumps({"indicators": items()[:1]}).encode())[0].keys() == {"203.0.113.50"}
    with pytest.raises(ValueError):
        feed.parse({"otra": []})
    with pytest.raises(ValueError):
        feed.parse("no es json")


def test_ttl_y_expira_explicito():
    e, _ = feed.parse(items(), ttl_days=30)
    assert e["203.0.113.50"]["expira"] == "2026-12-01"           # fecha + TTL
    assert e["evil.example.com"]["expira"] == "2026-07-01"
    assert e[HASH]["expira"] == "2026-12-31"                     # «expira» explícito manda sobre el TTL
    assert e["198.51.100.7"]["expira"] == ""                     # sin fecha, no vence
    assert feed.is_active(e["203.0.113.50"], TODAY) and not feed.is_active(e["evil.example.com"], TODAY)
    assert feed.is_active(e["198.51.100.7"], date(2099, 1, 1))
    assert feed.is_active({"expira": TODAY.isoformat()}, TODAY) and not feed.is_active({"expira": (TODAY - timedelta(days=1)).isoformat()}, TODAY)
    e0, _ = feed.parse(items(), ttl_days=0)
    assert e0["evil.example.com"]["expira"] == ""                # TTL 0: nada vence por tiempo


def test_archivo_se_relee_cuando_cambia(tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(items()[:1]))
    f = feed.Feed(str(p))
    f.ensure()
    assert f.ready and list(f.entries) == ["203.0.113.50"]
    p.write_text(json.dumps([{"valor": "198.51.100.7"}]))
    os.utime(p, (p.stat().st_atime, p.stat().st_mtime + 5))
    f.ensure()
    assert list(f.entries) == ["198.51.100.7"]
    p.write_text("roto")                                          # un archivo roto no borra lo que había
    os.utime(p, (p.stat().st_atime, p.stat().st_mtime + 10))
    f.ensure()
    assert list(f.entries) == ["198.51.100.7"] and f.error


def test_url_descarga_valida_y_conserva_la_anterior(tmp_path):
    body = {"b": json.dumps(items()[:1]).encode()}
    f = feed.Feed(url="https://feed.example/i.json", cache_dir=tmp_path)
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body["b"]))) as h:
        assert f.refresh_url(h) and f.ready
    body["b"] = b"<html>"
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body["b"]))) as h:
        assert not f.refresh_url(h)
    assert f.ready and f.error
    f2 = feed.Feed(url="https://feed.example/i.json", cache_dir=tmp_path)
    assert f2.load() and f2.ready                                 # la copia buena sigue en disco
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as h:
        assert not f2.refresh_url(h) and f2.ready


def test_from_env(monkeypatch):
    for k in ("FEED_PATH", "FEED_URL", "FEED_TTL_DAYS", "FEED_REFRESH_HOURS"):
        monkeypatch.delenv(k, raising=False)
    assert feed.Feed.from_env() is None
    monkeypatch.setenv("FEED_URL", "ftp://x")
    assert feed.Feed.from_env() is None
    monkeypatch.setenv("FEED_URL", "https://x/i.json")
    monkeypatch.setenv("FEED_TTL_DAYS", "45")
    assert feed.Feed.from_env().ttl == 45
    monkeypatch.setenv("FEED_TTL_DAYS", "abc")
    assert feed.Feed.from_env().ttl == 0
    monkeypatch.setenv("FEED_PATH", "/feed/i.json")
    assert feed.Feed.from_env().path == "/feed/i.json"


# ---------------------------------------------------------------- regla

def run(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df, meta = wazuh.rows_to_frame(rows)
    return analysis.analyze(df, meta)


def ssh_rows(ip="203.0.113.50", n=10):
    return [{"id": f"1700000300.{i}", "timestamp": f"2026-11-12T12:00:{i:02d}.000+0000", "rule": {"level": 5, "id": "5760", "description": "sshd: authentication failed"},
             "agent": {"id": "002", "name": "linux-1"}, "decoder": {"name": "sshd"},
             "full_log": f"Nov 12 12:00:{i:02d} linux-1 sshd[100]: Failed password for root from {ip} port 4242 ssh2"} for i in range(n)]


@pytest.fixture
def fd(tmp_path):
    e, s = feed.parse([{"valor": "203.0.113.50", "descripcion": "C2 conocido", "fuente": "lab", "fecha": "2026-11-01"},
                       {"valor": "evil.example.com", "fecha": "2020-01-01"}, {"valor": HASH}], ttl_days=3650)
    f = feed.Feed(str(tmp_path / "x.json"))
    f.entries, f.summary, f.ttl = e, s, 3650
    f.path = ""                                                    # sin archivo: se usa lo cargado en memoria
    f._loaded_at, f._refreshing = 1e12, True
    feed.set_feed(f)
    yield f
    feed.set_feed(None)


def test_regla_cruza_ip_y_cita_el_indicador(fd):
    a = run(ssh_rows())
    f = [x for x in a["findings"] if x["rule"] == "ctx_feed"]
    assert len(f) == 1 and f[0]["severity"] == "Alto" and f[0]["metrics"]["fuente"] == "lab" and len(f[0]["evidence_ids"]) == 10
    assert "C2 conocido" in f[0]["reasons"][0] and {"type": "IP", "value": "203.0.113.50", "note": "Coincide con tu feed"} in f[0]["iocs"]
    assert any(x["rule"] == "g_auth" for x in a["findings"])


def test_regla_cruza_dominio_y_subdominio_y_hash(fd):
    al = ssh_rows(ip="198.51.100.9", n=1)
    al[0]["full_log"] += " conexion a login.EVIL.example.com y sha256=" + HASH
    a = run(al)
    vals = {x["metrics"]["valor"]: x for x in a["findings"] if x["rule"] == "ctx_feed"}
    assert "evil.example.com" in vals and HASH in vals and vals["evil.example.com"]["metrics"]["tipo"] == "dominio"


def test_indicador_vencido_no_dispara(fd):
    fd.entries["203.0.113.50"]["expira"] = "2020-01-01"
    assert not [x for x in run(ssh_rows())["findings"] if x["rule"] == "ctx_feed"]
    assert fd.status()["expired"] >= 1 and fd.status()["active"] == len(fd.entries) - fd.status()["expired"]


def test_sin_feed_no_cambia_nada():
    feed.set_feed(None)
    assert not [x for x in run(ssh_rows())["findings"] if x["rule"] == "ctx_feed"]


def test_limites_y_aviso_y_estado(fd):
    assert "tu feed de indicadores" in " ".join(run(ssh_rows())["limitations"])
    assert "(Feed)" in notify.TelegramNotifier("t", "1").line({"rule": "ctx_feed", "severity": "Alto", "category": "Otras anomalías"})
    j = TestClient(main.app).get("/api/context/status").json()
    assert j["feed"]["configured"] and j["feed"]["indicators"] == 3 and "x.json" not in json.dumps(j)


def test_cache_de_misp_configurable(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://m")
    monkeypatch.setenv("MISP_KEY", "k")
    monkeypatch.setenv("MISP_CACHE_SECONDS", "30")
    assert misp.MispClient.from_env().cache_ok == 30
    monkeypatch.setenv("MISP_CACHE_SECONDS", "x")
    assert misp.MispClient.from_env().cache_ok == misp.CACHE_OK
    n, t = {"c": 0}, [0.0]

    def h(r):
        n["c"] += 1
        return httpx.Response(200, json={})
    c = misp.MispClient("https://m", "k", http=httpx.Client(transport=httpx.MockTransport(h)), clock=lambda: t[0], cache_seconds=30)
    c.search(["203.0.113.50"]); c.search(["203.0.113.50"])
    assert n["c"] == 1
    t[0] = 31
    c.search(["203.0.113.50"])
    assert n["c"] == 2
