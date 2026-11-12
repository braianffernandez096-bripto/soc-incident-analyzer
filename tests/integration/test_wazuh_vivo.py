"""Modo Wazuh en vivo: traducción de alertas, endpoint con clave, ciclo de análisis, avisos a Telegram e instantánea para el panel."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main, notify, wazuh, wazuh_live

TOKEN = "x" * 24
HDR = {"X-Wazuh-Token": TOKEN}
ROOT = Path(__file__).resolve().parents[2]


def win(i, ts, eid, ed, host="WS-01", ch="Security", rl=5, sv="AUDIT_FAILURE", desc="x"):
    return {"id": f"1700000000.{i}", "timestamp": ts, "rule": {"level": rl, "description": desc, "id": "60122"},
            "agent": {"id": "001", "name": host},
            "data": {"win": {"system": {"eventID": eid, "channel": ch, "computer": host + ".corp.local", "severityValue": sv}, "eventdata": ed}}}


def ssh(i, ts, ip="198.51.100.9"):
    return {"id": f"1700000001.{i}", "timestamp": ts, "rule": {"level": 5, "description": "sshd: authentication failed", "id": "5760"},
            "agent": {"id": "002", "name": "linux-1"}, "decoder": {"name": "sshd"},
            "full_log": f"Nov 12 13:00:{i:02d} linux-1 sshd[100]: Failed password for root from {ip} port 4242 ssh2"}


def ataque():
    a = [win(i, f"2026-11-12T12:00:{i:02d}.100+0000", "4625", {"targetUserName": "admin", "targetDomainName": "CORP", "ipAddress": "203.0.113.50",
                                                                "logonType": "3"}) for i in range(12)]
    a.append(win(20, "2026-11-12T12:01:10.000+0000", "4624", {"targetUserName": "admin", "targetDomainName": "CORP", "ipAddress": "203.0.113.50",
                                                              "logonType": "3"}, sv="AUDIT_SUCCESS", rl=3))
    a.append(win(21, "2026-11-12T12:01:20.000+0000", "4672", {"subjectUserName": "admin", "subjectDomainName": "CORP",
                                                              "privilegeList": "SeDebugPrivilege"}, sv="AUDIT_SUCCESS"))
    a.append(win(22, "2026-11-12T12:02:00.000+0000", "10", {"sourceImage": "C:\\Windows\\Temp\\x.exe", "targetImage": "C:\\Windows\\system32\\lsass.exe",
                                                            "grantedAccess": "0x1fffff"}, ch="Microsoft-Windows-Sysmon/Operational", rl=12))
    return a


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST", "on")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", TOKEN)
    monkeypatch.setenv("WAZUH_AUTOCYCLE", "off")
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    sent = []
    monkeypatch.setattr(main, "_LIVE", wazuh_live.LiveState(notifier=notify.TelegramNotifier("t", "1", post=lambda u, p: sent.append(p) or True)))
    main.SESSIONS.clear()
    main._hits.clear()
    c = TestClient(main.app)
    c.sent = sent
    return c


# ---------------------------------------------------------------- traductor

def test_traductor_windows_linux_y_otros():
    rows, st = wazuh.normalize_alerts(ataque() + [ssh(1, "2026-11-12T13:00:01.000+0000")] + [
        {"id": "z1", "timestamp": "2026-11-12T14:00:00.000+0000", "rule": {"level": 3, "id": "550", "description": "Integrity checksum changed",
                                                                          "mitre": {"id": ["T1565"]}}, "agent": {"name": "linux-1"}}])
    assert st["windows"] == 15 and st["linux_auth"] == 1 and st["otro"] == 1 and st["descartadas"] == 0
    by = {r["Log_ID"]: r for r in rows}
    f = by["1700000000.0"]
    assert (f["Event_ID"], f["Result"], f["User"], f["Source_IP"], f["Hostname"]) == ("4625", "Failure", "CORP\\admin", "203.0.113.50", "WS-01")
    assert "LogonType=3" in f["Event_Description"] and "TargetUserName: admin" in f["Event_Description"]
    assert by["1700000000.22"]["Log_Source"] == "Sysmon" and "TargetImage:" in by["1700000000.22"]["Event_Description"]
    s = by["1700000001.1"]
    assert (s["Event_ID"], s["Result"], s["User"], s["Source_IP"]) == ("ssh_login", "failed", "root", "198.51.100.9")
    assert by["z1"]["Event_ID"] == "wazuh_regla_550" and "T1565" in by["z1"]["Event_Description"]


@pytest.mark.parametrize("level,sev", [(0, "Informational"), (3, "Informational"), (5, "Low"), (8, "Medium"), (10, "High"), (12, "Critical"), ("x", "Informational")])
def test_nivel_a_severidad(level, sev):
    assert wazuh.severity_from_level(level) == sev


def test_descartes_con_motivo():
    rows, st = wazuh.normalize_alerts(["hola", {"a": 1}, {"id": "1", "rule": {}, "timestamp": "ayer"}, {"rule": {"level": 3}, "timestamp": "2026-11-12T12:00:00.000+0000"}])
    assert rows == [] and st["descartadas"] == 4
    assert st["motivos"] == {"no_es_objeto": 1, "sin_regla": 1, "sin_fecha_valida": 1, "sin_id": 1}


def test_datos_hostiles_se_recortan_y_sin_control():
    a = win(1, "2026-11-12T12:00:00.000+0000", "4688", {"commandLine": "A" * 9000 + "\x00\x07", "subjectUserName": "<script>x</script>\x1b[31m"})
    r, _ = wazuh.normalize_alert(a)
    assert len(r["Process_CommandLine"]) <= wazuh.MAX_CMD and "\x00" not in r["Process_CommandLine"] and "\x1b" not in r["User"]
    assert len(r["Event_Description"]) <= wazuh.MAX_DESC


def test_ip_basura_y_zona_horaria():
    a = win(1, "2026-11-12T12:00:00.000-0300", "4625", {"targetUserName": "u", "ipAddress": "-"})
    r, _ = wazuh.normalize_alert(a)
    assert r["Source_IP"] == "" and r["Timestamp"] == "2026-11-12T12:00:00.000-03:00"
    df, meta = wazuh.rows_to_frame([r])
    assert str(df["Timestamp"].iloc[0]).startswith("2026-11-12 15:00:00")      # el motor lo pasa a UTC


# ---------------------------------------------------------------- endpoint

def test_apagado_por_defecto_no_existe(monkeypatch):
    monkeypatch.delenv("WAZUH_INGEST", raising=False)
    c = TestClient(main.app)
    assert c.post("/api/wazuh/alerts", json={}, headers=HDR).status_code == 404
    assert c.get("/api/wazuh/status").json() == {"enabled": False}
    assert c.get("/api/wazuh/session").status_code == 404


def test_sin_clave_decente_queda_cerrado(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST", "on")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", "corta")
    c = TestClient(main.app)
    assert c.post("/api/wazuh/alerts", json={}, headers={"X-Wazuh-Token": "corta"}).status_code == 404
    assert c.get("/api/wazuh/status").json() == {"enabled": False}


def test_clave_incorrecta_y_bloqueo_por_fuerza_bruta(api):
    assert api.post("/api/wazuh/alerts", json={}).status_code == 401
    assert api.post("/api/wazuh/alerts", json={}, headers={"X-Wazuh-Token": "y" * 24}).status_code == 401
    codes = [api.post("/api/wazuh/alerts", json={}, headers={"X-Wazuh-Token": "y" * 24}).status_code for _ in range(12)]
    assert 429 in codes


def test_ingesta_formas_y_limites(api):
    one = ataque()[0]
    assert api.post("/api/wazuh/alerts", json=one, headers=HDR).json()["accepted"] == 1            # una alerta (lo que manda integratord)
    r = api.post("/api/wazuh/alerts", json={"alerts": ataque()}, headers=HDR)                      # contenedor
    assert r.status_code == 202 and r.json()["accepted"] == 14 and r.json()["duplicates"] == 1       # la primera ya estaba
    assert api.post("/api/wazuh/alerts", json=ataque(), headers=HDR).json()["duplicates"] == 15      # lista
    assert api.post("/api/wazuh/alerts", content=b"{no es json", headers=HDR).status_code == 400
    assert api.post("/api/wazuh/alerts", json=[one] * 201, headers=HDR).status_code == 413
    assert api.post("/api/wazuh/alerts", content=b"[" + b" " * (1024 * 1024 + 1) + b"]", headers=HDR).status_code == 413


def test_la_clave_de_la_app_no_reemplaza_la_de_wazuh(api, monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", "a" * 20)
    assert api.post("/api/wazuh/alerts", json=ataque()[0], headers={"Authorization": "Bearer " + "a" * 20}).status_code == 401
    assert api.post("/api/wazuh/alerts", json=ataque()[0], headers=HDR).status_code == 202       # su propia clave basta
    assert api.get("/api/wazuh/status").status_code == 401                                         # el resto sí exige la de la app
    assert api.get("/api/wazuh/status", headers={"Authorization": "Bearer " + "a" * 20}).status_code == 200


# ---------------------------------------------------------------- ciclo, avisos y panel

def test_ciclo_detecta_avisa_una_sola_vez_y_abre_instantanea(api):
    api.post("/api/wazuh/alerts", json={"alerts": ataque()}, headers=HDR)
    assert main._live_cycle() is True
    assert len(api.sent) == 1
    msg = api.sent[0]["text"]
    assert "Escalar" in msg and "Crítico" in msg
    for secreto in ("203.0.113.50", "admin", "lsass", "WS-01", "CORP"):          # el aviso no filtra usuarios, IPs, procesos ni equipos
        assert secreto.lower() not in msg.lower()
    assert main._live_cycle() is False                                           # sin alertas nuevas no hay ciclo
    api.post("/api/wazuh/alerts", json=ataque(), headers=HDR)                    # las mismas alertas: duplicadas
    assert main._live_cycle() is False and len(api.sent) == 1
    st = api.get("/api/wazuh/status").json()
    assert st["enabled"] and st["rows"] == 15 and st["has_analysis"] and st["telegram"]

    res = api.get("/api/wazuh/session").json()
    assert res["filename"] == "Alertas de Wazuh (en vivo)"
    rules = {f["rule"] for f in res["analysis"]["findings"]}
    assert {"brute_force", "external_logon", "privilege", "cred_lsass"} <= rules
    assert any("Instantánea" in x for x in res["analysis"]["limitations"])
    sid = res["session_id"]
    assert api.get(f"/api/sessions/{sid}/triage").status_code == 200                # es una sesión normal: triaje, informe, etc.
    assert api.post(f"/api/sessions/{sid}/report.html", data={"client": "", "analyst": ""}).status_code == 200


def test_media_y_baja_van_al_resumen_no_al_instante(api):
    t = [1000.0]
    live = wazuh_live.LiveState(notifier=notify.TelegramNotifier("t", "1", post=lambda u, p: api.sent.append(p) or True), digest_minutes=60, clock=lambda: t[0])
    main._LIVE = live
    api.post("/api/wazuh/alerts", json=[ssh(i, f"2026-11-12T13:00:{i:02d}.000+0000") for i in range(8)], headers=HDR)
    t[0] += 61
    assert main._live_cycle() is True
    assert api.sent == []                                                          # Medio: espera al resumen
    api.post("/api/wazuh/alerts", json=[ssh(9, "2026-11-12T13:30:00.000+0000", ip="198.51.100.77")], headers=HDR)
    t[0] += 3600
    main._live_cycle()
    assert len(api.sent) == 1 and "resumen" in api.sent[0]["text"] and "falsos positivos" in api.sent[0]["text"]


def test_ventana_en_memoria_expulsa_lo_viejo_y_lo_excedente():
    t = [0.0]
    live = wazuh_live.LiveState(max_rows=100, window_hours=1, clock=lambda: t[0])
    live.ingest([win(i, f"2026-11-12T12:{i // 60:02d}:{i % 60:02d}.000+0000", "4625", {"targetUserName": "u"}) for i in range(150)])
    assert live.size == 100
    t[0] += 3601
    assert live.size == 0 and live.snapshot() == []


def test_un_fallo_del_motor_se_reintenta_y_no_tumba(api, monkeypatch):
    api.post("/api/wazuh/alerts", json=ataque(), headers=HDR)
    live = main._live()
    assert live.run_cycle(lambda df, meta: 1 / 0) is False
    assert live.run_cycle(main.analyze) is True


def test_sin_alertas_no_hay_instantanea(api):
    assert api.get("/api/wazuh/session").status_code == 404


# ---------------------------------------------------------------- Telegram

def test_formato_minimo_y_host_opcional():
    f = {"severity": "Alto", "tactic": "Acceso a credenciales <b>", "mitre": ["T1110", "T1078", "T1000"], "hosts": ["SRV-1"], "ips": ["10.0.0.9"],
         "title": "Fuerza bruta desde 10.0.0.9", "actor_users": ["root"]}
    n = notify.TelegramNotifier("t", "1")
    txt = n.format([f], "Titulo")
    assert "Escalar" in txt and "T1110" in txt and "T1078" in txt and "T1000" not in txt
    assert not any(x in txt for x in ("10.0.0.9", "root", "SRV-1", "Fuerza bruta", "<b>"))
    assert "Equipo: SRV-1" in notify.TelegramNotifier("t", "1", include_host=True).format([f], "T")
    assert "Panel: https://soc.example" in notify.TelegramNotifier("t", "1", base_url="https://soc.example/").format([f], "T")
    muchos = n.format([f] * 15, "T")
    assert "y 5 más" in muchos


def test_telegram_nunca_lanza_ni_filtra_el_token(monkeypatch, caplog):
    import httpx
    def boom(*a, **k):
        raise httpx.ConnectError("sin red")
    monkeypatch.setattr(httpx, "post", boom)
    n = notify.TelegramNotifier("123:SECRETO", "1")
    assert n.send("hola") is False
    assert "SECRETO" not in caplog.text


def test_from_env(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    assert notify.TelegramNotifier.from_env() is None
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "1:a")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "9")
    monkeypatch.setenv("APP_BASE_URL", "javascript:alert(1)")
    n = notify.TelegramNotifier.from_env()
    assert n.chat_id == "9" and n.base_url == "" and n.include_host is False


# ---------------------------------------------------------------- script de integración

def test_script_de_integracion(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("cust", ROOT / "integrations" / "wazuh" / "custom-soc-analyzer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    f = tmp_path / "alerta.json"
    f.write_text(json.dumps(ataque()[0]))
    assert mod.main(["x"]) == 2
    assert mod.main(["x", str(f), "k", "ftp://malo"]) == 2
    assert mod.main(["x", str(tmp_path / "no.json"), "k", "http://127.0.0.1:9"]) == 2
    seen = {}

    class Resp:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class Op:
        def open(self, req, timeout=0):
            seen.update(url=req.full_url, tok=req.get_header("X-wazuh-token"), body=json.loads(req.data))
            return Resp()
    monkeypatch.setattr(mod.urllib.request, "build_opener", lambda *h: Op())
    assert mod.main(["x", str(f), "clave", "http://analyzer:8000/api/wazuh/alerts"]) == 0
    assert seen["tok"] == "clave" and seen["body"]["id"] == "1700000000.0"


# ------------------------------------------------------------------ Docker

def test_compose_passes_every_wazuh_and_telegram_variable():
    """El compose solo pasa al contenedor las variables que enumera: si falta una, el modo no se activa con Docker."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    example = (root / ".env.example").read_text(encoding="utf-8")
    wanted = set(re.findall(r"^#?\s*((?:WAZUH|TELEGRAM)_[A-Z_]+)=", example, re.M)) | {"APP_BASE_URL"}
    assert {"WAZUH_INGEST", "WAZUH_INGEST_TOKEN", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"} <= wanted
    missing = sorted(v for v in wanted if f"- {v}=${{{v}:-}}" not in compose)
    assert not missing, f"docker-compose.yml no pasa: {missing}"


def test_wazuh_compose_override_joins_the_external_network_with_alias():
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    data = yaml.safe_load((root / "docker-compose.wazuh.yml").read_text(encoding="utf-8"))
    assert data["networks"]["wazuh"]["external"] is True
    assert "soc-analyzer" in data["services"]["analyzer"]["networks"]["wazuh"]["aliases"]
    assert "ports" not in data["services"]["analyzer"]      # el puerto sigue solo en 127.0.0.1


# ------------------------------------------------------------------ una ráfaga que llega a medias

def _ssh_burst(first, last, ip="127.0.0.1"):
    return [{"id": f"2.{i}", "timestamp": f"2026-11-12T21:41:{i:02d}.100+0000", "rule": {"level": 5, "description": "x", "id": "5710"},
             "agent": {"id": "002", "name": "linux-1"}, "decoder": {"name": "sshd"},
             "full_log": f"Nov 12 21:41:{i:02d} linux-1 sshd[2411]: Failed password for invalid user falso from {ip} port {49000 + i} ssh2"}
            for i in range(first, last)]


class _Sink:
    def __init__(self):
        self.sent = []

    def format(self, findings, title):
        return title + " | " + ",".join(f["severity"] for f in findings)

    def send(self, text):
        self.sent.append(text)
        return True


def test_burst_that_arrives_in_two_parts_alerts_when_severity_rises():
    """Primero llegan 6 intentos (Medio, va al resumen) y después los 6 restantes (Alto): el Alto debe avisar de inmediato, una sola vez."""
    sink, t = _Sink(), [0.0]
    live = wazuh_live.LiveState(notifier=sink, clock=lambda: t[0])
    live.ingest(_ssh_burst(0, 6))
    live.run_cycle(main.analyze)
    assert sink.sent == [] and len(live._digest) == 1                      # Medio: espera al resumen
    t[0] += 60
    live.ingest(_ssh_burst(6, 12))
    live.run_cycle(main.analyze)
    assert len(sink.sent) == 1 and "mayor severidad" in sink.sent[0] and "Alto" in sink.sent[0]
    assert live._digest == []                                              # ya no va también en el resumen
    t[0] += 60
    live.ingest(_ssh_burst(12, 14))
    live.run_cycle(main.analyze)
    assert len(sink.sent) == 1                                             # misma severidad: no repite


def test_same_severity_finding_is_not_repeated_and_lower_severity_does_not_realert():
    sink = _Sink()
    live = wazuh_live.LiveState(notifier=sink)
    live.ingest(_ssh_burst(0, 12))
    live.run_cycle(main.analyze)
    assert len(sink.sent) == 1 and "nuevo(s) para revisar" in sink.sent[0]
    live._dirty = True
    live.run_cycle(main.analyze)
    assert len(sink.sent) == 1
