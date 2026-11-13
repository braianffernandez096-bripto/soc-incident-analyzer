"""Contexto opcional: CISA KEV, EPSS, MISP, regla de CVE en alertas de Wazuh y origen en el aviso de Telegram."""
import gzip
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import analysis, context, detection as D, main, misp, notify, wazuh

KEV = {"catalogVersion": "2026.11.10", "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
     "dueDate": "2021-12-24", "requiredAction": "Apply updates.", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2023-1111", "vendorProject": "Acme", "product": "Widget", "dateAdded": "2023-01-02", "dueDate": "2023-01-23",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "no-es-cve"}, "basura"]}
EPSS = ("#model_version:v2025.03.14,score_date:2026-11-11T12:55:00Z\ncve,epss,percentile\n"
        "CVE-2021-44228,0.94358,0.99990\nCVE-2023-1111,0.00200,0.40000\nCVE-2024-5555,0.31000,0.96000\nCVE-2024-6666,0.95,0.99\nCVE-2022-0001,abc,0.1\nroto\n")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTEXT_ENABLED", "on")
    s = context.Store(tmp_path)
    s.kev, s.kev_version = context.parse_kev(KEV)
    s.epss, s.epss_date = context.parse_epss(EPSS)
    s.loaded_at, s._refreshing = 1.0, True        # sin descargas en segundo plano durante las pruebas
    context.set_store(s)
    yield s
    context.set_store(None)


def vuln_alert(i, cve, host="srv-1", status="Active", pkg=("log4j-core", "2.14.1")):
    return {"id": f"1700000100.{i}", "timestamp": "2026-11-12T12:00:00.000+0000", "rule": {"level": 10, "id": "23504", "description": f"{cve} affects {pkg[0]}"},
            "agent": {"id": "003", "name": host}, "decoder": {"name": "json"},
            "data": {"vulnerability": {"cve": cve, "severity": "Critical", "status": status, "package": {"name": pkg[0], "version": pkg[1]}}}}


def run(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df, meta = wazuh.rows_to_frame(rows)
    return analysis.analyze(df, meta)


# ---------------------------------------------------------------- lectores

def test_parse_kev_tolera_basura():
    kev, ver = context.parse_kev(json.dumps(KEV).encode())
    assert ver == "2026.11.10" and set(kev) == {"CVE-2021-44228", "CVE-2023-1111"}
    assert kev["CVE-2021-44228"]["ransomware"] and not kev["CVE-2023-1111"]["ransomware"]
    assert context.parse_kev({"vulnerabilities": None})[0] == {}


def test_parse_epss_csv_y_gzip():
    ep, date = context.parse_epss(EPSS)
    assert date == "2026-11-11" and ep["CVE-2024-5555"] == (0.31, 0.96) and "CVE-2022-0001" not in ep and len(ep) == 4
    assert context.parse_epss(gzip.compress(EPSS.encode()))[0] == ep


def test_extract_cves():
    assert context.extract_cves("a cve-2021-44228 y CVE-2021-44228 y CVE-2023-1111; CVE-1-2") == ["CVE-2021-44228", "CVE-2023-1111"]


def test_apagado_por_defecto(monkeypatch):
    monkeypatch.delenv("CONTEXT_ENABLED", raising=False)
    context.set_store(None)
    assert context.get_store() is None


def test_refresh_guarda_valida_y_conserva_lo_anterior(tmp_path, monkeypatch):
    calls = {"kev": json.dumps(KEV).encode(), "epss": gzip.compress(EPSS.encode())}

    def handler(req):
        if "kev" in req.url.host or "cisa" in req.url.host:
            return httpx.Response(200, content=calls["kev"])
        return httpx.Response(200, content=calls["epss"])
    monkeypatch.setenv("CONTEXT_KEV_URL", "https://cisa.example/kev.json")
    monkeypatch.setenv("CONTEXT_EPSS_URL", "https://epss.example/e.csv.gz")
    s = context.Store(tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as h:
        res = s.refresh(h)
    assert res["kev"].startswith("ok") and res["epss"].startswith("ok") and s.ready
    assert s.lookup("CVE-2024-5555")["epss"] == 0.31 and s.lookup("CVE-1999-0000") is None
    # un archivo roto no pisa el bueno
    calls["kev"] = b"<html>no soy json</html>"
    with httpx.Client(transport=httpx.MockTransport(handler)) as h:
        res = s.refresh(h)
    assert res["kev"].startswith("error") and "CVE-2021-44228" in s.kev
    s2 = context.Store(tmp_path)
    assert s2.load() and "CVE-2021-44228" in s2.kev and s2.epss_date == "2026-11-11"
    assert s2.status()["kev_entries"] == 2


def test_refresh_error_de_red_no_lanza(tmp_path):
    def boom(req):
        raise httpx.ConnectError("sin red")
    s = context.Store(tmp_path)
    with httpx.Client(transport=httpx.MockTransport(boom)) as h:
        res = s.refresh(h)
    assert all(v.startswith("error") for v in res.values()) and not s.ready and s.error


# ---------------------------------------------------------------- regla de CVE

def test_traductor_de_wazuh_lleva_cve_paquete_y_estado():
    row, kind = wazuh.normalize_alert(vuln_alert(1, "CVE-2021-44228"))
    assert kind == "otro" and "CVE: CVE-2021-44228" in row["Event_Description"] and "Paquete: log4j-core 2.14.1" in row["Event_Description"]
    assert "Estado: Active" in row["Event_Description"]


def test_kev_con_ransomware_es_critico(store):
    a = run([vuln_alert(1, "CVE-2021-44228"), vuln_alert(2, "CVE-2021-44228", host="srv-2")])
    f = [x for x in a["findings"] if x["rule"] == "ctx_cve"]
    assert len(f) == 1 and f[0]["severity"] == "Crítico" and f[0]["metrics"]["equipos"] == 2 and f[0]["metrics"]["kev"]
    assert "CISA KEV" in f[0]["title"] and any("ransomware" in r for r in f[0]["reasons"]) and any("94" in r for r in f[0]["reasons"])


def test_kev_sin_ransomware_es_alto_y_epss_por_umbrales(store):
    a = run([vuln_alert(1, "CVE-2023-1111"), vuln_alert(2, "CVE-2024-5555"), vuln_alert(3, "CVE-2024-6666"), vuln_alert(4, "CVE-2030-0000")])
    sev = {x["metrics"]["cve"]: x["severity"] for x in a["findings"] if x["rule"] == "ctx_cve"}
    assert sev == {"CVE-2023-1111": "Alto", "CVE-2024-5555": "Medio", "CVE-2024-6666": "Alto"}      # sin datos o EPSS bajo: nada


def test_vulnerabilidad_corregida_no_dispara(store):
    a = run([vuln_alert(1, "CVE-2021-44228", status="Solved")])
    assert not [x for x in a["findings"] if x["rule"] == "ctx_cve"]


def test_apagado_o_sin_datos_no_cambia_nada(monkeypatch, tmp_path):
    monkeypatch.delenv("CONTEXT_ENABLED", raising=False)
    context.set_store(None)
    assert not [x for x in run([vuln_alert(1, "CVE-2021-44228")])["findings"] if x["rule"] == "ctx_cve"]
    monkeypatch.setenv("CONTEXT_ENABLED", "on")
    s = context.Store(tmp_path)
    s.loaded_at, s._refreshing = 1.0, True       # evita la descarga en segundo plano durante la prueba
    context.set_store(s)
    try:
        assert not [x for x in run([vuln_alert(1, "CVE-2021-44228")])["findings"] if x["rule"] == "ctx_cve"]
    finally:
        context.set_store(None)


def test_la_regla_figura_en_el_catalogo_y_tiene_guia(store):
    a = run([vuln_alert(1, "CVE-2021-44228")])
    assert {"ctx_cve", "ctx_misp"} <= {r["key"] for r in a["rules"]}
    from backend import playbook
    assert "ctx_cve" in playbook.PLAYBOOK and "ctx_misp" in playbook.PLAYBOOK


# ---------------------------------------------------------------- MISP

def misp_client(handler, **kw):
    return misp.MispClient("https://misp.lab/", "CLAVE-SECRETA", http=httpx.Client(transport=httpx.MockTransport(handler)), **kw)


RESP = {"response": {"Attribute": [
    {"value": "203.0.113.50", "type": "ip-dst", "category": "Network activity", "event_id": "7", "to_ids": True, "comment": "c2",
     "Event": {"id": "7", "info": "Feodo Tracker: botnet C2"}},
    {"value": "203.0.113.50", "type": "ip-dst", "event_id": "7", "to_ids": True, "Event": {"id": "7", "info": "dup"}},
    {"value": "203.0.113.50|443", "type": "ip-dst|port", "event_id": "8", "Event": {"id": "8", "info": "compuesto"}},
    "basura"]}}


def test_misp_consulta_y_parsea_sin_filtrar_la_clave(caplog):
    seen = {}

    def h(req):
        seen["url"], seen["auth"], seen["body"] = str(req.url), req.headers["authorization"], json.loads(req.content)
        return httpx.Response(200, json=RESP)
    c = misp_client(h)
    out = c.search(["203.0.113.50", "10.0.0.5", "8.8.8.8", "no-ip", "127.0.0.1"])
    assert seen["url"] == "https://misp.lab/attributes/restSearch" and seen["auth"] == "CLAVE-SECRETA"
    assert seen["body"]["value"] == ["203.0.113.50", "8.8.8.8"] and seen["body"]["to_ids"] == 1 and seen["body"]["enforceWarninglist"] is True
    assert list(out) == ["203.0.113.50"] and len(out["203.0.113.50"]) == 1 and out["203.0.113.50"][0]["event"].startswith("Feodo")
    c.search(["203.0.113.50"])                        # cache: no repite la consulta
    assert "CLAVE-SECRETA" not in caplog.text


def test_misp_errores_no_lanzan_y_se_reintentan(caplog):
    n = {"c": 0}
    t = [0.0]

    def h(req):
        n["c"] += 1
        return httpx.Response(403) if n["c"] == 1 else httpx.Response(200, json=RESP)
    c = misp.MispClient("https://misp.lab", "K", http=httpx.Client(transport=httpx.MockTransport(h)), clock=lambda: t[0])
    assert c.search(["203.0.113.50"]) == {}
    assert c.search(["203.0.113.50"]) == {} and n["c"] == 1          # error en caché breve
    t[0] = 120
    assert "203.0.113.50" in c.search(["203.0.113.50"]) and n["c"] == 2


def test_misp_privadas_solo_si_se_pide():
    c = misp_client(lambda r: httpx.Response(200, json={}))
    assert not c.queryable("192.168.1.5") and c.queryable("203.0.113.50") and c.queryable("a" * 64) and not c.queryable("abc")
    assert misp_client(lambda r: httpx.Response(200, json={}), include_private=True).queryable("192.168.1.5")


def test_misp_from_env(monkeypatch):
    for k in ("MISP_URL", "MISP_KEY", "MISP_VERIFY", "MISP_CA", "MISP_ONLY_IDS"):
        monkeypatch.delenv(k, raising=False)
    assert misp.MispClient.from_env() is None
    monkeypatch.setenv("MISP_URL", "ftp://x")
    monkeypatch.setenv("MISP_KEY", "k")
    assert misp.MispClient.from_env() is None
    monkeypatch.setenv("MISP_URL", "https://misp.lab")
    monkeypatch.setenv("MISP_ONLY_IDS", "0")
    c = misp.MispClient.from_env()
    assert c and not c.only_ids


def ssh_fail_rows():
    return [{"id": f"1700000200.{i}", "timestamp": f"2026-11-12T12:00:{i:02d}.000+0000", "rule": {"level": 5, "id": "5760", "description": "sshd: authentication failed"},
             "agent": {"id": "002", "name": "linux-1"}, "decoder": {"name": "sshd"},
             "full_log": f"Nov 12 12:00:{i:02d} linux-1 sshd[100]: Failed password for root from 203.0.113.50 port 4242 ssh2"} for i in range(10)]


def test_regla_misp_hallazgo_alto_con_ioc(monkeypatch):
    misp.set_client(misp_client(lambda r: httpx.Response(200, json=RESP)))
    try:
        a = run(ssh_fail_rows())
    finally:
        misp.set_client(None)
    f = [x for x in a["findings"] if x["rule"] == "ctx_misp"]
    assert len(f) == 1 and f[0]["severity"] == "Alto" and f[0]["metrics"]["valor"] == "203.0.113.50" and len(f[0]["evidence_ids"]) == 10
    assert {"type": "IP", "value": "203.0.113.50", "note": "Coincide con MISP"} in f[0]["iocs"]
    assert any(x["rule"] == "g_auth" for x in a["findings"])             # la regla de contexto no reemplaza a las demás


def test_regla_misp_sin_configurar_o_caido_no_rompe():
    misp.set_client(None)
    assert not [x for x in run(ssh_fail_rows())["findings"] if x["rule"] == "ctx_misp"]

    def boom(req):
        raise httpx.ConnectError("caído")
    misp.set_client(misp_client(boom))
    try:
        a = run(ssh_fail_rows())
    finally:
        misp.set_client(None)
    assert not [x for x in a["findings"] if x["rule"] == "ctx_misp"] and any(x["rule"] == "g_auth" for x in a["findings"])


# ---------------------------------------------------------------- Telegram y texto

def test_telegram_distingue_windows_de_ssh():
    n = notify.TelegramNotifier("t", "1")
    w = n.line({"rule": "brute_force", "severity": "Alto", "category": "Fuerza bruta", "tactic": "Acceso a credenciales", "mitre": ["T1110"], "evidence_ids": ["a"]})
    s = n.line({"rule": "g_auth", "severity": "Alto", "category": "Fuerza bruta", "tactic": "Acceso a credenciales", "mitre": ["T1110"], "evidence_ids": ["a"],
                "metrics": {"protocolo": "SSH"}})
    assert "Fuerza bruta (Windows)" in w and "Fuerza bruta (SSH)" in s and w != s
    assert "(Vulnerabilidad)" in n.line({"rule": "ctx_cve", "severity": "Alto", "category": "Otras anomalías"})
    assert "()" not in n.line({"rule": "desconocida", "severity": "Alto", "category": "X"})


def test_underclass_dice_informational_o_low():
    import pandas as pd
    from backend.parser import load_events  # noqa: F401
    a = run(ssh_fail_rows() + [vuln_alert(1, "CVE-2021-44228")])
    for f in a["findings"]:
        if f["rule"] == "siem_underclass":
            assert "Informational o Low" in f["title"]


def test_endpoint_de_estado(store, monkeypatch):
    misp.set_client(None)
    c = TestClient(main.app)
    j = c.get("/api/context/status").json()
    assert j["cve"]["enabled"] and j["cve"]["kev_entries"] == 2 and j["misp"] == {"configured": False}
    assert "CLAVE" not in json.dumps(j)


def test_limites_reflejan_el_contexto_usado(store, monkeypatch):
    misp.set_client(None)
    lim = " ".join(run([vuln_alert(1, "CVE-2021-44228")])["limitations"])
    assert "CISA KEV" in lim and "MISP" not in lim and "No hay inteligencia de amenazas" not in lim
    misp.set_client(misp_client(lambda r: httpx.Response(200, json={})))
    try:
        assert "tu MISP" in " ".join(run(ssh_fail_rows())["limitations"])
    finally:
        misp.set_client(None)
    context.set_store(None)
    monkeypatch.delenv("CONTEXT_ENABLED", raising=False)
    assert "No hay inteligencia de amenazas" in " ".join(run(ssh_fail_rows())["limitations"])


def test_archivos_de_ejemplo_de_la_documentacion(store):
    from pathlib import Path
    d = Path(__file__).resolve().parents[2] / "sample_data"
    from backend import parser
    df, meta = parser.load_events((d / "ejemplo_cve.csv").read_bytes(), "ejemplo_cve.csv")
    f = {x["metrics"]["cve"]: x for x in main.analyze(df, meta)["findings"] if x["rule"] == "ctx_cve"}
    assert f["CVE-2021-44228"]["severity"] == "Crítico" and f["CVE-2021-44228"]["metrics"]["equipos"] == 2       # la fila «Solved» no cuenta
    misp.set_client(misp_client(lambda r: httpx.Response(200, json=RESP)))
    try:
        df, meta = parser.load_events((d / "ejemplo_misp.csv").read_bytes(), "ejemplo_misp.csv")
        assert [x for x in main.analyze(df, meta)["findings"] if x["rule"] == "ctx_misp"]
    finally:
        misp.set_client(None)


def test_enlaces_de_las_guias_nuevas_existen():
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    for name in ("docs/MISP.md", "docs/SOLUCION_PROBLEMAS.md", "docs/CONTEXTO.md"):
        for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", (root / name).read_text(encoding="utf-8")):
            if not target.startswith("http"):
                assert (root / name).parent.joinpath(target).resolve().exists(), (name, target)
