"""Pruebas del motor de detección contra el Excel de ejemplo."""
from pathlib import Path

import pytest

from backend import detection as D
from backend.analysis import analyze
from backend.parser import ParseError, load_events

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


@pytest.fixture(scope="module")
def data():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


def finding(a, rule, contains=""):
    return next(f for f in a["findings"] if f["rule"] == rule and contains in f["title"])


def test_parser_loads_everything(data):
    df, _ = data
    assert len(df) == 715
    assert df["Log_ID"].is_unique
    assert list(df.columns)[:3] == ["Log_ID", "Timestamp", "Hostname"]


def test_documentation_ranges_are_external():
    # Python marca estos rangos como "privados"; para el análisis son externos.
    for ip in ("203.0.113.74", "198.51.100.77", "192.0.2.91", "203.0.113.88:443"):
        assert D.is_external(ip)
    for ip in ("10.10.1.14", "192.168.1.5", "172.16.0.9", "127.0.0.1", ""):
        assert not D.is_external(ip)


def test_six_distinct_incidents(data):
    _, a = data
    assert len(a["incidents"]) == 6
    sev = [i["severity"] for i in a["incidents"]]
    assert sev == ["Alto", "Crítico", "Crítico", "Crítico", "Alto", "Crítico"]
    # ventanas cronológicas y sin solape
    starts = [i["time_start"] for i in a["incidents"]]
    assert starts == sorted(starts)


def test_password_spraying(data):
    _, a = data
    f = finding(a, "brute_force", "203.0.113.74")
    assert f["metrics"]["intentos_fallidos"] == 33
    assert f["metrics"]["cuentas_objetivo"] == 8
    assert f["evidence_ids"][0] == "EVT-00057" and f["evidence_ids"][-1] == "EVT-00111"
    assert f["metrics"]["exitos_posteriores"] == ["EVT-00123"]
    assert f["severity"] == "Alto"


def test_rdp_bruteforce_then_admin_compromise(data):
    _, a = data
    bf = finding(a, "brute_force", "198.51.100.77")
    assert bf["metrics"]["intentos_fallidos"] == 4 and bf["metrics"]["cuentas_objetivo"] == 1
    lg = finding(a, "external_logon", "admin")
    assert lg["severity"] == "Crítico" and lg["evidence_ids"] == ["EVT-00188"]


def test_internal_noise_is_not_bruteforce(data):
    _, a = data
    assert all(D.is_external(f["metrics"]["ip_origen"]) for f in a["findings"] if f["rule"] == "brute_force")


def test_admin_chain_is_one_incident(data):
    _, a = data
    inc = next(i for i in a["incidents"] if "CORP\\admin" in i["actor_users"])
    rules = {f["rule"] for f in a["findings"] if f["incident_id"] == inc["id"]}
    assert {"brute_force", "external_logon", "privilege", "cmd_encoded_ps", "cmd_discovery", "lateral",
            "sensitive_share", "cmd_archive_staging", "outbound_shell"} <= rules
    assert set(inc["hosts"]) == {"APP-SRV01", "FS-SRV01"}
    lat = finding(a, "lateral")
    assert lat["metrics"]["origen"] == "APP-SRV01" and lat["metrics"]["destino"] == "FS-SRV01"


def test_backupsvc_incident_and_anti_recovery(data):
    _, a = data
    mass = finding(a, "mass_access")
    assert mass["metrics"]["archivos"] == 16 and mass["metrics"]["numeracion_consecutiva"] is True
    anti = finding(a, "cmd_anti_recovery")
    assert anti["severity"] == "Crítico" and anti["evidence_ids"] == ["EVT-00314"]
    assert mass["incident_id"] == anti["incident_id"]


def test_exfiltration_numbers(data):
    _, a = data
    f = finding(a, "exfil_proxy")
    assert f["metrics"]["peticiones"] == 22
    assert f["metrics"]["bytes_totales"] == 253_305_558
    assert f["severity"] == "Crítico"
    stage = finding(a, "cmd_archive_staging", "rrojas")
    assert stage["incident_id"] == f["incident_id"]


def test_persistence_beacon_interval(data):
    _, a = data
    f = finding(a, "persistence")
    assert f["metrics"]["ejecuciones"] == 5 and f["metrics"]["intervalo_s"] == 360 and f["metrics"]["periodico"]
    assert "wuhelper.exe" in " ".join(f["metrics"]["imagenes"])


def test_web_attack_rce(data):
    _, a = data
    w = finding(a, "web_attack")
    assert w["metrics"]["peticiones"] == 21 and w["metrics"]["posible_rce"] is True
    shell = finding(a, "cmd_web_service_shell")
    assert w["incident_id"] == shell["incident_id"] and shell["evidence_ids"] == ["EVT-00599"]


def test_siem_underclassification_and_data_quality(data):
    _, a = data
    f = finding(a, "siem_underclass")
    assert f["metrics"]["eventos_informational"] == 10 and f["incident_id"] is None
    assert finding(a, "dq_host_alias")["incident_id"] is None
    assert "dq_account_lookalike" in {x["rule"] for x in a["findings"]}


def test_incidents_not_merged_without_evidence(data):
    _, a = data
    # las cuentas atacadas por el spraying no fusionan los incidentes de rrojas/helpdesk/backupsvc
    spray = finding(a, "brute_force", "203.0.113.74")
    for rule in ("persistence", "exfil_proxy", "mass_access"):
        assert finding(a, rule)["incident_id"] != spray["incident_id"]
    assert len(a["hypotheses"]) >= 1 and all(h["confidence"] == "Baja" for h in a["hypotheses"])


def test_every_evidence_id_exists_in_the_excel(data):
    df, a = data
    known = set(df["Log_ID"])
    for f in a["findings"]:
        assert f["evidence_ids"], f["id"]
        assert set(f["evidence_ids"]) <= known
        assert f["severity"] in D.SEV_ORDER and f["reasons"]


def test_parse_errors_are_readable():
    with pytest.raises(ParseError):
        load_events(b"esto no es un excel")
