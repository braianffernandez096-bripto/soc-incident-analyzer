"""Reglas para logs que no son de Windows (SSH, web, DNS, correo, nube, Linux, endpoint) con un export multi-fuente."""
from pathlib import Path

import pytest

from backend.analysis import analyze
from backend.parser import load_events

SAMPLE = Path(__file__).parents[2] / "sample_data" / "logs_multifuente.json"
WINDOWS = Path(__file__).parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv"


@pytest.fixture(scope="module")
def res():
    df, meta = load_events(SAMPLE.read_bytes(), SAMPLE.name)
    return analyze(df, meta)


def _by_rule(res, rule):
    return [f for f in res["findings"] if f["rule"] == rule]


def test_loads_100_events_and_detects_nine_incidents(res):
    assert res["profile"]["rows"] == 100
    assert len(res["incidents"]) == 9


@pytest.mark.parametrize("rule,count", [
    ("g_web", 1), ("g_exfil", 1), ("g_phishing", 1), ("g_c2", 1), ("g_persistence", 1), ("g_share_probe", 1),
    ("g_ransomware", 1), ("g_privesc", 1), ("g_dns_tunnel", 1), ("g_cloud", 1), ("g_mining", 1), ("g_cmd", 1),
])
def test_each_scenario_produces_one_finding(res, rule, count):
    assert len(_by_rule(res, rule)) == count


def test_authentication_findings(res):
    auth = _by_rule(res, "g_auth")
    assert len(auth) == 3
    ssh = next(f for f in auth if "198.51.100.45" in f["title"])
    assert ssh["severity"] == "Crítico" and "T1078" in ssh["mitre"]
    spray = next(f for f in auth if "Password spraying" in f["title"])
    assert spray["metrics"]["cuentas_objetivo"] >= 10
    rdp = next(f for f in auth if f["metrics"]["protocolo"] == "RDP")
    assert rdp["metrics"]["origen_externo"] is False


def test_web_attack_chain_ends_in_exfiltration(res):
    inc = next(i for i in res["incidents"] if "exfiltración" in i["title"].lower())
    rules = {f["rule"] for f in res["findings"] if f["id"] in inc["finding_ids"]}
    assert {"g_web", "g_exfil"} <= rules


def test_ransomware_is_critical_and_detects_backup_deletion(res):
    f = _by_rule(res, "g_ransomware")[0]
    assert f["severity"] == "Crítico" and f["metrics"]["copias_borradas"] and f["metrics"]["archivos_cifrados"] >= 10


def test_phishing_attachment_name_is_clean_and_executed(res):
    f = _by_rule(res, "g_phishing")[0]
    assert f["metrics"]["adjunto"] == "invoice_urgent.pdf.exe" and f["metrics"]["ejecutado"]


def test_no_finding_mentions_windows_event_ids_or_sample_accounts(res):
    text = " ".join(f["title"] + f["explanation"] for f in res["findings"])
    assert "WEB-01" not in text and "mgarcia" not in text


def test_every_cited_technique_is_valid(res):
    from backend import attack
    known = set(attack.data()["techniques"] if "techniques" in attack.data() else attack.data())
    for f in res["findings"]:
        assert all(t in known for t in f["mitre"]), f["title"]


def test_windows_sample_is_unchanged():
    df, meta = load_events(WINDOWS.read_bytes(), WINDOWS.name)
    out = analyze(df, meta)
    assert len(out["findings"]) == 25 and len(out["incidents"]) == 6
    assert not [f for f in out["findings"] if f["rule"].startswith("g_")]
