"""Ejemplo de 500 eventos (SIEM mixto): 7 incidentes, 3 señuelos que no deben alertar y el mismo resultado en los 3 formatos."""
from pathlib import Path

import pytest

from backend.analysis import analyze
from backend.parser import load_events

DIR = Path(__file__).parents[2] / "sample_data"


def _run(ext):
    p = DIR / f"SIEM_Logs_500_Eventos.{ext}"
    df, meta = load_events(p.read_bytes(), p.name)
    return df, analyze(df, meta)


@pytest.fixture(scope="module")
def res():
    return _run("csv")[1]


def test_same_result_in_csv_xlsx_json(res):
    for ext in ("xlsx", "json"):
        df, other = _run(ext)
        assert len(df) == 500
        assert [i["title"] for i in other["incidents"]] == [i["title"] for i in res["incidents"]]
        assert len(other["findings"]) == len(res["findings"])


def test_seven_incidents_with_expected_themes(res):
    titles = " | ".join(i["title"] for i in res["incidents"])
    assert len(res["incidents"]) == 7
    for word in ("Fuerza bruta SSH", "Exfiltración", "Túnel DNS", "Ataque web", "Ransomware", "identidad cloud", "Persistencia"):
        assert word in titles


def test_edr_and_windows_accounts_are_one_incident(res):
    inc = next(i for i in res["incidents"] if "Ransomware" in i["title"])
    rules = {f["rule"] for f in res["findings"] if f["id"] in inc["finding_ids"]}
    assert {"g_phishing", "g_ransomware", "cmd_anti_recovery", "mass_access"} <= rules


def test_decoys_do_not_alert(res):
    text = " ".join(f["title"] + f["explanation"] for f in res["findings"])
    assert "10.20.9.9" not in text           # escáner interno bajo el umbral
    assert not [f for f in res["findings"] if f["rule"] in ("mass_access", "sensitive_share") and "inanc" in f["title"]]   # 6 archivos de finanzas
    assert "203.0.113.141" not in text       # subida legítima de 9 MB
