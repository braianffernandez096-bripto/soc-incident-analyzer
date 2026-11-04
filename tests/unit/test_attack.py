"""MITRE ATT&CK enrichment: bundled official data stays in sync with the rules; matrix and Navigator layer are well formed."""
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

from backend import attack

ROOT = Path(__file__).resolve().parents[2]
ID_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


def _builder():
    spec = importlib.util.spec_from_file_location("build_attack_data", ROOT / "scripts" / "build_attack_data.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _f(fid, severity, mitre):
    return SimpleNamespace(id=fid, severity=severity, mitre=mitre)


def test_every_technique_cited_by_the_code_exists_in_the_official_data():
    cited = {t for p in ("detection.py", "detection_generic.py", "phishing.py", "playbook.py", "ai.py") for t in ID_RE.findall((ROOT / "backend" / p).read_text(encoding="utf-8"))}
    assert len(cited) >= 25                                       # guard: the scan really found the techniques
    assert cited == set(attack.data()["techniques"]), "backend/data is out of sync: run scripts/build_attack_data.py"


def test_builder_script_sees_the_same_ids_as_the_data_file():
    assert set(_builder().referenced_ids()) == set(attack.data()["techniques"])


def test_bundled_data_is_complete_and_consistent():
    d = attack.data()
    assert d["domain"] == "enterprise-attack" and re.fullmatch(r"\d+\.\d+", d["attack_version"])
    for tid, t in d["techniques"].items():
        assert t["name"] and t["tactics"], tid
        assert t["url"] == attack.technique_url(tid)
        for tac in t["tactics"]:
            assert tac in d["tactics"] and tac in attack.TACTIC_ORDER and tac in attack.TACTIC_ES, (tid, tac)


def test_urls_and_labels():
    assert attack.technique_url("T1110") == "https://attack.mitre.org/techniques/T1110/"
    assert attack.technique_url("T1110.003") == "https://attack.mitre.org/techniques/T1110/003/"
    assert attack.label("T1110.003") == "T1110.003 Password Spraying"
    assert attack.label("T9999") == "T9999"                       # unknown id: just the id, never an exception


def test_matrix_groups_by_tactic_and_keeps_the_highest_severity():
    m = attack.build_matrix([_f("F-001", "Medio", ["T1110.003"]), _f("F-002", "Crítico", ["T1110.003", "T1190"]), _f("F-003", "Bajo", [])])
    cols = {t["key"]: t for t in m["tactics"]}
    assert [t["key"] for t in m["tactics"]] == [k for k in attack.TACTIC_ORDER if k in cols]     # kill-chain order
    cell = cols["credential-access"]["techniques"][0]
    assert cell["id"] == "T1110.003" and cell["count"] == 2 and cell["severity"] == "Crítico" and cell["finding_ids"] == ["F-001", "F-002"]
    assert "initial-access" in cols and m["findings_without_mapping"] == 1 and m["techniques_total"] == 2
    assert cols["credential-access"]["name_es"] == "Acceso a credenciales"


def test_a_technique_in_several_tactics_appears_in_each():
    m = attack.build_matrix([_f("F-001", "Alto", ["T1078"])])
    assert {t["key"] for t in m["tactics"]} >= {"initial-access", "persistence", "privilege-escalation"}
    assert m["techniques_total"] == 1


def test_unknown_techniques_are_reported_not_fatal():
    m = attack.build_matrix([_f("F-001", "Alto", ["T9999", "T1190"])])
    assert m["unknown"] == ["T9999"] and m["techniques_total"] == 1


def test_empty_matrix_and_layer():
    m = attack.build_matrix([])
    assert m["tactics"] == [] and attack.navigator_layer(m, "x")["techniques"] == []


def test_navigator_layer_follows_the_layer_format():
    m = attack.build_matrix([_f("F-001", "Crítico", ["T1110.003"]), _f("F-002", "Bajo", ["T1087"])])
    layer = attack.navigator_layer(m, "SOC Incident Analyzer - ejemplo.csv")
    assert layer["versions"] == {"attack": m["version"].split(".")[0], "navigator": attack.NAVIGATOR_VERSION, "layer": attack.LAYER_VERSION}
    assert layer["domain"] == "enterprise-attack" and layer["name"].startswith("SOC Incident Analyzer")
    e = {x["techniqueID"]: x for x in layer["techniques"]}
    assert e["T1110.003"]["tactic"] == "credential-access" and e["T1110.003"]["color"] == attack.SEV_COLOR["Crítico"]
    assert e["T1087"]["color"] == attack.SEV_COLOR["Bajo"] and e["T1110.003"]["score"] == 1
    for x in layer["techniques"]:
        assert x["tactic"] in attack.TACTIC_ORDER and x["enabled"] is True
    assert "F-001" in e["T1110.003"]["comment"] and layer["gradient"]["maxValue"] >= 1
    assert "evidencia" in layer["description"]


def test_layer_name_is_bounded():
    assert len(attack.navigator_layer(attack.build_matrix([]), "x" * 500)["name"]) == 120
