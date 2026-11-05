"""Consultas Splunk/KQL y reglas Sigma generadas a partir de los hallazgos."""
import re
from pathlib import Path

import pytest

from backend import siemqueries as S
from backend.analysis import analyze
from backend.parser import load_events

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv"


@pytest.fixture(scope="module")
def findings():
    df, meta = load_events(str(SAMPLE))
    return analyze(df, meta)["findings"]


def _base(rule, **kw):
    f = dict(rule=rule, time_start="2026-11-02 09:00:00", time_end="2026-11-02 09:10:00", hosts=["WS-01.corp.local"],
             users=["CORP\\ana"], actor_users=["CORP\\ana"], ips=["203.0.113.9"], link_ips=["203.0.113.9"])
    f.update(kw)
    return f


def test_every_supported_rule_has_splunk_and_kql():
    for rule in S.SUPPORTED:
        qs = S.queries_for(_base(rule))
        assert qs and qs["splunk"] and qs["kql"], rule


def test_unsupported_rules_have_no_queries():
    for rule in ("g_auth", "exfil_proxy", "web_attack", "dq_host_alias", "siem_underclass"):
        assert S.queries_for(_base(rule)) is None


def test_queries_use_the_finding_entities_and_window():
    qs = S.queries_for(_base("brute_force"))
    assert 'src_ip="203.0.113.9"' in qs["splunk"] and 'IpAddress == "203.0.113.9"' in qs["kql"]
    assert 'earliest="11/02/2026:08:30:00"' in qs["splunk"] and "datetime(2026-11-02 08:30:00)" in qs["kql"]
    assert 'host="WS-01*"' in S.queries_for(_base("persistence"))["splunk"]       # FQDN -> nombre corto + comodín


def test_every_finding_of_the_sample_is_either_covered_or_cleanly_skipped(findings):
    covered = 0
    for f in findings:
        qs = S.queries_for(f)
        assert (qs is not None) == (f["rule"] in S.SUPPORTED)
        covered += bool(qs)
    assert covered >= 5


@pytest.mark.parametrize("hostile", ['a"b', 'a\\"; | delete', "x\nindex=*", 'u" OR 1=1 //', "\\\\", "$(id)", "a`b"])
def test_hostile_values_cannot_escape_the_string_literal(hostile):
    f = _base("brute_force", ips=[hostile], link_ips=[hostile], hosts=[hostile], actor_users=[hostile], users=[hostile])
    for rule in S.SUPPORTED:
        f["rule"] = rule
        qs = S.queries_for(f)
        for txt in (qs["splunk"], qs["kql"]):
            # al quitar los literales correctamente escapados no puede quedar ninguna comilla suelta
            stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', txt)
            assert '"' not in stripped.replace('""', ""), (rule, hostile)


def test_control_characters_are_removed_from_entities():
    assert "\n" not in S.q("a\nb") and "\x00" not in S.q("a\x00b")


def test_sigma_is_valid_yaml_with_required_fields():
    yaml = pytest.importorskip("yaml")
    for rule in list(S.SUPPORTED) + ["brute_force"]:
        text = S.sigma_rule(rule)
        if not text:
            continue
        for doc in yaml.safe_load_all(text):
            assert doc["title"] and doc["id"] and doc["level"] in {"informational", "low", "medium", "high", "critical"}
            assert "detection" in doc or "correlation" in doc
            assert all(t.startswith("attack.t") for t in doc["tags"])
            if "detection" in doc:
                assert "condition" in doc["detection"] and doc["logsource"]


def test_sigma_ids_are_stable_between_runs():
    assert S.sigma_rule("cred_lsass") == S.sigma_rule("cred_lsass")


def test_sigma_bundle_lists_each_rule_once(findings):
    text, n = S.sigma_bundle(findings + findings)
    assert n >= 4 and text.count("\ntitle:") + text.startswith("title:") >= n


def test_sigma_lsass_uses_the_same_masks_and_exclusions_as_the_rule():
    t = S.sigma_rule("cred_lsass")
    assert "0x1fffff" in t and "\\\\svchost.exe" in t and "lsass.exe" in t


def test_command_queries_reuse_the_detection_regex():
    from backend import detection as D
    p = next(x for x in D.CMD_PATTERNS if x["key"] == "anti_recovery")
    assert "vssadmin" in p["rx"].pattern
    qs = S.queries_for(_base("cmd_anti_recovery"))
    assert "vssadmin" in qs["splunk"] and "vssadmin" in qs["kql"] and "vssadmin" in S.sigma_rule("cmd_anti_recovery")


def test_sigma_rules_parse_and_convert_with_pysigma_when_installed():
    """Comprobación con la librería oficial (opcional: pip install pysigma pysigma-backend-splunk). Detectó un CIDR inválido en su día."""
    pytest.importorskip("sigma")
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    text = "---\n".join(S.sigma_rule(r) for r in sorted(S.SUPPORTED | {"brute_force"}) if S.sigma_rule(r))
    col = SigmaCollection.from_yaml(text)
    assert len(col.rules) >= 12 and not any(r.errors for r in col.rules)
    assert "event_count >= 3" in "".join(SplunkBackend().convert(SigmaCollection([r for r in col.rules if "4625" in r.title or "Fuerza bruta" in r.title])))
