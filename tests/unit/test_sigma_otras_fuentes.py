"""Reglas Sigma para SSH, web, DNS, Linux y nube: válidas, coherentes con las reglas de la app y que coinciden con las evidencias de los ejemplos."""
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

from backend import siemqueries as S
from backend.analysis import analyze
from backend.parser import load_events

yaml = pytest.importorskip("yaml")
SAMPLES = Path(__file__).resolve().parents[2] / "sample_data"


def _load(name):
    df, meta = load_events(str(SAMPLES / name))
    return df, analyze(df, meta)


@pytest.fixture(scope="module")
def multi():
    return _load("logs_multifuente.json")


@pytest.fixture(scope="module")
def big():
    return _load("SIEM_Logs_500_Eventos.csv")


def _doc(rule):
    return next(iter(yaml.safe_load_all(S.sigma_rule(rule))))


def _patterns(rule):
    """(modificador, valor) de todos los campos de las selecciones de la regla (la primera regla del documento)."""
    out = []
    for key, sel in _doc(rule)["detection"].items():
        if key == "condition":
            continue
        if isinstance(sel, list):
            out += [("contains", v) for v in sel]
            continue
        for k, v in sel.items():
            mod = k.split("|")[1] if "|" in k else "equals"
            if mod in ("contains", "endswith", "re", "equals"):
                out += [(mod, x) for x in (v if isinstance(v, list) else [v])]
    return out


def _hits(rule, text):
    """¿Alguna condición de la regla se cumple con este texto? Los regex y «endswith» se prueban por palabra, porque en Sigma se aplican
    a un campo (el nombre de dominio, la ruta del programa), no a una frase entera."""
    t = unquote(text)
    palabras = t.split()
    for mod, v in _patterns(rule):
        v = str(v)
        if mod == "re" and (re.search(v, t) or any(re.search(v, w) for w in palabras)):
            return True
        if mod == "contains" and v.lower() in t.lower():
            return True
        if mod == "endswith" and any(w.lower().endswith(v.lower().replace("\\\\", "\\")) for w in palabras):
            return True
        if mod == "equals" and v.lower() in (w.lower() for w in palabras):
            return True
    return False


def test_todas_las_reglas_sigma_son_yaml_valido_con_los_campos_obligatorios():
    for rule in S.SIGMA_ONLY:
        d = _doc(rule)
        assert d["title"] and d["id"] and d["status"] == "experimental"
        assert d["level"] in {"low", "medium", "high", "critical"}
        assert d["logsource"] and d["detection"]["condition"]
        assert d["tags"] and all(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in d["tags"]), rule
        assert d["falsepositives"] and d["description"]


def test_los_id_son_estables_y_distintos():
    ids = [d["id"] for r in sorted(S.ALL_SUPPORTED) if S.sigma_rule(r) for d in yaml.safe_load_all(S.sigma_rule(r))]
    ids = list(dict.fromkeys(ids))      # persist_run y persistence se repiten en el documento conjunto de g_persistence
    assert len(ids) == len(set(ids)) and len(ids) >= 30
    assert S.sigma_rule("g_web") == S.sigma_rule("g_web")


def test_estas_reglas_son_solo_sigma():
    for rule in S.SIGMA_ONLY:
        f = dict(rule=rule, time_start="2026-11-02 09:00:00", time_end="2026-11-02 09:10:00", hosts=["h"], users=[], actor_users=[], ips=[], link_ips=[])
        qs = S.queries_for(f)
        assert qs["sigma"] and qs["splunk"] is None and qs["kql"] is None, rule


def test_exfiltracion_y_comando_y_control_no_tienen_regla():
    for rule in ("g_exfil", "g_c2"):
        assert S.sigma_rule(rule) is None


def test_el_boton_se_ofrece_para_los_hallazgos_de_otras_fuentes(multi):
    _, a = multi
    assert {f["rule"] for f in a["findings"]} & S.SIGMA_ONLY
    assert set(a["siem_rules"]) == set(S.ALL_SUPPORTED)


@pytest.mark.parametrize("rule", ["g_web", "g_dns_tunnel", "g_mining", "g_ransomware", "g_cloud", "g_phishing"])
def test_la_regla_sigma_coincide_con_la_evidencia_de_los_ejemplos(rule, multi, big):
    """Si la app detecta el hallazgo en un ejemplo, la regla Sigma equivalente debe encontrar al menos una de sus filas de evidencia."""
    visto = 0
    for df, a in (multi, big):
        idx = df.set_index("Log_ID")
        for f in a["findings"]:
            if f["rule"] != rule:
                continue
            visto += 1
            textos = [" ".join(str(x) for x in (r["Event_Description"], r["Process_CommandLine"], r["Destination"], r["Event_ID"]))
                      for _, r in idx.loc[f["evidence_ids"]].iterrows()]
            assert any(_hits(rule, t) for t in textos), (rule, f["id"], textos[:2])
    assert visto, f"ningún ejemplo produce {rule}"


def test_g_auth_coincide_con_un_auth_log_real():
    df, a = _load("auth_log_ejemplo.txt")
    fallos = df[df["Event_Description"].str.contains("Failed password|Invalid user", regex=True)]
    assert len(fallos) and all(_hits("g_auth", t) for t in fallos["Event_Description"])
    assert not _hits("g_auth", "Accepted publickey for deploy from 10.0.0.15 port 51022 ssh2")


def test_g_persistence_en_linux_y_la_regla_conjunta():
    for ataque in ("echo 'ssh-rsa AAAA x' >> /home/u/.ssh/authorized_keys", "(crontab -l; echo '* * * * * /tmp/x') | crontab -",
                   "cp job /etc/cron.d/job"):
        assert _hits("g_persistence", ataque), ataque
    assert not _hits("g_persistence", "crontab -l")          # solo listar no es persistencia
    docs = list(yaml.safe_load_all(S.sigma_rule("g_persistence")))
    assert len(docs) == 3 and {d["logsource"].get("product") for d in docs} == {"linux", "windows"}


def test_g_privesc_g_cmd_y_g_share_probe_detectan_lo_esperado():
    assert _doc("g_privesc")["detection"]["condition"] == "selection_img and selection_file"     # hacen falta la herramienta Y el archivo
    for rule, ok, no in (("g_cmd", "powershell -ExecutionPolicy Bypass -File a.ps1", "powershell Get-Date"),
                         ("g_share_probe", "\\\\srv\\IPC$", "\\\\srv\\datos")):
        assert _hits(rule, ok), rule
        assert not _hits(rule, no), rule


def test_el_regex_de_dns_no_marca_nombres_normales():
    rx = re.compile(_doc("g_dns_tunnel")["detection"]["selection"]["query|re"])
    for ok in ("www.google.com", "autodiscover.contoso.com", "mail.example.org", "cdn1.static.example.com"):
        assert not rx.search(ok)
    for bad in ("a0b9f872c3d0e512a.malicious-tunnel.com", "x7f3k9q2m1z8w4p6.evil.net",
                "omg3ld2wdx3vu51cea9sk6kj8ux2jws5.2nzz01g1es.cdn-sync-update.net"):
        assert rx.search(bad)


def test_el_patron_web_no_marca_peticiones_normales():
    for normal in ("/products.php?id=42", "/index.html", "/search?q=zapatillas+rojas", "/api/v1/users?page=2"):
        assert not _hits("g_web", normal)
    for ataque in ("/products.php?id=1%20OR%201=1", "/a?u=' or '1'='1", "/../../etc/passwd", "/x?q=<script>alert(1)</script>", "/${jndi:ldap://x/a}"):
        assert _hits("g_web", ataque), ataque


def test_la_regla_de_nube_usa_los_mismos_eventos_que_la_app():
    from backend.detection_generic import _IAM_PRIV
    assert set(_doc("g_cloud")["detection"]["selection"]["eventName"]) == set(_IAM_PRIV)


def test_las_reglas_se_convierten_con_pysigma_cuando_esta_instalado():
    pytest.importorskip("sigma")
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    for rule in sorted(S.SIGMA_ONLY):
        assert SplunkBackend().convert(SigmaCollection.from_yaml(S.sigma_rule(rule))), rule


def test_el_paquete_incluye_cada_regla_una_sola_vez(multi, big):
    _, a = multi
    texto, n = S.sigma_bundle(a["findings"] + a["findings"])
    assert n == len({f["rule"] for f in a["findings"] if f["rule"] in S.ALL_SUPPORTED | {"brute_force"}})
    assert len(list(yaml.safe_load_all(texto))) >= n
