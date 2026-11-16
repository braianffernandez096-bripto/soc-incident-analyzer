"""Confianza por hallazgo: cada ajuste a favor y en contra tiene su motivo, la criticidad no cambia y nada filtra datos al aviso.

Qué mide la confianza y sus límites: backend/confidence.py y docs/VALIDACION.md (sección 2.2).
"""
import importlib.util
from pathlib import Path

import pytest

from backend import confidence as C
from backend import detection as D
from backend import notify, triage
from backend.analysis import analyze
from backend.parser import load_events

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sample_data" / "SIEM_Logs_500_Eventos.xlsx"


def F(rule="persistence", sev="Alto", ev=("E1", "E2"), hosts=("WS-01",), users=("CORP\\ana",), actors=(), links=(), metrics=None,
      t0="2026-11-15 10:00:00", t1="2026-11-15 10:05:00", title=None):
    return D.Finding(rule=rule, title=title or f"Hallazgo {rule}", category="x", tactic="x", mitre=[], severity=sev, reasons=["r"], explanation="",
                     time_start=t0, time_end=t1, hosts=list(hosts), users=list(users), ips=[], actor_users=list(actors), link_ips=list(links),
                     evidence_ids=list(ev), metrics=metrics or {}, iocs=[])


def assess(f, others=()):
    C.assess(f, [f, *others])
    return f


# ---------------------------------------------------------------- punto de partida
@pytest.mark.parametrize("rule,level", [("cred_lsass", "Alta"), ("ctx_misp", "Alta"), ("persistence", "Media"), ("cmd_discovery", "Baja")])
def test_punto_de_partida_por_tipo_de_senal(rule, level):
    f = assess(F(rule=rule, ev=("E1", "E2", "E3")))
    assert f.confidence == level and f.confidence_basis


def test_observaciones_son_baja_y_lo_explican():
    f = assess(F(rule="siem_underclass"))
    assert f.confidence == "Baja" and "no un indicio de ataque" in f.confidence_basis and not f.confidence_for


# ---------------------------------------------------------------- ajustes generales
def test_corroboracion_independiente_sube():
    a = F(rule="persistence", ev=("E1",))
    b = F(rule="cmd_encoded_ps", ev=("E9",), title="PowerShell codificado en WS-01")
    assess(a, [b])
    assert a.confidence == "Alta" and any("independiente" in x and "PowerShell codificado" in x for x in a.confidence_for)


def test_misma_evidencia_no_es_corroboracion():
    a, b = F(rule="cmd_encoded_ps", ev=("E1",)), F(rule="cmd_download_cradle", ev=("E1",))
    assess(a, [b])
    assert not any("independiente" in x for x in a.confidence_for)


def test_otro_equipo_o_lejos_en_el_tiempo_no_corrobora():
    a = F(rule="persistence")
    otros = [F(rule="cmd_encoded_ps", ev=("E8",), hosts=("WS-99",)),
             F(rule="cmd_encoded_ps", ev=("E9",), t0="2026-11-15 18:00:00", t1="2026-11-15 18:01:00")]
    assess(a, otros)
    assert not a.confidence_for


def test_coincidencia_con_inteligencia_tiene_su_motivo():
    a = F(rule="brute_force", links=("203.0.113.9",), metrics={"intentos_fallidos": 20, "cuentas_objetivo": 1})
    b = F(rule="ctx_misp", ev=("E7",), links=("203.0.113.9",), title="IP en MISP")
    assess(a, [b])
    assert any("inteligencia de amenazas" in x for x in a.confidence_for)


def test_origen_interno_baja_y_externo_sube():
    interno = assess(F(rule="brute_force", links=("10.0.0.5",), metrics={"intentos_fallidos": 20, "cuentas_objetivo": 1}))
    externo = assess(F(rule="brute_force", links=("203.0.113.9",), metrics={"intentos_fallidos": 20, "cuentas_objetivo": 1}))
    assert any("IP interna" in x for x in interno.confidence_against) and any("IP pública" in x for x in externo.confidence_for)
    assert C.ORDER[externo.confidence] > C.ORDER[interno.confidence]


def test_cuenta_de_servicio_y_de_administracion():
    svc = assess(F(rule="persistence", users=("CORP\\svc_backup",)))
    adm = assess(F(rule="cmd_fw_change", users=("CORP\\admin.ana",)))
    assert any("servicio o de máquina" in x for x in svc.confidence_against)
    assert any("administración" in x for x in adm.confidence_against)


def test_un_solo_evento_resta_salvo_senales_que_valen_solas():
    assert any("un solo evento" in x for x in assess(F(rule="mass_access", ev=("E1",))).confidence_against)
    assert not any("un solo evento" in x for x in assess(F(rule="cred_lsass", ev=("E1",))).confidence_against)


# ---------------------------------------------------------------- ajustes propios
def test_fuerza_bruta_con_exito_y_volumen_es_alta():
    f = assess(F(rule="brute_force", links=("203.0.113.9",), metrics={"intentos_fallidos": 80, "cuentas_objetivo": 5, "exitos_posteriores": 1,
                                                                       "mediana_entre_intentos_s": 1}))
    assert f.confidence == "Alta" and len(f.confidence_for) >= 4


def test_exito_posterior_como_lista_de_eventos():
    # la regla guarda los Log_ID de los accesos exitosos, no un número
    f = assess(F(rule="brute_force", links=("203.0.113.9",), metrics={"intentos_fallidos": 12, "cuentas_objetivo": 1,
                                                                       "exitos_posteriores": ["demo.1.20"]}))
    assert any("inicio de sesión exitoso" in x for x in f.confidence_for)
    assert not any("olvidó su contraseña" in x for x in f.confidence_against)      # con un acceso exitoso, esa duda no aplica
    vacio = assess(F(rule="g_auth", links=("203.0.113.9",), metrics={"intentos_fallidos": 6, "cuentas_objetivo": 1, "exitos_posteriores": []}))
    assert not any("inicio de sesión exitoso" in x for x in vacio.confidence_for)


def test_pocos_intentos_internos_sobre_una_cuenta_es_baja():
    f = assess(F(rule="brute_force", links=("10.0.0.5",), metrics={"intentos_fallidos": 6, "cuentas_objetivo": 1, "mediana_entre_intentos_s": 40}))
    assert f.confidence == "Baja" and any("olvidó su contraseña" in x for x in f.confidence_against)


def test_winrm_oculto_desde_la_red_sube_y_local_baja():
    remoto = assess(F(rule="lat_winrm", metrics={"origen_red": ["10.0.0.9"], "oculto": True}))
    local = assess(F(rule="lat_winrm", metrics={"origen_red": [], "oculto": False}))
    assert remoto.confidence == "Alta" and local.confidence == "Baja"


def test_vulnerabilidad_no_es_explotacion():
    assert any("no que alguien lo haya explotado" in x for x in assess(F(rule="ctx_cve")).confidence_against)


# ---------------------------------------------------------------- con el análisis completo
def _sample():
    df, meta = load_events(SAMPLE.read_bytes(), SAMPLE.name)
    return df, meta


def test_la_confianza_no_cambia_criticidad_ni_hallazgos(monkeypatch):
    df, meta = _sample()
    con = analyze(df, meta)["findings"]
    monkeypatch.setattr(C, "assess_all", lambda fs: None)
    sin = analyze(df, meta)["findings"]
    key = lambda fs: sorted((f["rule"], f["title"], f["severity"], tuple(f["evidence_ids"])) for f in fs)
    assert key(con) == key(sin)


def test_todo_hallazgo_trae_confianza_y_motivo():
    for f in analyze(*_sample())["findings"]:
        assert f["confidence"] in ("Alta", "Media", "Baja") and f["confidence_basis"]
        assert isinstance(f["confidence_for"], list) and isinstance(f["confidence_against"], list)


def test_a_igual_criticidad_primero_lo_mas_seguro():
    a = analyze(*_sample())
    sueltos = [f for f in a["findings"] if not f["incident_id"]]
    for x, y in zip(sueltos, sueltos[1:]):
        if x["severity"] == y["severity"]:
            assert C.ORDER[x["confidence"]] >= C.ORDER[y["confidence"]]


def test_el_aviso_solo_lleva_el_nivel():
    f = {"severity": "Alto", "category": "Movimiento lateral", "confidence": "Media", "evidence_ids": ["E1"], "time_start": "2026-11-15 10:00:00",
         "confidence_for": ["Origen 203.0.113.9 de admin.ana"], "confidence_against": ["La cuenta CORP\\svc_x es de servicio"]}
    msg = notify.TelegramNotifier("t", "1").line(f)
    assert "• Confianza: Media" in msg and "203.0.113.9" not in msg and "svc_x" not in msg


def test_la_ia_recibe_la_confianza_y_la_evidencia_en_contra():
    df, meta = _sample()
    a = analyze(df, meta)
    inc = a["incidents"][0]
    p = triage._payload(a, df, inc, triage.baseline(a, inc))
    assert all({"confianza_motor", "a_favor", "en_contra"} <= set(h) for h in p["hallazgos"])
    assert "no prueba que la actividad sea legítima" in triage.TRIAGE_PROMPT


def test_informes_muestran_la_confianza():
    from backend import report_html, report
    f = {"confidence": "Media", "confidence_basis": "Base.", "confidence_for": ["Algo a favor"], "confidence_against": ["Algo en contra"]}
    html = report_html.confidence_html(f)
    assert "Confianza: Media" in html and "Algo a favor" in html and "Algo en contra" in html and "No cambia la criticidad" in html
    assert len(report.confidence_block(f)) == 4 and report_html.confidence_html({}) == "" and report.confidence_block({}) == []


# ---------------------------------------------------------------- medición (scripts/validar_datasets.py)
def _script():
    spec = importlib.util.spec_from_file_location("validar_datasets", ROOT / "scripts" / "validar_datasets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_reparto_de_confianza_excluye_observaciones():
    V = _script()
    rows = [{"hallazgos": [{"regla": "cred_lsass", "confianza": "Alta", "acierta": True},
                           {"regla": "cmd_encoded_ps", "confianza": "Media", "acierta": False},
                           {"regla": "siem_underclass", "confianza": "Baja", "acierta": False}]}]
    assert V.confidence_split(rows) == {"aciertos": {"Alta": 1, "Media": 0, "Baja": 0}, "incidentales": {"Alta": 0, "Media": 1, "Baja": 0}}
    assert V.hits_technique(["T1003.001"], {"mitre": ["T1003"]}) and not V.hits_technique(["T1021.002"], {"mitre": ["T1047"]})
