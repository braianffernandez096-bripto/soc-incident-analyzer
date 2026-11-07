"""Triaje asistido por IA: la IA recomienda, el motor conserva la severidad y el analista decide.
Se prueba con modelos simulados, incluido uno hostil que inventa Log_ID, baja la guardia o devuelve basura."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend import triage as T
from backend.analysis import analyze
from backend.parser import load_events

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


def _incident_of(text: str) -> str:
    import re
    return re.search(r'"id": "(INC-\d+)"', text).group(1)


def _honest(a):
    def call(tool, text, mt):
        inc = next(i for i in a["incidents"] if i["id"] == _incident_of(text))
        ev = T._incident_evidence(a, inc)
        return {"recommendation": "Escalar", "confidence": "Alta",
                "reasons": [f"La secuencia de {ev[0]} y {ev[1]} muestra actividad coherente con un ataque real contra {inc['hosts'][0]}."],
                "evidence_ids": ev[:2], "would_change_if": "El propietario de la cuenta confirma que la actividad fue autorizada por un cambio."}
    return call


def test_baseline_por_severidad(ctx):
    _, a = ctx
    for inc in a["incidents"]:
        b = T.baseline(a, inc)
        assert b["source"] == "motor" and b["recommendation"] in T.RECOMMENDATIONS
        assert b["evidence_ids"] and all(e in set(ctx[0]["Log_ID"]) for e in b["evidence_ids"])
        if inc["severity"] == "Crítico":
            assert b["recommendation"] == "Escalar" and b["confidence"] == "Alta"


def test_baseline_medio_y_bajo(ctx):
    _, a = ctx
    inc = dict(a["incidents"][0])
    assert T.baseline(a, {**inc, "severity": "Medio"})["recommendation"] == "Falta información"
    assert T.baseline(a, {**inc, "severity": "Bajo"})["recommendation"] == "Probable falso positivo"


def test_ia_honesta_se_acepta_y_no_toca_la_severidad(ctx):
    df, a = ctx
    before = [(i["id"], i["severity"]) for i in a["incidents"]]
    r = T.generate(a, df, _honest(a), provider="x", model="m")
    assert r["mode"] == "ia" and r["validation"]["con_ia"] == len(a["incidents"]) and not r["errors"]
    assert all(i["source"] == "ia" and i["recommendation"] == "Escalar" for i in r["items"])
    assert before == [(i["id"], i["severity"]) for i in a["incidents"]]


def test_ids_inventados_se_descartan(ctx):
    df, a = ctx

    def call(tool, text, mt):
        h = _honest(a)(tool, text, mt)
        h["evidence_ids"] = h["evidence_ids"] + ["EVT-99999"]
        h["reasons"] = h["reasons"] + ["El evento EVT-99999 desde 8.8.8.8 prueba la intrusión completa del servidor."]
        return h
    r = T.generate(a, df, call)
    assert r["validation"]["citas_descartadas"] >= len(a["incidents"]) and r["validation"]["ips_descartadas"] >= len(a["incidents"])
    blob = " ".join(" ".join(i["reasons"]) + " ".join(i["evidence_ids"]) for i in r["items"])
    assert "EVT-99999" not in blob and "8.8.8.8" not in blob


def test_ia_que_baja_la_guardia_en_incidente_grave_genera_conflicto(ctx):
    df, a = ctx

    def call(tool, text, mt):
        h = _honest(a)(tool, text, mt)
        h.update(recommendation="Probable falso positivo", confidence="Alta")
        return h
    r = T.generate(a, df, call)
    graves = [i for i in r["items"] if next(x for x in a["incidents"] if x["id"] == i["incident_id"])["severity"] in ("Crítico", "Alto")]
    assert graves and all(i["recommendation"] == "Escalar" and i["conflicto"] and i["ia_sugirio"]["recommendation"] == "Probable falso positivo" for i in graves)
    assert r["validation"]["conflictos"] == len(graves)


def test_medio_con_senales_de_abuso_no_se_puede_descartar(ctx):
    df, a = ctx
    inc = next(i for i in a["incidents"] if i["external_ips"])
    medio = {**inc, "severity": "Medio"}
    assert T.has_abuse_signals(a, medio)
    base = T.baseline(a, medio)
    allowed = set(T._incident_evidence(a, medio))
    ver = __import__("backend.ai", fromlist=["x"]).Verifier(df)
    raw = {"recommendation": "Probable falso positivo", "confidence": "Alta", "reasons": [f"El evento {sorted(allowed)[0]} parece actividad normal de mantenimiento."],
           "evidence_ids": sorted(allowed)[:1], "would_change_if": "Aparece un acceso exitoso desde la misma IP externa."}
    it = T._review(raw, base, allowed, ver, medio, T.has_abuse_signals(a, medio))
    assert it["recommendation"] == base["recommendation"] == "Falta información" and it["conflicto"] and it["source"] == "motor"
    assert it["ia_sugirio"]["recommendation"] == "Probable falso positivo"


def test_sin_senales_el_incidente_medio_si_puede_descartarse(ctx):
    _, a = ctx
    aislado = {**a["incidents"][0], "severity": "Medio", "external_ips": [], "finding_ids": a["incidents"][0]["finding_ids"][:1]}
    f = T._incident_findings(a, aislado)[0]
    quieto = {**aislado}
    # un único hallazgo Medio y sin IP externa no cuenta como señal de abuso
    a2 = {**a, "findings": [{**f, "severity": "Medio"}]}
    assert not T.has_abuse_signals(a2, quieto)


def test_ia_en_incidente_medio_puede_descartar_y_si_escala_mas_se_marca(ctx):
    df, a = ctx
    inc = {**a["incidents"][0], "severity": "Medio"}
    base = T.baseline(a, inc)
    ver = __import__("backend.ai", fromlist=["x"]).Verifier(df)
    allowed = set(T._incident_evidence(a, inc))
    raw = {"recommendation": "Probable falso positivo", "confidence": "Media", "reasons": [f"Solo hay un evento aislado {sorted(allowed)[0]} sin repetición."],
           "evidence_ids": sorted(allowed)[:1], "would_change_if": "Aparece un acceso exitoso desde la misma IP externa."}
    it = T._review(raw, base, allowed, ver, inc)
    assert it["recommendation"] == "Probable falso positivo" and it["source"] == "ia" and it["difiere"] and not it["conflicto"]
    it2 = T._review({**raw, "recommendation": "Escalar"}, base, allowed, ver, inc)
    assert it2["recommendation"] == "Escalar" and it2["difiere"]


@pytest.mark.parametrize("raw", [{}, {"recommendation": "Quemar el servidor", "reasons": ["algo concreto sobre el host"]},
                                 {"recommendation": "Escalar", "reasons": []}, {"recommendation": "Escalar", "reasons": ["revisar logs"]}])
def test_respuesta_basura_cae_al_motor(ctx, raw):
    df, a = ctx
    r = T.generate(a, df, lambda t, x, m: raw)
    assert r["mode"] == "motor" and all(i["source"] == "motor" for i in r["items"]) and r["errors"]


def test_fallo_de_un_incidente_no_tumba_el_resto(ctx):
    df, a = ctx
    ok = _honest(a)
    n = {"k": 0}

    def call(tool, text, mt):
        n["k"] += 1
        if n["k"] == 2:
            raise RuntimeError("timeout")
        return ok(tool, text, mt)
    r = T.generate(a, df, call)
    srcs = [i["source"] for i in r["items"]]
    assert srcs[1] == "motor" and srcs.count("ia") == len(srcs) - 1 and any("timeout" in e for e in r["errors"])


def test_proveedor_caido_no_espera_incidente_por_incidente(ctx):
    df, a = ctx
    llamadas = []

    def call(tool, text, mt):
        llamadas.append(1)
        raise RuntimeError("sin conexión")
    r = T.generate(a, df, call)
    assert len(llamadas) == T.MAX_CONSECUTIVE_FAILS and r["mode"] == "motor"
    assert sum("omitido" in e for e in r["errors"]) == len(a["incidents"]) - T.MAX_CONSECUTIVE_FAILS


def test_log_hostil_no_puede_cerrar_el_bloque(ctx):
    df, a = ctx
    seen = []

    def call(tool, text, mt):
        seen.append(text)
        return _honest(a)(tool, text, mt)
    T.generate(a, df, call)
    assert all(t.count("</incidente>") == 1 for t in seen)


# ---------------------------------------------------------------- API
@pytest.fixture()
def api(monkeypatch, ctx):
    main._hits.clear()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    c = TestClient(main.app)
    sid = c.post("/api/upload", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/octet-stream")}).json()["session_id"]
    return c, sid, ctx[1]


def test_api_triaje_inicial_es_del_motor(api):
    c, sid, a = api
    r = c.get(f"/api/sessions/{sid}/triage").json()
    assert r["mode"] == "motor" and len(r["items"]) == len(a["incidents"]) and r["resumen"]["pendientes"] == len(a["incidents"])


def test_api_ia_decision_y_pdf(api, monkeypatch):
    c, sid, a = api
    monkeypatch.setattr(main.ai_mod, "make_anthropic_call", lambda key, model: _honest(a))
    r = c.post(f"/api/sessions/{sid}/triage/ai")
    assert r.status_code == 200 and r.json()["mode"] == "ia"
    inc = a["incidents"][0]["id"]
    d = c.post(f"/api/sessions/{sid}/triage/{inc}/decision", data={"decision": "Escalado", "note": "  Se abrió ticket   a L2 <script>x</script> "})
    assert d.status_code == 200
    it = next(i for i in d.json()["items"] if i["incident_id"] == inc)
    assert it["decision"]["decision"] == "Escalado" and "ticket a L2" in it["decision"]["note"]
    assert d.json()["resumen"]["decididos"] == 1
    # la severidad del análisis no cambia
    assert c.get(f"/api/sessions/{sid}/triage").json()["items"][0]["incident_id"] == a["incidents"][0]["id"]
    pdf = c.post(f"/api/sessions/{sid}/report.pdf", data={"client": "X", "analyst": "Y"})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_api_validaciones(api):
    c, sid, a = api
    inc = a["incidents"][0]["id"]
    assert c.post(f"/api/sessions/{sid}/triage/{inc}/decision", data={"decision": "Cerrado"}).status_code == 400
    assert c.post(f"/api/sessions/{sid}/triage/INC-999/decision", data={"decision": "Escalado"}).status_code == 404
    assert c.post(f"/api/sessions/{sid}/triage/{inc}/decision").status_code == 422
    assert c.get("/api/sessions/nope/triage").status_code == 404
    assert c.post(f"/api/sessions/{sid}/triage/ai?provider=otro").status_code == 400


def test_api_sin_clave_no_llama(api, monkeypatch):
    c, sid, _ = api
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert c.post(f"/api/sessions/{sid}/triage/ai").status_code == 400


def test_api_modelo_basura_da_502_y_conserva_motor(api, monkeypatch):
    c, sid, _ = api
    monkeypatch.setattr(main.ai_mod, "make_anthropic_call", lambda key, model: (lambda t, x, m: {}))
    assert c.post(f"/api/sessions/{sid}/triage/ai").status_code == 502
    assert c.get(f"/api/sessions/{sid}/triage").json()["mode"] == "motor"


def test_nota_se_trunca(api):
    c, sid, a = api
    inc = a["incidents"][0]["id"]
    d = c.post(f"/api/sessions/{sid}/triage/{inc}/decision", data={"decision": "Descartado", "note": "a" * 2000}).json()
    assert len(d["items"][0]["decision"]["note"]) == T.NOTE_MAX


@pytest.mark.parametrize("motivo", ["No hay evidencia de acceso exitoso en los eventos revisados.", "La minería puede ser legítima si se autoriza explícitamente.",
                                     "No se observaron transferencias de datos hacia el exterior del equipo."])
def test_falso_positivo_solo_por_ausencia_se_trata_como_falta_informacion(ctx, motivo):
    df, a = ctx
    inc = {**a["incidents"][0], "severity": "Bajo", "external_ips": [], "finding_ids": a["incidents"][0]["finding_ids"][:1]}
    base = {**T.baseline(a, inc), "recommendation": "Falta información"}
    allowed = set(T._incident_evidence(a, inc))
    ver = __import__("backend.ai", fromlist=["x"]).Verifier(df)
    raw = {"recommendation": "Probable falso positivo", "confidence": "Alta", "reasons": [motivo],
           "evidence_ids": sorted(allowed)[:1], "would_change_if": "Aparece un acceso exitoso desde la misma IP externa."}
    it = T._review(raw, base, allowed, ver, inc)
    assert it["recommendation"] == "Falta información" and it["confidence"] == "Baja" and "ajuste" in it


def test_falso_positivo_con_prueba_positiva_se_acepta(ctx):
    df, a = ctx
    inc = {**a["incidents"][0], "severity": "Bajo", "external_ips": [], "finding_ids": a["incidents"][0]["finding_ids"][:1]}
    base = T.baseline(a, inc)
    allowed = set(T._incident_evidence(a, inc))
    ver = __import__("backend.ai", fromlist=["x"]).Verifier(df)
    raw = {"recommendation": "Probable falso positivo", "confidence": "Media",
           "reasons": [f"El evento {sorted(allowed)[0]} lo ejecuta la cuenta de servicio de respaldos en su horario habitual de mantenimiento."],
           "evidence_ids": sorted(allowed)[:1], "would_change_if": "La cuenta aparece además activa fuera de su ventana de mantenimiento."}
    assert T._review(raw, base, allowed, ver, inc)["recommendation"] == "Probable falso positivo"
