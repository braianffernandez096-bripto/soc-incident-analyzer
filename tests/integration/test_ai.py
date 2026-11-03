"""Pruebas de la capa de IA sin llamar a la API: se inyecta un 'modelo' falso."""
from pathlib import Path

import pytest

from backend import ai
from backend.analysis import analyze
from backend.parser import load_events

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


def test_deterministic_report_is_complete(ctx):
    df, a = ctx
    r = ai.build_deterministic(a)
    assert r["mode"] == "determinista"
    assert set(r["findings"]) == {f["id"] for f in a["findings"]}
    for fa in r["findings"].values():
        assert fa["technical_explanation"] and fa["impact"] and fa["severity_justification"]
        assert set(fa["action_plan"]) == {"investigate", "contain", "remediate"}
    assert set(r["incidents"]) == {i["id"] for i in a["incidents"]}
    assert r["executive_summary"] and r["cross_incident_assessment"] and r["prioritized_actions"]


def _fake_model(tool, text, max_tokens):
    """Simula un modelo que mezcla respuestas correctas con invenciones."""
    if tool["name"] == "submit_executive_report":
        return {"executive_summary": "Resumen. Se vio actividad desde 203.0.113.74 y también desde 8.8.8.8 (inventada).",
                "cross_incident_assessment": "Varios incidentes independientes.",
                "prioritized_actions": [{"priority": "Inmediata", "action": "Bloquear 203.0.113.74", "incident_ids": ["INC-001", "INC-999"]}],
                "general_recommendations": ["Habilitar MFA."]}
    import json
    payload = json.loads(text.split("<analisis>")[1].split("</analisis>")[0])
    fs = payload["hallazgos"]
    first = fs[0]
    ev = first["evidencia"][0]["Log_ID"]
    return {
        "incident_title": "Título del modelo", "narrative": "Narrativa verificable.",
        "kill_chain": [
            {"time": "08:25:00", "step": "Paso válido", "evidence_ids": [ev]},
            {"time": "08:26:00", "step": "Paso con evidencia inventada", "evidence_ids": ["EVT-99999"]},
        ],
        "confidence": "Alta", "confidence_reason": "porque sí",
        "findings": [
            {"finding_id": first["finding_id"],
             "technical_explanation": f"Ver {ev} y también EVT-88888 (inventado) con IP 9.9.9.9.",
             "severity_justification": "Justificación.", "impact": "Impacto.",
             "investigate": ["a"], "contain": ["b"], "remediate": ["c"]},
            {"finding_id": "F-999", "technical_explanation": "x", "severity_justification": "x", "impact": "x",
             "investigate": [], "contain": [], "remediate": []},
        ],
    }


def test_validator_drops_invented_citations(ctx):
    df, a = ctx
    r = ai.generate(a, df, api_key=None, call=_fake_model)
    assert r["mode"] == "ia"
    v = r["validation"]
    assert v["citas_descartadas"] > 0 and v["ips_descartadas"] > 0
    blob = str(r)
    for invented in ("EVT-99999", "EVT-88888", "9.9.9.9", "8.8.8.8", "F-999", "INC-999"):
        assert invented not in blob, invented
    assert "[Log_ID no verificado]" in blob and "[IP no verificada]" in blob
    # el paso con evidencia inexistente no entra a la cronología
    for g in r["incidents"].values():
        if g.get("source") == "ia":
            assert all(s["evidence_ids"] for s in g["kill_chain"])
    # los hallazgos que la IA no cubrió se completan con reglas, sin quedar vacíos
    assert set(r["findings"]) == {f["id"] for f in a["findings"]}
    assert any(x["source"] == "determinista" for x in r["findings"].values())
    assert v["hallazgos_con_ia"] + v["hallazgos_completados_con_reglas"] == v["hallazgos_total"]


def test_severity_is_never_changed_by_the_model(ctx):
    df, a = ctx
    before = {f["id"]: f["severity"] for f in a["findings"]}
    ai.generate(a, df, api_key=None, call=_fake_model)
    assert before == {f["id"]: f["severity"] for f in a["findings"]}


def test_model_failure_falls_back(ctx):
    df, a = ctx

    def boom(tool, text, mt):
        raise RuntimeError("sin red")
    r = ai.generate(a, df, api_key=None, call=boom)
    assert r["mode"] == "determinista" and r["errors"]
    assert set(r["findings"]) == {f["id"] for f in a["findings"]}


def test_prompt_marks_logs_as_untrusted_data():
    assert "DATOS no confiables" in ai.SYSTEM_PROMPT and "No inventes" in ai.SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Transporte real del SDK de Anthropic contra un servidor simulado (SSE)
# ---------------------------------------------------------------------------
def _httpx():
    """El SDK 2.x usa httpx2; versiones anteriores usan httpx."""
    try:
        import httpx2 as h
    except ImportError:
        import httpx as h
    return h


def _sse(events):
    import json as _json
    return "".join(f"event: {e['type']}\ndata: {_json.dumps(e)}\n\n" for e in events).encode()


def _anthropic_with_fake_server(seen):
    import json as _json

    import anthropic
    httpx = _httpx()

    def handler(request: httpx.Request) -> httpx.Response:
        body = _json.loads(request.content)
        seen.append(body)
        assert request.url.path == "/v1/messages" and body["stream"] is True
        tool = body["tools"][0]
        assert body["tool_choice"] == {"type": "auto"}   # un tool_choice forzado da HTTP 400 en algunos modelos
        assert "No inventes" in body["system"] and "<analisis>" in body["messages"][0]["content"]
        result = _json.dumps(_fake_model(tool, body["messages"][0]["content"], body["max_tokens"]))
        events = [
            {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                                                    "content": [], "stop_reason": None, "stop_sequence": None,
                                                    "usage": {"input_tokens": 10, "output_tokens": 1}}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": tool["name"], "input": {}}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": result}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 50}},
            {"type": "message_stop"},
        ]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(events))

    return anthropic.Anthropic(api_key="test-key", http_client=httpx.Client(transport=httpx.MockTransport(handler)), max_retries=0)


def test_sdk_streaming_and_tool_use_roundtrip(ctx):
    df, a = ctx
    seen = []
    r = ai.generate(a, df, api_key="test-key", client=_anthropic_with_fake_server(seen))
    assert r["mode"] == "ia" and not r["errors"]
    assert len(seen) == len(a["incidents"]) + 1 + 1   # un grupo por incidente + observaciones + resumen
    assert all(s["model"] == ai.DEFAULT_MODEL for s in seen)
    assert "EVT-99999" not in str(r)


def test_sdk_auth_error_falls_back(ctx):
    import anthropic
    httpx = _httpx()
    df, a = ctx
    client = anthropic.Anthropic(api_key="bad", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(401, json={"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}))))
    r = ai.generate(a, df, api_key="bad", client=client)
    assert r["mode"] == "determinista" and any("Authentication" in e or "401" in e for e in r["errors"])


def test_reintenta_si_el_modelo_responde_solo_texto():
    """Regresión: sin tool_choice forzado, el modelo puede contestar con texto; se reintenta una vez."""
    from types import SimpleNamespace as NS

    class FakeStream:
        def __init__(self, msg): self.msg = msg
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_message(self): return self.msg

    replies = [NS(content=[NS(type="text", text="hola")]), NS(content=[NS(type="tool_use", input={"ok": 1})])]
    calls = []

    class FakeClient:
        class messages:
            @staticmethod
            def stream(**kw):
                calls.append(kw)
                return FakeStream(replies[len(calls) - 1])

    out = ai._call_tool(FakeClient, "m", {"name": "submit_group_report"}, "texto", 100)
    assert out == {"ok": 1} and len(calls) == 2
    assert "no usaste la herramienta" in calls[1]["messages"][0]["content"]
    assert all(c["tool_choice"] == {"type": "auto"} for c in calls)


def test_falla_si_el_modelo_nunca_usa_la_herramienta():
    from types import SimpleNamespace as NS

    class FakeStream:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_message(self): return NS(content=[NS(type="text", text="sin herramienta")])

    class FakeClient:
        class messages:
            @staticmethod
            def stream(**kw): return FakeStream()

    with pytest.raises(RuntimeError):
        ai._call_tool(FakeClient, "m", {"name": "t"}, "x", 10)


# ---------------------------------------------------------------------------
# Regresión: el modelo a veces entrega listas como texto (visto con la API real)
# ---------------------------------------------------------------------------
def test_normalize_listas_entregadas_como_texto_pseudo_xml():
    schema = ai.SUMMARY_TOOL["input_schema"]
    raw = {"executive_summary": "Resumen <parameter name=\"x\">", "cross_incident_assessment": "ok",
           "general_recommendations": '<parameter name="0">Exigir MFA en accesos remotos.</parameter><parameter name="1">No exponer RDP.</parameter>',
           "prioritized_actions": "texto libre que no es JSON"}
    out = ai._normalize(raw, schema)
    assert out["general_recommendations"] == ["Exigir MFA en accesos remotos.", "No exponer RDP."]
    assert out["prioritized_actions"] == []                     # no inventa acciones: cae al respaldo por reglas
    assert "<parameter" not in out["executive_summary"]


def test_normalize_lista_json_como_texto_y_viñetas():
    schema = ai.SUMMARY_TOOL["input_schema"]
    acts = '[{"priority": "Inmediata", "action": "Aislar APP-SRV01", "incident_ids": ["INC-002"]}]'
    out = ai._normalize({"prioritized_actions": acts, "general_recommendations": "- Habilitar MFA\n- Segmentar la red"}, schema)
    assert out["prioritized_actions"][0]["action"] == "Aislar APP-SRV01"
    assert out["general_recommendations"] == ["Habilitar MFA", "Segmentar la red"]


def test_resumen_con_acciones_en_texto_no_genera_error_ni_letras_sueltas(ctx):
    df, a = ctx

    def model(tool, text, mt):
        if tool["name"] == "submit_executive_report":
            return ai._normalize({"executive_summary": "Resumen válido.", "cross_incident_assessment": "Varios.",
                                  "general_recommendations": "<parameter name=\"0\">Habilitar MFA.</parameter>",
                                  "prioritized_actions": "no es una lista"}, tool["input_schema"])
        return _fake_model(tool, text, mt)

    r = ai.generate(a, df, api_key=None, call=model)
    assert not [e for e in r["errors"] if e.startswith("resumen")]
    assert r["general_recommendations"] == ["Habilitar MFA."]
    assert r["prioritized_actions"] and all(len(x["action"]) > 5 for x in r["prioritized_actions"])


def test_verificador_acepta_citas_de_otros_hallazgos_del_mismo_incidente(ctx):
    """Regresión: citar evidencia de otro hallazgo del MISMO incidente es válido; citar otro incidente o un ID inexistente, no."""
    df, a = ctx
    inc = next(i for i in a["incidents"] if len(i["finding_ids"]) > 1)
    fs = [f for f in a["findings"] if f["incident_id"] == inc["id"]]
    mismo_incidente = fs[1]["evidence_ids"][0]
    otro_incidente = next(f for f in a["findings"] if f["incident_id"] and f["incident_id"] != inc["id"])["evidence_ids"][0]
    raw = {"findings": [{"finding_id": fs[0]["id"], "severity_justification": "", "impact": "", "investigate": [], "contain": [], "remediate": [],
                         "technical_explanation": f"Ver {mismo_incidente}, {otro_incidente} y EVT-88888."}]}
    _, findings = ai.validate_group(raw, fs, ai.Verifier(df))
    txt = findings[fs[0]["id"]]["technical_explanation"]
    assert mismo_incidente in txt
    assert otro_incidente not in txt and "EVT-88888" not in txt and txt.count("[Log_ID no verificado]") == 2


def test_verificador_acepta_direccion_de_red_si_el_excel_tiene_ip_de_ese_segmento(ctx):
    df, a = ctx
    ver = ai.Verifier(df)
    ok = ver.text("Mismo segmento 203.0.113.0/24 y 198.51.100.0/24.", set())
    assert "[IP no verificada]" not in ok
    mal = ver.text("Segmento 8.8.8.0/24 y la IP 8.8.8.8 y 203.0.113.250.", set())
    assert mal.count("[IP no verificada]") == 3      # un segmento ajeno al Excel y una IP inventada siguen descartándose


def test_reintenta_si_una_lista_requerida_llega_como_texto_irrecuperable():
    """Regresión (API real): prioritized_actions/findings llegaron como texto; se reintenta una vez y se usa el resultado válido."""
    from types import SimpleNamespace as NS

    class FakeStream:
        def __init__(self, msg): self.msg = msg
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_message(self): return self.msg

    mala = {"executive_summary": "x", "cross_incident_assessment": "y", "general_recommendations": ["a"], "prioritized_actions": "<parameter name=\"0\">texto</parameter>"}
    buena = dict(mala, prioritized_actions=[{"priority": "Inmediata", "action": "Aislar APP-SRV01", "incident_ids": ["INC-002"]}])
    replies = [NS(content=[NS(type="tool_use", input=mala)]), NS(content=[NS(type="tool_use", input=buena)])]
    calls = []

    class FakeClient:
        class messages:
            @staticmethod
            def stream(**kw):
                calls.append(kw)
                return FakeStream(replies[len(calls) - 1])

    out = ai._call_tool(FakeClient, "m", ai.SUMMARY_TOOL, "texto", 100)
    assert len(calls) == 2 and out["prioritized_actions"][0]["action"] == "Aislar APP-SRV01"
    assert "array JSON real" in calls[1]["messages"][0]["content"]


def test_prompt_exige_no_afirmar_resultados_que_el_log_no_muestra():
    assert "EJECUCIÓN de un comando no prueba" in ai.SYSTEM_PROMPT
