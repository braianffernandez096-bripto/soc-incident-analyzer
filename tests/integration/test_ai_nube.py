"""OpenAI y Gemini con servidores simulados (sin red ni claves reales): adaptadores, errores, API y garantías de seguridad."""
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import ai, ai_cloud, main
from backend.analysis import analyze
from backend.parser import load_events
from tests.integration.test_ai import _fake_model

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
KEY_OPENAI, KEY_GEMINI = "sk-test-clave-openai-123456", "AIza-test-clave-gemini-123456"


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(ai_cloud.time, "sleep", lambda s: None)
    for v in ("OPENAI_API_KEY", "GEMINI_API_KEY", "OPENAI_MODEL", "GEMINI_MODEL", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(v, raising=False)


def _triage_reply(text):
    return {"recommendation": "Escalar", "confidence": "Media", "evidence_ids": [],
            "reasons": ["El motor marcó el incidente por actividad sospechosa repetida desde una IP externa."],
            "would_change_if": "Que el responsable confirme que la actividad fue autorizada y documentada."}


class FakeCloud:
    """Simula OpenAI y Gemini. `status` fuerza un código de error; `args` reemplaza los argumentos de la función."""

    def __init__(self, status=200, args=None, statuses=None):
        self.requests, self.status, self.args, self.statuses = [], status, args, list(statuses or [])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        code = self.statuses.pop(0) if self.statuses else self.status
        if code != 200:
            return httpx.Response(code, json={"error": {"message": f"clave {KEY_OPENAI} inválida"}})
        body = json.loads(request.content)
        if request.url.host == "api.openai.com":
            name = body["tools"][0]["function"]["name"]
            text = body["messages"][-1]["content"]
        else:
            name = body["tools"][0]["functionDeclarations"][0]["name"]
            text = body["contents"][0]["parts"][0]["text"]
        args = self.args(name, text) if callable(self.args) else self.args
        if args is None:
            args = _triage_reply(text) if name == "submit_triage" else _fake_model({"name": name}, text, 1000)
        if request.url.host == "api.openai.com":
            msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}
            return httpx.Response(200, json={"choices": [{"message": msg}]})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"functionCall": {"name": name, "args": args}}]}}]})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


# ------------------------------------------------------------------ adaptadores
def test_openai_request_is_well_formed_and_response_is_parsed():
    srv = FakeCloud(args={"x": "hola"})
    tool = {"name": "t", "description": "d", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}}
    assert ai_cloud.make_call("openai", KEY_OPENAI, "gpt-5.4-mini", srv.client())(tool, "texto", 500) == {"x": "hola"}
    req, body = srv.requests[0], srv.bodies()[0]
    assert str(req.url) == ai_cloud.OPENAI_URL and req.headers["authorization"] == f"Bearer {KEY_OPENAI}"
    assert body["tool_choice"] == {"type": "function", "function": {"name": "t"}} and body["max_completion_tokens"] == 500
    assert body["model"] == "gpt-5.4-mini" and body["messages"][0]["role"] == "system"


def test_gemini_request_is_well_formed_and_schema_is_sanitized():
    srv = FakeCloud(args={"x": "hola"})
    tool = {"name": "t", "description": "d", "input_schema": {"type": "object", "additionalProperties": False, "$schema": "x", "title": "T",
            "properties": {"x": {"type": "string", "default": "a"}, "l": {"type": "array", "items": {"type": "string", "title": "i"}}}, "required": ["x"]}}
    assert ai_cloud.make_call("gemini", KEY_GEMINI, "gemini-3.8-flash", srv.client())(tool, "texto", 500) == {"x": "hola"}
    req, body = srv.requests[0], srv.bodies()[0]
    assert str(req.url) == ai_cloud.GEMINI_URL.format(model="gemini-3.8-flash") and req.headers["x-goog-api-key"] == KEY_GEMINI
    assert "key=" not in str(req.url)                                  # la clave va en cabecera, no en la URL (no queda en registros)
    params = body["tools"][0]["functionDeclarations"][0]["parameters"]
    assert "additionalProperties" not in params and "$schema" not in params and "title" not in params
    assert "default" not in params["properties"]["x"] and "title" not in params["properties"]["l"]["items"]
    assert params["required"] == ["x"] and "l" in params["properties"]    # una propiedad llamada igual que una palabra reservada no se pierde
    cfg = body["toolConfig"]["functionCallingConfig"]
    assert cfg["mode"] == "ANY" and cfg["allowedFunctionNames"] == ["t"] and body["generationConfig"]["maxOutputTokens"] > 500


def test_gemini_accepts_snake_case_function_call():
    def h(req):
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"function_call": {"name": "t", "args": {"x": "ok"}}}]}}]})
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}}
    assert ai_cloud.make_call("gemini", "k", "m", httpx.Client(transport=httpx.MockTransport(h)))(tool, "t", 10) == {"x": "ok"}


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_generation_report_with_cloud_model_keeps_engine_guarantees(ctx, provider):
    df, a = ctx
    before = [(f["id"], f["severity"]) for f in a["findings"]]
    r = ai.generate(a, df, None, model="m", call=ai_cloud.make_call(provider, "k", "m", FakeCloud().client()), provider=provider, workers=2)
    assert r["mode"] == "ia" and r["provider"] == provider
    assert [(f["id"], f["severity"]) for f in a["findings"]] == before            # la IA nunca cambia la severidad
    assert "EVT-99999" not in json.dumps(r, ensure_ascii=False) and "8.8.8.8" not in json.dumps(r)   # el verificador descarta lo inventado


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_hostile_model_cannot_change_severity(ctx, provider):
    df, a = ctx

    def hostile(name, text):
        out = _fake_model({"name": name}, text, 1000)
        out["severity"] = "Bajo"
        out["findings"] = [{**f, "severity": "Bajo"} for f in out.get("findings", [])]
        return out
    before = [f["severity"] for f in a["findings"]]
    ai.generate(a, df, None, model="m", call=ai_cloud.make_call(provider, "k", "m", FakeCloud(args=hostile).client()), provider=provider, workers=2)
    assert [f["severity"] for f in a["findings"]] == before


def test_json_text_inside_arrays_is_normalized():
    srv = FakeCloud(args={"items": json.dumps([{"n": "uno"}, {"n": "dos"}])})
    tool = {"name": "t", "input_schema": {"type": "object", "required": ["items"], "properties": {"items": {"type": "array", "items": {"type": "object", "properties": {"n": {"type": "string"}}}}}}}
    assert ai_cloud.make_call("openai", "k", "m", srv.client())(tool, "t", 10) == {"items": [{"n": "uno"}, {"n": "dos"}]}


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_response_without_function_call_fails_clearly_after_one_retry(provider):
    def h(req):
        if req.url.host == "api.openai.com":
            return httpx.Response(200, json={"choices": [{"message": {"content": "hola"}}]})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "hola"}]}}]})
    calls = []
    client = httpx.Client(transport=httpx.MockTransport(lambda r: (calls.append(1), h(r))[1]))
    with pytest.raises(ai_cloud.CloudError, match="resultado estructurado"):
        ai_cloud.make_call(provider, "k", "m", client)({"name": "t", "input_schema": {"type": "object"}}, "t", 10)
    assert len(calls) == 2


@pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": [{"message": {"tool_calls": [{"function": {"arguments": "no es json"}}]}}]},
                                     {"choices": [{"message": {"tool_calls": [{"function": {"arguments": "[1,2]"}}]}}]}, {"candidates": None}, {"candidates": [{}]}])
def test_malformed_responses_do_not_crash(payload):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload)))
    for p in ai_cloud.PROVIDERS:
        with pytest.raises(ai_cloud.CloudError):
            ai_cloud.make_call(p, "k", "m", client)({"name": "t", "input_schema": {"type": "object"}}, "t", 10)


@pytest.mark.parametrize("status,msg", [(401, "rechazó la clave"), (403, "rechazó la clave"), (404, "modelo"), (429, "cuota"), (400, "rechazó la solicitud"), (500, "código 500")])
@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_http_errors_have_readable_messages_without_echoing_the_server(provider, status, msg):
    with pytest.raises(ai_cloud.CloudError, match=msg) as e:
        ai_cloud.make_call(provider, KEY_OPENAI, "m", FakeCloud(status=status).client())({"name": "t", "input_schema": {}}, "t", 10)
    assert KEY_OPENAI not in str(e.value)                       # el cuerpo del error del proveedor puede traer parte de la clave: no se repite


def test_transient_errors_are_retried():
    srv = FakeCloud(statuses=[429, 503], args={"x": "ok"})
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}}
    assert ai_cloud.make_call("openai", "k", "m", srv.client())(tool, "t", 10) == {"x": "ok"} and len(srv.requests) == 3


def test_network_failure_and_timeout_have_readable_messages():
    def down(req):
        raise httpx.ConnectError("boom")

    def slow(req):
        raise httpx.ReadTimeout("lento")
    t = {"name": "t", "input_schema": {}}
    with pytest.raises(ai_cloud.CloudError, match="red"):
        ai_cloud.make_call("gemini", "k", "m", httpx.Client(transport=httpx.MockTransport(down)))(t, "t", 10)
    with pytest.raises(ai_cloud.CloudError, match="tardó"):
        ai_cloud.make_call("openai", "k", "m", httpx.Client(transport=httpx.MockTransport(slow)))(t, "t", 10)


def test_non_json_response_is_reported():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
    with pytest.raises(ai_cloud.CloudError, match="no es JSON"):
        ai_cloud.make_call("openai", "k", "m", client)({"name": "t", "input_schema": {}}, "t", 10)


@pytest.mark.parametrize("model", ["", "a b", "../x", "gpt?x=1", "m" * 81, "-x", "a/b", "a\nb"])
def test_invalid_model_names_are_rejected(model):
    with pytest.raises(ai_cloud.CloudError):
        ai_cloud.make_call("gemini", "k", model)


def test_missing_key_and_unknown_provider():
    with pytest.raises(ai_cloud.CloudError, match="Falta la clave"):
        ai_cloud.make_call("openai", "  ", "m")
    with pytest.raises(ai_cloud.CloudError):
        ai_cloud.make_call("otro", "k", "m")


def test_own_client_ignores_proxies_and_redirects(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalido:3128")
    c, own = ai_cloud._client(None)
    assert own and c.follow_redirects is False
    c.close()


def test_defaults_and_env_override(monkeypatch):
    assert ai_cloud.default_model("openai") == ai_cloud.DEFAULT_MODELS["openai"]
    monkeypatch.setenv("GEMINI_MODEL", "gemini-x-1")
    assert ai_cloud.default_model("gemini") == "gemini-x-1"
    monkeypatch.setenv("GEMINI_MODEL", "malo valor ../")
    assert ai_cloud.default_model("gemini") == ai_cloud.DEFAULT_MODELS["gemini"]


# ------------------------------------------------------------------ API
@pytest.fixture
def api(monkeypatch):
    monkeypatch.setitem(main.RATE_LIMITS, "/api/ai", (1000, 60))
    srv = FakeCloud()
    monkeypatch.setattr(main, "_cloud_http", srv.client)
    main._hits.clear()
    c = TestClient(main.app)
    sid = c.post("/api/upload", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/octet-stream")}).json()["session_id"]
    yield c, sid, srv
    main._hits.clear()


@pytest.mark.parametrize("provider,hdr,model", [("openai", KEY_OPENAI, "gpt-5.4-mini"), ("gemini", KEY_GEMINI, "gemini-3.8-flash")])
def test_report_with_key_from_header(api, provider, hdr, model):
    c, sid, srv = api
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": provider}, headers={"X-Provider-Key": hdr})
    assert r.status_code == 200, r.text
    ai_ = r.json()["ai"]
    assert ai_["mode"] == "ia" and ai_["provider"] == provider and ai_["model"] == model
    assert hdr not in r.text                                            # la clave nunca vuelve al navegador


def test_report_with_key_from_env_and_custom_model(api, monkeypatch):
    c, sid, srv = api
    monkeypatch.setenv("OPENAI_API_KEY", KEY_OPENAI)
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "openai", "model": "gpt-5"})
    assert r.status_code == 200 and r.json()["ai"]["model"] == "gpt-5"
    assert all(b["model"] == "gpt-5" for b in srv.bodies())


def test_missing_key_is_a_clear_400(api):
    c, sid, _ = api
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "gemini"})
    assert r.status_code == 400 and "GEMINI_API_KEY" in r.json()["detail"]


@pytest.mark.parametrize("model", ["../../x", "a b", "m;rm", "x" * 200])
def test_model_from_browser_cannot_inject_into_the_url(api, model):
    c, sid, srv = api
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "gemini", "model": model, "url": "http://169.254.169.254"}, headers={"X-Provider-Key": KEY_GEMINI})
    assert r.status_code == 400 and not srv.requests


def test_requests_only_go_to_the_fixed_hosts(api):
    c, sid, srv = api
    c.post(f"/api/sessions/{sid}/ai", params={"provider": "gemini", "base_url": "http://127.0.0.1:9"}, headers={"X-Provider-Key": KEY_GEMINI})
    assert {r.url.host for r in srv.requests} == {"generativelanguage.googleapis.com"}


def test_provider_error_becomes_clean_502_without_leaking_the_key(api, monkeypatch):
    c, sid, _ = api
    monkeypatch.setattr(main, "_cloud_http", FakeCloud(status=401).client)
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "openai"}, headers={"X-Provider-Key": KEY_OPENAI})
    assert r.status_code == 502 and "rechazó la clave" in r.json()["detail"] and KEY_OPENAI not in r.text


def test_triage_with_cloud_provider(api):
    c, sid, srv = api
    r = c.post(f"/api/sessions/{sid}/triage/ai", params={"provider": "openai"}, headers={"X-Provider-Key": KEY_OPENAI})
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["mode"] == "ia" and t["provider"] == "openai" and t["model"] == "gpt-5.4-mini"
    assert KEY_OPENAI not in r.text


def test_triage_cloud_model_cannot_lower_a_critical_incident(api, monkeypatch):
    c, sid, _ = api
    low = lambda name, text: {"recommendation": "Probable falso positivo", "confidence": "Alta", "evidence_ids": [],
                              "reasons": ["La actividad parece administrativa y habitual según el contexto observado."], "would_change_if": "Evidencia de acceso exitoso desde fuera de la red."}
    monkeypatch.setattr(main, "_cloud_http", FakeCloud(args=low).client)
    r = c.post(f"/api/sessions/{sid}/triage/ai", params={"provider": "gemini"}, headers={"X-Provider-Key": KEY_GEMINI})
    assert r.status_code in (200, 502)               # si todos los incidentes son graves, nada de lo que dijo la IA se acepta y se avisa
    t = c.get(f"/api/sessions/{sid}/triage").json()
    graves = {i["id"] for i in main.SESSIONS[sid].analysis["incidents"] if i["severity"] in ("Crítico", "Alto")}
    assert graves and all(i["recommendation"] == "Escalar" for i in t["items"] if i["incident_id"] in graves)


def test_providers_and_health_expose_no_keys(api, monkeypatch):
    c, _, _ = api
    monkeypatch.setenv("OPENAI_API_KEY", KEY_OPENAI)
    p = c.get("/api/ai/providers").json()
    assert p["openai"]["configured"] is True and p["gemini"]["configured"] is False and p["gemini"]["suggested"]
    h = c.get("/api/health")
    assert h.json()["ai_keys"] == {"anthropic": False, "openai": True, "gemini": False}
    assert KEY_OPENAI not in h.text and KEY_OPENAI not in json.dumps(p)


def test_anthropic_and_ollama_paths_are_unchanged(api):
    c, sid, _ = api
    r = c.post(f"/api/sessions/{sid}/ai")
    assert r.status_code == 400 and "Anthropic" in r.json()["detail"]
    assert c.post(f"/api/sessions/{sid}/ai", params={"provider": "otro"}).status_code == 400
