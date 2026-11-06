"""IA local con Ollama contra un servidor simulado (sin red, sin Ollama y sin claves): estado, adaptador, API y garantías de seguridad."""
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import ai, ai_local, main
from backend.analysis import analyze
from backend.parser import load_events
from tests.integration.test_ai import _fake_model

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
MODELS = ["llama3.1:8b", "qwen2.5:14b"]


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


class FakeOllama:
    """Servidor Ollama simulado. `reply(body)` decide el contenido del mensaje; guarda las peticiones recibidas."""

    def __init__(self, reply=None, models=MODELS, chat_status=200):
        self.requests, self.models, self.chat_status = [], models, chat_status
        self.reply = reply or self.default_reply

    @staticmethod
    def default_reply(body):
        props = body["format"].get("properties", {})
        tool = {"name": "submit_executive_report" if "executive_summary" in props else "group"}
        return json.dumps(_fake_model(tool, body["messages"][-1]["content"], 1000), ensure_ascii=False)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": m} for m in self.models]})
        if request.url.path == "/api/chat":
            if self.chat_status != 200:
                return httpx.Response(self.chat_status, json={"error": "x"})
            body = json.loads(request.content)
            return httpx.Response(200, json={"message": {"role": "assistant", "content": self.reply(body)}})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def chats(self):
        return [json.loads(r.content) for r in self.requests if r.url.path == "/api/chat"]


# ------------------------------------------------------------------ dirección y estado
@pytest.mark.parametrize("value,expected", [
    ("", "http://127.0.0.1:11434"), ("http://localhost:11434", "http://localhost:11434"),
    ("192.168.1.20:11434", "http://192.168.1.20:11434"), ("https://ollama.lab.example/", "https://ollama.lab.example"),
])
def test_host_valid(monkeypatch, value, expected):
    monkeypatch.setenv("OLLAMA_HOST", value)
    assert ai_local.host() == expected


@pytest.mark.parametrize("value", ["ftp://x:11434", "http://user:pass@host:11434", "http://host:11434/api/chat", "http://host:11434/?a=1", "file:///etc/passwd"])
def test_host_invalid_is_rejected(monkeypatch, value):
    monkeypatch.setenv("OLLAMA_HOST", value)
    with pytest.raises(ai_local.OllamaError):
        ai_local.host()


@pytest.mark.parametrize("h,local", [("http://127.0.0.1:11434", True), ("http://localhost:11434", True), ("http://[::1]:11434", True),
                                     ("http://192.168.1.20:11434", False), ("https://ollama.lab.example", False)])
def test_is_local(h, local):
    assert ai_local.is_local(h) is local


def test_status_lists_models(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    st = ai_local.status(FakeOllama().client())
    assert st["available"] and st["local"] and st["models"] == sorted(MODELS) and st["error"] is None


def test_status_without_models_explains_how_to_install(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    st = ai_local.status(FakeOllama(models=[]).client())
    assert st["available"] and not st["models"] and "ollama pull" in st["error"]


def test_status_when_ollama_is_down_does_not_raise(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    def down(request):
        raise httpx.ConnectError("refused")
    st = ai_local.status(httpx.Client(transport=httpx.MockTransport(down)))
    assert not st["available"] and "¿Está en ejecución?" in st["error"]


def test_own_client_ignores_proxies_and_redirects():
    c, own = ai_local._client(None, 5)
    try:
        assert own and c.follow_redirects is False and c.trust_env is False
    finally:
        c.close()


# ------------------------------------------------------------------ redacción
def test_generation_with_local_model(ctx, monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    df, a = ctx
    before = {f["id"]: f["severity"] for f in a["findings"]}
    srv = FakeOllama()
    r = ai.generate(a, df, None, model="llama3.1:8b", call=ai_local.make_call("llama3.1:8b", srv.client()), provider="ollama", workers=1)
    assert r["mode"] == "ia" and r["provider"] == "ollama" and r["model"] == "llama3.1:8b"
    assert before == {f["id"]: f["severity"] for f in a["findings"]}                      # la criticidad no la toca el modelo
    blob = str(r)
    for invented in ("EVT-99999", "EVT-88888", "9.9.9.9", "8.8.8.8", "F-999", "INC-999"):
        assert invented not in blob, invented                                              # el verificador sigue actuando
    chat = srv.chats()[0]
    assert chat["stream"] is False and chat["format"]["type"] == "object"
    assert chat["options"]["num_ctx"] >= 16384                                            # sin recorte silencioso de la evidencia
    assert all("authorization" not in r.headers for r in srv.requests)                    # no hay clave ni cabeceras de cuenta


def test_hostile_local_model_cannot_change_severity(ctx, monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    df, a = ctx
    before = {f["id"]: f["severity"] for f in a["findings"]}

    def hostile(body):
        out = json.loads(FakeOllama.default_reply(body))
        out["severity"] = "Bajo"
        for f in out.get("findings", []):
            f["severity"] = "Bajo"
        return json.dumps(out)
    r = ai.generate(a, df, None, model="m", call=ai_local.make_call("m", FakeOllama(reply=hostile).client()), provider="ollama", workers=1)
    assert before == {f["id"]: f["severity"] for f in a["findings"]}
    assert all(v.get("severity", "x") != "Bajo" or before.get(k) == "Bajo" for k, v in r["findings"].items())


def test_json_inside_code_fence_is_accepted(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}}
    call = ai_local.make_call("m", FakeOllama(reply=lambda b: "```json\n{\"x\": \"hola\"}\n```").client())
    assert call(tool, "texto", 100) == {"x": "hola"}


def test_invalid_json_is_retried_once_and_then_fails_clearly(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    srv = FakeOllama(reply=lambda b: "no soy JSON")
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}}
    with pytest.raises(ai_local.OllamaError, match="JSON válido"):
        ai_local.make_call("m", srv.client())(tool, "texto", 100)
    assert len(srv.chats()) == 2


def test_unrecoverable_list_is_retried(monkeypatch):
    """Una lista de objetos entregada como texto libre no se puede reconstruir: se reintenta una vez, como con Claude."""
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    answers = iter(['{"items": "paso uno y paso dos"}', '{"items": [{"n": "uno"}, {"n": "dos"}]}'])
    srv = FakeOllama(reply=lambda b: next(answers))
    obj = {"type": "object", "properties": {"n": {"type": "string"}}}
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {"items": {"type": "array", "items": obj}}, "required": ["items"]}}
    assert ai_local.make_call("m", srv.client())(tool, "texto", 100) == {"items": [{"n": "uno"}, {"n": "dos"}]}
    assert len(srv.chats()) == 2


@pytest.mark.parametrize("value,expected", [("", 3600.0), ("1800", 1800.0), ("5", 60.0), ("999999", 14400.0), ("abc", 3600.0)])
def test_call_timeout_is_configurable_and_bounded(monkeypatch, value, expected):
    monkeypatch.setenv("OLLAMA_TIMEOUT", value)
    assert ai_local.call_timeout() == expected


@pytest.mark.parametrize("status,msg", [(404, "ollama pull"), (500, "código 500")])
def test_http_errors_have_readable_messages(monkeypatch, status, msg):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {}}}
    with pytest.raises(ai_local.OllamaError, match=msg):
        ai_local.make_call("m", FakeOllama(chat_status=status).client())(tool, "texto", 100)


def test_connection_failure_and_timeout_have_readable_messages(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    tool = {"name": "t", "input_schema": {"type": "object", "properties": {}}}
    for exc, msg in ((httpx.ConnectError("x"), "¿Está en ejecución"), (httpx.ReadTimeout("x"), "OLLAMA_TIMEOUT")):
        def boom(request, exc=exc):
            raise exc
        with pytest.raises(ai_local.OllamaError, match=msg):
            ai_local.make_call("m", httpx.Client(transport=httpx.MockTransport(boom)))(tool, "t", 10)


def test_model_failure_falls_back_to_rules(ctx, monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    df, a = ctx
    r = ai.generate(a, df, None, model="m", call=ai_local.make_call("m", FakeOllama(chat_status=500).client()), provider="ollama", workers=1)
    assert r["mode"] == "determinista" and r["errors"] and r["provider"] is None
    assert set(r["findings"]) == {f["id"] for f in a["findings"]}


# ------------------------------------------------------------------ API
@pytest.fixture
def api(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setitem(main.RATE_LIMITS, "/api/ai", (1000, 60))
    srv = FakeOllama()
    monkeypatch.setattr(main, "_ollama_http", srv.client)
    main._hits.clear()
    c = TestClient(main.app)
    sid = c.post("/api/upload", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/octet-stream")}).json()["session_id"]
    yield c, sid, srv
    main._hits.clear()                                                                      # no deja consumido el límite de las demás pruebas


def test_providers_endpoint(api):
    c, _, _ = api
    r = c.get("/api/ai/providers").json()
    assert r["anthropic"]["configured"] is False and r["ollama"]["available"] and r["ollama"]["models"] == sorted(MODELS)


def test_report_with_ollama_needs_no_key(api):
    c, sid, _ = api
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "ollama", "model": "llama3.1:8b"})
    assert r.status_code == 200, r.text
    ai_result = r.json()["ai"]
    assert ai_result["mode"] == "ia" and ai_result["provider"] == "ollama" and ai_result["model"] == "llama3.1:8b"
    pdf = c.get(f"/api/sessions/{sid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


@pytest.mark.parametrize("params,msg", [({"provider": "ollama"}, "modelo instalado"), ({"provider": "ollama", "model": "otro:1b"}, "modelo instalado"),
                                        ({"provider": "otro"}, "no reconocido")])
def test_api_rejects_unknown_model_or_provider(api, params, msg):
    c, sid, srv = api
    r = c.post(f"/api/sessions/{sid}/ai", params=params)
    assert r.status_code == 400 and msg in r.text
    assert not srv.chats()                                                                  # no se llegó a consultar el modelo


def test_api_when_ollama_is_down(api, monkeypatch):
    c, sid, _ = api

    def down(request):
        raise httpx.ConnectError("x")
    monkeypatch.setattr(main, "_ollama_http", lambda: httpx.Client(transport=httpx.MockTransport(down)))
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "ollama", "model": "llama3.1:8b"})
    assert r.status_code == 400 and "Ollama" in r.text


def test_anthropic_path_is_unchanged(api):
    c, sid, _ = api
    r = c.post(f"/api/sessions/{sid}/ai")
    assert r.status_code == 400 and "API key de Anthropic" in r.text


def test_model_name_from_the_browser_cannot_redirect_the_request(api):
    """El nombre del modelo solo se acepta si Ollama lo lista; la dirección del servidor no sale del navegador."""
    c, sid, srv = api
    r = c.post(f"/api/sessions/{sid}/ai", params={"provider": "ollama", "model": "../../x", "host": "http://169.254.169.254"})
    assert r.status_code == 400
    assert all(req.url.host != "169.254.169.254" for req in srv.requests)
