"""Proveedores de IA en la nube con clave propia del usuario: OpenAI y Gemini (Google).

Misma interfaz que Claude y Ollama: ``call(tool, texto, max_tokens) -> dict``. La app solo cambia el adaptador; el motor sigue fijando la severidad
y el verificador sigue descartando lo inventado, sea cual sea el modelo.

Seguridad:
- Las direcciones de los servicios están fijas aquí. El navegador solo elige de una lista y nunca envía una URL (si no, la app serviría para consultar
  direcciones internas de la red). Sin redirecciones ni proxies del entorno.
- El nombre del modelo se valida con una expresión estricta antes de usarse (va en la URL de Gemini).
- La clave viaja por cabecera, no se guarda ni se registra, y los mensajes de error no repiten lo que devuelve el proveedor (podría incluir parte de la clave).
Sin dependencias nuevas: solo httpx, que ya usa el adaptador de Ollama.
"""
from __future__ import annotations

import os
import re
import time
from typing import Callable

import httpx

from .ai import SYSTEM_PROMPT, _normalize

PROVIDERS = ("openai", "gemini")
LABELS = {"openai": "OpenAI", "gemini": "Gemini (Google)"}
KEY_ENV = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}
MODEL_ENV = {"openai": "OPENAI_MODEL", "gemini": "GEMINI_MODEL"}
# Los nombres de modelo cambian seguido: son valores por defecto y sugerencias, el usuario puede escribir otro o fijarlo en .env
DEFAULT_MODELS = {"openai": "gpt-5.4-mini", "gemini": "gemini-3.8-flash"}
SUGGESTED = {"openai": ["gpt-5.4-mini", "gpt-5"], "gemini": ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-4-argon"]}
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
TIMEOUT = 180.0
RETRIES = 2
_GEMINI_SCHEMA_KEYS = {"type", "description", "properties", "items", "enum", "required", "nullable", "format", "minItems", "maxItems", "minimum", "maximum"}


class CloudError(RuntimeError):
    """Error con mensaje apto para mostrar (sin datos del log, de la clave ni del servidor)."""


def default_model(provider: str) -> str:
    env = os.environ.get(MODEL_ENV[provider], "").strip()
    return env if MODEL_RE.match(env) else DEFAULT_MODELS[provider]


def env_key(provider: str) -> str | None:
    return os.environ.get(KEY_ENV[provider], "").strip() or None


def valid_model(model: str | None) -> str | None:
    m = (model or "").strip()
    return m if MODEL_RE.match(m) else None


def _client(http: httpx.Client | None) -> tuple[httpx.Client, bool]:
    if http is not None:
        return http, False
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False, trust_env=False), True


def _gemini_schema(node):
    """Gemini acepta solo un subconjunto de JSON Schema: se descartan las palabras que no entiende."""
    if isinstance(node, dict):
        return {k: _gemini_schema(v) if k not in ("properties",) else {p: _gemini_schema(s) for p, s in v.items()}
                for k, v in node.items() if k in _GEMINI_SCHEMA_KEYS}
    return node


def _status_error(provider: str, status: int) -> CloudError:
    name = LABELS[provider]
    if status in (401, 403):
        return CloudError(f"{name} rechazó la clave (error {status}). Revísala y confirma que tiene permiso para usar la API.")
    if status == 404:
        return CloudError(f"{name} no encontró ese modelo. Revisa el nombre del modelo.")
    if status == 429:
        return CloudError(f"{name} limitó las consultas o se agotó la cuota o el saldo de la cuenta (error 429). Espera un momento o revisa tu plan.")
    if status in (400, 422):
        return CloudError(f"{name} rechazó la solicitud (error {status}). Verifica que el modelo admita herramientas y que el nombre sea correcto.")
    return CloudError(f"{name} respondió con el código {status}. Intenta de nuevo en unos minutos.")


def _post(client: httpx.Client, provider: str, url: str, headers: dict, body: dict) -> dict:
    for attempt in range(RETRIES + 1):
        try:
            r = client.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except httpx.TimeoutException as exc:
            raise CloudError(f"{LABELS[provider]} tardó más de {int(TIMEOUT // 60)} minutos en responder.") from exc
        except httpx.HTTPError as exc:
            raise CloudError(f"Error de red al hablar con {LABELS[provider]} ({type(exc).__name__}).") from exc
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError as exc:
                raise CloudError(f"{LABELS[provider]} devolvió una respuesta que no es JSON.") from exc
        if r.status_code in (429, 500, 502, 503, 504) and attempt < RETRIES:
            time.sleep(1.5 * (attempt + 1))
            continue
        raise _status_error(provider, r.status_code)
    raise CloudError(f"{LABELS[provider]} no respondió.")      # inalcanzable, por claridad


def _openai_args(data: dict) -> dict | None:
    import json
    for choice in (data.get("choices") or [])[:1]:
        for tc in ((choice.get("message") or {}).get("tool_calls") or []):
            try:
                args = json.loads((tc.get("function") or {}).get("arguments") or "")
            except ValueError:
                continue
            if isinstance(args, dict):
                return args
    return None


def _gemini_args(data: dict) -> dict | None:
    for cand in (data.get("candidates") or [])[:1]:
        for part in ((cand.get("content") or {}).get("parts") or []):
            fc = part.get("functionCall") or part.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("args"), dict):
                return fc["args"]
    return None


def make_call(provider: str, api_key: str, model: str, http: httpx.Client | None = None) -> Callable[[dict, str, int], dict]:
    """Devuelve `call(tool, texto, max_tokens)` para OpenAI o Gemini, con la misma firma que Claude y Ollama."""
    if provider not in PROVIDERS:
        raise CloudError("Proveedor de IA no reconocido.")
    if not valid_model(model):
        raise CloudError("El nombre del modelo no es válido.")
    if not (api_key or "").strip():
        raise CloudError(f"Falta la clave de {LABELS[provider]}.")
    client, _ = _client(http)

    def call(tool: dict, user_text: str, max_tokens: int) -> dict:
        schema = tool.get("input_schema", {})
        must = f"\n\nResponde ÚNICAMENTE llamando a la función `{tool['name']}`; no escribas texto fuera de ella."
        best = None
        for attempt in (1, 2):
            extra = ("\nIMPORTANTE: el intento anterior no fue válido. Llama a la función y entrega cada lista como un arreglo JSON real, no como texto."
                     if attempt == 2 else "")
            text = user_text + must + extra
            if provider == "openai":
                body = {"model": model, "max_completion_tokens": max_tokens,
                        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": text}],
                        "tools": [{"type": "function", "function": {"name": tool["name"], "description": tool.get("description", ""), "parameters": schema}}],
                        "tool_choice": {"type": "function", "function": {"name": tool["name"]}}}
                data = _post(client, provider, OPENAI_URL, {"Authorization": f"Bearer {api_key.strip()}"}, body)
                raw = _openai_args(data)
            else:
                body = {"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                        "contents": [{"role": "user", "parts": [{"text": text}]}],
                        "tools": [{"functionDeclarations": [{"name": tool["name"], "description": tool.get("description", ""), "parameters": _gemini_schema(schema)}]}],
                        "toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": [tool["name"]]}},
                        # los modelos con razonamiento gastan parte del tope en pensar: se deja margen
                        "generationConfig": {"maxOutputTokens": max_tokens + 4096}}
                data = _post(client, provider, GEMINI_URL.format(model=model), {"x-goog-api-key": api_key.strip()}, body)
                raw = _gemini_args(data)
            if not raw:
                continue
            out = _normalize(raw, schema)
            lost = [k for k in schema.get("required", []) if schema.get("properties", {}).get(k, {}).get("type") == "array"
                    and not out.get(k) and raw.get(k)]
            if not lost:
                return out
            best = out
        if best is not None:
            return best
        raise CloudError(f"{LABELS[provider]} no devolvió el resultado estructurado esperado. Prueba con otro modelo.")

    return call
