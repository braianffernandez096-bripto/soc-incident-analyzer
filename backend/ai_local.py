"""IA local con Ollama: la misma redacción del informe, sin enviar datos a un tercero.

Ollama corre en tu equipo (o en uno que tú elijas) y expone una API HTTP. Aquí solo se reemplaza la llamada al modelo; todo lo demás
es igual que con Claude: el motor decide la criticidad, el verificador descarta los `Log_ID` y las IP inventados y, si el modelo falla,
el informe sigue saliendo por reglas.

- La dirección de Ollama se define solo en el servidor (`OLLAMA_HOST`, por defecto http://127.0.0.1:11434); nunca viene del navegador,
  para que nadie pueda usar la app para consultar otras direcciones de la red.
- No hay dependencias nuevas: se usa `httpx`, que el proyecto ya tiene. No se siguen redirecciones ni se usan los proxies del entorno.
- El nombre del modelo debe estar instalado en ese Ollama (`ollama pull <modelo>`); la app no lo adivina.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Callable
from urllib.parse import urlsplit

import httpx

from .ai import SYSTEM_PROMPT, _normalize

DEFAULT_HOST = "http://127.0.0.1:11434"
PROBE_TIMEOUT = 3.0            # s: ver si Ollama responde y qué modelos tiene
DEFAULT_CALL_TIMEOUT = 3600    # s por consulta: un equipo de 2 procesadores sin GPU puede tardar más de 15 minutos en un incidente grande
DEFAULT_NUM_CTX = 16384        # Ollama usa por defecto un contexto de 2.048-4.096 tokens y recortaría la evidencia en silencio

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.I)


class OllamaError(RuntimeError):
    """Error de Ollama con mensaje apto para mostrar (sin datos del log ni del servidor)."""


def host() -> str:
    """Dirección del servidor Ollama, validada. Solo http/https, sin usuario ni ruta."""
    raw = (os.environ.get("OLLAMA_HOST", "").strip() or DEFAULT_HOST)
    if "://" not in raw:
        raw = "http://" + raw
    u = urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise OllamaError("OLLAMA_HOST no es válido: usa solo http(s)://equipo:puerto, por ejemplo http://127.0.0.1:11434.")
    return f"{u.scheme}://{u.netloc}"


def is_local(h: str) -> bool:
    """True si Ollama está en este mismo equipo (los datos no salen de él)."""
    name = urlsplit(h).hostname or ""
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def num_ctx() -> int:
    try:
        return max(2048, min(int(os.environ.get("OLLAMA_NUM_CTX", DEFAULT_NUM_CTX)), 131072))
    except ValueError:
        return DEFAULT_NUM_CTX


def call_timeout() -> float:
    """Tiempo máximo de espera por consulta, en segundos (`OLLAMA_TIMEOUT`; entre 60 s y 4 h)."""
    try:
        return float(max(60, min(int(os.environ.get("OLLAMA_TIMEOUT", DEFAULT_CALL_TIMEOUT)), 14400)))
    except ValueError:
        return float(DEFAULT_CALL_TIMEOUT)


def _client(http: httpx.Client | None, timeout: float) -> tuple[httpx.Client, bool]:
    if http is not None:
        return http, False
    return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False, headers={"user-agent": "soc-incident-analyzer"}), True


def status(http: httpx.Client | None = None) -> dict:
    """Estado para la interfaz: si responde, en qué equipo está y qué modelos tiene instalados. Nunca lanza."""
    out = {"host": None, "local": None, "available": False, "models": [], "error": None}
    try:
        h = host()
    except OllamaError as exc:
        out["error"] = str(exc)
        return out
    out["host"], out["local"] = h, is_local(h)
    client, own = _client(http, PROBE_TIMEOUT)
    try:
        r = client.get(f"{h}/api/tags", timeout=PROBE_TIMEOUT)
        r.raise_for_status()
        names = sorted({m.get("name", "") for m in (r.json().get("models") or []) if isinstance(m, dict) and m.get("name")})
        out["available"], out["models"] = True, names
        if not names:
            out["error"] = "Ollama responde, pero no tiene modelos instalados. Instala uno con `ollama pull <modelo>`."
    except (httpx.HTTPError, ValueError):
        out["error"] = f"No se pudo conectar con Ollama en {h}. ¿Está en ejecución?"
    finally:
        if own:
            client.close()
    return out


def _parse(content: str) -> dict:
    text = _FENCE_RE.sub("", content or "").strip()
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def make_call(model: str, http: httpx.Client | None = None) -> Callable[[dict, str, int], dict]:
    """Devuelve `call(tool, texto, max_tokens)` con la misma firma que usa `ai.generate` para Claude."""
    h = host()
    ctx = num_ctx()
    limit = call_timeout()
    client, own = _client(http, limit)

    def call(tool: dict, user_text: str, max_tokens: int) -> dict:
        schema = tool.get("input_schema", {})
        must = ("\n\nResponde ÚNICAMENTE con un objeto JSON que cumpla el esquema indicado; no escribas texto fuera del JSON. "
                "Cada lista debe ser un arreglo JSON real.")
        best = None
        for attempt in (1, 2):
            extra = "\nIMPORTANTE: el intento anterior no fue válido. Entrega solo el objeto JSON completo, con las listas como arreglos." if attempt == 2 else ""
            body = {"model": model, "stream": False, "format": schema,
                    "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_text + must + extra}],
                    "options": {"temperature": 0.2, "num_ctx": ctx, "num_predict": max_tokens}}
            try:
                r = client.post(f"{h}/api/chat", json=body, timeout=limit)
            except httpx.ConnectError as exc:
                raise OllamaError(f"No se pudo conectar con Ollama en {h}. ¿Está en ejecución?") from exc
            except httpx.TimeoutException as exc:
                raise OllamaError(f"Ollama tardó más de {int(limit // 60)} minutos en responder. Sube OLLAMA_TIMEOUT, usa un modelo más chico o analiza menos eventos.") from exc
            except httpx.HTTPError as exc:
                raise OllamaError(f"Error de red al hablar con Ollama ({type(exc).__name__}).") from exc
            if r.status_code == 404:
                raise OllamaError(f"Ollama no tiene el modelo «{model}». Instálalo con `ollama pull {model}`.")
            if r.status_code != 200:
                raise OllamaError(f"Ollama respondió con el código {r.status_code}.")
            try:
                content = (r.json().get("message") or {}).get("content", "")
            except ValueError:
                content = ""
            raw = _parse(content)
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
        raise OllamaError("El modelo local no devolvió un JSON válido con el esquema esperado. Un modelo más grande suele resolverlo.")

    return call
