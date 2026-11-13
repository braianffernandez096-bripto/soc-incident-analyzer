"""API y servidor web de SOC Incident Analyzer.

Ejecutar desde la raíz del proyecto:
    uvicorn backend.main:app --reload --port 8000
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import copy
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Annotated
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import ai as ai_mod
from . import ai_cloud
from . import ai_local
from . import attack as attack_mod
from . import captcha as captcha_mod
from . import detection as D
from . import dnsdoh
from . import domaincheck
from . import filecheck
from . import intel as intel_mod
from . import lookalikes as lookalikes_mod
from . import phishing as phishing_mod
from . import report_html as report_html_mod
from . import senderreview
from . import triage as triage_mod
from . import notify as notify_mod
from . import wazuh_indexer
from . import wazuh_live
from . import siemqueries
from .analysis import analyze, rows_for
from .parser import SUPPORTED_EXT, ParseError, load_events
from .report import build_pdf, build_phishing_pdf

ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_SESSIONS = 10
MAX_PARALLEL_ANALYSES = 2      # análisis simultáneos (son CPU pura): el resto recibe 503 y reintenta
W_MAX_ALERTS = wazuh_live.W.MAX_ALERTS_PER_CALL


def _load_dotenv() -> None:
    """Lector mínimo de .env (KEY=VALUE) para no depender de paquetes extra."""
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format="ts=%(asctime)s level=%(levelname)s logger=%(name)s %(message)s")
for _noisy in ("httpx", "httpcore", "anthropic", "urllib3"):      # these log every outbound URL at INFO
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("soc.api")


class SafeJSON(JSONResponse):
    """JSON tolerante a tipos de numpy/pandas."""

    def render(self, content) -> bytes:
        def default(o):
            if hasattr(o, "item"):
                return o.item()
            if isinstance(o, (set, tuple)):
                return list(o)
            return str(o)
        return json.dumps(content, ensure_ascii=False, default=default).encode("utf-8")


_DOCS = os.environ.get("ENABLE_DOCS", "").strip().lower() in ("1", "true", "yes")      # API docs reveal the full surface: opt-in
app = FastAPI(title="SOC Incident Analyzer", version="1.11.0", default_response_class=SafeJSON,
              docs_url="/docs" if _DOCS else None, redoc_url="/redoc" if _DOCS else None, openapi_url="/openapi.json" if _DOCS else None)


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cache-Control": "no-store",
}


# ---- optional access token --------------------------------------------------------------------------
# Off by default (the app binds to localhost). When APP_ACCESS_TOKEN is set, every /api/ route except the two
# below requires "Authorization: Bearer <token>". It is ONE shared secret, not a user system: serve it over HTTPS.
OPEN_API_PATHS = {"/api/health", "/api/auth/status", "/api/wazuh/alerts"}      # la ingesta de Wazuh se autentica con su propia clave (X-Wazuh-Token)


def _access_token() -> str:
    return os.environ.get("APP_ACCESS_TOKEN", "").strip()


# ---- allowed Host names (DNS rebinding) ---------------------------------------------------------------
# A page on any website can make the browser talk to http://127.0.0.1:8000 under its own name (DNS rebinding) and then
# read the API as same-origin. Browsers always send the name they used in "Host", so anything but our own names is refused.
# Extra names (reverse proxy, another computer) go in ALLOWED_HOSTS, comma separated; the host of APP_BASE_URL is added too.
HOST_EXEMPT_PATHS = {"/api/wazuh/alerts"}      # machine to machine (Docker alias), authenticated with its own key; no browser data comes back


def _allowed_hosts() -> set[str]:
    hosts = {"127.0.0.1", "localhost", "::1"}
    hosts |= {h.strip().lower().rstrip(".") for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
    try:
        base = urlsplit(os.environ.get("APP_BASE_URL", "").strip()).hostname
    except ValueError:
        base = None
    if base:
        hosts.add(base.lower().rstrip("."))
    return hosts


def _host_ok(request: Request) -> bool:
    allowed = _allowed_hosts()
    if "*" in allowed:
        return True
    raw = request.headers.get("host", "").strip().lower()
    if raw.startswith("["):                      # [::1]:8000
        name = raw[1:].split("]", 1)[0]
    else:
        name = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
    return name.rstrip(".") in allowed


def _token_ok(request: Request, token: str) -> bool:
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    return scheme.lower() == "bearer" and secrets.compare_digest(supplied.strip().encode(), token.encode())


@app.middleware("http")
async def access_control(request: Request, call_next):
    token = _access_token()
    path = request.url.path
    if path not in HOST_EXEMPT_PATHS and not _host_ok(request):
        log.warning("host_rejected host=%r path=%s", request.headers.get("host", "")[:80], path[:80])
        return JSONResponse({"detail": "Nombre de host no permitido. Si accedes a la app con otro nombre, agrégalo en ALLOWED_HOSTS."}, status_code=400)
    if token and path.startswith("/api/") and path not in OPEN_API_PATHS and not _token_ok(request, token):
        try:
            _rate_limit(request, "/auth-fail", 10, 60)      # only failures count: brute force gets 429
            _rate_limit_key("*", "/auth-fail-all", 100, 60)  # and a cap across all IPs: the per-IP one depends on the proxy setup
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=429)
        return JSONResponse({"detail": "Acceso no autorizado. Introduce la clave de acceso."}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    return await call_next(request)


if 0 < len(_access_token()) < 16:
    logging.getLogger("soc.api").warning("access_token_weak length=%d (use 16+ characters)", len(_access_token()))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


# Límite de peticiones por IP (ventana deslizante en memoria). Protege los endpoints costosos.
RATE_LIMITS = {"/api/upload": (20, 60), "/api/ai": (6, 60), "/api/intel": (6, 60), "/api/captcha": (30, 60), "/api/dns": (6, 60)}      # (peticiones, segundos)
_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _rate_limit(request: Request, key: str, limit: int, window: int) -> None:
    _rate_limit_key(request.client.host if request.client else "unknown", key, limit, window)


def _rate_limit_key(ip: str, key: str, limit: int, window: int) -> None:
    now = time.monotonic()
    with _hits_lock:
        q = _hits[(ip, key)]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            log.warning("rate_limited ip=%s endpoint=%s", ip, key)
            raise HTTPException(429, "Demasiadas solicitudes. Espera un momento e inténtalo de nuevo.")
        q.append(now)


@dataclass
class Session:
    df: pd.DataFrame
    analysis: dict
    ai: dict
    filename: str
    client: str = ""
    analyst: str = ""
    created: float = field(default_factory=time.time)
    intel: dict | None = None      # estado de la consulta de reputación (VirusTotal / AbuseIPDB)
    phish_id: str = ""             # análisis de correos asociado (se añade al PDF)
    triage: dict | None = None     # recomendaciones de triaje generadas con IA (sin ellas se usa la del motor)
    decisions: dict = field(default_factory=dict)   # decisión del analista por incidente (solo en memoria, como la sesión)
    origin: str = ""               # "wazuh" si la sesión es la instantánea de las alertas de Wazuh (única que puede consultar el Indexer)


SESSIONS: dict[str, Session] = {}


@dataclass
class PhishSession:
    items: list
    errors: list
    created: float = field(default_factory=time.time)
    intel: dict | None = None
    client: str = ""
    analyst: str = ""


PHISH: dict[str, PhishSession] = {}
MAX_EML_FILES = 5
PASTED_NAME = "cabeceras-pegadas"


def _get(sid: str) -> Session:
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(404, "Sesión no encontrada. Vuelve a cargar el archivo.")
    return s


def _api_key(header_key: str | None) -> str | None:
    return (header_key or "").strip() or os.environ.get("ANTHROPIC_API_KEY", "").strip() or None


def _ai_keys() -> dict:
    """Qué proveedores de nube tienen la clave definida en el servidor (nunca la clave en sí)."""
    return {"anthropic": bool(_api_key(None)), **{p: bool(ai_cloud.env_key(p)) for p in ai_cloud.PROVIDERS}}


def _intel_keys(vt_header: str | None = None, abuse_header: str | None = None) -> tuple[str | None, str | None]:
    vt = (vt_header or "").strip() or os.environ.get("VT_API_KEY", "").strip() or None
    ab = (abuse_header or "").strip() or os.environ.get("ABUSEIPDB_API_KEY", "").strip() or None
    return vt, ab


def _new_http():
    """Cliente HTTP para las consultas de reputación (None = el módulo crea el suyo). Punto de inyección para las pruebas."""
    return None


# --------------------------------------------------------------------------
@app.get("/api/auth/status")
def auth_status():
    return {"required": bool(_access_token())}


@app.get("/api/auth/check")
def auth_check():
    """Reaches here only with a valid token (the middleware answers 401 otherwise)."""
    return {"ok": True}


@app.get("/api/health")
def health(request: Request):
    token = _access_token()
    if token and not _token_ok(request, token):
        return {"ok": True}                      # liveness only: which AI providers are configured is not public
    return {"ok": True, "ai_configured": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
            "model": os.environ.get("ANTHROPIC_MODEL") or ai_mod.DEFAULT_MODEL, "ai_keys": _ai_keys()}


# ---- captcha local (opcional: CAPTCHA=on) ------------------------------------------------------------
# Protege las rutas que reciben archivos (/api/upload y /api/phishing). Los datos de ejemplo son archivos fijos del repositorio
# y no se protegen. Ver backend/captcha.py.
def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_captcha(request: Request) -> None:
    if captcha_mod.enabled() and not captcha_mod.consume_pass(request.headers.get("x-captcha-pass", ""), _client_ip(request)):
        raise HTTPException(403, "Resuelve el captcha para continuar.", headers={"X-Captcha-Required": "1"})


class CaptchaAnswer(BaseModel):
    """Imágenes: ``selected``. Rompecabezas: ``x`` (posición final de la pieza) y ``track`` ([ms, x] del arrastre)."""
    token: str = Field(max_length=100)
    selected: list[int] = Field(default_factory=list, max_length=captcha_mod.GRID)
    x: int | None = Field(default=None, ge=0, le=captcha_mod.PUZ_W)
    track: list[Annotated[list[int], Field(min_length=2, max_length=2)]] = Field(default_factory=list, max_length=400)


@app.get("/api/captcha/status")
def captcha_status():
    return {"enabled": captcha_mod.enabled()}


@app.post("/api/captcha/challenge")
def captcha_challenge(request: Request):
    if not captcha_mod.enabled():
        raise HTTPException(404, "El captcha no está activado en este servidor.")
    _rate_limit(request, "/api/captcha", *RATE_LIMITS["/api/captcha"])
    return captcha_mod.new_challenge()


@app.post("/api/captcha/verify")
def captcha_verify(request: Request, body: CaptchaAnswer):
    if not captcha_mod.enabled():
        raise HTTPException(404, "El captcha no está activado en este servidor.")
    _rate_limit(request, "/api/captcha", *RATE_LIMITS["/api/captcha"])
    if body.x is not None:
        grant = captcha_mod.verify_puzzle(body.token, body.x, body.track, _client_ip(request))
    else:
        grant = captcha_mod.verify(body.token, body.selected, _client_ip(request))
    if not grant:
        _rate_limit(request, "/captcha-fail", 10, 300)         # solo los fallos cuentan: adivinar a ciegas acaba en 429
        raise HTTPException(400, "Selección incorrecta o desafío caducado. Prueba con uno nuevo.")
    return {"pass": grant, "uses": captcha_mod.PASS_USES, "ttl": captcha_mod.PASS_TTL}


def _register_session(df: pd.DataFrame, analysis: dict, name: str, client: str = "", analyst: str = "", origin: str = "") -> dict:
    sid = secrets.token_urlsafe(16)
    SESSIONS[sid] = Session(df=df, analysis=analysis, ai=ai_mod.build_deterministic(analysis), filename=name,
                            client=client.strip(), analyst=analyst.strip(), origin=origin)
    while len(SESSIONS) > MAX_SESSIONS:
        SESSIONS.pop(min(SESSIONS, key=lambda k: SESSIONS[k].created))
    s = SESSIONS[sid]
    return {"session_id": sid, "filename": name, "client": s.client, "analyst": s.analyst,
            "analysis": analysis, "ai": s.ai, "ai_configured": bool(_api_key(None)), "ai_keys": _ai_keys()}


_ANALYSIS_SLOTS = threading.BoundedSemaphore(MAX_PARALLEL_ANALYSES)


def _with_slot(fn, *args):
    """Run a CPU-heavy analysis in one of the few slots. Without a free slot the caller gets 503 instead of piling up work."""
    if not _ANALYSIS_SLOTS.acquire(blocking=False):
        raise HTTPException(503, "El servidor está analizando otros archivos. Espera unos segundos e inténtalo de nuevo.", headers={"Retry-After": "15"})
    try:
        return fn(*args)
    finally:
        _ANALYSIS_SLOTS.release()


def _analyze_upload(data: bytes, name: str, client: str, analyst: str) -> dict:
    check = filecheck.inspect_upload(data, name)
    if check.reject:
        log.warning("upload_rejected reason=content_mismatch ext=%s size=%d", os.path.splitext(name)[1].lower(), len(data))
        raise HTTPException(422, check.reject)
    return _create_session(data, name, client, analyst, check.warnings)


def _create_session(data: bytes, name: str, client: str, analyst: str, warnings: list[str] | None = None) -> dict:
    try:
        df, meta = load_events(data, name)
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from exc
    t0 = time.perf_counter()
    analysis = analyze(df, meta)
    analysis["limitations"] = list(analysis.get("limitations", [])) + list(warnings or []) + filecheck.formula_warnings(df)
    log.info("analysis_done rows=%d findings=%d incidents=%d ms=%d", len(df), len(analysis["findings"]), len(analysis["incidents"]), (time.perf_counter() - t0) * 1000)
    return _register_session(df, analysis, name, client, analyst)


@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...), client: str = Form(""), analyst: str = Form("")):
    _rate_limit(request, "/api/upload", *RATE_LIMITS["/api/upload"])
    _require_captcha(request)
    name = os.path.basename(file.filename or "export.xlsx")[:120]
    if not name.lower().endswith(SUPPORTED_EXT):
        raise HTTPException(400, "Formato no soportado. Usa Excel (.xlsx), CSV/TSV o JSON/NDJSON.")
    chunks, size = [], 0
    while chunk := await file.read(1024 * 1024):   # lectura acotada: no carga archivos enormes completos en memoria
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "El archivo supera el límite de 25 MB.")
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(400, "El archivo está vacío.")
    # parsing and detection are pure CPU: off the event loop, or one upload freezes every other request (health included)
    return await run_in_threadpool(_with_slot, _analyze_upload, data, name, client, analyst)


SAMPLE_FILE = ROOT / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv"


@app.post("/api/sample")
def use_sample(request: Request, client: str = Form(""), analyst: str = Form("")):
    """Analyse the synthetic export shipped with the project (fixed path: nothing from the request picks the file)."""
    _rate_limit(request, "/api/upload", *RATE_LIMITS["/api/upload"])
    if not SAMPLE_FILE.is_file():
        raise HTTPException(404, "Este despliegue no incluye los datos de ejemplo.")
    return _with_slot(_create_session, SAMPLE_FILE.read_bytes(), SAMPLE_FILE.name, client, analyst)


@app.get("/api/sessions/{sid}")
def get_session(sid: str):
    s = _get(sid)
    return {"session_id": sid, "filename": s.filename, "client": s.client, "analyst": s.analyst, "analysis": s.analysis, "ai": s.ai}


@app.get("/api/sessions/{sid}/events")
def events(sid: str, page: int = 1, page_size: int = Query(50, ge=10, le=200), q: str = "", severity: str = "",
           flagged: str = "", host: str = "", user: str = "", event_id: str = "", finding: str = ""):
    s = _get(sid)
    df = s.df
    fm = s.analysis["flag_map"]
    m = pd.Series(True, index=df.index)
    if q.strip():
        needle = q.strip().lower()
        blob = (df["Log_ID"] + " " + df["Hostname"] + " " + df["User"] + " " + df["Source_IP"] + " " + df["Destination"] + " "
                + df["Event_Description"] + " " + df["Process_CommandLine"] + " " + df["Event_ID"]).str.lower()
        m &= blob.str.contains(needle, regex=False)
    if severity:
        m &= df["Severity"].str.lower() == severity.lower()
    if host:
        m &= df["Hostname"] == host
    if user:
        m &= df["User"] == user
    if event_id:
        m &= df["Event_ID"] == event_id
    incident_rows = {e for f in s.analysis["findings"] if f["incident_id"] for e in f["evidence_ids"]}
    if flagged == "1":   # solo eventos que forman parte de un incidente
        m &= df["Log_ID"].isin(incident_rows)
    if finding:
        m &= df["Log_ID"].map(lambda i: finding in fm.get(i, []))
    sub = df[m]
    total = len(sub)
    pages = max(1, -(-total // page_size))
    page = min(max(1, page), pages)
    chunk = sub.iloc[(page - 1) * page_size: page * page_size]
    rows = rows_for(df, list(chunk["Log_ID"]), fm)
    sev_by_id: dict[str, str] = {}
    for f in s.analysis["findings"]:
        if f["incident_id"]:
            for e in f["evidence_ids"]:
                sev_by_id[e] = D.max_sev([sev_by_id.get(e, "Bajo"), f["severity"]])
    for r in rows:
        r["flag_severity"] = sev_by_id.get(r["Log_ID"])
    return {
        "rows": rows, "total": total, "page": page, "pages": pages,
        "options": {"hosts": sorted(set(df["Hostname"]) - {""}), "users": sorted(set(df["User"]) - {""}),
                    "event_ids": sorted(set(df["Event_ID"])), "severities": sorted(set(df["Severity"]) - {""})},
    }


@app.get("/api/sessions/{sid}/findings/{fid}/evidence")
def finding_evidence(sid: str, fid: str):
    s = _get(sid)
    f = next((x for x in s.analysis["findings"] if x["id"] == fid), None)
    if not f:
        raise HTTPException(404, "Hallazgo no encontrado.")
    return {"rows": rows_for(s.df, f["evidence_ids"], s.analysis["flag_map"])}


@app.get("/api/sessions/{sid}/findings/{fid}/queries")
def finding_queries(sid: str, fid: str):
    """Consultas Splunk/KQL y regla Sigma del hallazgo, generadas con plantillas (nada sale del servidor)."""
    s = _get(sid)
    f = next((x for x in s.analysis["findings"] if x["id"] == fid), None)
    if not f:
        raise HTTPException(404, "Hallazgo no encontrado.")
    qs = siemqueries.queries_for(f)
    if not qs:
        raise HTTPException(404, "Este tipo de hallazgo no tiene consultas equivalentes.")
    return qs


@app.get("/api/sessions/{sid}/findings/{fid}/wazuh-context")
def finding_wazuh_context(sid: str, fid: str, request: Request):
    """Lo que el Indexer de Wazuh guardó del mismo equipo o IP alrededor del hallazgo. La consulta la arma el servidor; solo lectura."""
    if not wazuh_indexer.configured():
        raise HTTPException(404, "El contexto del Indexer de Wazuh no está configurado en este servidor.")
    _rate_limit(request, "/api/wazuh-context", 30, 60)
    s = _get(sid)
    if s.origin != "wazuh":       # un archivo subido puede traer cualquier equipo, IP u hora: no se le abre el Indexer
        raise HTTPException(403, "El contexto del Indexer solo está disponible en las alertas de Wazuh en vivo, no en archivos subidos.")
    f = next((x for x in s.analysis["findings"] if x["id"] == fid), None)
    if not f:
        raise HTTPException(404, "Hallazgo no encontrado.")
    try:
        return wazuh_indexer.context_for(f)
    except wazuh_indexer.IndexerError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/sessions/{sid}/sigma.yml")
def sigma_rules(sid: str):
    """Reglas Sigma de todos los tipos de hallazgo de la sesión (un documento YAML por regla)."""
    s = _get(sid)
    text, n = siemqueries.sigma_bundle(s.analysis["findings"])
    if not n:
        raise HTTPException(404, "Ningún hallazgo de esta sesión tiene una regla Sigma equivalente.")
    return Response(text, media_type="application/yaml",
                    headers={"Content-Disposition": 'attachment; filename="reglas_sigma.yml"'})


@app.post("/api/sessions/{sid}/meta")
def set_meta(sid: str, client: str = Form(""), analyst: str = Form("")):
    s = _get(sid)
    s.client, s.analyst = client.strip(), analyst.strip()
    return {"ok": True}


def _ollama_http():
    """Cliente HTTP para Ollama (None = el módulo crea el suyo, sin proxies ni redirecciones). Punto de inyección para las pruebas."""
    return None


def _cloud_http():
    """Cliente HTTP para OpenAI/Gemini (None = el módulo crea el suyo, sin proxies ni redirecciones). Punto de inyección para las pruebas."""
    return None


@app.get("/api/ai/providers")
def ai_providers(request: Request):
    """Qué proveedores de IA hay disponibles. Consulta solo la dirección de Ollama definida en el servidor."""
    _rate_limit(request, "/api/ai", *RATE_LIMITS["/api/ai"])
    return {"anthropic": {"configured": bool(_api_key(None)), "model": os.environ.get("ANTHROPIC_MODEL") or ai_mod.DEFAULT_MODEL},
            "ollama": ai_local.status(_ollama_http()),
            **{p: {"configured": bool(ai_cloud.env_key(p)), "model": ai_cloud.default_model(p), "suggested": ai_cloud.SUGGESTED[p]}
               for p in ai_cloud.PROVIDERS}}


def _resolve_provider(provider: str, model: str | None, header_key: str | None,
                      provider_key: str | None = None) -> tuple[dict, str | None]:
    """Valida el proveedor de IA y devuelve (kwargs para generate, clave de Anthropic). Lo comparten el informe y el triaje."""
    if provider not in ("anthropic", "ollama", *ai_cloud.PROVIDERS):
        raise HTTPException(400, "Proveedor de IA no reconocido.")
    if provider in ai_cloud.PROVIDERS:
        label = ai_cloud.LABELS[provider]
        key = (provider_key or "").strip() or ai_cloud.env_key(provider)
        if not key:
            raise HTTPException(400, f"No hay clave de {label}. Define {ai_cloud.KEY_ENV[provider]} en el archivo .env o pégala en el campo de la interfaz.")
        chosen = ai_cloud.valid_model(model) if (model or "").strip() else ai_cloud.default_model(provider)
        if not chosen:
            raise HTTPException(400, "El nombre del modelo no es válido (letras, números, punto, guion y guion bajo).")
        try:
            return {"model": chosen, "call": ai_cloud.make_call(provider, key, chosen, _cloud_http()), "provider": provider, "workers": 2}, None
        except ai_cloud.CloudError as exc:
            raise HTTPException(400, str(exc)) from exc
    if provider == "ollama":
        st = ai_local.status(_ollama_http())
        if not st["available"] or not st["models"]:
            raise HTTPException(400, st["error"] or "Ollama no está disponible.")
        if not model or model not in st["models"]:
            raise HTTPException(400, "Elige un modelo instalado en Ollama.")
        try:
            return {"model": model, "call": ai_local.make_call(model, _ollama_http()), "provider": "ollama", "workers": 1}, None
        except ai_local.OllamaError as exc:
            raise HTTPException(400, str(exc)) from exc
    key = _api_key(header_key)
    if not key:
        raise HTTPException(400, "No hay API key de Anthropic. Define ANTHROPIC_API_KEY en el archivo .env o pégala en el campo de la interfaz.")
    return {}, key


@app.post("/api/sessions/{sid}/ai")
def run_ai(sid: str, request: Request, x_anthropic_key: str | None = Header(default=None),
           x_provider_key: str | None = Header(default=None), provider: str = "anthropic", model: str | None = None):
    _rate_limit(request, "/api/ai", *RATE_LIMITS["/api/ai"])
    s = _get(sid)
    kwargs, key = _resolve_provider(provider, model, x_anthropic_key, x_provider_key)
    try:
        result = ai_mod.generate(s.analysis, s.df, key, **kwargs)
    except Exception as exc:  # error inesperado de la llamada global: detalle al log, mensaje genérico al usuario
        log.exception("ai_failed session=%s", sid)
        raise HTTPException(502, f"No se pudo completar el análisis con IA ({type(exc).__name__}). Revisa la clave y la conexión; se mantiene el informe por reglas.") from exc
    if result["mode"] != "ia":
        first = result["errors"][0] if result["errors"] else "el modelo no devolvió resultados verificables"
        log.warning("ai_fallback session=%s reason=%s", sid, first[:200])
        raise HTTPException(502, f"No se pudo usar la IA ({first}). Se mantiene el informe generado por reglas.")
    s.ai = result
    return {"ai": result}


# ---------------------------------------------------------------- triaje asistido por IA
@app.get("/api/sessions/{sid}/triage")
def get_triage(sid: str):
    """Recomendación por incidente (la del motor, o la de la IA si se generó) y la decisión del analista."""
    s = _get(sid)
    return triage_mod.view(s.analysis, s.triage, s.decisions)


@app.post("/api/sessions/{sid}/triage/ai")
def run_triage_ai(sid: str, request: Request, x_anthropic_key: str | None = Header(default=None),
                  x_provider_key: str | None = Header(default=None), provider: str = "anthropic", model: str | None = None):
    _rate_limit(request, "/api/ai", *RATE_LIMITS["/api/ai"])
    s = _get(sid)
    if not s.analysis["incidents"]:
        raise HTTPException(400, "No hay incidentes para evaluar.")
    kwargs, key = _resolve_provider(provider, model, x_anthropic_key, x_provider_key)
    used = kwargs.get("model") or os.environ.get("ANTHROPIC_MODEL") or ai_mod.DEFAULT_MODEL
    call = kwargs.get("call") or ai_mod.make_anthropic_call(key, used)
    try:
        result = triage_mod.generate(s.analysis, s.df, call, provider=provider, model=used)
    except Exception as exc:
        log.exception("triage_failed session=%s", sid)
        raise HTTPException(502, f"No se pudo completar el triaje con IA ({type(exc).__name__}). Se mantiene la recomendación del motor.") from exc
    if result["mode"] != "ia":
        first = result["errors"][0] if result["errors"] else "el modelo no devolvió resultados verificables"
        log.warning("triage_fallback session=%s reason=%s", sid, first[:200])
        raise HTTPException(502, f"No se pudo usar la IA ({first}). Se mantiene la recomendación del motor.")
    s.triage = result
    return triage_mod.view(s.analysis, s.triage, s.decisions)


@app.post("/api/sessions/{sid}/triage/{incident_id}/decision")
def set_decision(sid: str, incident_id: str, decision: str = Form(...), note: str = Form(""), tz: int = Form(0)):
    """Decisión del analista sobre un incidente. La IA no la toma ni la cambia; no modifica la severidad del motor."""
    s = _get(sid)
    if incident_id not in {i["id"] for i in s.analysis["incidents"]}:
        raise HTTPException(404, "Incidente no encontrado.")
    if decision not in triage_mod.DECISIONS:
        raise HTTPException(400, "Decisión no válida.")
    s.decisions[incident_id] = {"decision": decision, "note": triage_mod.clean_note(note),
                                "by": s.analyst or "", "at": triage_mod.local_stamp(time.time(), tz)}
    return triage_mod.view(s.analysis, s.triage, s.decisions)


# ---------------------------------------------------------------- inteligencia de amenazas (opcional)
def _intel_state(obj, iocs: list[dict], include_reserved: bool) -> dict:
    """Qué se consultaría (sin tocar la red), qué proveedores tienen clave en el servidor y el estado de la última consulta."""
    return {"configured": {"virustotal": bool(os.environ.get("VT_API_KEY", "").strip()),
                           "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY", "").strip())},
            "plan": intel_mod.build_plan(iocs, include_reserved), "job": obj.intel}


def _intel_worker(s, queries: list[dict], vt: str | None, ab: str | None) -> None:
    def progress(p: dict) -> None:
        s.intel.update(done=p["done"], results=p["results"], notices=p["notices"])
    try:
        out = intel_mod.lookup(queries, vt, ab, http=_new_http(), on_progress=progress)
        s.intel.update(status="done", done=len(out["results"]), results=out["results"], notices=out["notices"], queried_at=out["queried_at"])
    except Exception:  # error inesperado: detalle al log (sin claves), mensaje genérico al usuario
        log.exception("intel_failed")
        s.intel.update(status="error", notices=["No se pudo completar la consulta de reputación."])


def _intel_launch(obj, sid: str, iocs: list[dict], request: Request, include_reserved: bool, vt_header, ab_header) -> dict:
    _rate_limit(request, "/api/intel", *RATE_LIMITS["/api/intel"])
    if obj.intel and obj.intel.get("status") == "running":
        raise HTTPException(409, "Ya hay una consulta de reputación en curso.")
    vt, ab = _intel_keys(vt_header, ab_header)
    if not (vt or ab):
        raise HTTPException(400, "No hay claves de VirusTotal ni de AbuseIPDB. Defínelas en el archivo .env (VT_API_KEY, ABUSEIPDB_API_KEY) o pégalas en la interfaz.")
    plan = intel_mod.build_plan(iocs, include_reserved)
    if not plan["queries"]:
        raise HTTPException(400, "No hay indicadores públicos para consultar: todas las IP son internas o de documentación.")
    providers = intel_mod.available_providers(vt, ab)
    obj.intel = {"status": "running", "started": time.time(), "total": len(plan["queries"]), "done": 0, "results": [],
                 "notices": [], "providers": providers, "queried_at": ""}
    log.info("intel_start session=%s indicators=%d providers=%s", sid, len(plan["queries"]), ",".join(providers))   # nunca las claves
    threading.Thread(target=_intel_worker, args=(obj, plan["queries"], vt, ab), daemon=True).start()
    return {"job": obj.intel}


@app.get("/api/sessions/{sid}/intel")
def intel_state(sid: str, include_reserved: bool = False):
    s = _get(sid)
    return _intel_state(s, s.analysis["iocs"], include_reserved)


@app.post("/api/sessions/{sid}/intel")
def intel_start(sid: str, request: Request, include_reserved: bool = False, x_vt_key: str | None = Header(default=None),
                x_abuseipdb_key: str | None = Header(default=None)):
    s = _get(sid)
    return _intel_launch(s, sid, s.analysis["iocs"], request, include_reserved, x_vt_key, x_abuseipdb_key)


# ---------------------------------------------------------------- correos sospechosos (.eml)
def _enrich_mitre(items: list[dict]) -> list[dict]:
    """Nombre y enlace oficial de cada técnica ATT&CK citada (la interfaz no tiene el análisis de logs a mano)."""
    for i in items:
        i["mitre_info"] = {t: {"name": attack_mod.technique_name(t), "url": attack_mod.technique_url(t)} for t in i["mitre"]}
    return items


def _get_phish(pid: str) -> PhishSession:
    p = PHISH.get(pid)
    if not p:
        raise HTTPException(404, "Análisis de correos no encontrado. Vuelve a cargar los archivos.")
    return p


@app.post("/api/phishing")
async def phishing_upload(request: Request, files: list[UploadFile] | None = File(default=None), sid: str = Form(""), expected: str = Form(""),
                          headers_text: str = Form("")):
    """Analiza hasta 5 correos: archivos .eml o cabeceras pegadas como texto. Solo se leen como texto: no se abre ningún enlace ni se ejecuta ningún adjunto."""
    _rate_limit(request, "/api/upload", *RATE_LIMITS["/api/upload"])
    _require_captcha(request)
    files = files or []
    pasted_text = headers_text.strip()
    if len(files) + (1 if pasted_text else 0) < 1 or len(files) + (1 if pasted_text else 0) > MAX_EML_FILES:
        raise HTTPException(400, f"Sube de 1 a {MAX_EML_FILES} archivos .eml o pega las cabeceras del correo.")
    batch: list[tuple[str, bytes]] = []
    pasted_names: set[str] = set()
    if pasted_text:
        try:
            batch.append((PASTED_NAME, phishing_mod.paste_to_eml(pasted_text)))
        except phishing_mod.EmlError as exc:
            raise HTTPException(422, str(exc)) from exc
        pasted_names.add(PASTED_NAME)
    for f in files:
        name = os.path.basename(f.filename or "correo.eml")[:120]
        if not name.lower().endswith(".eml"):
            raise HTTPException(400, f"«{name}» no es un .eml. Exporta el correo original desde tu cliente de correo (Guardar como .eml).")
        chunks, size = [], 0
        while chunk := await f.read(1024 * 1024):
            size += len(chunk)
            if size > phishing_mod.MAX_EML_BYTES:
                raise HTTPException(413, f"«{name}» supera el límite de 5 MB.")
            chunks.append(chunk)
        batch.append((name, b"".join(chunks)))
    result = await run_in_threadpool(_with_slot, phishing_mod.analyze_many, batch, expected.strip()[:200], frozenset(pasted_names))
    _enrich_mitre(result["items"])
    if not result["items"]:
        raise HTTPException(422, result["errors"][0]["error"] if result["errors"] else "No se pudo analizar ningún correo.")
    pid = secrets.token_urlsafe(16)
    PHISH[pid] = PhishSession(items=result["items"], errors=result["errors"])
    while len(PHISH) > MAX_SESSIONS:
        PHISH.pop(min(PHISH, key=lambda k: PHISH[k].created))
    if sid and sid in SESSIONS:
        SESSIONS[sid].phish_id = pid
    log.info("phishing_done mails=%d errors=%d max_severity=%s", len(result["items"]), len(result["errors"]), result["items"][0]["severity"])
    return {"phishing_id": pid, "items": result["items"], "errors": result["errors"]}


# ---- herramientas de dominio (DNS sobre HTTPS): solo se consultan cuando el analista lo pide ------------------------
def _new_resolver() -> "dnsdoh.DohResolver":
    """Resolvedor DNS (punto de inyección para las pruebas: nada sale a Internet en el CI)."""
    return dnsdoh.DohResolver(http=_new_http())


def _domain_arg(text: str) -> str:
    try:
        return dnsdoh.clean_domain(text)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _dns_errors(exc: Exception) -> HTTPException:
    if isinstance(exc, dnsdoh.DnsDisabled):
        return HTTPException(503, str(exc))
    if isinstance(exc, domaincheck.DomainNotFound):
        return HTTPException(404, str(exc))
    return HTTPException(502, str(exc) if isinstance(exc, dnsdoh.DnsError) else "No se pudo consultar el DNS.")


@app.post("/api/domain/grade")
def domain_grade(request: Request, domain: str = Form(...)):
    """Evalúa SPF, DKIM y DMARC de un dominio leyendo sus registros DNS públicos. Solo sale el nombre de dominio."""
    _rate_limit(request, "/api/dns", *RATE_LIMITS["/api/dns"])
    name = _domain_arg(domain)
    _require_captcha(request)
    resolver = _new_resolver()
    try:
        result = domaincheck.grade_domain(name, resolver)
    except (dnsdoh.DnsError, domaincheck.DomainNotFound) as exc:
        raise _dns_errors(exc) from exc
    finally:
        resolver.close()
    log.info("domain_graded grade=%s score=%d queries=%d", result["grade"], result["score"], resolver.queries)
    return result


@app.post("/api/phishing/{pid}/items/{idx}/dns")
def phishing_sender_dns(pid: str, idx: int, request: Request):
    """Verifica en DNS el remitente de un correo ya analizado (SPF frente a su IP de origen, clave de su firma DKIM, DMARC). Solo salen nombres de dominio."""
    p = _get_phish(pid)
    if not 0 <= idx < len(p.items):
        raise HTTPException(404, "Correo no encontrado.")
    _rate_limit(request, "/api/dns", *RATE_LIMITS["/api/dns"])
    _require_captcha(request)
    resolver = _new_resolver()
    try:
        result = senderreview.review(p.items[idx], resolver)
    except (dnsdoh.DnsError, domaincheck.DomainNotFound) as exc:
        raise _dns_errors(exc) from exc
    finally:
        resolver.close()
    p.items[idx]["dns_review"] = result
    log.info("sender_dns_reviewed grade=%s queries=%d", result["grade"], result["queries"])
    return result


@app.post("/api/domain/lookalikes")
def domain_lookalikes(request: Request, domain: str = Form(...), check: bool = Form(False)):
    """Variantes de typosquatting de un dominio. Generarlas es local; con ``check`` se consulta el DNS (hasta 60) para ver cuáles están registradas."""
    _rate_limit(request, "/api/dns", *RATE_LIMITS["/api/dns"])
    name = _domain_arg(domain)
    variants = lookalikes_mod.generate(name)
    states: dict[str, str] = {}
    if check:
        _require_captcha(request)
        resolver = _new_resolver()
        try:
            states = lookalikes_mod.check_registered([v["domain"] for v in variants], resolver)
        except dnsdoh.DnsError as exc:
            raise _dns_errors(exc) from exc
        finally:
            resolver.close()
    for v in variants:
        v["state"] = states.get(v["domain"], "")
        v["state_label"] = lookalikes_mod.STATES.get(v["state"], "")
    label, suffix = lookalikes_mod.split_domain(name)
    return {"domain": f"{label}.{suffix}", "variants": variants, "total": len(variants), "checked": len(states), "check_limit": lookalikes_mod.MAX_CHECK,
            "limitations": ["La lista es de variantes probables, no exhaustiva: un atacante puede elegir otras.",
                            "«Sin DNS» no significa que esté libre ni que sea seguro: puede estar registrado sin DNS o reservado.",
                            "Solo se comprueban los " + str(lookalikes_mod.MAX_CHECK) + " primeros (los más probables)."]}


SAMPLE_EML_DIR = ROOT / "sample_data" / "correos"
MAX_SAMPLE_EML = 12          # los ejemplos son archivos del repositorio (carpeta fija), no una subida: no aplica el tope de 5


@app.post("/api/phishing/sample")
def phishing_sample(request: Request, sid: str = Form("")):
    """Analiza los correos sintéticos del repositorio (carpeta fija: nada de la petición elige los archivos)."""
    _rate_limit(request, "/api/upload", *RATE_LIMITS["/api/upload"])
    paths = sorted(SAMPLE_EML_DIR.glob("*.eml"))[:MAX_SAMPLE_EML]
    if not paths:
        raise HTTPException(404, "Este despliegue no incluye los correos de ejemplo.")
    result = _with_slot(phishing_mod.analyze_many, [(q.name, q.read_bytes()) for q in paths])
    _enrich_mitre(result["items"])
    pid = secrets.token_urlsafe(16)
    PHISH[pid] = PhishSession(items=result["items"], errors=result["errors"])
    while len(PHISH) > MAX_SESSIONS:
        PHISH.pop(min(PHISH, key=lambda k: PHISH[k].created))
    if sid and sid in SESSIONS:
        SESSIONS[sid].phish_id = pid
    return {"phishing_id": pid, "items": result["items"], "errors": result["errors"]}


@app.post("/api/sessions/{sid}/phishing")
def link_phishing(sid: str, pid: str = Form(...)):
    """Asocia un análisis de correos a una sesión de logs: el PDF de logs incluirá la sección de phishing."""
    s = _get(sid)
    _get_phish(pid)
    s.phish_id = pid
    return {"ok": True}


@app.get("/api/phishing/{pid}/intel")
def phishing_intel_state(pid: str, include_reserved: bool = False):
    p = _get_phish(pid)
    return _intel_state(p, phishing_mod.all_iocs(p.items), include_reserved)


@app.post("/api/phishing/{pid}/intel")
def phishing_intel_start(pid: str, request: Request, include_reserved: bool = False, x_vt_key: str | None = Header(default=None),
                         x_abuseipdb_key: str | None = Header(default=None)):
    p = _get_phish(pid)
    return _intel_launch(p, pid, phishing_mod.all_iocs(p.items), request, include_reserved, x_vt_key, x_abuseipdb_key)


@app.post("/api/phishing/{pid}/report.pdf")
def phishing_report(pid: str, client: str = Form(""), analyst: str = Form("")):
    p = _get_phish(pid)
    intel = p.intel if p.intel and p.intel.get("results") else None
    pdf = build_phishing_pdf(p.items, {"client": client.strip(), "analyst": analyst.strip()}, intel)
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="informe_phishing.pdf"'})


@app.post("/api/phishing/{pid}/report.html")
def phishing_report_html(pid: str, client: str = Form(""), analyst: str = Form("")):
    p = _get_phish(pid)
    intel = p.intel if p.intel and p.intel.get("results") else None
    doc = report_html_mod.build_phishing_html(p.items, {"client": client.strip(), "analyst": analyst.strip()}, intel)
    return Response(doc, media_type="text/html; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="informe_phishing.html"'})


@app.get("/api/sessions/{sid}/attack-layer.json")
def attack_layer(sid: str):
    """MITRE ATT&CK Navigator layer with the techniques suggested by the findings (download, nothing is sent anywhere)."""
    s = _get(sid)
    layer = attack_mod.navigator_layer(s.analysis["attack"], f"SOC Incident Analyzer - {s.filename}")
    return Response(json.dumps(layer, ensure_ascii=False, indent=1), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="attack_navigator_layer.json"'})


def _pdf_response(s: Session) -> Response:
    intel = s.intel if s.intel and s.intel.get("results") else None
    ph = PHISH.get(s.phish_id)
    tv = triage_mod.view(s.analysis, s.triage, s.decisions) if (s.triage or s.decisions) else None
    pdf = build_pdf(s.analysis, s.ai, s.df, {"client": s.client, "analyst": s.analyst, "filename": s.filename}, intel=intel,
                    phishing=ph.items if ph else None, triage=tv)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="informe_incidentes_seguridad.pdf"'})


def _html_response(s: Session) -> Response:
    """Informe en un único archivo HTML (se abre sin conexión). Mismo contenido que el PDF; todo dato se escapa al generarlo."""
    intel = s.intel if s.intel and s.intel.get("results") else None
    ph = PHISH.get(s.phish_id)
    tv = triage_mod.view(s.analysis, s.triage, s.decisions) if (s.triage or s.decisions) else None
    doc = report_html_mod.build_html(s.analysis, s.ai, s.df, {"client": s.client, "analyst": s.analyst, "filename": s.filename}, intel=intel,
                                     phishing=ph.items if ph else None, triage=tv)
    return Response(doc, media_type="text/html; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="informe_incidentes_seguridad.html"'})


@app.post("/api/sessions/{sid}/report.html")
def report_html_post(sid: str, client: str = Form(""), analyst: str = Form("")):
    """Los nombres de cliente y analista viajan en el cuerpo, no en la URL (igual que el PDF)."""
    s = _get(sid)
    s.client, s.analyst = client.strip(), analyst.strip()
    return _html_response(s)


@app.post("/api/sessions/{sid}/report.pdf")
def report_pdf_post(sid: str, client: str = Form(""), analyst: str = Form("")):
    """Preferred way to download the report: the client and analyst names travel in the body, not in the URL."""
    s = _get(sid)
    s.client, s.analyst = client.strip(), analyst.strip()
    return _pdf_response(s)


@app.get("/api/sessions/{sid}/report.pdf")
def report_pdf(sid: str, client: str | None = None, analyst: str | None = None):
    """Kept for compatibility. Names in a query string end up in access logs: the UI uses the POST route instead."""
    s = _get(sid)
    if client is not None:
        s.client = client.strip()
    if analyst is not None:
        s.analyst = analyst.strip()
    return _pdf_response(s)


# ---- Wazuh en vivo (opcional: WAZUH_INGEST=on y WAZUH_INGEST_TOKEN de 16+ caracteres) ----------------------------------------
# Wazuh envía cada alerta a POST /api/wazuh/alerts (integratord). Se acumulan en memoria, un ciclo las analiza con el mismo motor y avisa a Telegram
# (si está configurado). El panel abre una **instantánea** del último análisis: las decisiones del analista viven en esa instantánea. Ver docs/WAZUH.md.
MAX_WAZUH_BODY = 1024 * 1024
_LIVE: wazuh_live.LiveState | None = None
_LIVE_LOCK = threading.Lock()
_LIVE_CYCLE_LOCK = threading.Lock()


def _live() -> wazuh_live.LiveState:
    global _LIVE
    with _LIVE_LOCK:
        if _LIVE is None:
            _LIVE = wazuh_live.LiveState(notifier=notify_mod.TelegramNotifier.from_env())
            if os.environ.get("WAZUH_AUTOCYCLE", "on").strip().lower() not in ("0", "off", "false", "no"):
                every = wazuh_live._int_env("WAZUH_ANALYZE_SECONDS", 60, 10, 3600)
                threading.Thread(target=_live_loop, args=(_LIVE, every), daemon=True).start()
        return _LIVE


def _live_cycle() -> bool:
    live = _live()
    with _LIVE_CYCLE_LOCK:
        return live.run_cycle(analyze)


def _live_loop(live: wazuh_live.LiveState, every: int) -> None:
    while True:
        time.sleep(every)
        try:
            _live_cycle()
        except Exception:
            log.exception("wazuh_loop_error")


@app.post("/api/wazuh/alerts", status_code=202)
async def wazuh_alerts(request: Request):
    if not wazuh_live.usable():
        raise HTTPException(404, "No encontrado.")
    if not secrets.compare_digest(request.headers.get("x-wazuh-token", "").encode(), wazuh_live.token().encode()):
        _rate_limit(request, "/wazuh-auth-fail", 10, 60)
        raise HTTPException(401, "Clave de Wazuh no válida.")
    _rate_limit(request, "/api/wazuh", 600, 60)
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > MAX_WAZUH_BODY:
        raise HTTPException(413, "El cuerpo supera 1 MB.")
    body = await request.body()
    if len(body) > MAX_WAZUH_BODY:
        raise HTTPException(413, "El cuerpo supera 1 MB.")
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "El cuerpo no es un JSON válido.") from exc
    alerts = obj.get("alerts") if isinstance(obj, dict) and isinstance(obj.get("alerts"), list) else obj if isinstance(obj, list) else [obj]
    if len(alerts) > W_MAX_ALERTS:
        raise HTTPException(413, f"Máximo {W_MAX_ALERTS} alertas por llamada.")
    return _live().ingest(alerts)


WAZUH_LOCKED_MSG = ("Las alertas de Wazuh en vivo solo se abren con APP_ACCESS_TOKEN definido en el servidor: "
                     "sin él, cualquiera que llegue al puerto podría leerlas.")

if wazuh_live.usable() and not _access_token():
    log.warning("wazuh_panel_locked: WAZUH_INGEST is on without APP_ACCESS_TOKEN; alerts are ingested but the live snapshot stays closed")


@app.get("/api/wazuh/status")
def wazuh_status():
    if not wazuh_live.usable():
        return {"enabled": False}
    return {**_live().status(), "needs_token": not _access_token()}


@app.get("/api/wazuh/session")
def wazuh_session():
    """Abre una instantánea del último análisis de las alertas de Wazuh (una sesión normal: se puede pedir triaje, informe, etc.)."""
    if not wazuh_live.usable():
        raise HTTPException(404, "El modo Wazuh no está activado en este servidor.")
    if not _access_token():      # live alerts are real data that nobody uploaded: never served without the access key
        raise HTTPException(403, WAZUH_LOCKED_MSG)
    _live_cycle()
    latest = _live().latest
    if not latest:
        raise HTTPException(404, "Todavía no llegaron alertas de Wazuh.")
    df, meta, analysis = latest
    analysis = copy.deepcopy(analysis)
    analysis["limitations"] = list(analysis.get("limitations", [])) + [
        "Instantánea de las alertas de Wazuh de las últimas %d h (hasta %d filas). Es una foto: las alertas nuevas aparecen al volver a abrirla y las "
        "decisiones que tomes viven en esta foto." % (_live().window // 3600, _live().max_rows)]
    analysis["wazuh_context"] = wazuh_indexer.configured()
    return _register_session(df.copy(), analysis, "Alertas de Wazuh (en vivo)", origin="wazuh")


@app.get("/api/context/status")
def context_status():
    """Estado del contexto opcional (CISA KEV / EPSS y MISP). No devuelve claves ni la URL de MISP."""
    from . import context as ctx_mod, feed as feed_mod, misp as misp_mod
    store, fd = ctx_mod.get_store(), feed_mod.get_feed()
    return {"cve": store.status() if store else {"enabled": False}, "misp": {"configured": misp_mod.get_client() is not None},
            "feed": fd.status() if fd else {"configured": False}}


# el frontend se sirve como estático (debe montarse al final)
app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="frontend")
