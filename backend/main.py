"""API y servidor web de SOC Incident Analyzer.

Ejecutar desde la raíz del proyecto:
    uvicorn backend.main:app --reload --port 8000
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import ai as ai_mod
from . import detection as D
from . import intel as intel_mod
from .analysis import analyze, rows_for
from .parser import SUPPORTED_EXT, ParseError, load_events
from .report import build_pdf

ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_SESSIONS = 10


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


app = FastAPI(title="SOC Incident Analyzer", version="1.0", default_response_class=SafeJSON)


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


# Límite de peticiones por IP (ventana deslizante en memoria). Protege los endpoints costosos.
RATE_LIMITS = {"/api/upload": (20, 60), "/api/ai": (6, 60), "/api/intel": (6, 60)}      # (peticiones, segundos)
_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _rate_limit(request: Request, key: str, limit: int, window: int) -> None:
    ip = request.client.host if request.client else "unknown"
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


SESSIONS: dict[str, Session] = {}


def _get(sid: str) -> Session:
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(404, "Sesión no encontrada. Vuelve a cargar el archivo.")
    return s


def _api_key(header_key: str | None) -> str | None:
    return (header_key or "").strip() or os.environ.get("ANTHROPIC_API_KEY", "").strip() or None


def _intel_keys(vt_header: str | None = None, abuse_header: str | None = None) -> tuple[str | None, str | None]:
    vt = (vt_header or "").strip() or os.environ.get("VT_API_KEY", "").strip() or None
    ab = (abuse_header or "").strip() or os.environ.get("ABUSEIPDB_API_KEY", "").strip() or None
    return vt, ab


def _new_http():
    """Cliente HTTP para las consultas de reputación (None = el módulo crea el suyo). Punto de inyección para las pruebas."""
    return None


# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"ok": True, "ai_configured": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
            "model": os.environ.get("ANTHROPIC_MODEL") or ai_mod.DEFAULT_MODEL}


def _create_session(data: bytes, name: str, client: str, analyst: str) -> dict:
    try:
        df, meta = load_events(data, name)
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from exc
    t0 = time.perf_counter()
    analysis = analyze(df, meta)
    log.info("analysis_done rows=%d findings=%d incidents=%d ms=%d", len(df), len(analysis["findings"]), len(analysis["incidents"]), (time.perf_counter() - t0) * 1000)
    sid = secrets.token_urlsafe(8)
    SESSIONS[sid] = Session(df=df, analysis=analysis, ai=ai_mod.build_deterministic(analysis), filename=name,
                            client=client.strip(), analyst=analyst.strip())
    while len(SESSIONS) > MAX_SESSIONS:
        SESSIONS.pop(min(SESSIONS, key=lambda k: SESSIONS[k].created))
    s = SESSIONS[sid]
    return {"session_id": sid, "filename": name, "client": s.client, "analyst": s.analyst,
            "analysis": analysis, "ai": s.ai, "ai_configured": bool(_api_key(None))}


@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...), client: str = Form(""), analyst: str = Form("")):
    _rate_limit(request, "/api/upload", *RATE_LIMITS["/api/upload"])
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
    return _create_session(data, name, client, analyst)


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


@app.post("/api/sessions/{sid}/meta")
def set_meta(sid: str, client: str = Form(""), analyst: str = Form("")):
    s = _get(sid)
    s.client, s.analyst = client.strip(), analyst.strip()
    return {"ok": True}


@app.post("/api/sessions/{sid}/ai")
def run_ai(sid: str, request: Request, x_anthropic_key: str | None = Header(default=None)):
    _rate_limit(request, "/api/ai", *RATE_LIMITS["/api/ai"])
    s = _get(sid)
    key = _api_key(x_anthropic_key)
    if not key:
        raise HTTPException(400, "No hay API key de Anthropic. Define ANTHROPIC_API_KEY en el archivo .env o pégala en el campo de la interfaz.")
    try:
        result = ai_mod.generate(s.analysis, s.df, key)
    except Exception as exc:  # error inesperado de la llamada global: detalle al log, mensaje genérico al usuario
        log.exception("ai_failed session=%s", sid)
        raise HTTPException(502, f"No se pudo completar el análisis con IA ({type(exc).__name__}). Revisa la clave y la conexión; se mantiene el informe por reglas.") from exc
    if result["mode"] != "ia":
        first = result["errors"][0] if result["errors"] else "el modelo no devolvió resultados verificables"
        log.warning("ai_fallback session=%s reason=%s", sid, first[:200])
        raise HTTPException(502, f"No se pudo usar la IA ({first}). Se mantiene el informe generado por reglas.")
    s.ai = result
    return {"ai": result}


# ---------------------------------------------------------------- inteligencia de amenazas (opcional)
@app.get("/api/sessions/{sid}/intel")
def intel_state(sid: str, include_reserved: bool = False):
    """Qué se consultaría (sin tocar la red), qué proveedores tienen clave en el servidor y el estado de la última consulta."""
    s = _get(sid)
    return {"configured": {"virustotal": bool(os.environ.get("VT_API_KEY", "").strip()),
                           "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY", "").strip())},
            "plan": intel_mod.build_plan(s.analysis["iocs"], include_reserved), "job": s.intel}


def _intel_worker(s: Session, queries: list[dict], vt: str | None, ab: str | None) -> None:
    def progress(p: dict) -> None:
        s.intel.update(done=p["done"], results=p["results"], notices=p["notices"])
    try:
        out = intel_mod.lookup(queries, vt, ab, http=_new_http(), on_progress=progress)
        s.intel.update(status="done", done=len(out["results"]), results=out["results"], notices=out["notices"], queried_at=out["queried_at"])
    except Exception:  # error inesperado: detalle al log (sin claves), mensaje genérico al usuario
        log.exception("intel_failed")
        s.intel.update(status="error", notices=["No se pudo completar la consulta de reputación."])


@app.post("/api/sessions/{sid}/intel")
def intel_start(sid: str, request: Request, include_reserved: bool = False, x_vt_key: str | None = Header(default=None),
                x_abuseipdb_key: str | None = Header(default=None)):
    _rate_limit(request, "/api/intel", *RATE_LIMITS["/api/intel"])
    s = _get(sid)
    if s.intel and s.intel.get("status") == "running":
        raise HTTPException(409, "Ya hay una consulta de reputación en curso.")
    vt, ab = _intel_keys(x_vt_key, x_abuseipdb_key)
    if not (vt or ab):
        raise HTTPException(400, "No hay claves de VirusTotal ni de AbuseIPDB. Defínelas en el archivo .env (VT_API_KEY, ABUSEIPDB_API_KEY) o pégalas en la interfaz.")
    plan = intel_mod.build_plan(s.analysis["iocs"], include_reserved)
    if not plan["queries"]:
        raise HTTPException(400, "No hay indicadores públicos para consultar: todas las IP son internas o de documentación.")
    providers = intel_mod.available_providers(vt, ab)
    s.intel = {"status": "running", "started": time.time(), "total": len(plan["queries"]), "done": 0, "results": [],
               "notices": [], "providers": providers, "queried_at": ""}
    log.info("intel_start session=%s indicators=%d providers=%s", sid, len(plan["queries"]), ",".join(providers))   # nunca las claves
    threading.Thread(target=_intel_worker, args=(s, plan["queries"], vt, ab), daemon=True).start()
    return {"job": s.intel}


@app.get("/api/sessions/{sid}/report.pdf")
def report_pdf(sid: str, client: str | None = None, analyst: str | None = None):
    s = _get(sid)
    if client is not None:
        s.client = client.strip()
    if analyst is not None:
        s.analyst = analyst.strip()
    intel = s.intel if s.intel and s.intel.get("results") else None
    pdf = build_pdf(s.analysis, s.ai, s.df, {"client": s.client, "analyst": s.analyst, "filename": s.filename}, intel=intel)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="informe_incidentes_seguridad.pdf"'})


# el frontend se sirve como estático (debe montarse al final)
app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="frontend")
