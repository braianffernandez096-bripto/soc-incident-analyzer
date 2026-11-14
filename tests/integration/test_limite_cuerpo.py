"""Límite de tamaño del cuerpo de la petición (resource exhaustion).

El tope por ruta (/api/upload: 25 MB) solo se comprueba DESPUÉS de que Starlette haya volcado el cuerpo
multipart a un archivo temporal en disco. MaxBodySizeMiddleware rechaza el cuerpo antes de parsearlo o
volcarlo, para que una "subida" enorme no llene el disco solo para ser rechazada como «>25 MB».
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.main import MAX_REQUEST_BYTES, MaxBodySizeMiddleware, app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clean():
    main._hits.clear()
    yield
    main._hits.clear()


def test_content_length_over_cap_is_refused_413():
    # Cuerpo declarado por encima del tope: debe rechazarse por Content-Length, sin tocar el disco.
    body = b"x" * (MAX_REQUEST_BYTES + 1)
    r = client.post("/api/upload", content=body,
                    headers={"Content-Type": "multipart/form-data; boundary=zzz"})
    assert r.status_code == 413
    assert "lim" in r.json()["detail"].lower()
    # El 413 temprano conserva las cabeceras de seguridad.
    assert r.headers["x-content-type-options"] == "nosniff"


def test_streaming_body_without_length_is_aborted_at_the_cap():
    # Sin Content-Length el tope se aplica contando los bytes conforme llegan: el middleware ASGI
    # debe cortar en cuanto se supera, sin esperar a recibir todo el cuerpo. Se envuelve una app
    # mínima que drena el flujo (como hace el parser multipart) para aislar la lógica del contador.
    cap = 4 * 1024 * 1024
    over = cap + 10 * 1024 * 1024
    sent = {"n": 0}

    async def inner(scope, receive, send):           # consume el cuerpo igual que el parser real
        while True:
            m = await receive()
            if not m.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        if sent["n"] >= over:
            return {"type": "http.request", "body": b"", "more_body": False}
        chunk = b"a" * (1024 * 1024)
        sent["n"] += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": True}

    sink = []

    async def send(message):
        sink.append(message)

    scope = {"type": "http", "path": "/api/upload", "method": "POST", "headers": []}
    mw = MaxBodySizeMiddleware(inner, max_body=cap)
    asyncio.run(mw(scope, receive, send))

    start = next(m for m in sink if m["type"] == "http.response.start")
    assert start["status"] == 413
    # Se cortó cerca del tope, no tras recibir el cuerpo entero (`over`).
    assert sent["n"] <= cap + 1024 * 1024
    assert sent["n"] < over


def test_upload_within_cap_still_works():
    csv = b"Timestamp,Event_ID,Hostname,User,Source_IP,Event_Description\n" \
          b"2026-01-01T00:00:00,4625,HOST,alice,10.0.0.1,fallo de inicio de sesion\n" * 50
    r = client.post("/api/upload", files={"file": ("logs.csv", csv, "text/csv")})
    assert r.status_code == 200, r.text
    assert r.json()["session_id"]


def test_streaming_over_cap_through_the_real_app_is_413_not_400():
    # FastAPI convierte cualquier excepción al leer el cuerpo en «400 There was an error parsing the body».
    # Con la app real y sin Content-Length (chunked) la respuesta debe seguir siendo 413.
    mw = MaxBodySizeMiddleware(_inner_app(), max_body=1024 * 1024)
    head = b'--zzz\r\nContent-Disposition: form-data; name="file"; filename="a.csv"\r\nContent-Type: text/csv\r\n\r\n'
    chunks = [head] + [b"a" * (256 * 1024)] * 12
    pos = {"i": 0}

    async def receive():
        if pos["i"] >= len(chunks):
            return {"type": "http.request", "body": b"\r\n--zzz--\r\n", "more_body": False}
        pos["i"] += 1
        return {"type": "http.request", "body": chunks[pos["i"] - 1], "more_body": True}

    sink = []

    async def send(message):
        sink.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/api/upload",
             "raw_path": b"/api/upload", "query_string": b"", "root_path": "", "client": ("127.0.0.1", 1), "server": ("testserver", 80),
             "headers": [(b"host", b"testserver"), (b"content-type", b"multipart/form-data; boundary=zzz"), (b"transfer-encoding", b"chunked")]}
    asyncio.run(mw(scope, receive, send))
    starts = [m for m in sink if m["type"] == "http.response.start"]
    assert [m["status"] for m in starts] == [413]          # una sola respuesta, y es el 413
    assert pos["i"] < len(chunks)                           # se cortó antes de recibir todo


def _inner_app():
    """La app sin el MaxBodySizeMiddleware global (para probar uno con un tope pequeño sobre las rutas reales)."""
    stack = app.build_middleware_stack()          # ServerError -> MaxBodySize -> ...
    node = stack
    while not isinstance(node, MaxBodySizeMiddleware):
        node = node.app
    return node.app
