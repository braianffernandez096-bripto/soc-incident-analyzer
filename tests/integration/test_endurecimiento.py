"""Endurecimiento: nombres de host permitidos (DNS rebinding), análisis fuera del bucle de eventos, libros de Excel con millones de celdas,
/api/health sin detalles para quien no tiene la clave y tope global de intentos fallidos."""
import io
import threading
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main, parser

client = TestClient(main.app, raise_server_exceptions=False)
DATA = Path(__file__).resolve().parents[2] / "sample_data"
CSV = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv").read_bytes()
XLSX = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx").read_bytes()
TOKEN = "correct-horse-battery-staple-9"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("APP_BASE_URL", raising=False)
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    main._hits.clear()
    yield
    main._hits.clear()


# ---------------------------------------------------------------- nombres de host
@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "localhost.evil.example:8000", ""])
def test_un_nombre_de_host_ajeno_se_rechaza(host):
    for path in ("/api/health", "/api/auth/status", "/", "/app.js"):
        r = client.get(path, headers={"Host": host})
        assert r.status_code == 400, (host, path)
        assert r.headers["x-content-type-options"] == "nosniff"          # el rechazo también lleva las cabeceras de seguridad
    assert client.post("/api/sample", headers={"Host": host}).status_code == 400
    assert not [k for k in main._hits if k[1] == "/api/upload"]             # se corta antes de tocar nada


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "localhost", "LOCALHOST:8000", "[::1]:8000", "localhost.:8000"])
def test_los_nombres_propios_se_aceptan(host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


def test_nombres_extra_por_variable_y_por_app_base_url(monkeypatch):
    assert client.get("/api/health", headers={"Host": "soc.empresa.example"}).status_code == 400
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver, SOC.empresa.example")
    assert client.get("/api/health", headers={"Host": "soc.empresa.example"}).status_code == 200
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("APP_BASE_URL", "https://panel.empresa.example/")
    assert client.get("/api/health", headers={"Host": "panel.empresa.example"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "otro.empresa.example"}).status_code == 400
    monkeypatch.setenv("ALLOWED_HOSTS", "*")                                # salida de emergencia explícita
    assert client.get("/api/health", headers={"Host": "otro.empresa.example"}).status_code == 200


def test_la_ingesta_de_wazuh_no_depende_del_nombre_de_host(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST", "on")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", "w" * 24)
    r = client.post("/api/wazuh/alerts", json={}, headers={"Host": "soc-analyzer:8000"})      # el manager llega por el alias de Docker
    assert r.status_code == 401                                                               # pasó el filtro de host; lo frena su propia clave


# ---------------------------------------------------------------- /api/health y fuerza bruta
def test_health_sin_clave_solo_dice_que_esta_vivo(monkeypatch):
    assert "ai_keys" in client.get("/api/health").json()                    # sin APP_ACCESS_TOKEN no hay nada que ocultar a quien ya usa la app
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.get("/api/health").json() == {"ok": True}
    assert client.get("/api/health", headers={"Authorization": "Bearer otra-clave-cualquiera"}).json() == {"ok": True}
    full = client.get("/api/health", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert full["ok"] is True and "ai_keys" in full and "model" in full


def test_los_fallos_de_clave_tienen_un_tope_que_no_depende_de_la_ip(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    for i in range(100):                                                    # cada intento «desde otra IP»: el tope por IP no llega a actuar
        main._rate_limit_key("*", "/auth-fail-all", 100, 60)
    assert client.get("/api/auth/check", headers={"Authorization": "Bearer mala"}).status_code == 429
    assert client.get("/api/auth/check", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200      # quien tiene la clave nunca queda fuera


# ---------------------------------------------------------------- Excel con millones de celdas
def _workbook(rows: int, cols: int, prefix: str = "") -> bytes:
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    p = f"{prefix}:" if prefix else ""
    decl = f'xmlns:{prefix}="http://schemas.openxmlformats.org/spreadsheetml/2006/main"' if prefix else ns
    row = (f"<{p}row>" + f"<{p}c><{p}v>1</{p}v></{p}c>" * cols + f"</{p}row>").encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml", f'<?xml version="1.0"?><workbook {ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   '<sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        with z.open("xl/worksheets/sheet1.xml", "w") as f:
            f.write(f'<?xml version="1.0"?><{p}worksheet {decl}><{p}sheetData>'.encode())
            block = row * 1000
            for _ in range(rows // 1000):
                f.write(block)
            f.write(row * (rows % 1000))
            f.write(f"</{p}sheetData></{p}worksheet>".encode())
    return buf.getvalue()


def test_el_conteo_de_filas_y_celdas_es_exacto_aunque_las_etiquetas_caigan_en_el_borde_de_un_bloque():
    for prefix in ("", "x"):
        data = _workbook(70_123, 3, prefix)            # ~3 MB de XML: varias lecturas de 1 MB, con etiquetas partidas entre bloques
        with zipfile.ZipFile(io.BytesIO(data)) as z, z.open("xl/worksheets/sheet1.xml") as fh:
            assert parser._count_sheet(fh) == (70_123, 210_369)


def test_un_excel_pequeno_con_demasiadas_filas_se_rechaza_en_segundos_sin_abrirlo(monkeypatch):
    data = _workbook(150_000, 20)                      # 190 KB comprimido, 3 millones de celdas: antes tenía al servidor ~19 s leyendo
    assert len(data) < 400_000
    monkeypatch.setattr(parser.pd, "read_excel", lambda *a, **k: pytest.fail("no debe llegar a abrirse con pandas"))
    t = time.perf_counter()
    r = client.post("/api/upload", files={"file": ("bomba.xlsx", data, "application/octet-stream")})
    assert r.status_code == 422 and "máximo soportado es 100.000" in r.json()["detail"]
    assert time.perf_counter() - t < 5


def test_un_excel_con_pocas_filas_y_millones_de_celdas_tambien_se_rechaza(monkeypatch):
    monkeypatch.setattr(parser, "MAX_CELLS", 200_000)
    monkeypatch.setattr(parser.pd, "read_excel", lambda *a, **k: pytest.fail("no debe llegar a abrirse con pandas"))
    with pytest.raises(parser.ParseError, match="celdas"):
        parser.load_events(_workbook(5_000, 60), "ancho.xlsx")


def test_el_excel_de_ejemplo_sigue_cargando():
    r = client.post("/api/upload", files={"file": ("ok.xlsx", XLSX, "application/octet-stream")})
    assert r.status_code == 200 and r.json()["analysis"]["incidents"]


def test_openpyxl_lee_con_defusedxml():
    import openpyxl
    assert openpyxl.DEFUSEDXML is True


# ---------------------------------------------------------------- análisis fuera del bucle de eventos
def test_el_analisis_no_corre_en_el_bucle_de_eventos(monkeypatch):
    seen = {}
    real = main._create_session

    def spy(*a, **k):
        seen["thread"] = threading.current_thread()
        return real(*a, **k)
    monkeypatch.setattr(main, "_create_session", spy)
    with TestClient(main.app) as c:                    # un solo bucle de eventos para comparar
        loop_thread = c.portal.call(threading.current_thread)
        assert c.post("/api/upload", files={"file": ("x.csv", CSV, "text/csv")}).status_code == 200
    assert seen["thread"] is not loop_thread


def test_sin_cupo_de_analisis_responde_503_y_lo_libera_despues():
    held = [main._ANALYSIS_SLOTS.acquire(blocking=False) for _ in range(main.MAX_PARALLEL_ANALYSES)]
    assert all(held)
    try:
        r = client.post("/api/upload", files={"file": ("x.csv", CSV, "text/csv")})
        assert r.status_code == 503 and r.headers["retry-after"] == "15"
        assert client.post("/api/sample").status_code == 503
        assert client.post("/api/phishing/sample").status_code == 503
        assert client.get("/api/health").status_code == 200                 # lo demás sigue respondiendo
    finally:
        for _ in held:
            main._ANALYSIS_SLOTS.release()
    assert client.post("/api/sample").status_code == 200


def test_un_archivo_rechazado_devuelve_el_cupo():
    for _ in range(main.MAX_PARALLEL_ANALYSES + 2):
        assert client.post("/api/upload", files={"file": ("x.csv", b"MZ\x90\x00binario", "text/csv")}).status_code == 422
    assert client.post("/api/sample").status_code == 200


# ---------------------------------------------------------------- forma exacta del nombre de host
@pytest.mark.parametrize("host", ["[::1].evil.example", "127.0.0.1:8000, evil.example", "localhost evil.example", "localhost:8000:1", "localhost:",
                                  "localhost:abc", "localhost/evil.example", "localhost@evil.example", "[::1]x:8000", "[localhost]", "127.0.0.1:999999"])
def test_un_host_mal_formado_se_rechaza_aunque_empiece_por_un_nombre_propio(host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 400


# ---------------------------------------------------------------- vida de las sesiones
@pytest.fixture
def sesiones(monkeypatch):
    monkeypatch.delenv("SESSION_TTL_MINUTES", raising=False)
    main.SESSIONS.clear()
    main.PHISH.clear()
    yield
    main.SESSIONS.clear()
    main.PHISH.clear()


def _nueva() -> str:
    return client.post("/api/sample").json()["session_id"]


def test_quien_crea_sesiones_en_serie_se_desaloja_a_si_mismo_y_no_a_los_demas(sesiones):
    victima = _nueva()
    main.SESSIONS[victima].owner = "10.0.0.7"
    main._hits.clear()
    for _ in range(main.MAX_SESSIONS + 4):             # el mismo cliente, muy por encima del cupo
        _nueva()
        main._hits.clear()
    assert len(main.SESSIONS) == main.MAX_SESSIONS
    assert victima in main.SESSIONS                    # antes salía la más antigua de todas: la de la víctima
    assert client.get(f"/api/sessions/{victima}").status_code == 200


def test_con_un_solo_cliente_sale_la_mas_antigua(sesiones):
    ids = []
    for _ in range(main.MAX_SESSIONS + 2):
        ids.append(_nueva())
        main._hits.clear()
    assert set(main.SESSIONS) == set(ids[2:])


def test_las_sesiones_sin_uso_vencen_y_las_que_se_usan_no(sesiones, monkeypatch):
    monkeypatch.setenv("SESSION_TTL_MINUTES", "30")
    vieja, usada = _nueva(), _nueva()
    pid = client.post("/api/phishing/sample").json()["phishing_id"]
    for obj in (main.SESSIONS[vieja], main.SESSIONS[usada], main.PHISH[pid]):
        obj.touched -= 29 * 60
    assert client.get(f"/api/sessions/{usada}").status_code == 200           # usarla renueva el plazo
    for obj in (main.SESSIONS[vieja], main.SESSIONS[usada], main.PHISH[pid]):
        obj.touched -= 2 * 60
    assert client.get("/api/health").status_code == 200                      # el healthcheck hace de temporizador
    assert vieja not in main.SESSIONS and pid not in main.PHISH and usada in main.SESSIONS
    assert client.get(f"/api/sessions/{vieja}").status_code == 404
    assert client.get(f"/api/phishing/{pid}/intel").status_code == 404


def test_el_plazo_tiene_limites_razonables(monkeypatch):
    for value, minutes in (("", 240), ("abc", 240), ("0", 5), ("1", 5), ("90", 90), ("9999999", 7 * 24 * 60)):
        monkeypatch.setenv("SESSION_TTL_MINUTES", value)
        assert main._session_ttl() == minutes * 60


def test_borrar_la_sesion_la_quita_de_la_memoria(sesiones):
    sid = _nueva()
    pid = client.post("/api/phishing/sample").json()["phishing_id"]
    assert client.delete(f"/api/sessions/{sid}").json() == {"ok": True, "deleted": True}
    assert sid not in main.SESSIONS and client.get(f"/api/sessions/{sid}").status_code == 404
    assert client.delete(f"/api/sessions/{sid}").json() == {"ok": True, "deleted": False}       # idempotente
    assert client.delete(f"/api/phishing/{pid}").json()["deleted"] is True and pid not in main.PHISH


def test_borrar_exige_la_clave_de_acceso(sesiones, monkeypatch):
    sid = _nueva()
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.delete(f"/api/sessions/{sid}").status_code == 401 and sid in main.SESSIONS
    assert client.delete(f"/api/sessions/{sid}", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


# ---------------------------------------------------------------- cliente y analista acotados
def test_cliente_y_analista_se_recortan_y_quedan_en_una_linea(sesiones):
    largo = "A" * 900_000
    r = client.post("/api/sample", data={"client": largo, "analyst": "  Ana\r\nLópez\x00  "}).json()
    assert len(r["client"]) == main.MAX_META and r["analyst"] == "Ana  López"
    sid = r["session_id"]
    client.post(f"/api/sessions/{sid}/meta", data={"client": largo, "analyst": largo})
    assert len(main.SESSIONS[sid].client) == main.MAX_META == len(main.SESSIONS[sid].analyst)
    assert client.post(f"/api/sessions/{sid}/report.html", data={"client": largo}).status_code == 200
    assert len(main.SESSIONS[sid].client) == main.MAX_META
    assert client.get(f"/api/sessions/{sid}/report.pdf", params={"analyst": "B" * 5000}).status_code == 200
    assert len(main.SESSIONS[sid].analyst) == main.MAX_META
    pid = client.post("/api/phishing/sample").json()["phishing_id"]
    doc = client.post(f"/api/phishing/{pid}/report.html", data={"client": "Z" * 5000}).text
    assert "Z" * main.MAX_META in doc and "Z" * (main.MAX_META + 1) not in doc
