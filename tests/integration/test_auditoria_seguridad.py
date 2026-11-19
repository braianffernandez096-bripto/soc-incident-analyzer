"""Regresiones de la auditoría de seguridad (noviembre de 2026).

1. CSRF: una web ajena no puede hacer POST/DELETE a la app desde el navegador del analista.
2. Volumen de .xlsx: tope de celdas acorde al límite de memoria del contenedor.
3. /api/wazuh/session: mismo límite por IP y mismo cupo de análisis que una subida.
4. El registro del límite por IP no crece sin tope.
5. GET /report.pdf es de solo lectura.
6. Dos consultas de reputación simultáneas no lanzan dos hilos.
7. Una APP_ACCESS_TOKEN corta cierra la API (falla cerrado).
"""
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend import main, notify, parser, wazuh_demo, wazuh_live

client = TestClient(main.app, raise_server_exceptions=False)
TOKEN = "correct-horse-battery-staple-9"
EVIL = {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    main._hits.clear()
    main.SESSIONS.clear()
    yield
    main._hits.clear()


def _sample() -> str:
    r = client.post("/api/sample", data={"client": "ACME"})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


# ---- 1. CSRF -------------------------------------------------------------------------------------------

def test_post_desde_otro_sitio_se_rechaza_y_no_desaloja_la_sesion_del_analista():
    victim = _sample()
    codes = {client.post("/api/sample", headers=EVIL).status_code for _ in range(main.MAX_SESSIONS + 2)}
    assert codes == {403}
    assert client.get(f"/api/sessions/{victim}").status_code == 200


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},                    # otra app en otro puerto de localhost
    {"Origin": "https://evil.example"},                 # navegador viejo sin Sec-Fetch-*
    {"Origin": "null"},                                 # iframe aislado o archivo local
])
def test_variantes_de_origen_ajeno(headers):
    sid = _sample()
    assert client.delete(f"/api/sessions/{sid}", headers=headers).status_code == 403
    assert client.post(f"/api/sessions/{sid}/meta", data={"client": "x"}, headers=headers).status_code == 403
    assert sid in main.SESSIONS


def test_mismo_origen_navegacion_directa_y_clientes_sin_navegador_siguen_funcionando():
    assert client.post("/api/sample", headers={"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}).status_code == 200
    assert client.post("/api/sample", headers={"Sec-Fetch-Site": "none"}).status_code == 200
    assert client.post("/api/sample").status_code == 200                       # curl / scripts: sin cabeceras de navegador


def test_el_origen_de_allowed_hosts_se_acepta(monkeypatch):
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver,soc.midominio.com")
    assert client.post("/api/sample", headers={"Origin": "https://soc.midominio.com"}).status_code == 200


def test_detras_de_un_proxy_que_reescribe_el_host_la_interfaz_sigue_funcionando(monkeypatch):
    # nginx por defecto: Host del upstream (127.0.0.1:8000) y Origin con el nombre público, que no está en ALLOWED_HOSTS
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    proxied = TestClient(main.app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False)
    same = {"Origin": "https://soc.midominio.com", "Sec-Fetch-Site": "same-origin"}
    assert proxied.post("/api/sample", headers=same).status_code == 200
    assert proxied.post("/api/sample", headers={**same, "Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_get_desde_otro_sitio_no_se_bloquea():
    sid = _sample()                                     # las lecturas no cambian estado y CORS impide leer la respuesta
    assert client.get(f"/api/sessions/{sid}", headers=EVIL).status_code == 200


def test_la_ingesta_de_wazuh_no_pasa_por_el_chequeo_csrf(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST", "on")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", "w" * 24)
    r = client.post("/api/wazuh/alerts", json=[], headers={**EVIL, "X-Wazuh-Token": "otra-clave-mala-123"})
    assert r.status_code == 401                         # llega al endpoint (y su propia clave decide), no a la regla CSRF


# ---- 2. volumen de .xlsx -------------------------------------------------------------------------------

def test_tope_de_celdas_y_de_descompresion():
    assert parser.MAX_CELLS <= 2_000_000
    assert parser.MAX_UNCOMPRESSED_BYTES <= 150 * 1024 * 1024
    assert parser.MAX_CELLS >= parser.MAX_ROWS * 20     # un export de logs normal (100.000 filas x 20 columnas) sigue entrando


# ---- 3. /api/wazuh/session -----------------------------------------------------------------------------

@pytest.fixture
def demo(monkeypatch):
    for k in ("WAZUH_INGEST", "WAZUH_INGEST_TOKEN", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("WAZUH_DEMO", "on")
    monkeypatch.setenv("WAZUH_AUTOCYCLE", "off")
    monkeypatch.setattr(main, "_LIVE", wazuh_live.LiveState(notifier=notify.TelegramNotifier("t", "1", post=lambda u, p: True),
                                                            label=wazuh_demo.LABEL))
    return client


def test_abrir_wazuh_en_bucle_termina_en_429(demo):
    limit = main.RATE_LIMITS["/api/upload"][0]
    codes = [demo.get("/api/wazuh/session").status_code for _ in range(limit + 1)]
    assert codes[-1] == 429


def test_abrir_wazuh_respeta_el_cupo_de_analisis(demo):
    held = [main._ANALYSIS_SLOTS.acquire(blocking=False) for _ in range(main.MAX_PARALLEL_ANALYSES)]
    try:
        assert all(held)
        assert demo.get("/api/wazuh/session").status_code == 503
    finally:
        for _ in held:
            main._ANALYSIS_SLOTS.release()


# ---- 4. registro del límite por IP ---------------------------------------------------------------------

def test_el_registro_de_limites_no_crece_sin_tope(monkeypatch):
    monkeypatch.setattr(main, "MAX_RATE_KEYS", 200)
    for i in range(2_000):
        main._rate_limit_key(f"2001:db8::{i:x}", "/api/upload", 20, 60)
    assert len(main._hits) <= 200


def test_las_entradas_inactivas_se_barren_y_el_tope_global_se_conserva(monkeypatch):
    monkeypatch.setattr(main, "MAX_RATE_KEYS", 50)
    main._rate_limit_key("*", "/auth-fail-all", 100, 60)
    for i in range(49):
        main._rate_limit_key(f"10.0.0.{i}", "/api/upload", 20, 60)
    for q in main._hits.values():                        # todas viejas
        q[-1] -= main.RATE_KEY_IDLE + 1
    main._hits[("*", "/auth-fail-all")][-1] += main.RATE_KEY_IDLE + 1
    main._rate_limit_key("10.9.9.9", "/api/upload", 20, 60)
    assert ("*", "/auth-fail-all") in main._hits and len(main._hits) == 2


def test_borrar_entradas_no_deja_saltar_un_limite_vigente():
    for _ in range(10):
        main._rate_limit_key("192.0.2.1", "/auth-fail", 10, 60)
    with pytest.raises(main.HTTPException):
        main._rate_limit_key("192.0.2.1", "/auth-fail", 10, 60)


# ---- 5. GET del PDF de solo lectura --------------------------------------------------------------------

def test_get_del_pdf_no_cambia_los_nombres():
    sid = _sample()
    r = client.get(f"/api/sessions/{sid}/report.pdf", params={"client": "Atacante", "analyst": "Atacante"})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert main.SESSIONS[sid].client == "ACME" and main.SESSIONS[sid].analyst == ""


# ---- 6. consulta de reputación: una sola a la vez ------------------------------------------------------

def test_dos_consultas_simultaneas_lanzan_un_solo_hilo(monkeypatch):
    sid = _sample()
    s = main.SESSIONS[sid]
    s.analysis["iocs"] = [{"type": "ip", "value": "8.8.8.8", "count": 1}]
    started, release = [], threading.Event()

    def slow_worker(obj, queries, vt, ab):
        started.append(1)
        release.wait(5)
        obj.intel.update(status="done")

    monkeypatch.setattr(main, "_intel_worker", slow_worker)
    def slow_plan(iocs, inc):                       # ensancha la ventana entre «¿hay una en curso?» y «marcar en curso»
        time.sleep(0.2)
        return {"queries": [{"indicator": "8.8.8.8", "kind": "ip"}]}

    monkeypatch.setattr(main.intel_mod, "build_plan", slow_plan)
    monkeypatch.setenv("VT_API_KEY", "k")
    results, barrier = [], threading.Barrier(4)

    def hit():
        barrier.wait()
        results.append(client.post(f"/api/sessions/{sid}/intel").status_code)

    threads = [threading.Thread(target=hit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    time.sleep(0.2)
    release.set()
    assert sorted(results) == [200, 409, 409, 409]
    assert len(started) == 1


# ---- 7. clave de acceso corta --------------------------------------------------------------------------

def test_una_clave_corta_cierra_la_api(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", "short")
    r = client.get("/api/auth/check", headers={"Authorization": "Bearer short"})
    assert r.status_code == 503 and "demasiado corta" in r.json()["detail"]
    assert client.post("/api/sample", headers={"Authorization": "Bearer short"}).status_code == 503
    assert client.get("/api/health").status_code == 200          # el healthcheck del contenedor sigue vivo
    assert "short" not in client.get("/api/health").text


def test_una_clave_valida_sigue_funcionando(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", TOKEN)
    assert client.get("/api/auth/check", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
