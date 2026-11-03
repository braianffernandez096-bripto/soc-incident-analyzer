"""Reputación de indicadores (VirusTotal / AbuseIPDB): privacidad, parseo, errores y límites. Sin red ni claves reales."""
import json
import logging

import httpx
import pytest

from backend import intel
from backend.intel import ProviderStop, build_plan, classify_domain, classify_ip, lookup, verdict

VT_KEY, AB_KEY = "vt-secret-KEY-123", "ab-secret-KEY-456"


def _ioc(t, v):
    return {"type": t, "value": v}


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def vt_ok(mal=0, sus=0, harmless=60, undet=10):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": undet},
                                    "reputation": -5, "last_analysis_date": 1792742400, "country": "US", "as_owner": "ACME NET", "asn": 64500}}}


def ab_ok(score=0, reports=0):
    return {"data": {"abuseConfidenceScore": score, "totalReports": reports, "numDistinctUsers": 3, "countryCode": "NL",
                     "isp": "Host SA", "usageType": "Data Center", "isTor": False, "isWhitelisted": False,
                     "lastReportedAt": "2026-10-20T10:00:00+00:00"}}


@pytest.fixture(autouse=True)
def _rapido(monkeypatch):
    monkeypatch.setattr(intel, "VT_INTERVAL", 0)
    monkeypatch.setattr(intel, "ABUSE_INTERVAL", 0)


# ---- qué puede salir de la red ------------------------------------------------------------

@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.0.9", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1"])
def test_ip_internas_nunca_se_consultan(ip):
    ok, why = classify_ip(ip)
    assert not ok and why


@pytest.mark.parametrize("ip", ["192.0.2.10", "198.51.100.7", "203.0.113.200", "2001:db8::5"])
def test_rangos_de_documentacion_se_omiten(ip):
    ok, why = classify_ip(ip)
    assert not ok and why.startswith("rango de documentación")


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_ip_publicas_son_consultables(ip):
    assert classify_ip(ip) == (True, "")


def test_ip_invalida():
    assert classify_ip("999.1.1.1")[0] is False and classify_ip("abc")[0] is False


@pytest.mark.parametrize("d", ["evil.example.org", "c2.bad-site.io", "a.b.c.xyz"])
def test_dominios_publicos(d):
    assert classify_domain(d) == (True, "")


@pytest.mark.parametrize("d", ["srv01.corp", "host.local", "printer.lan", "localhost", "a.example", "no_valido", "x", "-a.com", "http://x.com"])
def test_dominios_internos_o_invalidos(d):
    assert classify_domain(d)[0] is False


def test_plan_solo_incluye_ip_y_dominios_publicos():
    iocs = [_ioc("IP", "8.8.8.8"), _ioc("IP", "10.0.0.5"), _ioc("IP", "203.0.113.9"),
            _ioc("Cuenta", "CORP\\admin"), _ioc("Host", "WS-018"), _ioc("Comando", "powershell -enc AAAA"),
            _ioc("URL/URI", "http://evil.example.org/a.php?x=1"), _ioc("URL/URI", "/index.php?id=1' OR 1=1"),
            _ioc("URL/URI", "https://1.1.1.1/x"), _ioc("IP", "8.8.8.8")]
    plan = build_plan(iocs)
    assert [(q["kind"], q["value"]) for q in plan["queries"]] == [("ip", "8.8.8.8"), ("domain", "evil.example.org"), ("ip", "1.1.1.1")]
    enviado = json.dumps(plan["queries"])
    for secreto in ("admin", "WS-018", "powershell", "10.0.0.5", "203.0.113.9", "OR 1=1", "a.php"):
        assert secreto not in enviado
    motivos = {s["value"]: s["reason"] for s in plan["skipped"]}
    assert motivos["10.0.0.5"] == "IP interna o privada" and motivos["203.0.113.9"].startswith("rango de documentación")
    assert plan["reserved_available"] == 1


def test_plan_con_ip_de_documentacion_solo_si_se_pide():
    iocs = [_ioc("IP", "203.0.113.9"), _ioc("IP", "10.0.0.1")]
    assert build_plan(iocs)["queries"] == []
    p = build_plan(iocs, include_reserved=True)
    assert p["queries"] == [{"kind": "ip", "value": "203.0.113.9", "reserved": True}]       # la privada sigue fuera


def test_plan_aplica_el_tope(monkeypatch):
    monkeypatch.setattr(intel, "MAX_INDICATORS", 3)
    p = build_plan([_ioc("IP", f"8.8.8.{i}") for i in range(1, 8)])
    assert len(p["queries"]) == 3 and p["truncated"] == 4


# ---- veredicto ----------------------------------------------------------------------------

def test_umbrales_del_veredicto():
    v = lambda m=0, s=0, a=None: verdict({"status": "ok", "malicious": m, "suspicious": s}, None if a is None else {"status": "ok", "score": a})
    assert v(3) == "Malicioso" and v(0, 0, 75) == "Malicioso"
    assert v(1) == "Sospechoso" and v(0, 1) == "Sospechoso" and v(0, 0, 25) == "Sospechoso"
    assert v(0, 0, 24) == "Sin reportes" and v(0) == "Sin reportes"
    assert verdict(None, None) == "Sin datos"
    assert verdict({"status": "not_found"}, {"status": "error"}) == "Sin datos"
    assert verdict({"status": "not_found"}, {"status": "ok", "score": 80}) == "Malicioso"


# ---- consultas -----------------------------------------------------------------------------

def test_lookup_ip_con_ambos_proveedores_y_cabeceras_correctas():
    vistos = []

    def handler(req: httpx.Request):
        vistos.append(req)
        if "virustotal" in req.url.host:
            assert req.url.path == "/api/v3/ip_addresses/8.8.8.8" and req.headers["x-apikey"] == VT_KEY
            return httpx.Response(200, json=vt_ok(mal=5))
        assert req.url.path == "/api/v2/check" and req.headers["Key"] == AB_KEY
        assert req.url.params["ipAddress"] == "8.8.8.8" and req.url.params["maxAgeInDays"] == "90"
        return httpx.Response(200, json=ab_ok(score=90, reports=12))

    out = lookup([{"kind": "ip", "value": "8.8.8.8", "reserved": False}], VT_KEY, AB_KEY, http=_client(handler), sleep=lambda s: None)
    r = out["results"][0]
    assert r["verdict"] == "Malicioso" and r["vt"]["malicious"] == 5 and r["vt"]["total"] == 75 and r["vt"]["owner"] == "ACME NET"
    assert r["abuse"]["score"] == 90 and r["abuse"]["reports"] == 12 and r["abuse"]["last_reported"] == "2026-10-20"
    assert r["vt"]["link"].startswith("https://www.virustotal.com/gui/ip-address/") and "abuseipdb.com/check/8.8.8.8" in r["abuse"]["link"]
    assert len(vistos) == 2 and out["queried_at"].endswith("UTC")


def test_dominio_solo_va_a_virustotal():
    hosts = []

    def handler(req):
        hosts.append(req.url.host)
        assert req.url.path == "/api/v3/domains/evil.example.org"
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 70}, "registrar": "NameCo",
                                                                  "creation_date": 1700000000, "categories": {"a": "phishing", "b": "malware"}}}})

    out = lookup([{"kind": "domain", "value": "evil.example.org"}], VT_KEY, AB_KEY, http=_client(handler), sleep=lambda s: None)
    assert hosts == ["www.virustotal.com"] and out["results"][0]["abuse"] is None
    assert out["results"][0]["vt"]["categories"] == ["malware", "phishing"] and out["results"][0]["verdict"] == "Sospechoso"


def test_solo_el_proveedor_con_clave_recibe_consultas():
    hosts = set()
    lookup([{"kind": "ip", "value": "8.8.8.8"}], None, AB_KEY, http=_client(lambda r: (hosts.add(r.url.host), httpx.Response(200, json=ab_ok()))[1]), sleep=lambda s: None)
    assert hosts == {"api.abuseipdb.com"}


def test_404_de_virustotal_es_sin_datos_no_error():
    out = lookup([{"kind": "ip", "value": "8.8.4.4"}], VT_KEY, None, http=_client(lambda r: httpx.Response(404, json={"error": {}})), sleep=lambda s: None)
    assert out["results"][0]["vt"]["status"] == "not_found" and out["results"][0]["verdict"] == "Sin datos" and not out["notices"]


@pytest.mark.parametrize("code", [401, 403])
def test_clave_rechazada_detiene_ese_proveedor_con_aviso(code):
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(code)

    qs = [{"kind": "ip", "value": f"8.8.8.{i}"} for i in range(1, 6)]
    out = lookup(qs, VT_KEY, None, http=_client(handler), sleep=lambda s: None)
    assert n["c"] == 1 and "rechazó la clave" in out["notices"][0]          # no insiste con una clave mala


def test_un_proveedor_caido_no_detiene_al_otro():
    def handler(req):
        return httpx.Response(401) if "virustotal" in req.url.host else httpx.Response(200, json=ab_ok(score=30))

    out = lookup([{"kind": "ip", "value": "8.8.8.1"}, {"kind": "ip", "value": "8.8.8.2"}], VT_KEY, AB_KEY, http=_client(handler), sleep=lambda s: None)
    assert len(out["results"]) == 2 and all(r["abuse"]["score"] == 30 and r["verdict"] == "Sospechoso" for r in out["results"])


def test_429_espera_y_reintenta_una_vez():
    calls, esperas = {"n": 0}, []

    def handler(req):
        calls["n"] += 1
        return httpx.Response(429) if calls["n"] == 1 else httpx.Response(200, json=vt_ok())

    out = lookup([{"kind": "ip", "value": "8.8.8.8"}], VT_KEY, None, http=_client(handler), sleep=esperas.append)
    assert 60 in esperas and calls["n"] == 2 and out["results"][0]["vt"]["status"] == "ok"


def test_429_persistente_agota_la_cuota_con_aviso():
    out = lookup([{"kind": "ip", "value": f"8.8.8.{i}"} for i in range(1, 4)], VT_KEY, None, http=_client(lambda r: httpx.Response(429)), sleep=lambda s: None)
    assert "límite" in out["notices"][0] and out["results"][0]["vt"]["status"] == "stopped"


def test_abuseipdb_429_avisa_limite_diario():
    out = lookup([{"kind": "ip", "value": "8.8.8.8"}], None, AB_KEY, http=_client(lambda r: httpx.Response(429)), sleep=lambda s: None)
    assert "1.000 por día" in out["notices"][0]


@pytest.mark.parametrize("resp", [httpx.Response(500), httpx.Response(200, content=b"<html>no json</html>"), httpx.Response(200, json=["lista"]),
                                  httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": "x"}}}})])
def test_respuestas_raras_no_rompen(resp):
    out = lookup([{"kind": "ip", "value": "8.8.8.8"}], VT_KEY, None, http=_client(lambda r: resp), sleep=lambda s: None)
    assert out["results"][0]["verdict"] == "Sin datos"


def test_timeout_y_error_de_red_no_rompen_y_no_filtran_la_clave():
    def handler(req):
        raise httpx.ConnectTimeout("timeout", request=req)

    out = lookup([{"kind": "ip", "value": "8.8.8.8"}], VT_KEY, AB_KEY, http=_client(handler), sleep=lambda s: None)
    r = out["results"][0]
    assert r["vt"]["status"] == "error" and r["abuse"]["status"] == "error"
    assert VT_KEY not in json.dumps(out) and AB_KEY not in json.dumps(out)


def test_las_claves_nunca_aparecen_en_logs_ni_resultados(caplog):
    caplog.set_level(logging.DEBUG)

    def handler(req):
        raise httpx.ReadError("falló", request=req)

    out = lookup([{"kind": "ip", "value": "8.8.8.8"}], VT_KEY, AB_KEY, http=_client(handler), sleep=lambda s: None)
    assert VT_KEY not in caplog.text and AB_KEY not in caplog.text and VT_KEY not in json.dumps(out)


def test_ritmo_de_virustotal_respeta_el_intervalo(monkeypatch):
    monkeypatch.setattr(intel, "VT_INTERVAL", 15.5)
    esperas = []
    lookup([{"kind": "ip", "value": f"8.8.8.{i}"} for i in range(1, 4)], VT_KEY, None,
           http=_client(lambda r: httpx.Response(200, json=vt_ok())), sleep=esperas.append)
    assert len(esperas) == 2 and all(0 < e <= 15.5 for e in esperas)         # la 1.ª consulta no espera


def test_progreso_se_informa_por_indicador():
    pasos = []
    lookup([{"kind": "ip", "value": f"8.8.8.{i}"} for i in range(1, 4)], None, AB_KEY,
           http=_client(lambda r: httpx.Response(200, json=ab_ok())), sleep=lambda s: None, on_progress=lambda p: pasos.append((p["done"], p["total"])))
    assert pasos == [(1, 3), (2, 3), (3, 3)]


def test_valor_con_caracteres_raros_se_codifica_en_la_url():
    visto = {}
    lookup([{"kind": "domain", "value": "a.com/../../users"}], VT_KEY, None,
           http=_client(lambda r: (visto.update(p=r.url.raw_path.decode()), httpx.Response(404))[1]), sleep=lambda s: None)
    assert "/../" not in visto["p"] and visto["p"].startswith("/api/v3/domains/a.com%2F")


def test_provider_stop_es_una_excepcion_propia():
    assert issubclass(ProviderStop, Exception)
