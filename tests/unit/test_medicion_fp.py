"""Medición de falsos positivos contra el Indexer de Wazuh (backend/medicion_fp.py), con el Indexer simulado: sin red.

Comprueba la lectura paginada (scroll) y su limpieza, los errores sin filtrar credenciales, que los eventos de archives sin regla ni «id»
se analizan, que la actividad normal no genera hallazgos y que la cobertura avisa de los tipos de evento que faltan.
"""
import json

import httpx
import pandas as pd
import pytest

from backend import medicion_fp as M
from backend import wazuh_demo

T0, T1 = pd.Timestamp("2026-11-16T12:00:00Z"), pd.Timestamp("2026-11-17T12:00:00Z")
SECRET = "clave-super-secreta-123"


@pytest.fixture
def indexer(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.lab:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "lector")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", SECRET)
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY", "0")


def _hit(i, eid="4624", agent="WIN-A"):
    return {"_id": f"doc{i}", "_source": {"timestamp": "2026-11-16T12:00:00.000+0000", "@timestamp": "2026-11-16T12:00:00Z", "agent": {"name": agent},
                                          "data": {"win": {"system": {"eventID": eid, "channel": "Security", "computer": "WIN-A.lab"},
                                                           "eventdata": {"targetUserName": "ana", "logonType": "2", "ipAddress": "-"}}}}}


def _client(pages, calls, status=200):
    def handler(req: httpx.Request):
        calls.append((req.method, req.url.path, json.loads(req.content or b"{}")))
        if req.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        if status != 200:
            return httpx.Response(status, json={})
        page = pages.pop(0) if pages else []
        return httpx.Response(200, json={"_scroll_id": "S1", "hits": {"hits": page}})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_lee_todas_las_paginas_y_libera_el_scroll(indexer):
    calls = []
    docs, cut = M.fetch(["WIN-A"], T0, T1, http=_client([[_hit(1), _hit(2)], [_hit(3)], []], calls))
    assert [d["_doc_id"] for d in docs] == ["doc1", "doc2", "doc3"] and not cut
    assert calls[0][1] == "/wazuh-archives-*/_search" and calls[1][1] == "/_search/scroll" and calls[-1][0] == "DELETE"
    q = calls[0][2]["query"]["bool"]["filter"]
    assert {"WIN-A", "win-a"} <= set(q[0]["terms"]["agent.name"]) and q[1]["range"]["@timestamp"]["gte"].startswith("2026-11-16T12:00")


def test_respeta_el_tope_de_eventos(indexer):
    docs, cut = M.fetch(["WIN-A"], T0, T1, max_events=2, http=_client([[_hit(1), _hit(2), _hit(3)], [_hit(4)]], []))
    assert len(docs) == 2 and cut


@pytest.mark.parametrize("status,texto", [(401, "rechazó"), (403, "rechazó"), (500, "HTTP 500")])
def test_errores_sin_credenciales(indexer, status, texto):
    with pytest.raises(M.MedicionError) as e:
        M.fetch(["WIN-A"], T0, T1, http=_client([], [], status=status))
    assert texto in str(e.value) and SECRET not in str(e.value) and "indexer.lab" not in str(e.value)


def test_sin_configuracion_lo_dice(monkeypatch):
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    with pytest.raises(M.MedicionError, match="Falta la conexión"):
        M.fetch(["WIN-A"], T0, T1)


def test_actividad_normal_no_genera_hallazgos():
    docs = [{**_hit(i)["_source"], "_doc_id": f"doc{i}"} for i in range(200)]
    m = M.measure(docs, "jornada")
    assert m["eventos_interpretados"] == 200 and m["hallazgos"] == 0 and m["por_1000_eventos"] == 0
    assert m["cobertura"]["4624"] == 200 and m["cobertura"]["5145"] == 0
    txt = M.as_text(m)
    # sin 5145: o no hubo accesos o falta la auditoría (un cero no lo distingue); sin 4625 porque no hubo fallos: no es un problema
    assert "? Acceso a recursos compartidos (5145): 0  → no hubo ninguno o falta su auditoría" in txt and "no se midieron control remoto de servicios" in txt
    assert "· Inicios de sesión fallidos (4625): 0  → no ocurrió en este rango" in txt


def test_eventos_de_archives_sin_regla_ni_id_se_analizan():
    docs = []
    for _, lote in wazuh_demo.stages():
        for a in lote:
            d = dict(a)
            d["_doc_id"] = d.pop("id")
            d.pop("rule")
            docs.append(d)
    m = M.measure(docs)
    assert m["traductor"]["descartadas"] == 0 and m["hallazgos"] >= 5
    assert {"brute_force", "cred_lsass", "persist_run"} <= set(m["por_regla"])
    assert all(d["confianza"] in ("Alta", "Media", "Baja") for d in m["detalle"])


def test_main_imprime_medicion_y_json(monkeypatch, capsys):
    monkeypatch.setattr(M, "fetch", lambda *a, **k: ([{**_hit(1)["_source"], "_doc_id": "doc1"}], False))
    assert M.main(["--agente", "WIN-A", "--desde", "2026-11-16T09:00-03:00", "--hasta", "2026-11-17T09:00-03:00", "--etiqueta", "jornada"]) == 0
    out = capsys.readouterr().out
    assert "Medición de falsos positivos · jornada" in out and "por cada 1.000 eventos: 0" in out
    assert M.main(["--agente", "WIN-A", "--desde", "2026-11-16T09:00-03:00", "--hasta", "2026-11-17T09:00-03:00", "--json", "--sin-detalle"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rango_utc"][0].startswith("2026-11-16T12:00") and "detalle" not in data


@pytest.mark.parametrize("desde,hasta", [("ayer", "2026-11-17T09:00"), ("2026-11-17T09:00", "2026-11-16T09:00")])
def test_fechas_invalidas(desde, hasta, capsys):
    assert M.main(["--agente", "WIN-A", "--desde", desde, "--hasta", hasta]) == 2
    assert "Error:" in capsys.readouterr().err


def test_sin_eventos_explica_por_que():
    txt = M.as_text(M.measure([], "x"))
    assert "No se leyó ningún evento" in txt and "nombre del agente" in txt and "--indice alertas" in txt


def test_no_consulta_misp_y_lo_restaura(monkeypatch):
    from backend import misp
    sentinel = object()
    misp.set_client(sentinel)
    seen = []
    monkeypatch.setattr(M, "analyze", lambda df, meta: seen.append(misp.get_client()) or {"findings": []})
    try:
        M.measure([{**_hit(1)["_source"], "_doc_id": "doc1"}])
        assert seen == [None] and misp.get_client() is sentinel        # apagado durante la medición, restaurado después
    finally:
        misp.set_client(None)


def _discovery_docs():
    docs = []
    for i, cmd in enumerate(["whoami /all", "ipconfig /all", "systeminfo", "net user", "tasklist"]):
        docs.append({"_doc_id": f"d{i}", "timestamp": f"2026-11-16T15:01:0{i}.000+0000", "agent": {"name": "WIN10"},
                     "data": {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "WIN10"},
                                      "eventdata": {"image": "C:\\Windows\\System32\\cmd.exe", "commandLine": cmd, "user": "NT AUTHORITY\\SYSTEM",
                                                    "parentImage": "C:\\Windows\\System32\\svchost.exe"}}}})
    return docs


def test_detalle_con_ejemplos_hora_local_y_duda_por_cuenta_de_sistema():
    m = M.measure(_discovery_docs(), tz=pd.Timestamp("2026-11-16T09:00-03:00").tzinfo)
    d = [x for x in m["detalle"] if x["regla"] == "cmd_discovery"]
    assert d, m["detalle"]
    d = d[0]
    assert d["inicio"].startswith("2026-11-16 12:01")                 # 15:01 UTC = 12:01 en -03:00
    assert d["ejemplos"] and any("whoami" in e or "ipconfig" in e for e in d["ejemplos"])
    assert any("servicio o de máquina" in x for x in d["en_contra"])
    txt = M.as_text(m)
    assert "ejemplo:" in txt and "horas en UTC-03:00" in txt


def test_opcion_procesos_muestra_el_arbol_sin_cuentas():
    m = M.measure(_discovery_docs(), processes=True)
    d = [x for x in m["detalle"] if x["regla"] == "cmd_discovery"][0]
    assert d["procesos"] and all(p["evento"] == "1" and p["padre"].lower().endswith("svchost.exe") for p in d["procesos"])
    txt = M.as_text(m)
    assert "proceso [1]:" in txt and "SYSTEM" not in "".join(str(p) for p in d["procesos"])
    assert "procesos" not in M.measure(_discovery_docs())["detalle"][0]


def _proc_doc(n, wazuh_id, image, cmd, user, eid="1"):
    return {"_doc_id": f"idx{n}", "id": wazuh_id, "timestamp": f"2026-11-17T17:43:{10 + n:02d}.000+0000", "agent": {"name": "WIN-A"},
            "data": {"win": {"system": {"eventID": eid, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "WIN-A"},
                             "eventdata": {"image": image, "commandLine": cmd, "parentImage": r"C:\Windows\System32\cmd.exe", "user": user}}}}


def test_id_de_wazuh_repetido_no_mezcla_eventos_ajenos():
    """En archives, el «id» de Wazuh se repite entre eventos distintos. Antes, la evidencia arrastraba eventos ajenos: aparecía un hallazgo
    a nombre de SYSTEM con «svchost.exe» de ejemplo. Se analiza con el «_id» del Indexer, que es único."""
    docs = []
    for i, c in enumerate(["whoami /all", "ipconfig /all", "systeminfo", "net user"]):
        docs.append(_proc_doc(2 * i, f"1795.{i}", rf"C:\Windows\System32\{c.split()[0]}.exe", c, "WIN-A\\ana"))
        docs.append(_proc_doc(2 * i + 1, f"1795.{i}", r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\svchost.exe -k netsvcs",
                              "NT AUTHORITY\\SYSTEM"))
    m = M.measure(docs, processes=True)
    assert m["ids_repetidos"] == 4
    disc = [d for d in m["detalle"] if d["regla"] == "cmd_discovery"]
    assert len(disc) == 1 and "SYSTEM" not in disc[0]["titulo"] and disc[0]["eventos"] == 4
    assert not any("svchost" in x for x in disc[0]["ejemplos"]) and not any("svchost" in p["programa"] for p in disc[0]["procesos"])
    assert "id» de Wazuh repetido: 4" in M.as_text(m)


def test_ejemplos_en_una_sola_linea():
    assert M._examples({"ejemplos": ["Service startup type was changed\nParam3: inicio por solicitud\nParam4: BITS"]}) == [
        "Service startup type was changed Param3: inicio por solicitud Param4: BITS"]
