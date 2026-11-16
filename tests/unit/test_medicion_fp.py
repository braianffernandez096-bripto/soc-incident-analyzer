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
    assert "✘ Acceso a recursos compartidos (5145): 0" in txt and "sin medir: control remoto de servicios" in txt


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
