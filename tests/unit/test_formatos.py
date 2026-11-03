"""Formatos de entrada: CSV/TSV y JSON/NDJSON dan el mismo análisis que el Excel."""
import json
from pathlib import Path

import pytest

from backend import parser
from backend.analysis import analyze
from backend.parser import ParseError, load_events

DATA = Path(__file__).resolve().parents[2] / "sample_data"
XLSX = DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
CSV = DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv"
NDJSON = DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.ndjson"

HEADER = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP"]


def _rows(n=5, ts="2026-10-23 08:00:00"):
    return [[f"EVT-{i}", ts, "H1", "4625", "CORP\\u", "1.2.3.4"] for i in range(n)]


def _csv(rows, header=HEADER, sep=","):
    return "\n".join(sep.join(map(str, r)) for r in [header] + rows).encode()


@pytest.fixture(scope="module")
def base():
    df, meta = load_events(str(XLSX))
    return df, analyze(df, meta)


# ---- equivalencia con el Excel -------------------------------------------------

def test_csv_de_ejemplo_equivale_al_excel(base):
    df, a = base
    d2, m2 = load_events(str(CSV))
    assert d2.equals(df)
    assert m2["format"] == "csv" and not m2["timezone_converted"]
    a2 = analyze(d2, m2)
    assert len(a2["incidents"]) == 6 and len(a2["findings"]) == 25
    assert [i["id"] for i in a2["incidents"]] == [i["id"] for i in a["incidents"]]


def test_ndjson_estilo_elastic_equivale_al_excel(base):
    df, _ = base
    d2, m2 = load_events(str(NDJSON))
    assert d2.equals(df)
    assert m2["format"] == "json" and m2["sheet"] == "NDJSON"
    assert m2["timezone_converted"]            # @timestamp termina en Z: se normaliza a UTC
    assert len(analyze(d2, m2)["incidents"]) == 6


def test_el_informe_avisa_cuando_se_convirtio_la_zona_horaria():
    d, m = load_events(str(NDJSON))
    lims = analyze(d, m)["limitations"]
    assert any("convirtieron a UTC" in x for x in lims)
    d, m = load_events(str(CSV))
    assert any("no indican zona horaria" in x for x in analyze(d, m)["limitations"])


# ---- CSV: separadores y codificaciones ------------------------------------------

@pytest.mark.parametrize("sep", [",", ";", "\t", "|"])
def test_csv_detecta_el_separador(sep):
    df, meta = load_events(_csv(_rows(), sep=sep), "export.csv")
    assert len(df) == 5 and df["Event_ID"].iloc[0] == "4625" and meta["format"] == "csv"


def test_tsv_por_extension():
    df, _ = load_events(_csv(_rows(), sep="\t"), "export.tsv")
    assert len(df) == 5


def test_csv_con_bom_utf8_y_acentos():
    rows = [["E1", "2026-10-23 08:00:00", "H1", "4625", "CORP\\u", "1.2.3.4", "Inicio de sesión fallido"]]
    data = "﻿".encode("utf-8") + _csv(rows, HEADER + ["Descripción"])
    df, _ = load_events(data, "x.csv")
    assert df["Event_Description"].iloc[0] == "Inicio de sesión fallido"


def test_csv_windows_1252():
    rows = [["E1", "2026-10-23 08:00:00", "H1", "4625", "CORP\\u", "1.2.3.4", "Inicio de sesión"]]
    data = _csv(rows, HEADER + ["Descripcion"]).decode().encode("cp1252")
    df, _ = load_events(data, "x.csv")
    assert df["Event_Description"].iloc[0] == "Inicio de sesión"


def test_csv_utf16_con_bom():
    data = _csv(_rows()).decode().encode("utf-16")      # incluye BOM, típico de exports de Windows
    df, _ = load_events(data, "x.csv")
    assert len(df) == 5


def test_csv_con_filas_de_titulo_antes_de_la_cabecera():
    data = b"Reporte SIEM\nGenerado por X\n" + _csv(_rows())
    df, _ = load_events(data, "x.csv")
    assert len(df) == 5


def test_csv_con_comillas_y_saltos_de_linea_en_el_campo():
    data = ('Log_ID,Timestamp,Hostname,Event_ID,User,Source_IP,Event_Description\n'
            'E1,2026-10-23 08:00:00,H1,4625,u,1.2.3.4,"linea1\nlinea2, con coma"\n').encode()
    df, _ = load_events(data, "x.csv")
    assert df["Event_Description"].iloc[0] == "linea1\nlinea2, con coma"


def test_csv_sin_log_id_genera_identificadores():
    data = _csv([r[1:] for r in _rows()], HEADER[1:] + [])
    df, meta = load_events(data, "x.csv")
    assert meta["generated_log_ids"] and df["Log_ID"].iloc[0].startswith("ROW-")


def test_celdas_con_formulas_se_conservan_como_texto():
    data = _csv([["E1", "2026-10-23 08:00:00", "H1", "4625", "=HYPERLINK(\"http://x\")", "1.2.3.4"]])
    df, _ = load_events(data, "x.csv")
    assert df["User"].iloc[0] == '=HYPERLINK("http://x")'


# ---- JSON ------------------------------------------------------------------------

def _recs(n=3):
    return [{"Log_ID": f"E{i}", "Timestamp": "2026-10-23 08:00:00", "Hostname": "H", "Event_ID": 4625,
             "User": "u", "Source_IP": "1.2.3.4"} for i in range(n)]


def test_json_arreglo_simple():
    df, meta = load_events(json.dumps(_recs()).encode(), "x.json")
    assert len(df) == 3 and df["Event_ID"].iloc[0] == "4625" and meta["sheet"] == "JSON"


@pytest.mark.parametrize("wrap", [lambda r: {"events": r}, lambda r: {"data": {"records": r}}, lambda r: {"results": r}])
def test_json_dentro_de_un_contenedor(wrap):
    df, _ = load_events(json.dumps(wrap(_recs())).encode(), "x.json")
    assert len(df) == 3


def test_json_respuesta_de_elasticsearch():
    resp = {"took": 3, "hits": {"total": {"value": 2}, "hits": [
        {"_id": "abc1", "_source": {"@timestamp": "2026-10-23T08:00:00Z", "host": {"name": "H1"},
                                    "winlog": {"event_id": 4625}, "user": {"name": "u"}, "source": {"ip": "1.2.3.4"}}},
        {"_id": "abc2", "_source": {"@timestamp": "2026-10-23T08:00:05Z", "host": {"name": "H1"},
                                    "winlog": {"event_id": 4624}, "user": {"name": "u"}, "source": {"ip": "1.2.3.4"}}},
    ]}}
    df, meta = load_events(json.dumps(resp).encode(), "x.json")
    assert list(df["Log_ID"]) == ["abc1", "abc2"] and list(df["Event_ID"]) == ["4625", "4624"]
    assert df["Hostname"].iloc[0] == "H1" and meta["timezone_converted"]


def test_json_lines_de_splunk_con_epoch():
    lines = [json.dumps({"preview": False, "result": {"_time": str(1792742400 + i), "host": "H1", "EventCode": "4625",
                                                    "user": "u", "src_ip": "1.2.3.4", "Message": "fallo"}})
             for i in range(3)]
    df, meta = load_events("\n".join(lines).encode(), "export.jsonl")
    assert len(df) == 3 and str(df["Timestamp"].iloc[0]) == "2026-10-23 08:00:00" and meta["timezone_converted"]


def test_json_dentro_de_un_txt_se_detecta_por_contenido():
    df, meta = load_events(json.dumps(_recs()).encode(), "salida.txt")
    assert meta["format"] == "json" and len(df) == 3


def test_zonas_horarias_se_convierten_a_utc():
    recs = _recs(2)
    recs[0]["Timestamp"] = "2026-10-23T10:00:00+02:00"
    recs[1]["Timestamp"] = "2026-10-23T08:00:00Z"
    df, meta = load_events(json.dumps(recs).encode(), "x.json")
    assert meta["timezone_converted"]
    assert {str(t) for t in df["Timestamp"]} == {"2026-10-23 08:00:00"}


def test_json_anidado_profundo_no_rompe():
    r = _recs(1)[0]
    deep = cur = {}
    for _ in range(40):
        cur["a"] = {}
        cur = cur["a"]
    r["extra"] = deep
    df, _ = load_events(json.dumps([r]).encode(), "x.json")
    assert len(df) == 1


# ---- errores y límites -----------------------------------------------------------

def test_json_invalido():
    with pytest.raises(ParseError, match="JSON válido"):
        load_events(b'{"a": 1}\n{no es json}\n', "x.json")


def test_json_sin_lista_de_eventos():
    with pytest.raises(ParseError, match="lista de eventos"):
        load_events(b'{"a": {"b": {"c": 1}}}', "x.json")


def test_json_con_demasiado_anidamiento_se_rechaza_con_mensaje():
    with pytest.raises(ParseError):
        load_events(("[" * 100_000).encode(), "x.json")


def test_archivo_binario_como_csv_se_rechaza():
    with pytest.raises(ParseError, match="binario"):
        load_events(b"MZ\x90\x00\x03\x00\x00\x00" * 100, "x.csv")


def test_csv_sin_columnas_reconocibles():
    with pytest.raises(ParseError, match="cabecera"):
        load_events(b"a,b,c\n1,2,3\n", "x.csv")


def test_csv_vacio():
    with pytest.raises(ParseError, match="vacío"):
        load_events(b"\n\n", "x.csv")


def test_extension_no_soportada():
    with pytest.raises(ParseError, match="no soportado"):
        load_events(b"x", "x.exe")


def test_tope_de_filas_csv(monkeypatch):
    monkeypatch.setattr(parser, "MAX_ROWS", 3)
    with pytest.raises(ParseError, match="filas"):
        load_events(_csv(_rows(500)), "x.csv")


def test_tope_de_filas_json(monkeypatch):
    monkeypatch.setattr(parser, "MAX_ROWS", 3)
    with pytest.raises(ParseError, match="filas"):
        load_events(json.dumps(_recs(500)).encode(), "x.json")


def test_tope_de_columnas_json(monkeypatch):
    monkeypatch.setattr(parser, "MAX_COLUMNS", 5)
    with pytest.raises(ParseError, match="campos distintos"):
        load_events(json.dumps(_recs(2)).encode(), "x.json")
