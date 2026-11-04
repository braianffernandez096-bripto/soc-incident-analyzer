"""JSON guardado en una hoja de cálculo, contenedores con otro nombre y esquemas sin Event_ID (action/category)."""
import csv
import io
import json

import pytest
from openpyxl import Workbook

from backend.analysis import analyze
from backend.parser import ParseError, load_events

LOGS = [
    {"timestamp": "2026-11-04T10:00:41Z", "category": "authentication", "user": "root", "source_ip": "198.51.100.45",
     "destination_ip": "10.0.1.50", "action": "ssh_login", "status": "failed", "message": "Invalid credentials for root",
     "mitre_technique": "T1110.001", "severity": "medium"},
    {"timestamp": "2026-11-04T10:01:26Z", "category": "authentication", "user": "root", "source_ip": "198.51.100.45",
     "destination_ip": "10.0.1.50", "action": "ssh_login", "status": "failed", "message": "Invalid credentials for root",
     "mitre_technique": "T1110.001", "severity": "medium"},
]
DOC = {"report_metadata": {"title": "Lab"}, "incidents": [{"id": "INC-001", "name": "x"}],
       "findings": [{"id": "F-1"}, {"id": "F-2"}, {"id": "F-3"}], "logs_database": LOGS}


def _como_csv(lines: list[str]) -> bytes:
    """Lo que pasa al abrir un .json en una hoja y guardarlo como CSV: una celda (entre comillas) por línea."""
    out = io.StringIO()
    csv.writer(out, quoting=csv.QUOTE_ALL).writerows([[x] for x in lines])
    return out.getvalue().encode()


def _lineas(doc) -> list[str]:
    return json.dumps(doc, indent=2).splitlines()


def test_logs_database_container_is_found_and_preferred_over_other_lists():
    df, meta = load_events(json.dumps(DOC).encode(), "datos.json")
    assert len(df) == 2 and meta["format"] == "json"


def test_action_becomes_event_id_and_category_log_source():
    df, meta = load_events(json.dumps(LOGS).encode(), "logs.json")
    assert set(df["Event_ID"]) == {"ssh_login"} and set(df["Log_Source"]) == {"authentication"}
    assert df["Result"].iloc[0] == "failed" and df["Destination"].iloc[0] == "10.0.1.50"


def test_a_real_event_id_wins_over_action():
    rows = [{"timestamp": "2026-11-04 10:00:00", "event_id": "4625", "action": "logon", "user": "u", "source_ip": "1.2.3.4",
             "message": "m"}]
    df, _ = load_events(json.dumps(rows).encode(), "x.json")
    assert df["Event_ID"].iloc[0] == "4625"


def test_json_saved_as_csv_one_line_per_cell_is_rebuilt():
    df, meta = load_events(_como_csv(_lineas(DOC)), "datos.csv")
    assert len(df) == 2 and meta["json_in_sheet"] is True and meta["json_repaired"] is False


def test_json_saved_as_xlsx_one_line_per_cell_is_rebuilt():
    wb = Workbook()
    ws = wb.active
    for line in _lineas(DOC):
        ws.append([line])
    buf = io.BytesIO()
    wb.save(buf)
    df, meta = load_events(buf.getvalue(), "datos.xlsx")
    assert len(df) == 2 and meta["json_in_sheet"] is True


def test_damaged_json_with_missing_lines_still_yields_the_events():
    lineas = [x for x in _lineas(DOC) if '"name"' not in x and '"id": "F-2"' not in x]      # líneas perdidas dentro de objetos
    lineas = [x.replace('"id": "INC-001",', '"id": "INC-001",') for x in lineas]
    df, meta = load_events(_como_csv(lineas), "datos.csv")
    assert len(df) == 2 and meta["json_repaired"] is True


def test_unrecoverable_json_in_a_sheet_gets_an_explicit_message():
    lineas = _lineas(DOC)[:12]                                  # cortado por la mitad: no hay forma de leerlo
    with pytest.raises(ParseError, match="JSON guardado en una hoja"):
        load_events(_como_csv(lineas), "datos.csv")


def test_plain_text_without_header_keeps_the_original_message():
    with pytest.raises(ParseError, match="cabecera reconocible"):
        load_events(_como_csv(["hola", "esto no es un export"]), "datos.csv")


def test_limitations_do_not_name_accounts_that_are_not_in_the_file():
    df, meta = load_events(_como_csv(_lineas(DOC)), "datos.csv")
    texto = " ".join(analyze(df, meta)["limitations"])
    assert "backupsvc" not in texto and "rrojas" not in texto and "helpdesk" not in texto
    assert "JSON guardado línea por línea" in texto
