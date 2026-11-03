"""Límites del parser: zip bomb y tope de filas."""
import io
import zipfile

import pytest

from backend import parser
from backend.parser import ParseError, load_events


def test_zip_con_contenido_descomprimido_desproporcionado_se_rechaza(monkeypatch):
    monkeypatch.setattr(parser, "MAX_UNCOMPRESSED_BYTES", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/sheet.xml", "A" * 100_000)   # comprime muy bien: poco en disco, mucho en memoria
    with pytest.raises(ParseError, match="descomprimido"):
        load_events(buf.getvalue())


def test_archivo_que_no_es_zip_se_rechaza_con_mensaje_claro():
    with pytest.raises(ParseError, match="no es un Excel"):
        load_events(b"texto plano")


def test_tope_de_filas(monkeypatch):
    import openpyxl
    monkeypatch.setattr(parser, "MAX_ROWS", 3)
    wb = openpyxl.Workbook(); ws = wb.active
    ws.append(["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP"])
    for i in range(10):
        ws.append([f"E{i}", "2026-10-23 08:00:00", "H", "4625", "u", "1.2.3.4"])
    buf = io.BytesIO(); wb.save(buf)
    with pytest.raises(ParseError, match="filas"):
        load_events(buf.getvalue())
