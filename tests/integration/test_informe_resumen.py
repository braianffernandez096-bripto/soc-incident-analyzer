"""Mejoras de lectura del informe en modo reglas: resumen con prioridades, gramática, reglas sin ruido y hosts sin dato."""
import re
from pathlib import Path

import pytest

from backend import ai as ai_mod
from backend.analysis import analyze
from backend.parser import load_events

S = Path(__file__).resolve().parents[2] / "sample_data"


@pytest.fixture(scope="module")
def mf():
    df, meta = load_events(str(S / "logs_multifuente.json"))
    return df, analyze(df, meta)


def test_resumen_con_prioridades_y_gramatica(mf):
    _, a = mf
    r = ai_mod.deterministic_report(a)["executive_summary"]
    assert "requiere(n)" not in r and "1 medio," in r and "6 incidentes son críticos y requieren" in r
    assert "Qué atender primero:" in r and "\n\n• INC-" in r and "la IP externa" in r


def test_singular_en_un_solo_incidente_critico():
    df, meta = load_events(str(S / "auth_log_ejemplo.txt"))
    r = ai_mod.deterministic_report(analyze(df, meta))["executive_summary"]
    assert "1 incidente es crítico y requiere" in r and "1 hallazgo " in r or "1 hallazgo (" in r


def test_hosts_vacios_no_cuentan_como_host(mf):
    df, a = mf
    assert a["profile"]["hosts"] == 0


def test_pdf_solo_lista_reglas_con_hallazgos(mf):
    import io
    from pypdf import PdfReader
    from backend.report import build_pdf
    df, a = mf
    pdf = build_pdf(a, ai_mod.build_deterministic(a), df, {"client": "X", "analyst": "Y", "filename": "f.json"})
    txt = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    assert "sin dato de host" in txt and "Se evaluaron" in txt and "Qué atender primero" in txt
    assert "kerberoast" not in txt          # regla de Windows sin hallazgos: ya no aparece en la tabla
    assert "g_ransomware" in txt
