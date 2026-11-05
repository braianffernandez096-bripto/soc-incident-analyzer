"""scripts/generar_informe_ejemplo.py: protege las llamadas de pago a la IA (simulacro sin red, caché en disco, no escribe PDF incompleto)."""
import importlib.util
import socket
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("gen", Path(__file__).resolve().parents[2] / "scripts" / "generar_informe_ejemplo.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


@pytest.fixture
def no_net(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("el simulacro no debe abrir conexiones")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


def test_dry_run_makes_pdf_without_network(tmp_path, no_net, capsys):
    out = tmp_path / "s.pdf"
    assert gen.main(["--out", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF")
    assert "SIMULACRO" in capsys.readouterr().out


def test_real_without_key_calls_nobody(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = []
    monkeypatch.setattr(gen, "real_model", lambda *a, **k: called.append(1))
    assert gen.main(["--real", "--cache", str(tmp_path / "c.json"), "--out", str(tmp_path / "x.pdf")]) == 2
    assert not called and not (tmp_path / "x.pdf").exists()


def test_real_asks_confirmation_and_cancel_calls_nobody(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    calls = []
    monkeypatch.setattr(gen, "real_model", lambda *a, **k: (lambda t, x, m: calls.append(1) or gen.fake_model(t, x, m)))
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    assert gen.main(["--real", "--cache", str(tmp_path / "c.json"), "--out", str(tmp_path / "x.pdf")]) == 1
    assert calls == [] and not (tmp_path / "x.pdf").exists()


def test_cache_saves_paid_answers_and_rerun_only_calls_what_is_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    cache, out = tmp_path / "c.json", tmp_path / "x.pdf"
    calls, fail = [], {"on": True}

    def inner(tool, text, mt):
        if fail["on"] and tool["name"] == "submit_executive_report":     # falla justo la llamada del resumen
            raise RuntimeError("503 simulado")
        calls.append(tool["name"])
        return gen.fake_model(tool, text, mt)

    monkeypatch.setattr(gen, "real_model", lambda *a, **k: inner)
    args = ["--real", "--yes", "--cache", str(cache), "--out", str(out)]
    assert gen.main(args) == 3                                           # incompleto: NO escribe el PDF
    assert not out.exists() and cache.exists()
    first = len(calls)
    assert first >= 2                                                    # los grupos ya pagados quedaron guardados
    fail["on"] = False
    assert gen.main(args) == 0 and out.read_bytes().startswith(b"%PDF")
    assert len(calls) == first + 1                                       # solo se repitió la llamada que faltaba
    n_before = len(calls)
    assert gen.main(args) == 0 and len(calls) == n_before               # tercera vez: todo desde el caché, cero llamadas
