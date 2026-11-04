"""Captcha en la API: apagado por defecto; con CAPTCHA=on protege las subidas y deja libres los ejemplos."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import captcha, main
from backend.main import app

client = TestClient(app, raise_server_exceptions=False)
DATA = Path(__file__).resolve().parents[2] / "sample_data"
CSV = (DATA / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.csv").read_bytes()
EML = sorted((DATA / "correos").glob("*.eml"))[0]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("CAPTCHA", raising=False)
    monkeypatch.delenv("APP_ACCESS_TOKEN", raising=False)
    main._hits.clear()
    captcha.reset()
    yield
    main._hits.clear()
    captcha.reset()


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setenv("CAPTCHA", "on")


def _up(headers=None):
    return client.post("/api/upload", files={"file": ("x.csv", CSV, "text/csv")}, headers=headers or {})


def _eml(headers=None):
    return client.post("/api/phishing", files=[("files", (EML.name, EML.read_bytes(), "message/rfc822"))], headers=headers or {})


def _solve(ok=True):
    c = client.post("/api/captcha/challenge").json()
    right = sorted(captcha._challenges[c["token"]][0])
    sel = right if ok else [i for i in range(6) if i not in right]
    return client.post("/api/captcha/verify", json={"token": c["token"], "selected": sel})


# ---- apagado por defecto ----------------------------------------------------------------------------

def test_off_by_default_and_everything_works_without_it():
    assert client.get("/api/captcha/status").json() == {"enabled": False}
    assert _up().status_code == 200
    assert _eml().status_code == 200
    assert client.post("/api/captcha/challenge").status_code == 404
    assert client.post("/api/captcha/verify", json={"token": "x", "selected": [0, 1, 2]}).status_code == 404


# ---- activado ---------------------------------------------------------------------------------------

def test_status_reports_enabled(on):
    assert client.get("/api/captcha/status").json() == {"enabled": True}


def test_uploads_require_a_pass(on):
    for r in (_up(), _eml()):
        assert r.status_code == 403
        assert r.headers["x-captcha-required"] == "1"
        assert "captcha" in r.json()["detail"].lower()


def test_bad_pass_is_rejected(on):
    assert _up({"X-Captcha-Pass": "falso"}).status_code == 403
    assert _eml({"X-Captcha-Pass": ""}).status_code == 403


@pytest.mark.parametrize("send", [_up, _eml])
def test_full_flow_unlocks_one_analysis(on, send):
    r = _solve()
    assert r.status_code == 200
    assert send({"X-Captcha-Pass": r.json()["pass"]}).status_code == 200


def test_each_analysis_needs_its_own_captcha(on):
    """El pase es de un solo uso: el segundo análisis, aunque sea inmediato, vuelve a pedir el captcha."""
    h = {"X-Captcha-Pass": _solve().json()["pass"]}
    assert _up(h).status_code == 200
    assert _up(h).status_code == 403 and _eml(h).status_code == 403
    assert _eml({"X-Captcha-Pass": _solve().json()["pass"]}).status_code == 200


def test_results_stay_available_without_any_pass(on):
    """Mirar los resultados no depende del captcha ni de ningún tiempo."""
    sid = client.post("/api/sample").json()["session_id"]
    assert client.get(f"/api/sessions/{sid}").status_code == 200
    assert client.get(f"/api/sessions/{sid}/events").status_code == 200
    assert client.get(f"/api/sessions/{sid}/attack-layer.json").status_code == 200


def test_samples_are_not_protected(on):
    assert client.post("/api/sample").status_code == 200
    assert client.post("/api/phishing/sample").status_code == 200


def test_wrong_selection_is_rejected_and_gives_no_pass(on):
    r = _solve(ok=False)
    assert r.status_code == 400 and "pass" not in r.json()


def test_challenge_cannot_be_retried_after_failure(on):
    c = client.post("/api/captcha/challenge").json()
    right = sorted(captcha._challenges[c["token"]][0])
    wrong = [i for i in range(6) if i not in right]
    assert client.post("/api/captcha/verify", json={"token": c["token"], "selected": wrong}).status_code == 400
    assert client.post("/api/captcha/verify", json={"token": c["token"], "selected": right}).status_code == 400


def test_guessing_blindly_ends_in_429(on):
    codes = [client.post("/api/captcha/verify", json={"token": "x", "selected": [0, 1, 2]}).status_code for _ in range(12)]
    assert codes[:10] == [400] * 10 and 429 in codes[10:]


def test_challenge_requests_are_rate_limited(on):
    main._hits.clear()
    codes = [client.post("/api/captcha/challenge").status_code for _ in range(32)]
    assert codes.count(200) == main.RATE_LIMITS["/api/captcha"][0] and 429 in codes


@pytest.mark.parametrize("body", [{}, {"token": "x"}, {"selected": [1, 2, 3]}, {"token": "x", "selected": "abc"},
                                  {"token": "x", "selected": [0, 1, 2, 3, 4, 5, 6]}, {"token": "x" * 500, "selected": [1]}])
def test_malformed_verify_body_is_422(on, body):
    assert client.post("/api/captcha/verify", json=body).status_code == 422


def test_challenge_response_does_not_leak_the_answer(on):
    c = client.post("/api/captcha/challenge").json()
    assert set(c) == {"token", "images", "prompt", "expires_in"}
    assert len(c["images"]) == 6


def test_a_pass_from_another_ip_is_useless(on):
    """El pase está ligado a la IP de quien resolvió el captcha."""
    grant = _solve().json()["pass"]
    captcha._passes[grant][2] = "otra-ip"
    assert _up({"X-Captcha-Pass": grant}).status_code == 403


def test_access_token_still_guards_captcha_routes(on, monkeypatch):
    monkeypatch.setenv("APP_ACCESS_TOKEN", "correct-horse-battery-staple-9")
    assert client.post("/api/captcha/challenge").status_code == 401
    ok = client.post("/api/captcha/challenge", headers={"Authorization": "Bearer correct-horse-battery-staple-9"})
    assert ok.status_code == 200
