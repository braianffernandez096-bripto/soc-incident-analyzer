"""Ruta de saltos (Received), cabeceras pegadas y desglose del puntaje: cada señal con su caso positivo y su caso negativo."""
from pathlib import Path

import pytest

from backend import phishing as P

DIR = Path(__file__).parents[2] / "sample_data" / "correos"
AUTH_OK = "mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"


def recv(frm, ip, by, when, extra=""):
    return f"Received: from {frm} ({frm} [{ip}]) by {by} with ESMTPS id x{extra}; {when}"


def raw_mail(received=(), date="Mon, 02 Nov 2026 09:00:00 +0000", frm="Ana <ana@corp.example>", body="Texto simple.", auth=AUTH_OK, extra=()):
    """Correo escrito a mano: los Received se dan del MÁS RECIENTE al más antiguo, como en un correo real."""
    lines = list(received) + [f"From: {frm}", "To: user@corp.example", "Subject: Hola", f"Date: {date}", "Message-ID: <1@corp.example>"]
    if auth:
        lines.append(f"Authentication-Results: {auth}")
    lines += list(extra)
    return ("\n".join(lines) + "\n\n" + body + "\n").encode()


def run(**kw):
    return P.analyze_eml(raw_mail(**kw), "t.eml")


def titles(r):
    return [s["title"] for s in r["signals"]]


GW = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 09:00:05 +0000")
ORIGIN = recv("mailer.example", "203.0.113.9", "gw.corp.example", "Mon, 02 Nov 2026 09:00:00 +0000")


# ---------------------------------------------------------------- orden y datos de cada salto
def test_hops_are_chronological_with_origin_first_and_delays():
    r = run(received=[GW, ORIGIN])
    h = r["hops"]
    assert [x["n"] for x in h] == [1, 2] and h[0]["ip"] == "203.0.113.9" and h[1]["ip"] == "10.0.0.5"
    assert h[0]["delay_s"] is None and h[1]["delay_s"] == 5
    assert h[0]["ts"] == "2026-11-02 09:00:00" and h[0]["public"] and not h[1]["public"]
    assert r["origin_ip"] == "203.0.113.9" and r["route"]["count"] == 2 and r["route"]["span_s"] == 5


def test_protocol_and_tls_are_read_from_the_hop():
    r = run(received=[recv("a.example", "203.0.113.9", "mx.corp.example", "Mon, 02 Nov 2026 09:00:00 +0000")])
    assert r["hops"][0]["protocol"] == "ESMTPS" and r["hops"][0]["tls"] and r["route"]["with_tls"] == 1
    plain = raw_mail(received=["Received: from a.example ([203.0.113.9]) by mx.corp.example with SMTP; Mon, 02 Nov 2026 09:00:00 +0000"])
    assert not P.analyze_eml(plain, "t.eml")["hops"][0]["tls"]


def test_time_with_a_comment_and_other_offsets_is_converted_to_utc():
    r = run(received=[recv("a.example", "203.0.113.9", "mx.corp.example", "Mon, 02 Nov 2026 06:00:00 -0300 (UTC)")])
    assert r["hops"][0]["ts"] == "2026-11-02 09:00:00"


# ---------------------------------------------------------------- hora fuera de orden
def test_a_hop_earlier_than_the_previous_one_is_flagged():
    back = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 08:30:00 +0000")        # 30 min ANTES del origen
    r = run(received=[back, ORIGIN])
    assert "hora_anterior" in r["hops"][1]["flags"] and "Horas fuera de orden en el recorrido" in titles(r)


def test_small_clock_skew_is_not_flagged():
    skew = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 08:58:30 +0000")         # 90 s antes: reloj desajustado, normal
    r = run(received=[skew, ORIGIN])
    assert r["hops"][1]["flags"] == [] and "Horas fuera de orden en el recorrido" not in titles(r)


# ---------------------------------------------------------------- retraso largo
def test_a_delay_of_six_hours_or_more_is_flagged_and_five_is_not():
    late = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 15:00:00 +0000")        # +6 h
    r = run(received=[late, ORIGIN])
    assert "retraso_largo" in r["hops"][1]["flags"] and "Retraso largo entre servidores" in titles(r)
    ok = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 14:00:00 +0000")          # +5 h
    r2 = run(received=[ok, ORIGIN])
    assert r2["hops"][1]["flags"] == [] and "Retraso largo entre servidores" not in titles(r2)


def test_hop_without_a_readable_date_is_marked_but_not_a_signal():
    r = run(received=["Received: from a.example ([203.0.113.9]) by mx.corp.example"])
    assert r["hops"][0]["flags"] == ["sin_fecha"] and r["hops"][0]["ts"] == "" and r["route"]["undated"] == 1
    assert not any("recorrido" in t.lower() for t in titles(r))


# ---------------------------------------------------------------- Date contra el recorrido
def test_message_date_far_from_the_route_is_flagged_and_close_is_not():
    r = run(received=[ORIGIN], date="Wed, 28 Oct 2026 09:00:00 +0000")                                      # 5 días antes
    assert "La fecha del mensaje no coincide con el recorrido" in titles(r)
    r2 = run(received=[ORIGIN], date="Mon, 02 Nov 2026 08:00:00 +0000")
    assert "La fecha del mensaje no coincide con el recorrido" not in titles(r2)


def test_unreadable_date_header_does_not_crash_the_route_check():
    r = run(received=[ORIGIN], date="ayer a la tarde")
    assert "La fecha del mensaje no coincide con el recorrido" not in titles(r)


# ---------------------------------------------------------------- recorrido largo
def test_more_than_twelve_hops_is_flagged_and_twelve_is_not():
    def chain(n):
        return [recv(f"h{i}.example", "203.0.113.9" if i == 0 else "10.0.0.5", f"h{i + 1}.example", f"Mon, 02 Nov 2026 09:{i:02d}:00 +0000") for i in range(n)][::-1]
    assert "Recorrido inusualmente largo" in titles(run(received=chain(13)))
    assert "Recorrido inusualmente largo" not in titles(run(received=chain(12)))


def test_all_hops_up_to_the_cap_are_kept_so_the_origin_is_never_lost():
    chain = [recv(f"h{i}.example", "203.0.113.9" if i == 0 else "10.0.0.5", f"h{i + 1}.example", f"Mon, 02 Nov 2026 09:{i:02d}:00 +0000") for i in range(20)][::-1]
    r = run(received=chain)
    assert len(r["hops"]) == 20 and r["origin_ip"] == "203.0.113.9"


def test_route_signals_are_low_weight_and_never_decide_on_their_own():
    back = recv("gw.corp.example", "10.0.0.5", "mx.corp.example", "Mon, 02 Nov 2026 08:00:00 +0000")
    r = run(received=[back, ORIGIN], date="Wed, 28 Oct 2026 09:00:00 +0000")
    assert r["score"] == 2 and r["severity"] == "Bajo"          # dos señales de 1 punto: por debajo del umbral Medio (3)
    assert all(s["severity"] == "Bajo" for s in r["signals"])


def test_sample_emails_with_a_normal_route_have_no_route_signals():
    for name in ("01_factura_adjunto_pdf_exe.eml", "05_legitimo_interno.eml"):
        r = P.analyze_eml((DIR / name).read_bytes(), name)
        assert not {"Horas fuera de orden en el recorrido", "Retraso largo entre servidores", "Recorrido inusualmente largo"} & set(titles(r))


def test_the_route_note_about_untrusted_hops_appears_only_with_several_hops():
    assert any("Received que añade tu propio servidor" in x for x in run(received=[GW, ORIGIN])["limitations"])
    assert not any("Received que añade tu propio servidor" in x for x in run(received=[ORIGIN])["limitations"])


# ---------------------------------------------------------------- cabeceras pegadas
GMAIL_PAGE = """Message ID\t<abc@x.example>
Created at:\tMon, 2 Nov 2026 (Delivered after 5 seconds)
SPF:\tPASS with IP 203.0.113.9

Delivered-To: user@corp.example
Received: from mailer.example (mailer.example [203.0.113.9]) by mx.corp.example with ESMTPS id 1; Mon, 02 Nov 2026 09:00:00 +0000
From: Banco <soporte@bancoo.example>
Subject: Hola
Date: Mon, 02 Nov 2026 08:59:00 +0000
Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=bancoo.example
"""


def test_pasted_headers_drop_the_summary_above_and_are_analyzed_as_headers_only():
    r = P.analyze_eml(P.paste_to_eml(GMAIL_PAGE), "pegado", pasted=True)
    assert r["headers"]["from_addr"] == "soporte@bancoo.example" and r["origin_ip"] == "203.0.113.9"
    assert "SPF falló (fail)" in titles(r) and r["auth"]["spf"] == "fail"
    assert r["headers_only"] is True and r["source"] == "cabeceras pegadas"
    assert "Correo sin cuerpo legible" not in titles(r)
    assert any("solo las cabeceras pegadas" in x for x in r["limitations"])


def test_an_eml_file_without_body_still_gets_the_empty_body_signal():
    r = P.analyze_eml(raw_mail(body=""), "t.eml")
    assert r["headers_only"] is False and r["source"] == "archivo .eml" and "Correo sin cuerpo legible" in titles(r)


def test_pasting_the_whole_message_source_analyzes_the_body_too():
    text = GMAIL_PAGE + "Content-Type: text/plain\n\nAbre https://bancoo-login.example/ingresar ya\n"
    r = P.analyze_eml(P.paste_to_eml(text), "pegado", pasted=True)
    assert r["headers_only"] is False and any("bancoo-login" in u["url"] for u in r["urls"])


def test_windows_line_endings_and_a_missing_blank_line_are_normalized():
    text = GMAIL_PAGE.replace("\n", "\r\n").rstrip()
    r = P.analyze_eml(P.paste_to_eml(text), "pegado", pasted=True)
    assert r["headers"]["subject"] == "Hola" and r["headers_only"]


@pytest.mark.parametrize("text", ["", "   \n  ", "hola, esto no es un correo", "Message ID <x>\nCreated at: hoy"])
def test_text_without_mail_headers_is_rejected_with_a_clear_message(text):
    with pytest.raises(P.EmlError, match="cabeceras"):
        P.paste_to_eml(text)


def test_pasted_text_over_the_limit_is_rejected():
    with pytest.raises(P.EmlError, match="demasiado largo"):
        P.paste_to_eml("From: a@b.example\n" + "x" * P.MAX_PASTE_CHARS)


def test_pasted_headers_make_no_network_calls(monkeypatch):
    import socket

    def prohibido(*a, **k):
        raise AssertionError("analizar cabeceras no debe abrir conexiones")
    monkeypatch.setattr(socket, "socket", prohibido)
    monkeypatch.setattr(socket, "create_connection", prohibido)
    monkeypatch.setattr(socket, "getaddrinfo", prohibido)
    assert P.analyze_eml(P.paste_to_eml(GMAIL_PAGE), "p", pasted=True)["auth"]["spf"] == "fail"


def test_analyze_many_marks_only_the_pasted_entries():
    out = P.analyze_many([("a.eml", raw_mail(body="")), ("pegado", P.paste_to_eml(GMAIL_PAGE))], pasted=frozenset({"pegado"}))
    by = {i["filename"]: i for i in out["items"]}
    assert by["pegado"]["headers_only"] is True and by["a.eml"]["headers_only"] is False


# ---------------------------------------------------------------- desglose del puntaje
def test_breakdown_adds_up_to_the_score_and_lists_every_signal():
    r = P.analyze_eml((DIR / "01_factura_adjunto_pdf_exe.eml").read_bytes(), "x")
    b = r["score_breakdown"]
    assert b["total"] == r["score"] == sum(c["applied"] for c in b["categories"]) and b["severity"] == r["severity"]
    assert sum(len(c["signals"]) for c in b["categories"]) == len(r["signals"])
    assert {c["category"] for c in b["categories"]} == {s["category"] for s in r["signals"]}


def test_every_signal_reports_what_it_really_added():
    r = P.analyze_eml((DIR / "02_enlace_enganoso_microsoft.eml").read_bytes(), "x")
    assert all(0 <= s["applied"] <= s["points"] for s in r["signals"])
    assert sum(s["applied"] for s in r["signals"]) == r["score"]


def test_the_category_cap_is_visible_when_it_cuts_points():
    # tres señales de 3 puntos en una categoría con tope 5: el desglose lo debe mostrar
    sig = P._Sig()
    for i in range(3):
        sig.add("Contenido", "Medio", 3, f"s{i}", "d")
    cap = {"Contenido": 5}
    applied = 0
    for s in sorted(sig.items, key=lambda x: -x["points"]):
        add = max(0, min(s["points"], cap["Contenido"] - applied))
        s["applied"] = add
        applied += add
    b = P._score_breakdown(sig.items, cap, applied, "Medio", False)
    c = b["categories"][0]
    assert c["raw"] == 9 and c["applied"] == 5 and c["cap"] == 5 and c["capped"] is True and b["total"] == 5
    assert [s["applied"] for s in c["signals"]] == [3, 2, 0]


@pytest.mark.parametrize("score,crit,sev,text", [(14, False, "Crítico", "12 o más"), (9, False, "Alto", "entre 6 y 11"), (4, False, "Medio", "entre 3 y 5"),
                                                  (1, False, "Bajo", "menor que 3"), (2, True, "Crítico", "señal de criticidad Crítico")])
def test_the_reason_explains_which_rule_set_the_severity(score, crit, sev, text):
    b = P._score_breakdown([], {}, score, sev, crit)
    assert text in b["why"] and [t["severity"] for t in b["thresholds"]] == ["Crítico", "Alto", "Medio", "Bajo"]


def test_legitimate_email_has_an_empty_breakdown():
    b = P.analyze_eml((DIR / "05_legitimo_interno.eml").read_bytes(), "x")["score_breakdown"]
    assert b["total"] == 0 and b["categories"] == []
