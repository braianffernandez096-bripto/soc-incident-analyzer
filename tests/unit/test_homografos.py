"""Ataques homógrafos: letras que se ven iguales y no lo son (I/l, a latina/cirílica…). Casos positivos y negativos."""
import json
from pathlib import Path

import pytest

from backend import homograph as H
from backend import phishing as P

DIR = Path(__file__).parents[2] / "sample_data" / "correos"
CYR_A, CYR_O, GRE_O = "а", "о", "ο"
LEGIT = "banco.universal@bancouniversal.gob"
FAKE_I = "banco.universaI@bancouniversal.gob"          # «I» mayúscula en vez de «l»


def eml(frm, to="cliente@ejemplo.com.ar", extra="", body="Hola.", subject="Aviso"):
    head = f"From: {frm}\nTo: {to}\nSubject: {subject}\nDate: Tue, 03 Nov 2026 10:00:00 +0000\nMessage-ID: <a@ejemplo.com.ar>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n{extra}\n"
    return (head + body + "\n").encode("utf-8")


def run(frm, expected="", **kw):
    return P.analyze_eml(eml(frm, **kw), "t.eml", expected)


def titles(r):
    return [s["title"] for s in r["signals"]]


def has(r, text):
    return any(text in t for t in titles(r))


# ---------------------------------------------------------------- núcleo
def test_script_detection():
    assert H.script_of("a") == "Latino" and H.script_of(CYR_A) == "Cirílico" and H.script_of(GRE_O) == "Griego"
    assert H.script_of("1") == "Común" and H.script_of("é") == "Latino" and H.script_of("ñ") == "Latino"


@pytest.mark.parametrize("a,b", [("universal", "universaI"), ("universal", "universa1"), ("google", "g00gle"), ("banco", f"b{CYR_A}nco"),
                                 ("banco", f"banc{CYR_O}"), ("modern", "rnodern"), ("wow", "vvow"), ("paypal", f"p{CYR_A}yp{CYR_A}l"),
                                 ("apple", f"{CYR_A}ррӏе")])
def test_skeleton_equal_when_they_look_alike(a, b):
    assert H.skeleton(a) == H.skeleton(b) and a != b


@pytest.mark.parametrize("a,b", [("banco", "banca"), ("universal", "universe"), ("ana", "anna")])
def test_skeleton_differs_when_they_do_not(a, b):
    assert H.skeleton(a) != H.skeleton(b)


@pytest.mark.parametrize("text", [LEGIT, "josé.pérez@empresa.com.ar", "Ivan.Perez@x.com", "Info@Empresa.com", "müller@bücher.de", "user01@x.com",
                                  "a-b_c.d+tag@x.com", "ИВАН@почта.рф", "MARIA.LOPEZ@EMPRESA.COM", "IBM.admin@ibm.com", "soporte@ejemplo.com.ar"])
def test_legitimate_addresses_are_not_suspicious(text):
    assert H.inspect(text)["suspicious"] is False


@pytest.mark.parametrize("text,key", [
    (f"banco@b{CYR_A}ncouniversal.gob", "mixed"), (f"s{CYR_O}porte@ejemplo.com.ar", "mixed"), (f"s{GRE_O}porte@ejemplo.com.ar", "mixed"),
    (FAKE_I, "odd_case"), (f"{CYR_A}ррӏе.com", "whole_script"), ("user@exa​mple.com", "invisible"), ("fact‮ura@x.com", "invisible"),
    ("m1ke@x.com", "digit_swap"), ("ａdmin@x.com", "mixed")])
def test_suspicious_addresses_are_flagged(text, key):
    r = H.inspect(text)
    assert r["suspicious"] and r[key]


def test_mixed_script_is_judged_per_word_not_per_address():
    """Un usuario latino en un dominio cirílico (o al revés) no es una mezcla dentro de una palabra."""
    assert H.inspect("ivan@почта.рф")["mixed"] == []


def test_breakdown_gives_code_name_and_script_per_character():
    r = H.inspect(FAKE_I)
    cells, trunc = H.breakdown(FAKE_I, r["flagged"])
    c = cells[14]
    assert (c["ch"], c["code"], c["name"], c["script"], c["flag"]) == ("I", "U+0049", "LATIN CAPITAL LETTER I", "Latino", "ambiguo")
    assert cells[13]["ch"] == "a" and cells[13]["flag"] == "" and not trunc
    assert len(cells) == len(FAKE_I)


def test_breakdown_marks_the_cyrillic_letter():
    t = f"b{CYR_A}nco.com"
    cells, _ = H.breakdown(t, H.inspect(t)["flagged"])
    assert cells[1]["code"] == "U+0430" and cells[1]["name"] == "CYRILLIC SMALL LETTER A" and cells[1]["script"] == "Cirílico"
    assert cells[1]["flag"] == "alfabeto" and cells[1]["looks_like"] == "a"


def test_breakdown_is_capped_and_hides_invisible_characters():
    cells, trunc = H.breakdown("a" * 500)
    assert len(cells) == H.MAX_CHARS and trunc
    assert H.breakdown("a​b")[0][1]["ch"] == "·"


def test_spelled_separates_every_character():
    assert H.spelled("ab.I") == "a b . I"


def test_compare_ignores_case_only_differences():
    assert H.compare("Banco@X.com", "banco@x.com")["kind"] == "igual"


def test_compare_pinpoints_the_changed_character():
    r = H.compare(FAKE_I, LEGIT)
    assert r["kind"] == "parecida" and r["distance"] == 1
    d = r["diffs"][0]
    assert d["pos"] == 15 and d["found"] == "I" and d["expected"] == "l"
    assert d["found_detail"][0]["code"] == "U+0049" and d["expected_detail"][0]["code"] == "U+006C"


def test_compare_cyrillic_substitution():
    r = H.compare(f"b{CYR_A}nco@x.com", "banco@x.com")
    assert r["kind"] == "parecida" and r["diffs"][0]["found_detail"][0]["script"] == "Cirílico"


@pytest.mark.parametrize("found,kind", [("banco.universa@bancouniversal.gob", "casi"), ("otro.usuario@dominio-distinto.com", "distinta")])
def test_compare_non_lookalike_cases(found, kind):
    assert H.compare(found, LEGIT)["kind"] == kind


def test_decode_host_roundtrip():
    host = f"b{CYR_A}ncouniversal.gob"
    ascii_host = host.encode("idna").decode()
    assert ascii_host.startswith("xn--") and H.decode_host(ascii_host) == host and H.ascii_form(host) == ascii_host
    assert H.decode_host("xn--.com") == "xn--.com"          # etiqueta no decodificable: se deja tal cual, sin error


# ---------------------------------------------------------------- en el análisis del correo
def test_user_example_capital_i_is_flagged_and_spelled_out():
    r = run(f"Banco <{FAKE_I}>")
    assert has(r, "Mayúscula inusual") and r["severity"] in ("Medio", "Alto", "Crítico")
    e = r["homograph"]["entries"][0]
    assert e["label"] == "Remitente (From)" and e["value"] == FAKE_I
    assert e["spelled"].startswith("b a n c o . u n i v e r s a I @")
    assert e["chars"][14]["code"] == "U+0049" and e["chars"][14]["flag"] == "ambiguo"
    assert "T1684.001" in r["mitre"]


def test_legitimate_sender_gets_the_breakdown_but_no_alert():
    r = run(f"Banco <{LEGIT}>")
    assert not any(k in t for t in titles(r) for k in ("Alfabetos", "Mayúscula", "imita", "invisible"))
    assert r["homograph"]["suspicious"] is False and len(r["homograph"]["entries"]) == 1
    assert all(not c["flag"] for c in r["homograph"]["entries"][0]["chars"])


def test_expected_address_catches_the_lookalike_as_critical():
    r = run(f"Banco <{FAKE_I}>", expected=LEGIT)
    assert r["severity"] == "Crítico" and has(r, "imita visualmente la dirección esperada")
    ex = r["homograph"]["expected"]
    assert ex["kind"] == "parecida" and ex["diffs"][0]["pos"] == 15
    assert any("posición 15" in s["detail"] and "U+0049" in s["detail"] for s in r["signals"])


def test_expected_address_matching_is_a_favourable_sign():
    r = run(f"Banco <{LEGIT}>", expected="BANCO.UNIVERSAL@bancouniversal.gob")
    assert r["homograph"]["expected"]["kind"] == "igual" and r["severity"] == "Bajo"
    assert any("coincide carácter por carácter" in f for f in r["favorable"])


def test_expected_address_that_is_just_different():
    r = run("Ana <ana@otra-empresa.com>", expected=LEGIT)
    assert r["homograph"]["expected"]["kind"] == "distinta" and has(r, "no es la dirección esperada")


def test_expected_domain_only_compares_the_domain():
    r = run(f"X <ayuda@b{CYR_A}ncouniversal.gob>", expected="bancouniversal.gob")
    assert r["homograph"]["expected"]["compared"].endswith("ncouniversal.gob") and r["homograph"]["expected"]["kind"] == "parecida"


def test_expected_is_bounded():
    r = run(f"Banco <{LEGIT}>", expected="a" * 5000)
    assert len(r["homograph"]["expected"]["expected"]) <= 200


def test_cyrillic_domain_in_sender():
    r = run(f"Soporte <soporte@b{CYR_A}ncouniversal.gob>")
    assert has(r, "Alfabetos mezclados en el remitente") and r["severity"] in ("Alto", "Crítico")
    cell = next(c for c in r["homograph"]["entries"][0]["chars"] if c["flag"])
    assert cell["code"] == "U+0430" and "CYRILLIC" in cell["name"]
    assert any("Cirílico" in n for n in r["homograph"]["entries"][0]["notes"])


def test_cyrillic_letter_in_local_part():
    r = run(f"Mesa <s{CYR_O}porte@ejemplo.com.ar>")
    assert has(r, "Alfabetos mezclados") and any(c["code"] == "U+043E" for c in r["homograph"]["entries"][0]["chars"])


def test_invisible_characters_in_sender():
    r = run("Mesa <so​porte@ejemplo.com.ar>")
    assert has(r, "Caracteres invisibles") and r["severity"] in ("Alto", "Crítico", "Medio")


def test_display_name_with_cyrillic_brand_letter_is_caught():
    r = run(f"Microsoft Security <alertas@dominio-cualquiera.com>".replace("i", "і", 1))
    assert has(r, "Se hace pasar por microsoft") and has(r, "Alfabetos mezclados en el nombre visible")


def test_url_with_cyrillic_host():
    r = run(f"Banco <{LEGIT}>", body=f"Ingrese a https://b{CYR_A}ncouniversal.gob/login ahora.")
    u = r["urls"][0]
    assert "Alfabetos mezclados" in u["flags"] and u["host_ascii"].startswith("xn--") and any(c["code"] == "U+0430" for c in u["host_chars"])
    assert has(r, "Dominio con alfabetos mezclados")


def test_punycode_url_is_decoded_and_judged():
    puny = f"b{CYR_A}ncouniversal.gob".encode("idna").decode()
    r = run(f"Banco <{LEGIT}>", body=f"Ingrese a https://{puny}/login")
    u = r["urls"][0]
    assert u["host_unicode"] == f"b{CYR_A}ncouniversal.gob" and "Alfabetos mezclados" in u["flags"] and "Punycode" in u["flags"]


def test_legit_idn_url_is_only_informational():
    r = run(f"Ana <ana@ejemplo.com.ar>", body="Mira https://bücher.de/libros")
    u = r["urls"][0]
    assert "Dominio con caracteres no ASCII" in u["flags"] and "Alfabetos mezclados" not in u["flags"]
    assert u["host_ascii"] == "xn--bcher-kva.de"
    assert r["severity"] == "Bajo"


def test_reply_to_that_looks_identical_but_is_not():
    r = run(f"Mesa <s{CYR_O}porte@ejemplo.com.ar>", extra="Reply-To: soporte@ejemplo.com.ar\n")
    assert has(r, "Direcciones que se ven iguales pero no lo son") and r["homograph"]["comparisons"]


def test_display_name_address_that_looks_identical():
    r = run(f'"{LEGIT}" <{FAKE_I}>')
    assert has(r, "Direcciones que se ven iguales pero no lo son") and has(r, "El nombre visible muestra otra dirección")


def test_sender_domain_that_imitates_the_recipients_domain_is_critical():
    r = run("Recursos Humanos <rrhh@rniempresa.com.ar>", to="empleado@miempresa.com.ar")
    assert r["severity"] == "Crítico" and has(r, "imita al del destinatario")


def test_same_domain_as_recipient_is_fine():
    r = run("Recursos Humanos <rrhh@miempresa.com.ar>", to="empleado@miempresa.com.ar")
    assert not has(r, "imita al del destinatario")


def test_brand_domain_written_with_cyrillic_letters():
    r = run(f"Aviso <seguridad@p{CYR_A}yp{CYR_A}l.com>")
    assert has(r, "imita a paypal")


@pytest.mark.parametrize("frm", ["José Pérez <josé.pérez@empresa.com.ar>", "Ana <ana@empresa.com.ar>", "María Núñez <maria.nunez@empresa.com.ar>",
                                 "Ivan Petrov <ivan@почта.рф>", "Info <Info@Empresa.com.ar>"])
def test_no_false_positive_on_legitimate_senders(frm):
    r = run(frm, to="equipo@empresa.com.ar", extra="Authentication-Results: mx.empresa.com.ar; spf=pass smtp.mailfrom=empresa.com.ar; dkim=pass header.d=empresa.com.ar; dmarc=pass header.from=empresa.com.ar\n")
    assert r["homograph"]["suspicious"] is False
    assert not any(k in t for t in titles(r) for k in ("Alfabetos", "Mayúscula", "imita", "invisible"))


def test_hostile_long_sender_does_not_break_anything():
    r = run("X <" + "a" * 5000 + "@x.com>")
    e = r["homograph"]["entries"][0]
    assert e["truncated"] and len(e["chars"]) == H.MAX_CHARS and len(e["value"]) <= 200
    json.dumps(r)


def test_result_is_json_serialisable():
    json.dumps(run(f"Banco <{FAKE_I}>", expected=LEGIT))


def test_verify_advice_mentions_comparing_character_by_character():
    r = run(f"Banco <{FAKE_I}>")
    assert any("carácter por carácter" in v for v in r["verify"]) and any("referencia" in x for x in r["limitations"])


# ---------------------------------------------------------------- ejemplos del repositorio
@pytest.mark.parametrize("name,sev", [("06_homografo_I_mayuscula.eml", "Crítico"), ("07_homografo_cirilico_dominio.eml", "Crítico"),
                                      ("08_homografo_cirilico_usuario.eml", "Alto"), ("09_dominio_imita_destinatario_rn.eml", "Crítico"),
                                      ("10_legitimo_con_acentos.eml", "Bajo")])
def test_homograph_samples(name, sev):
    r = P.analyze_eml((DIR / name).read_bytes(), name)
    assert r["severity"] == sev
    assert r["homograph"]["suspicious"] is (sev != "Bajo")


def test_samples_cover_each_kind_of_homograph():
    out = {f.name: P.analyze_eml(f.read_bytes(), f.name) for f in sorted(DIR.glob("*.eml"))}
    assert any(s["title"] == "Mayúscula inusual en el remitente (From)" for s in out["06_homografo_I_mayuscula.eml"]["signals"])
    assert any("Alfabetos mezclados" in s["title"] for s in out["07_homografo_cirilico_dominio.eml"]["signals"])
    assert any("Alfabetos mezclados" in s["title"] for s in out["08_homografo_cirilico_usuario.eml"]["signals"])
    assert any("imita al del destinatario" in s["title"] for s in out["09_dominio_imita_destinatario_rn.eml"]["signals"])
