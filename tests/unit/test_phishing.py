"""Módulo de phishing: cada señal con su caso positivo y su caso negativo, adjuntos, robustez y seguridad del .eml."""
import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from backend import attack, phishing as P

DIR = Path(__file__).parents[2] / "sample_data" / "correos"
AUTH_OK = "mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"


def mail(frm="Ana <ana@corp.example>", subject="Hola", body="Texto simple.", html=None, headers=None, attachments=(), auth=AUTH_OK):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = frm, "user@corp.example", subject, "Mon, 02 Nov 2026 09:00:00 +0000", "<1@corp.example>"
    if auth:
        m["Authentication-Results"] = auth
    for k, v in (headers or {}).items():
        del m[k]
        m[k] = v
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data, sub in attachments:
        m.add_attachment(data, maintype="application", subtype=sub, filename=name)
    return bytes(m)


def run(**kw):
    return P.analyze_eml(mail(**kw), "t.eml")


def titles(r):
    return [s["title"] for s in r["signals"]]


def has(r, text):
    return any(text in t for t in titles(r))


# ---------------------------------------------------------------- ejemplos del repositorio
@pytest.mark.parametrize("name,sev,floor", [
    ("01_factura_adjunto_pdf_exe.eml", "Crítico", 12), ("02_enlace_enganoso_microsoft.eml", "Crítico", 12),
    ("03_suplantacion_banco_gmail.eml", "Alto", 6), ("04_documento_con_macros.eml", "Alto", 6), ("05_legitimo_interno.eml", "Bajo", 0)])
def test_sample_emails_get_the_expected_severity(name, sev, floor):
    r = P.analyze_eml((DIR / name).read_bytes(), name)
    assert r["severity"] == sev and r["score"] >= floor


def test_legitimate_sample_has_no_signals_no_iocs_no_mitre():
    r = P.analyze_eml((DIR / "05_legitimo_interno.eml").read_bytes(), "x")
    assert r["signals"] == [] and r["iocs"] == [] and r["mitre"] == []
    assert r["favorable"] == ["SPF = pass", "DKIM = pass", "DMARC = pass"] and r["verdict"] == "Sin señales relevantes"


def test_analyze_many_orders_by_severity_and_reports_bad_files():
    out = P.analyze_many([("ok.eml", (DIR / "05_legitimo_interno.eml").read_bytes()), ("mal.eml", b"esto no es un correo"),
                          ("mal2.eml", (DIR / "01_factura_adjunto_pdf_exe.eml").read_bytes())])
    assert [i["severity"] for i in out["items"]] == ["Crítico", "Bajo"] and out["items"][0]["id"] == "MAIL-01"
    assert out["errors"][0]["filename"] == "mal.eml"


def test_every_technique_in_the_samples_is_in_the_official_data():
    known = attack.data()["techniques"]
    for f in DIR.glob("*.eml"):
        assert all(t in known for t in P.analyze_eml(f.read_bytes(), f.name)["mitre"]), f.name


# ---------------------------------------------------------------- encabezados (positivo y negativo)
def test_reply_to_other_domain_vs_same_domain():
    assert has(run(headers={"Reply-To": "x@otro.example"}), "Reply-To de otro dominio")
    assert not has(run(headers={"Reply-To": "ventas@corp.example"}), "Reply-To")


def test_display_name_with_a_different_address():
    assert has(run(frm='"jefe@corp.example" <malo@evil.example>'), "nombre visible muestra otra dirección")
    assert not has(run(frm='"ana@corp.example" <ana@corp.example>'), "nombre visible muestra otra dirección")


def test_brand_impersonation_depends_on_the_real_domain():
    assert has(run(frm='"PayPal Soporte" <x@pagos-rapidos.example>'), "Se hace pasar por paypal")
    assert not has(run(frm='"PayPal" <service@paypal.com>'), "Se hace pasar")


def test_free_mail_with_an_official_looking_name():
    assert has(run(frm='"Soporte Técnico" <ayuda@gmail.com>'), "Cuenta gratuita")
    assert not has(run(frm='"Marta Pérez" <marta@gmail.com>'), "Cuenta gratuita")


def test_auth_results_fail_softfail_and_pass():
    bad = run(headers={"Authentication-Results": "mx; spf=fail smtp.mailfrom=corp.example; dkim=fail header.d=corp.example; dmarc=fail header.from=corp.example"})
    assert has(bad, "DMARC falló") and has(bad, "SPF falló") and has(bad, "DKIM falló") and bad["severity"] in ("Alto", "Crítico")
    assert has(run(headers={"Authentication-Results": "mx; spf=softfail smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"}), "softfail")
    good = run()
    assert not any(s["category"] == "Autenticación" for s in good["signals"]) and good["severity"] == "Bajo"


def test_pass_that_is_not_aligned_is_flagged_unless_dmarc_passes():
    # sin DMARC en «pass», un SPF válido de otro dominio no prueba nada
    r = run(headers={"Authentication-Results": "mx; spf=pass smtp.mailfrom=bulk.example; dkim=none; dmarc=none header.from=corp.example"})
    assert has(r, "SPF pasa pero no se alinea")
    # con DMARC en «pass» una de las dos ya está alineada: la otra es ruido de envíos masivos (medido con correo legítimo real)
    r = run(headers={"Authentication-Results": "mx; spf=pass smtp.mailfrom=bulk.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"})
    assert not has(r, "SPF pasa pero no se alinea")


def test_missing_auth_headers_is_low_severity_only():
    r = P.analyze_eml(mail(auth=None), "t.eml")
    assert has(r, "Sin resultados de SPF") and r["severity"] == "Bajo"


def test_origin_is_the_oldest_public_hop():
    r = run(headers={"Received": "from a ([10.0.0.5]) by b; Mon, 02 Nov 2026 09:00:00 +0000"})
    assert r["origin_ip"] == ""
    m = mail().replace(b"Message-ID", b"Received: from x.example ([203.0.113.9]) by mx; Mon, 02 Nov 2026 08:59:00 +0000\nReceived: from mx ([10.0.0.5]) by gw; Mon, 02 Nov 2026 08:59:30 +0000\nMessage-ID", 1)
    assert P.analyze_eml(m, "t.eml")["origin_ip"] == "203.0.113.9"


# ---------------------------------------------------------------- URL (positivo y negativo)
def url_flags(url, text="", html=True):
    body = f'<a href="{url}">{text}</a>' if html else url
    r = run(html=f"<html><body>{body}</body></html>") if html else run(body=body)
    return [f for u in r["urls"] for f in u["flags"]], r


@pytest.mark.parametrize("url,flag", [
    ("http://203.0.113.5/login", "IP en vez de dominio"), ("https://bit.ly/abc123", "Acortador"),
    ("https://xn--pypal-4ve.example/", "Punycode"), ("https://banco.com@evil.example/x", "Usuario en la URL"),
    ("https://login.paypal.com.evil.example/", "Suplanta paypal"), ("https://paypa1.com/login", "Parecido a paypal"),
    ("https://descarga.top/x", "TLD .top"), ("http://sitio.example/", "Sin HTTPS")])
def test_url_signals_fire(url, flag):
    flags, _ = url_flags(url)
    assert flag in flags


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://login.microsoftonline.com/", "https://mail.google.com/mail",
                                 "https://intranet.corp.example/agenda", "https://www.mercadolibre.com.ar/ofertas", "https://docs.corp.example/a?b=1"])
def test_legitimate_urls_are_not_flagged(url):
    flags, r = url_flags(url)
    assert flags == [] and r["severity"] == "Bajo"


def test_link_text_that_shows_another_domain():
    flags, _ = url_flags("https://evil.example/x", "https://www.banco.com/ingresar")
    assert "Texto engañoso" in flags
    flags, _ = url_flags("https://www.banco.com/x", "Ingresar a banco.com")
    assert "Texto engañoso" not in flags


def test_dangerous_schemes_and_forms():
    flags, r = url_flags("javascript:alert(1)", "clic")
    assert "Esquema peligroso" in flags and has(r, "esquema")
    r = run(html='<form action="https://colector.example/p"><input name=x></form>')
    assert has(r, "Formulario")


def test_urls_are_defanged_and_never_active():
    r = run(body="mira https://sitio.example/ruta?x=1 ahora")
    u = r["urls"][0]
    assert u["defanged"] == "hxxps://sitio[.]example/ruta?x=1" and "http" not in u["defanged"].replace("hxxp", "")


def test_url_list_is_capped():
    r = run(body=" ".join(f"https://s{i}.example/p" for i in range(200)))
    assert len(r["urls"]) <= P.MAX_URLS and r["truncated"]


def test_anchor_text_and_adjacent_blocks_do_not_glue_into_fake_urls():
    r = run(html='<p><a href="https://a.example/x">https://a.example/x</a></p><p><a href="https://b.example/y">Ver más</a></p>')
    assert [u["host"] for u in r["urls"]] == ["a.example", "b.example"]


# ---------------------------------------------------------------- adjuntos (positivo y negativo)
def _zip(names, encrypt=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    data = bytearray(b.getvalue())
    if encrypt:
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            while i != -1:
                data[i + off] |= 1
                i = data.find(sig, i + 1)
    return bytes(data)


def att(name, data, sub="octet-stream"):
    return run(attachments=[(name, data, sub)])


def test_double_extension_and_executables():
    assert has(att("factura.pdf.exe", b"MZ" + b"\0" * 30), "Doble extensión")
    assert has(att("setup.exe", b"MZ" + b"\0" * 30), "ejecutable o script")
    assert has(att("run.js", b"alert(1)"), "ejecutable o script")


def test_executable_content_with_a_document_name():
    r = att("informe.pdf", b"MZ\x90" + b"\0" * 40)
    assert has(r, "Ejecutable disfrazado") and r["severity"] == "Crítico"


def test_real_documents_are_not_flagged():
    assert att("a.pdf", b"%PDF-1.4\n%%EOF\n", "pdf")["signals"] == []
    assert att("foto.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 20, "png")["signals"] == []
    assert att("notas.txt", b"hola", "plain")["signals"] == []


def test_wrong_file_type_for_pdf_and_image_names():
    assert has(att("a.pdf", b"esto no es un pdf"), "no es un PDF")
    assert has(att("foto.jpg", _zip(["a.txt"])), "no coincide con la extensión")


def test_macro_documents():
    assert has(att("plan.docm", _zip(["word/document.xml"])), "macros habilitadas")
    r = att("plan.docx", _zip(["word/document.xml", "word/vbaProject.bin"]))
    assert has(r, "macros VBA")
    assert not has(att("plan.docx", _zip(["word/document.xml"])), "macros")


def test_archives_encrypted_and_with_executables():
    assert has(att("datos.zip", _zip(["a.txt"], encrypt=True)), "protegido con contraseña")
    r = att("datos.zip", _zip(["leeme.txt", "instalar.exe"]))
    assert has(r, "contiene ejecutables")
    assert not has(att("datos.zip", _zip(["a.txt", "b.csv"])), "contiene ejecutables")


def test_pdf_with_active_content_and_html_attachment():
    assert has(att("f.pdf", b"%PDF-1.7\n<< /OpenAction << /S /JavaScript >> >>", "pdf"), "contenido activo")
    assert has(att("p.html", b"<html><form></form></html>", "html"), "HTML/SVG")


def test_attachment_hash_is_sha256_and_nothing_is_decompressed():
    data = _zip(["a.txt"])
    r = att("d.zip", data)
    import hashlib
    assert r["attachments"][0]["sha256"] == hashlib.sha256(data).hexdigest() and r["attachments"][0]["size"] == len(data)


# ---------------------------------------------------------------- contenido
def test_urgency_credentials_and_enable_content_text():
    assert has(run(body="Es URGENTE, verifica tu cuenta ahora."), "urgencia") and has(run(body="Es URGENTE, verifica tu cuenta ahora."), "verificar la cuenta")
    assert has(run(body="Por favor habilite el contenido para ver el documento."), "habilitar contenido")
    r = run(body="Hola, adjunto el acta de la reunión.")
    assert not any(s["category"] == "Contenido" for s in r["signals"])


# ---------------------------------------------------------------- robustez y seguridad
def test_rejects_non_mail_oversize_and_garbage():
    with pytest.raises(P.EmlError):
        P.analyze_eml(b"hola, esto es solo texto", "x.eml")
    with pytest.raises(P.EmlError):
        P.analyze_eml(b"\x00\x01\x02" * 100, "x.eml")
    with pytest.raises(P.EmlError, match="5 MB"):
        P.analyze_eml(b"From: a@b.example\n\n" + b"x" * (P.MAX_EML_BYTES + 1), "x.eml")


def test_control_and_direction_override_characters_are_stripped():
    r = run(subject="Factura‮gpj.exe\x07 urgente", frm='"Ana‮" <ana@corp.example>')
    assert "‮" not in r["headers"]["subject"] and "\x07" not in r["headers"]["subject"] and "‮" not in r["headers"]["from_name"]


def test_markup_in_fields_is_returned_as_data_not_interpreted():
    r = run(subject="<script>alert(1)</script>", html="<html><script>alert(2)</script><p>hola</p></html>")
    assert r["headers"]["subject"] == "<script>alert(1)</script>"      # el frontend lo escapa; aquí solo viaja como texto


def test_malformed_headers_and_dates_do_not_crash():
    raw = b"From: <<<>>>\nTo:\nSubject: =?utf-8?q?x?=\nDate: ayer a la tarde\nReceived: basura\nMessage-ID: sin-arroba\n\ncuerpo"
    r = P.analyze_eml(raw, "x.eml")
    assert r["severity"] in ("Bajo", "Medio") and r["headers"]["date"] == "ayer a la tarde"


def test_analysis_makes_no_network_calls(monkeypatch):
    import socket

    def prohibido(*a, **k):
        raise AssertionError("el análisis de un .eml no debe abrir conexiones")
    monkeypatch.setattr(socket, "socket", prohibido)
    monkeypatch.setattr(socket, "create_connection", prohibido)
    monkeypatch.setattr(socket, "getaddrinfo", prohibido)
    data = (DIR / "02_enlace_enganoso_microsoft.eml").read_bytes()
    assert P.analyze_eml(data, "x")["severity"] == "Crítico"


def test_iocs_for_reputation_have_only_the_expected_shapes():
    items = P.analyze_many([(f.name, f.read_bytes()) for f in sorted(DIR.glob("*.eml"))])["items"]
    iocs = P.all_iocs(items)
    assert {i["type"] for i in iocs} <= {"IP", "URL/URI", "SHA256"}
    assert not any(i["type"] == "SHA256" and len(i["value"]) != 64 for i in iocs)
    legit = next(i for i in items if i["severity"] == "Bajo")
    assert all(x["value"] not in [i["value"] for i in iocs] for x in legit["iocs"])


def test_defang_helper():
    assert P.defang("http://a.b.example/x") == "hxxp://a[.]b[.]example/x"
    assert P.reg_domain("a.b.empresa.com.ar") == "empresa.com.ar" and P.reg_domain("x.y.example.com") == "example.com"
