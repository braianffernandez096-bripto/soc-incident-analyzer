"""Casos tomados de correos y comandos públicos reales (phishing_pot, Atomic Red Team) que la herramienta no resolvía bien.

Cada prueba reproduce el patrón con datos mínimos escritos a mano: no se incluyen muestras reales (son maliciosas y pesadas).
"""
from email.message import EmailMessage

import pytest

from backend import deobf, homograph, phishing as P

AUTH = "mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"


def mail(frm="Ana <ana@corp.example>", subject="Hola", body="Texto.", html=None, auth=AUTH):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = frm, "u@corp.example", subject, "Mon, 02 Nov 2026 09:00:00 +0000", "<1@corp.example>"
    if auth:
        m["Authentication-Results"] = auth
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return P.analyze_eml(bytes(m), "t.eml")


def titles(r):
    return [s["title"] for s in r["signals"]]


def has(r, text):
    return any(text in t for t in titles(r))


# ---- bug real: una plantilla sin rellenar rompía el análisis del correo entero (ValueError de urlparse)
@pytest.mark.parametrize("href", ["http://[placeholder_1]/x", "http://[::1/x", "https://[bad host]/"])
def test_malformed_url_does_not_crash_the_analysis(href):
    r = mail(html=f'<a href="{href}">Ver</a>')
    assert r["severity"] in ("Bajo", "Medio", "Alto", "Crítico")


def test_unfilled_template_link_is_not_called_obfuscated():
    r = mail(html='<a href="{{{ pm:unsubscribe }}}">Baja</a>')
    assert not has(r, "URL con ofuscación")


# ---- IP en octal y decimal, vistas en phishing real
def test_real_world_octal_and_decimal_ip_links_are_resolved():
    for host, ip in (("0137.0323.0053.0062", "95.211.43.50"), ("010036057335", "64.120.94.221")):
        r = mail(html=f'<a href="http://{host}/4SVKhG13096">Ver</a>')
        assert has(r, "URL con ofuscación") and r["urls"][0]["host"] == ip


# ---- nombres visibles con caracteres que no se ven
@pytest.mark.parametrize("name", ["Tr\U000e0139u\U000e0139st Wallet", "Apܿplܿe ID", "E͏q͏u͏i͏p͏e"])
def test_invisible_marks_inside_display_name_are_flagged(name):
    assert has(mail(frm=f'"{name}" <x@mailer.example>'), "Caracteres invisibles")


@pytest.mark.parametrize("name", ["❤️ Meet-Seniors", "⚠️ Aviso", "José Pérez", "ขอบคุณ ครับ", "Café Müller"])
def test_emoji_selectors_accents_and_other_scripts_are_not_flagged(name):
    assert not has(mail(frm=f'"{name}" <x@mailer.example>'), "Caracteres invisibles")


def test_variation_selector_helper():
    assert homograph.is_invisible("\U000e0100") and not homograph.is_invisible("️") and not homograph.is_invisible("é")


# ---- marcas muy suplantadas que faltaban
@pytest.mark.parametrize("name,dom", [("Ledger", "cleario.app"), ("Trust Wallet", "trustwallet-nanoweb3.com"), ("MetaMask-Team", "seedphroz.firebaseapp.com"),
                                      ("Kraken Support", "cashia.com"), ("Banco Bradesco", "bradesco"), ("Correios", "correios")])
def test_impersonated_brand_in_display_name(name, dom):
    assert has(mail(frm=f"{name} <noreply@{dom}>", auth=None), "Se hace pasar por")


@pytest.mark.parametrize("name,dom", [("Ledger", "ledger.com"), ("Kraken", "kraken.com"), ("Ana Pérez", "gmail.com"), ("Solidworks Team", "solidworks.com"), ("Chase Morgan", "corp.example")])
def test_real_brand_domain_or_unrelated_name_is_not_flagged(name, dom):
    assert not has(mail(frm=f"{name} <x@{dom}>"), "Se hace pasar por")


# ---- estafas sin enlaces y cebo cripto
SCAM = ("Dear beloved friend, I am the widow of the late chairman. I inherited $8,500,000 and want to donate it to charity. "
        "Please reply to my private email so my lawyer can transfer the funds.")


def test_advance_fee_scam_without_links():
    assert has(mail(body=SCAM, frm="Mrs Ana <ana123@gmail.com>", auth=None), "estafa de adelanto de pago")


def test_ordinary_text_is_not_an_advance_fee_scam():
    assert not has(mail(body="Hola, adjunto el acta de la reunión y la donación al comedor de la escuela. Responde cuando puedas."), "estafa")


def test_crypto_claim_lure_needs_a_link():
    body = "Your wallet is eligible: claim your tokens in the airdrop."
    assert has(mail(body=body, html=f"<p>{body}</p><a href='https://claim.example/x'>Claim</a>"), "reclamar o validar criptoactivos")
    assert not has(mail(body=body), "reclamar o validar criptoactivos")


# ---- comandos reales de Atomic Red Team
def test_format_operator_obfuscation_is_resolved():
    cmd = """&("{0}{2}{3}{1}{4}" -f'In','SiO','vOKe-EXp','ReS','n') (gc x)"""
    r = deobf.command(cmd)
    assert "InvOKe-EXpReSSiOn" in r["text"] and deobf.reveals(cmd, r)


def test_character_array_command_is_revealed():
    cmd = "$ps = [char[]](112,111,119,101,114,115,104,101,108,108)\n& (-join $ps) '-Command' calc"
    assert deobf.reveals(cmd, deobf.command(cmd)) and "powershell" in deobf.command(cmd)["text"]


def test_powershell_escapes_and_format_strings_are_not_corrupted():
    cmd = '$header = $Title + "`r`n" + ("=" * $Title.Length) + "`r`n"'
    r = deobf.command(cmd)
    assert "`r`n" in r["text"] and not deobf.reveals(cmd, r)
    assert deobf.command("Write-Host -f'nv'")["text"] == "Write-Host -f'nv'"


# ---- falsos positivos medidos con 20 correos legítimos reales (boletines, LinkedIn, GitHub, cursos…): 14 de 20 salían como Medio o más
ESP_AUTH = "mx.corp.example; spf=pass smtp.mailfrom=bounce.sendgrid.net; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"


def test_bulk_mail_with_dmarc_pass_is_not_penalized_for_misalignment():
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = "Cursos <info@corp.example>", "u@corp.example", "Novedades", "Mon, 02 Nov 2026 09:00:00 +0000", "<abc@mail.esp-bulk.example>"
    m["Authentication-Results"] = ESP_AUTH
    m["Return-Path"] = "<bounce+8812@bounce.sendgrid.net>"
    m.set_content("Hola, estas son las novedades del mes.")
    r = P.analyze_eml(bytes(m), "t.eml")
    assert r["severity"] == "Bajo" and not has(r, "no se alinea") and not has(r, "Message-ID de otro") and not has(r, "Return-Path de otro")


def test_misalignment_still_counts_when_dmarc_does_not_pass():
    assert has(mail(auth="mx; spf=pass smtp.mailfrom=bulk.example; dkim=none; dmarc=fail header.from=corp.example"), "SPF pasa pero no se alinea")


def test_own_click_tracking_is_not_a_deceptive_link():
    r = mail(html='<a href="https://track.corp.example/c/abc">youtu.be/g6SECS3RLho</a>')
    assert not has(r, "El texto del enlace muestra otro dominio")


def test_own_domain_tracking_is_not_trusted_when_the_link_talks_about_billing():
    # así se abusó una plataforma de envío real: el texto promete billing.spotify.com y el enlace pasa por el dominio del remitente
    r = mail(html='<a href="https://email.corp.example/c/abc">https://billing.spotify.com/account/payment/update</a>')
    assert has(r, "El texto del enlace muestra otro dominio")


def test_known_bulk_sender_tracker_is_low_signal_unless_sensitive():
    assert has(mail(html='<a href="https://u123.ct.sendgrid.net/ls/click?x=1">www.corp.example/blog</a>'), "Enlace de seguimiento de un servicio de envío")
    assert has(mail(html='<a href="https://u123.ct.sendgrid.net/ls/click?x=1">https://login.microsoft.com/verify</a>'), "El texto del enlace muestra otro dominio")


def test_newsletter_preheader_padding_is_not_obfuscation_but_split_words_are():
    pad = "<div style='display:none'>Resumen " + "‌­͏ " * 40 + "</div><p>Hola</p>"
    assert not has(mail(html=pad), "invisibles")
    split = "<p>" + " ".join("pa​ypal" for _ in range(6)) + "</p>"
    assert has(mail(html=split), "invisibles dentro de palabras")


def test_bounce_addresses_with_digits_are_not_lookalikes():
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = "LinkedIn <jobs@corp.example>", "u@corp.example", "Alertas", "Mon, 02 Nov 2026 09:00:00 +0000", "<1@corp.example>"
    m["Return-Path"] = "<bounces-0l1o@corp.example>"
    m.set_content("Hola")
    assert not has(P.analyze_eml(bytes(m), "t.eml"), "Cifra que imita una letra en el Return-Path")
