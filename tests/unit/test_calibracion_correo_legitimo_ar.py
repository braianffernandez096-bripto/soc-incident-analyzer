"""Falsos positivos hallados con correo legítimo real de bancos, billeteras y boletines en Argentina (19 correos aportados por el autor; no se publican).

Se reproducen aquí con correos sintéticos: tres causas, más los ataques parecidos que no deben dejar de detectarse.
"""
import pytest

from backend import phishing as P
from tests.unit.test_phishing import has, mail

AUTH = "mx.corp.example; spf=pass smtp.mailfrom=b.example; dkim=pass header.d=b.example; dmarc=pass header.from=b.example"


def run(**kw):
    return P.analyze_eml(mail(**kw), "t.eml")


@pytest.mark.parametrize("host", ["mail.galicia.ar", "galicia.gedco.com.ar", "www.galicia.com.ar"])
def test_known_domains_of_the_bank_are_not_lookalikes(host):
    r = run(frm=f"Galicia <aviso@{host}>", body="Hola", html=f'<a href="https://{host}/x">Ver</a>', auth=AUTH.replace("b.example", host))
    assert not has(r, "Se hace pasar por galicia") and not has(r, "imita a galicia")


def test_galicia_under_another_domain_is_still_flagged():
    r = run(frm="Galicia <aviso@galicia.cuentas-seguras.example>", html='<a href="https://galicia.cuentas-seguras.example/x">Ver</a>')
    assert has(r, "galicia")


def test_tracking_link_through_a_known_sending_platform_is_not_deception():
    html = '<a href="https://nts.embluemail.com/p/cl?s=abc">https://smn.gob.ar/alertas</a>'
    assert not has(run(frm="Gobierno <hola@comunicacion.example.gob.ar>", html=html, auth=AUTH), "muestra otro dominio")


@pytest.mark.parametrize("text", [
    "Aprendé qué son los tokens y los prompts de la inteligencia artificial.",
    "Tu billetera virtual ahora es más clara: mirá cómo se mueve tu plata.",
    "Verificá tu cuenta desde la app. Tu billetera sigue igual.",
])
def test_ordinary_use_of_wallet_or_token_words_is_not_a_crypto_bait(text):
    assert not has(run(body=text, html=f'<p>{text}</p><a href="https://corp.example/x">ver</a>'), "criptoactivos")


@pytest.mark.parametrize("text", [
    "Claim your tokens now before the airdrop ends.",
    "Validate your wallet to keep your account active.",
    "Reclamá tus tokens: conectá tu billetera.",
    "Migrate your wallet to the new network.",
])
def test_crypto_bait_is_still_flagged(text):
    assert has(run(body=text, html=f'<p>{text}</p><a href="https://corp.example/x">ver</a>'), "criptoactivos")


# ---- texto con alfabetos mezclados dentro de las palabras (phishing real recibido en una cuenta de Hotmail, enviado por un servicio legítimo de encuestas)
CYR = "асоер"        # а с о е р: parecen a c o e p


def test_body_words_mixing_latin_and_cyrillic_are_flagged():
    body = f"N{CYR[3]}w {CYR[0]}{CYR[1]}{CYR[1]}{CYR[2]}unt {CYR[0]}ctivity is r{CYR[3]}ady. Ch{CYR[3]}{CYR[1]}k y{CYR[2]}ur b{CYR[0]}lance."
    r = run(body=body, html=f"<p>{body}</p><a href='https://corp.example/x'>ver</a>")
    assert has(r, "letras de otro alfabeto mezcladas dentro de las palabras")


@pytest.mark.parametrize("text", ["Hola, esto es un texto normal con acentos: canción, año.", "Привет, это обычное сообщение на русском языке.",
                                  "Compra en MercadoLibre y pagá con Mercado Pago, ñandú."])
def test_normal_text_in_any_language_is_not_flagged_for_mixed_alphabets(text):
    assert not has(run(body=text), "alfabeto mezcladas")
