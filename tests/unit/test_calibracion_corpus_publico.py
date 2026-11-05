"""Falsos positivos hallados al medir correo legítimo del corpus público de SpamAssassin (boletines y listas de correo de 2002-2003).

Dos señales saltaban con correo legítimo: «Dominio que imita a apple» con un subdominio llamado applecore, y «Enlace escrito con entidades HTML numéricas»
con el mailto: escrito con entidades (técnica legítima contra los recolectores de correo). Se fijan aquí, junto con los casos de ataque que no deben perderse.
"""
from email.message import EmailMessage

import pytest

from backend import htmlscan, phishing

BRAND_FP = [("apple", ["applecore", "lockergnome"]), ("apple", ["pineapple", "example"]), ("arca", ["marcaweb", "example"]),
            ("amazon", ["amazonia-viajes", "example"]), ("github", ["githubusercontent-mirror", "example"])]
BRAND_ATTACK = [("apple", ["apple-id-support", "example"]), ("apple", ["appleid", "example"]), ("paypal", ["paypal", "evil"]),
                ("paypal", ["secure-paypal-login", "example"]), ("paypal", ["pay-pal", "example"]), ("microsoft", ["microsoft365-login", "example"]),
                ("paypal", ["login", "paypal", "evil"]), ("amazon", ["amazon", "verify", "example"])]


@pytest.mark.parametrize("brand,labels", BRAND_FP)
def test_brand_word_inside_another_word_is_not_a_lookalike(brand, labels):
    assert not phishing._brand_in_host(brand, labels)


@pytest.mark.parametrize("brand,labels", BRAND_ATTACK)
def test_brand_as_whole_word_or_with_phishing_words_is_still_flagged(brand, labels):
    assert phishing._brand_in_host(brand, labels)


def nument(html_text):
    return any(s["key"] == "nument" for s in htmlscan.scan(html_text)["signals"])


def test_mailto_written_with_entities_is_legitimate_anti_harvesting():
    assert not nument('<a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;ana&#64;example.org">escríbenos</a>')


def test_ampersand_entity_inside_a_normal_url_is_not_obfuscation():
    assert not nument('<a href="http://example.org/p?a=1&#38;b=2&#38;c=3">ver</a>')


@pytest.mark.parametrize("href", ["&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;login-banco.example/verificar", "http://&#101;vil.example/login"])
def test_link_scheme_or_host_hidden_with_entities_is_still_flagged(href):
    assert nument(f'<a href="{href}">Verificar mi cuenta</a>')


def _eml(html_body, sender="Apple Core <news@lockergnome.com>"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "lector@example.org", "Boletín semanal"
    m.set_content("Boletín")
    m.add_alternative(html_body, subtype="html")
    return bytes(m)


def test_newsletter_from_a_subdomain_named_applecore_raises_neither_signal():
    body = ('<html><body><a href="http://applecore.lockergnome.com/issue">Leer</a> <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;a&#64;lockergnome.com">Contacto</a></body></html>')
    titles = [s["title"] for s in phishing.analyze_eml(_eml(body), "b.eml")["signals"]]
    assert not any("imita a apple" in t or "entidades HTML" in t for t in titles)
