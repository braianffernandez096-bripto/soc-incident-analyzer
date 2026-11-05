"""SPF evaluado contra una IP y verificación en DNS del remitente (DNS simulado: nada sale a Internet)."""
import pytest

from backend import phishing, senderreview, spfeval
from backend.domaincheck import DomainNotFound
from tests.unit.test_dominios import Fake, _key

DNS = {
    ("empresa.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 include:_spf.g.com mx -all"],
    ("_spf.g.com", "TXT"): ["v=spf1 ip4:198.51.100.7 ip6:2001:db8::/32 ~all"],
    ("empresa.com", "MX"): ["10 mx.empresa.com."], ("mx.empresa.com", "A"): ["192.0.2.25"],
    ("a.com", "TXT"): ["v=spf1 a:srv.a.com/28 mx/24 -all"], ("srv.a.com", "A"): ["10.1.1.16"], ("a.com", "MX"): ["5 m.a.com"], ("m.a.com", "A"): ["10.9.9.9"],
    ("b.com", "TXT"): ["v=spf1 redirect=a.com"], ("c.com", "TXT"): ["v=spf1 exists:%{i}.x.com -all"], ("d.com", "TXT"): ["v=spf1 include:zz.com -all"],
    ("e.com", "TXT"): ["v=spf1 ~all"], ("f.com", "TXT"): ["v=spf1 ?all"], ("g.com", "TXT"): ["v=spf1 -all", "v=spf1 +all"], ("h.com", "TXT"): ["v=spf1 +all"],
}


@pytest.mark.parametrize("ip,dom,result", [
    ("203.0.113.50", "empresa.com", "pass"), ("198.51.100.7", "empresa.com", "pass"), ("192.0.2.25", "empresa.com", "pass"),
    ("8.8.8.8", "empresa.com", "fail"), ("2001:db8::1", "empresa.com", "pass"), ("::ffff:203.0.113.5", "empresa.com", "pass"),
    ("10.1.1.20", "a.com", "pass"), ("10.1.1.40", "a.com", "fail"), ("10.9.9.77", "a.com", "pass"), ("10.1.1.20", "b.com", "pass"),
    ("1.1.1.1", "e.com", "softfail"), ("1.1.1.1", "f.com", "neutral"), ("1.1.1.1", "h.com", "pass"), ("1.1.1.1", "nope.com", "none"),
])
def test_spf_results(ip, dom, result):
    assert spfeval.evaluate(ip, dom, Fake(DNS))["result"] == result


def test_include_reports_the_deciding_mechanism():
    assert spfeval.evaluate("198.51.100.7", "empresa.com", Fake(DNS))["mechanism"] == "+include:_spf.g.com → +ip4:198.51.100.7"


@pytest.mark.parametrize("dom,result", [("c.com", "unsupported"), ("d.com", "permerror"), ("g.com", "permerror")])
def test_unevaluable_or_broken_records_are_not_guessed(dom, result):
    assert spfeval.evaluate("1.1.1.1", dom, Fake(DNS))["result"] == result


def test_lookup_limit_is_enforced():
    d = {("x.com", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.com" for n in range(12)) + " -all"]}
    for n in range(12):
        d[(f"i{n}.com", "TXT")] = ["v=spf1 ip4:9.9.9.9 ~all"]
    r = spfeval.evaluate("1.1.1.1", "x.com", Fake(d))
    assert r["result"] == "permerror" and "10" in r["note"]


def test_include_loop_does_not_hang():
    d = {("l1.com", "TXT"): ["v=spf1 include:l2.com -all"], ("l2.com", "TXT"): ["v=spf1 include:l1.com -all"]}
    assert spfeval.evaluate("1.1.1.1", "l1.com", Fake(d))["result"] == "permerror"


def test_invalid_ip_and_dns_failure():
    assert spfeval.evaluate("no-es-ip", "empresa.com", Fake(DNS))["result"] == "unsupported"

    class Broken:
        def query(self, *a, **k):
            from backend.dnsdoh import DnsError
            raise DnsError("sin conexión")
    assert spfeval.evaluate("1.1.1.1", "empresa.com", Broken())["result"] == "temperror"


# ---------------------------------------------------------------- correo -> verificación
def mail(spf_ip="198.51.100.77", says_spf="pass", sig="d=empresa.com; s=k1", extra=""):
    return phishing.analyze_eml((
        "Return-Path: <bounce@mail.empresa.com>\n"
        + (f"Received-SPF: {says_spf} (google.com: domain of bounce@mail.empresa.com) client-ip={spf_ip};\n" if spf_ip else "")
        + f"Authentication-Results: mx.google.com; dkim=pass header.s=k1; spf={says_spf} smtp.mailfrom=bounce@mail.empresa.com; dmarc=pass header.from=empresa.com\n"
        + (f"DKIM-Signature: v=1; a=rsa-sha256; {sig}; h=from; bh=x; b=y\n" if sig else "") + extra
        + "From: Soporte <soporte@empresa.com>\nTo: ana@x.com\nSubject: hola\nDate: Mon, 02 Nov 2026 09:00:00 +0000\nMessage-ID: <1@empresa.com>\n\nhola\n").encode())


GOOD = {("empresa.com", "TXT"): ["v=spf1 include:_spf.g.com -all"], ("mail.empresa.com", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
        ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=reject"], ("k1._domainkey.empresa.com", "TXT"): ["v=DKIM1; k=rsa; p=" + _key(2048)],
        ("empresa.com", "MX"): ["10 mx.empresa.com"]}


def by(r, cid):
    return next(c for c in r["checks"] if c["id"] == cid)


def test_item_carries_dkim_selector_client_ip_and_mailfrom():
    m = mail()
    assert m["dkim_sigs"] == [{"d": "empresa.com", "s": "k1", "a": "rsa-sha256"}] and m["spf_ip"] == "198.51.100.77" and m["mailfrom_domain"] == "mail.empresa.com"


def test_consistent_mail_passes_every_check():
    r = senderreview.review(mail(), Fake(GOOD))
    assert by(r, "spf_ip")["status"] == "ok" and by(r, "dkim_firma")["status"] == "ok" and r["grade"] in "AB"


def test_header_says_pass_but_dns_does_not_authorize_is_flagged():
    r = senderreview.review(mail(spf_ip="8.8.8.8"), Fake(GOOD))
    c = by(r, "spf_ip")
    assert c["status"] == "fail" and "no son fiables" in c["detail"]


def test_dkim_selector_that_does_not_exist_is_flagged_even_if_header_claims_pass():
    d = {k: v for k, v in GOOD.items() if k[0] != "k1._domainkey.empresa.com"}
    c = by(senderreview.review(mail(), Fake(d)), "dkim_firma")
    assert c["status"] == "fail" and "no publica ninguna clave" in c["detail"] and "DKIM=pass" in c["detail"]


def test_revoked_and_weak_keys():
    d = {**GOOD, ("k1._domainkey.empresa.com", "TXT"): ["v=DKIM1; k=rsa; p="]}
    assert "revocada" in by(senderreview.review(mail(), Fake(d)), "dkim_firma")["title"]
    d = {**GOOD, ("k1._domainkey.empresa.com", "TXT"): ["v=DKIM1; k=rsa; p=" + _key(512)]}
    assert by(senderreview.review(mail(), Fake(d)), "dkim_firma")["status"] == "warn"


def test_signature_from_another_domain_does_not_prove_the_sender():
    d = {**GOOD, ("k1._domainkey.mailer.net", "TXT"): ["v=DKIM1; k=rsa; p=" + _key(2048)]}
    c = by(senderreview.review(mail(sig="d=mailer.net; s=k1"), Fake(d)), "dkim_firma")
    assert "no demuestra" in c["detail"]


def test_dmarc_none_is_a_domain_risk_not_a_verdict():
    d = {**GOOD, ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=none"]}
    assert by(senderreview.review(mail(), Fake(d)), "dmarc_none")["status"] == "warn"


def test_without_receiver_ip_the_route_ip_is_used_and_says_so_or_nothing_is_checked():
    r = senderreview.review(mail(spf_ip=""), Fake(GOOD))
    assert by(r, "spf_ip")["status"] == "info" and "no trae la IP" in by(r, "spf_ip")["detail"]


def test_mail_without_dkim_signature_and_unknown_domain():
    assert by(senderreview.review(mail(sig=""), Fake(GOOD)), "dkim_firma")["title"] == "El correo no trae firma DKIM"
    with pytest.raises(DomainNotFound):
        senderreview.review(mail(), Fake(nx={"empresa.com"}))


def test_hostile_signature_values_are_ignored():
    m = mail(sig='d=evil.com"; DROP; s=a b')
    assert m["dkim_sigs"] == []
