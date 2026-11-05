"""Herramientas de dominio: DoH (transporte simulado), evaluador SPF/DKIM/DMARC y dominios parecidos. Nada sale a Internet."""
import base64
import json

import httpx
import pytest

from backend import dnsdoh, domaincheck, lookalikes


class Fake:
    """Resolvedor simulado: {(nombre, tipo): [respuestas]}; lo que no está, no tiene datos (status 0, sin respuestas)."""

    def __init__(self, data=None, nx=()):
        self.data, self.nx, self.calls = data or {}, set(nx), []

    def query(self, name, rtype="TXT"):
        self.calls.append((name, rtype))
        if name in self.nx:
            return {"status": 3, "answers": [], "provider": "Fake"}
        return {"status": 0, "answers": list(self.data.get((name, rtype), [])), "provider": "Fake"}


def _key(bits):
    """SubjectPublicKeyInfo RSA mínimo con un módulo de `bits` bits (solo para medir el tamaño)."""
    def tlv(t, v):
        n = len(v)
        ln = bytes([n]) if n < 128 else (b"\x81" + bytes([n]) if n < 256 else b"\x82" + n.to_bytes(2, "big"))
        return bytes([t]) + ln + v
    mod = b"\x00" + b"\xff" * (bits // 8)
    rsa = tlv(0x30, tlv(0x02, mod) + tlv(0x02, b"\x01\x00\x01"))
    alg = tlv(0x30, tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") + b"\x05\x00")
    return base64.b64encode(tlv(0x30, alg + tlv(0x03, b"\x00" + rsa))).decode()


# ------------------------------------------------------------------ dnsdoh
@pytest.mark.parametrize("raw,ok", [("Empresa.COM.ar", "empresa.com.ar"), ("https://empresa.com/ruta?x=1", "empresa.com"), ("juan@empresa.com", "empresa.com"),
                                    ("empresa.com:8080", "empresa.com"), ("bаnco.com", "xn--bnco-53d.com")])
def test_clean_domain_accepts(raw, ok):
    assert dnsdoh.clean_domain(raw) == ok


@pytest.mark.parametrize("raw", ["", "   ", "1.2.3.4", "localhost", "servidor.local", "a b.com", "-x.com", "x..com", "a" * 64 + ".com", "x.123", "mi.intranet"])
def test_clean_domain_rejects(raw):
    with pytest.raises(ValueError):
        dnsdoh.clean_domain(raw)


def test_txt_value_joins_segments():
    assert dnsdoh._txt_value('"v=DKIM1; k=rsa; p=AAA" "BBB"') == "v=DKIM1; k=rsa; p=AAABBB"
    assert dnsdoh._txt_value("sin comillas") == "sin comillas"


def _http(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ans(status=0, data=None, rtype=16):
    return {"Status": status, "Answer": [{"name": "x", "type": rtype, "data": d} for d in (data or [])]}


def test_resolver_parses_cache_and_counts():
    n = []

    def h(req):
        n.append(req.url.params["name"])
        assert req.url.params["type"] == "TXT" and req.headers["accept"] == "application/dns-json"
        return httpx.Response(200, json=_ans(data=['"v=spf1 -all"']))
    r = dnsdoh.DohResolver(http=_http(h))
    a = r.query("Empresa.com", "TXT")
    assert a["answers"] == ["v=spf1 -all"] and a["provider"] == "Cloudflare" and a["status"] == 0
    r.query("empresa.com", "TXT")
    assert len(n) == 1 and r.queries == 1


def test_resolver_filters_other_types_and_strips_dot():
    body = {"Status": 0, "Answer": [{"type": 5, "data": "otro.com."}, {"type": 2, "data": "ns1.x.com."}]}
    r = dnsdoh.DohResolver(http=_http(lambda req: httpx.Response(200, json=body)))
    assert r.query("x.com", "NS")["answers"] == ["ns1.x.com"]


def test_resolver_nxdomain():
    r = dnsdoh.DohResolver(http=_http(lambda req: httpx.Response(200, json={"Status": 3})))
    assert r.query("noexiste.com", "NS") == {"status": 3, "answers": [], "provider": "Cloudflare"}


def test_resolver_falls_back_to_second_provider():
    hosts = []

    def h(req):
        hosts.append(req.url.host)
        return httpx.Response(500) if req.url.host == "cloudflare-dns.com" else httpx.Response(200, json=_ans(data=['"ok"']))
    res = dnsdoh.DohResolver(http=_http(h)).query("x.com")
    assert hosts == ["cloudflare-dns.com", "dns.google"] and res["provider"] == "Google"


@pytest.mark.parametrize("resp", [httpx.Response(200, content=b"no es json"), httpx.Response(200, json=[1]), httpx.Response(200, json={"x": 1}),
                                  httpx.Response(200, content=b"{" + b" " * (dnsdoh.MAX_BODY + 10) + b"}"), httpx.Response(302, headers={"location": "http://evil/"})])
def test_resolver_rejects_bad_answers(resp):
    with pytest.raises(dnsdoh.DnsError):
        dnsdoh.DohResolver(http=_http(lambda req: resp)).query("x.com")


def test_resolver_network_error_is_dnserror():
    def h(req):
        raise httpx.ConnectError("sin red")
    with pytest.raises(dnsdoh.DnsError):
        dnsdoh.DohResolver(http=_http(h)).query("x.com")


def test_resolver_disabled(monkeypatch):
    monkeypatch.setenv("DNS_LOOKUPS", "off")
    assert not dnsdoh.enabled()
    called = []
    r = dnsdoh.DohResolver(http=_http(lambda req: called.append(1) or httpx.Response(200, json={"Status": 0})))
    with pytest.raises(dnsdoh.DnsDisabled):
        r.query("x.com")
    assert not called


def test_resolver_sends_only_domain_name():
    seen = []
    r = dnsdoh.DohResolver(http=_http(lambda req: seen.append(str(req.url)) or httpx.Response(200, json={"Status": 0})))
    r.query("empresa.com", "MX")
    assert seen and all(u.startswith(("https://cloudflare-dns.com/", "https://dns.google/")) for u in seen) and "empresa.com" in seen[0]


def test_resolver_closes_only_own_client():
    c = _http(lambda req: httpx.Response(200, json={"Status": 0}))
    dnsdoh.DohResolver(http=c).close()
    assert not c.is_closed
    own = dnsdoh.DohResolver()
    own.query  # noqa: B018
    own._client()
    own.close()
    assert own._http is None


# ------------------------------------------------------------------ SPF / DMARC / DKIM
def test_parse_spf():
    p = domaincheck.parse_spf("v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all")
    assert p["all"] == "~all" and [m["type"] for m in p["mechanisms"]] == ["ip4", "include", "all"]
    assert domaincheck.parse_spf("v=spf1 redirect=_spf.x.com")["redirect"] == "_spf.x.com"
    assert domaincheck.parse_spf("v=spf1 +all")["all"] == "+all"


def _good():
    return {("empresa.com", "TXT"): ["v=spf1 include:_spf.g.com -all"], ("_spf.g.com", "TXT"): ["v=spf1 ip4:1.1.1.1 -all"],
            ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@empresa.com"], ("empresa.com", "MX"): ["10 mx.empresa.com"],
            ("google._domainkey.empresa.com", "TXT"): ["v=DKIM1; k=rsa; p=" + _key(2048)]}


def _ids(res, status=None):
    return {c["id"]: c for c in res["checks"] if status is None or c["status"] == status}


def test_grade_well_configured_is_a():
    r = domaincheck.grade_domain("empresa.com", Fake(_good()))
    assert r["grade"] == "A" and r["score"] == 100 and not r["recommendations"]
    assert r["dkim"]["found"][0]["bits"] >= 2040 and r["spf"]["lookups"] == 1


def test_grade_missing_everything_is_f():
    r = domaincheck.grade_domain("empresa.com", Fake({("empresa.com", "MX"): ["10 mx.x.com"]}))
    c = _ids(r)
    assert c["spf_presente"]["status"] == "fail" and c["dmarc_presente"]["status"] == "fail" and r["grade"] == "F" and r["score"] == 25
    assert any("v=spf1" in x for x in r["recommendations"])


@pytest.mark.parametrize("spf,pts", [("v=spf1 +all", 35), ("v=spf1 ?all", 20), ("v=spf1 ~all", 5), ("v=spf1 mx", 20)])
def test_spf_all_variants(spf, pts):
    d = _good(); d[("empresa.com", "TXT")] = [spf]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))["spf_all"]["points"] == pts


def test_spf_duplicate_and_ptr_and_lookup_limit():
    d = _good(); d[("empresa.com", "TXT")] = ["v=spf1 -all", "v=spf1 -all"]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))["spf_unico"]["points"] == 30
    d[("empresa.com", "TXT")] = ["v=spf1 ptr " + " ".join(f"include:i{i}.x.com" for i in range(11)) + " -all"]
    for i in range(11):
        d[(f"i{i}.x.com", "TXT")] = ["v=spf1 ip4:1.1.1.1 -all"]
    c = _ids(domaincheck.grade_domain("empresa.com", Fake(d)))
    assert c["spf_lookups"]["status"] == "fail" and c["spf_ptr"]["points"] == 5


def test_spf_include_without_record_and_redirect():
    d = _good(); d[("empresa.com", "TXT")] = ["v=spf1 include:nada.x.com -all"]
    assert "spf_include" in _ids(domaincheck.grade_domain("empresa.com", Fake(d)))
    d[("empresa.com", "TXT")] = ["v=spf1 redirect=_spf.g.com"]
    r = domaincheck.grade_domain("empresa.com", Fake(d))
    assert _ids(r)["spf_all"]["status"] == "info" and r["spf"]["lookups"] == 1


def test_spf_recursion_is_capped():
    d = _good(); d[("empresa.com", "TXT")] = ["v=spf1 include:a0.x.com -all"]
    for i in range(30):
        d[(f"a{i}.x.com", "TXT")] = [f"v=spf1 include:a{i + 1}.x.com -all"]
    f = Fake(d)
    domaincheck.grade_domain("empresa.com", f)
    assert len(f.calls) < 60


@pytest.mark.parametrize("rec,pid,pts", [("v=DMARC1; p=none; rua=mailto:a@b.c", "dmarc_politica", 25), ("v=DMARC1; p=quarantine; rua=mailto:a@b.c", "dmarc_politica", 8),
                                         ("v=DMARC1; p=bogus; rua=mailto:a@b.c", "dmarc_politica", 35), ("v=DMARC1; p=reject; pct=50; rua=mailto:a@b.c", "dmarc_pct", 10),
                                         ("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c", "dmarc_sp", 5), ("v=DMARC1; p=reject", "dmarc_rua", 5)])
def test_dmarc_variants(rec, pid, pts):
    d = _good(); d[("_dmarc.empresa.com", "TXT")] = [rec]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))[pid]["points"] == pts


def test_dmarc_duplicate_and_inherited_from_org_domain():
    d = _good(); d[("_dmarc.empresa.com", "TXT")] = ["v=DMARC1; p=reject", "v=DMARC1; p=none"]
    assert "dmarc_unico" in _ids(domaincheck.grade_domain("empresa.com", Fake(d)))
    d = _good(); del d[("_dmarc.empresa.com", "TXT")]
    d[("_dmarc.empresa.com", "TXT")] = []
    d[("mail.empresa.com", "TXT")] = ["v=spf1 -all"]
    d[("_dmarc.empresa.com", "TXT")] = ["v=DMARC1; p=reject; rua=mailto:d@empresa.com"]
    r = domaincheck.grade_domain("mail.empresa.com", Fake(d))
    assert r["dmarc"]["inherited_from"] == "empresa.com" and _ids(r)["dmarc_presente"]["status"] == "ok"


def test_rsa_bits_and_dkim_findings():
    assert 2040 <= domaincheck.rsa_bits(_key(2048)) <= 2048
    assert 1016 <= domaincheck.rsa_bits(_key(1024)) <= 1024
    assert domaincheck.rsa_bits("%%%") is None and domaincheck.rsa_bits("") is None
    d = _good(); d[("google._domainkey.empresa.com", "TXT")] = ["v=DKIM1; p=" + _key(512)]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))["dkim_clave"]["status"] == "fail"
    d[("google._domainkey.empresa.com", "TXT")] = ["v=DKIM1; p=" + _key(1024)]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))["dkim_clave"]["points"] == 3
    d[("google._domainkey.empresa.com", "TXT")] = ["v=DKIM1; t=y; p=" + _key(2048)]
    assert "dkim_test" in _ids(domaincheck.grade_domain("empresa.com", Fake(d)))
    d[("google._domainkey.empresa.com", "TXT")] = ["v=DKIM1; p="]
    assert _ids(domaincheck.grade_domain("empresa.com", Fake(d)))["dkim_selector"]["status"] == "warn"


def test_dkim_not_found_is_info_without_penalty():
    d = _good(); del d[("google._domainkey.empresa.com", "TXT")]
    r = domaincheck.grade_domain("empresa.com", Fake(d))
    assert _ids(r)["dkim_selector"]["status"] == "info" and r["score"] == 100


def test_nxdomain_and_null_domain():
    with pytest.raises(domaincheck.DomainNotFound):
        domaincheck.grade_domain("noexiste.com", Fake(nx={"noexiste.com"}))
    d = {("parked.com", "TXT"): ["v=spf1 -all"], ("_dmarc.parked.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@parked.com"], ("parked.com", "MX"): ["0 ."]}
    r = domaincheck.grade_domain("parked.com", Fake(d))
    assert r["mx"]["null"] and "dominio_mudo" in _ids(r)


@pytest.mark.parametrize("s,g", [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (60, "C"), (40, "D"), (39, "F"), (0, "F")])
def test_grade_scale(s, g):
    assert domaincheck.grade_of(s) == g


# ------------------------------------------------------------------ dominios parecidos
def test_generate_variants_are_valid_and_cover_kinds():
    v = lookalikes.generate("bancouniversal.gob")
    names = [x["domain"] for x in v]
    assert 50 < len(v) <= lookalikes.MAX_VARIANTS and len(set(names)) == len(names) and "bancouniversal.gob" not in names
    assert {x["kind"] for x in v} >= {"visual", "homografo", "transposicion", "omision", "teclado", "repeticion", "tld", "guion", "palabra"}
    assert all(n.isascii() and all(0 < len(p) < 64 for p in n.split(".")) for n in names)
    idn = [x for x in v if x["kind"] == "homografo"]
    assert idn and all(x["domain"].startswith("xn--") or "xn--" in x["domain"] for x in idn) and all(x["unicode"] and not x["unicode"].isascii() for x in idn)
    assert all(x["kind_label"] and x["note"] for x in v)


def test_generate_orders_by_priority_and_limits():
    v = lookalikes.generate("paypal.com")
    prio = [lookalikes.KINDS[x["kind"]][1] for x in v]
    assert prio == sorted(prio)
    assert any(x["domain"] == "paypa1.com" for x in v) and any(x["domain"] == "paypal.net" for x in v)
    assert len(lookalikes.generate("paypal.com", 5)) == 5 and len(lookalikes.generate("paypal.com", 10_000)) <= lookalikes.MAX_VARIANTS


def test_generate_handles_second_level_suffix_and_short_names():
    v = lookalikes.generate("ejemplo.com.ar")
    assert all(x["domain"].endswith((".ar", ".com", ".net", ".org", ".co", ".io", ".info", ".biz", ".online", ".site", ".xyz", ".top", ".app")) for x in v)
    assert any(x["domain"] == "ejemplo.com" for x in v)
    assert lookalikes.generate("ab.io")  # no falla con etiquetas cortas


def test_check_registered_states():
    d = {("a.com", "NS"): ["ns1.a.com"]}
    f = Fake(d, nx={"b.com"})
    assert lookalikes.check_registered(["a.com", "b.com", "c.com", "a.com"], f) == {"a.com": "registrado", "b.com": "libre", "c.com": "sin_datos"}


def test_check_registered_caps_and_errors(monkeypatch):
    f = Fake()
    out = lookalikes.check_registered([f"d{i}.com" for i in range(200)], f)
    assert len(out) == lookalikes.MAX_CHECK == len(f.calls)

    class Boom:
        def query(self, *a, **k):
            raise dnsdoh.DnsError("x")
    with pytest.raises(dnsdoh.DnsError):
        lookalikes.check_registered(["a.com", "b.com"], Boom())
    monkeypatch.setenv("DNS_LOOKUPS", "off")
    with pytest.raises(dnsdoh.DnsDisabled):
        lookalikes.check_registered(["a.com"], Fake())
