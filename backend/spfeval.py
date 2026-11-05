"""Evaluación de SPF (RFC 7208) de una IP contra el registro de un dominio, leído por DNS sobre HTTPS.

Responde a la pregunta «¿este dominio autoriza a esta IP a enviar correo?». Implementa ip4, ip6, a, mx, include, redirect y all con sus
calificadores y prefijos, y respeta el límite de 10 consultas DNS. No implementa macros (``%{i}``), ``exists`` ni ``ptr`` (desaconsejado):
si el registro los necesita, el resultado es «no evaluable» y se dice por qué, en lugar de adivinar.
"""
from __future__ import annotations

import ipaddress
import re

from .dnsdoh import DnsError
from .domaincheck import parse_spf, spf_records

LOOKUP_LIMIT = 10
MAX_DEPTH = 6
MAX_MX_HOSTS = 10
QUALIFIER = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


class _Stop(Exception):
    def __init__(self, result: str, note: str) -> None:
        self.result, self.note = result, note


def _ip(text: str):
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def _net(arg: str, default: int, ip):
    """Red de un mecanismo ip4/ip6 o de un registro A: «1.2.3.0/24», «1.2.3.4»."""
    base, _, plen = arg.partition("/")
    try:
        return ipaddress.ip_network(f"{base}/{plen or default}", strict=False)
    except ValueError:
        return None


def _in(ip, net) -> bool:
    return net is not None and ip.version == net.version and ip in net


class _Eval:
    def __init__(self, ip, resolver) -> None:
        self.ip, self.resolver, self.lookups, self.trace = ip, resolver, 0, []

    def _count(self) -> None:
        self.lookups += 1
        if self.lookups > LOOKUP_LIMIT:
            raise _Stop("permerror", f"El registro exige más de {LOOKUP_LIMIT} consultas DNS (límite del RFC 7208).")

    def _addrs(self, name: str) -> list:
        out = []
        for rtype in ("A", "AAAA"):
            for a in self.resolver.query(name, rtype)["answers"]:
                ip = _ip(a)
                if ip:
                    out.append(ip)
        return out

    def _match_host(self, name: str, cidr4: int, cidr6: int) -> bool:
        for a in self._addrs(name):
            if _in(self.ip, _net(str(a), cidr4 if a.version == 4 else cidr6, a)):
                return True
        return False

    @staticmethod
    def _cidrs(arg: str) -> tuple[str, int, int]:
        """«dominio/24//64» → (dominio, 24, 64); cualquier parte puede faltar."""
        m = re.fullmatch(r"(?P<host>[^/]*)(?:/(?P<c4>\d{1,2}))?(?://(?P<c6>\d{1,3}))?", arg)
        if not m or int(m.group("c4") or 0) > 32 or int(m.group("c6") or 0) > 128:
            raise _Stop("permerror", f"Prefijo inválido en «{arg}».")
        return m.group("host"), int(m.group("c4") or 32), int(m.group("c6") or 128)

    def check(self, domain: str, depth: int) -> tuple[str, str]:
        """(resultado, mecanismo que decidió). Los errores se propagan como _Stop."""
        if depth > MAX_DEPTH:
            raise _Stop("permerror", "Demasiados niveles de include/redirect.")
        res = self.resolver.query(domain, "TXT")
        recs = spf_records(res["answers"])
        if not recs:
            return "none", ""
        if len(recs) > 1:
            raise _Stop("permerror", f"{domain} publica más de un registro SPF.")
        if "%" in recs[0]:
            raise _Stop("unsupported", f"El registro de {domain} usa macros SPF (%{{…}}), que esta herramienta no evalúa.")
        parsed = parse_spf(recs[0])
        self.trace.append(f"{domain}: {recs[0]}")
        for m in parsed["mechanisms"]:
            kind, arg, q = m["type"], m["arg"], QUALIFIER[m["q"]]
            label = f"{m['q']}{kind}" + (f":{arg}" if arg else "")
            hit = False
            if kind == "all":
                hit = True
            elif kind in ("ip4", "ip6"):
                hit = _in(self.ip, _net(arg, 32 if kind == "ip4" else 128, self.ip))
            elif kind in ("a", "mx"):
                self._count()
                host, c4, c6 = self._cidrs(arg)
                target = host or domain
                if kind == "a":
                    hit = self._match_host(target, c4, c6)
                else:
                    for mx in [x.split()[-1].rstrip(".") for x in self.resolver.query(target, "MX")["answers"]][:MAX_MX_HOSTS]:
                        if self._match_host(mx, c4, c6):
                            hit = True
                            break
            elif kind == "include":
                self._count()
                sub, via = self.check(arg, depth + 1)
                if sub == "none":
                    raise _Stop("permerror", f"El include «{arg}» no publica un registro SPF.")
                hit = sub == "pass"
                if hit:
                    label = f"{label} → {via}" if via else label
            elif kind in ("exists", "ptr"):
                raise _Stop("unsupported", f"El registro de {domain} usa «{kind}», que esta herramienta no evalúa.")
            if hit:
                return q, label
        if parsed["redirect"]:
            self._count()
            return self.check(parsed["redirect"], depth + 1)
        return "neutral", ""


def evaluate(ip: str, domain: str, resolver) -> dict:
    """{result, mechanism, lookups, note, trace}. result: pass, fail, softfail, neutral, none, permerror, temperror o unsupported."""
    addr = _ip(ip)
    if addr is None:
        return {"result": "unsupported", "mechanism": "", "lookups": 0, "note": "La IP de origen no es válida.", "trace": []}
    ev = _Eval(addr, resolver)
    try:
        result, mech = ev.check(domain, 0)
        note = ""
    except _Stop as stop:
        result, mech, note = stop.result, "", stop.note
    except DnsError as exc:
        result, mech, note = "temperror", "", str(exc)
    return {"result": result, "mechanism": mech, "lookups": ev.lookups, "note": note, "trace": ev.trace[:12]}
