"""Evaluador de la protección de correo de un dominio: SPF, DKIM y DMARC.

Lee los registros DNS públicos del dominio (por DNS sobre HTTPS, ver ``dnsdoh``), revisa cada configuración y da una nota de A a F.
La nota sale de **descuentos fijos y visibles**: cada comprobación indica cuántos puntos resta y por qué. Es una ayuda para
la defensa y el triage, no una auditoría: no evalúa el resto de la seguridad del dominio.
"""
from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .dnsdoh import DnsError
from .phishing import reg_domain

COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "zoho", "mxvault"]
SPF_LOOKUP_LIMIT = 10          # RFC 7208: más de 10 consultas DNS en la evaluación es un error permanente (permerror)
MAX_SPF_FETCHES = 15           # tope propio de consultas para seguir include/redirect (protege al servidor)
MAX_SPF_DEPTH = 5


class DomainNotFound(LookupError):
    """El dominio no existe en el DNS (NXDOMAIN)."""


def _check(cid: str, title: str, status: str, points: int, detail: str, fix: str = "") -> dict:
    return {"id": cid, "title": title, "status": status, "points": points, "detail": detail, "fix": fix}


# ---------------------------------------------------------------- SPF
def spf_records(txts: list[str]) -> list[str]:
    return [t for t in txts if re.match(r"^v=spf1(\s|$)", t.strip(), re.I)]


def parse_spf(record: str) -> dict:
    mechs, redirect, all_q = [], "", ""
    for term in record.split()[1:]:
        mod = re.match(r"^(redirect|exp)=(.*)$", term, re.I)
        if mod:                                  # modificadores: solo «redirect» cambia la evaluación
            if mod.group(1).lower() == "redirect":
                redirect = mod.group(2).lower().rstrip(".")
            continue
        q = "+"
        if term[:1] in "+-~?":
            q, term = term[0], term[1:]
        kind, _, arg = term.partition(":")
        kind = kind.lower()
        if kind == "all":
            all_q = q
        mechs.append({"q": q, "type": kind, "arg": arg.lower().rstrip(".")})
    return {"mechanisms": mechs, "redirect": redirect, "all": f"{all_q}all" if all_q else ""}


def _count_lookups(parsed: dict, resolver, depth: int, state: dict) -> None:
    """Cuenta las consultas DNS que exige evaluar el SPF y sigue include/redirect (con tope propio)."""
    targets = []
    for m in parsed["mechanisms"]:
        if m["type"] in ("include", "a", "mx", "ptr", "exists"):
            state["n"] += 1
            if m["type"] == "include" and m["arg"]:
                targets.append(m["arg"])
    if parsed["redirect"]:
        state["n"] += 1
        targets.append(parsed["redirect"])
    for t in targets:
        if depth >= MAX_SPF_DEPTH or state["fetched"] >= MAX_SPF_FETCHES:
            state["truncated"] = True
            continue
        state["fetched"] += 1
        res = resolver.query(t, "TXT")
        recs = spf_records(res["answers"])
        if not recs:
            state["problems"].append(f"«{t}» no publica un registro SPF")
        elif len(recs) > 1:
            state["problems"].append(f"«{t}» publica más de un registro SPF")
        else:
            _count_lookups(parse_spf(recs[0]), resolver, depth + 1, state)


def _grade_spf(domain: str, txts: list[str], resolver) -> tuple[list[dict], dict]:
    checks: list[dict] = []
    recs = spf_records(txts)
    info = {"record": recs[0] if recs else "", "records": len(recs), "all": "", "lookups": 0, "problems": []}
    if not recs:
        checks.append(_check("spf_presente", "SPF publicado", "fail", 35, "El dominio no publica ningún registro SPF: cualquiera puede enviar correo diciendo ser este dominio sin que el receptor lo detecte.",
                             f"Publica un TXT en {domain} como «v=spf1 include:<tu proveedor de correo> -all»."))
        return checks, info
    if len(recs) > 1:
        checks.append(_check("spf_unico", "Un solo registro SPF", "fail", 30, f"Hay {len(recs)} registros SPF. Con más de uno el resultado es un error permanente y muchos receptores lo ignoran.",
                             "Une todos los orígenes en un único registro «v=spf1 …»."))
    else:
        checks.append(_check("spf_presente", "SPF publicado", "ok", 0, "Hay un registro SPF."))
    parsed = parse_spf(recs[0])
    info["all"] = parsed["all"]
    kind = parsed["all"]
    if kind == "-all":
        checks.append(_check("spf_all", "Termina en «-all»", "ok", 0, "Rechaza lo que no está autorizado (-all): es la política más estricta."))
    elif kind == "~all":
        checks.append(_check("spf_all", "Termina en «~all» (softfail)", "warn", 5, "Marca como sospechoso lo no autorizado pero no lo rechaza. Es habitual mientras se ajusta el registro.",
                             "Cuando confirmes que todos los orígenes legítimos están incluidos, cambia «~all» por «-all»."))
    elif kind == "?all":
        checks.append(_check("spf_all", "Termina en «?all» (neutral)", "warn", 20, "«?all» no dice nada sobre lo no autorizado: no protege.", "Termina el registro con «-all» (o «~all» mientras ajustas)."))
    elif kind == "+all":
        checks.append(_check("spf_all", "Termina en «+all»", "fail", 35, "«+all» autoriza a CUALQUIER servidor a enviar como este dominio: anula la protección de SPF.", "Reemplaza «+all» por «-all»."))
    elif parsed["redirect"]:
        checks.append(_check("spf_all", "Delega con «redirect»", "info", 0, f"El registro delega la decisión en {parsed['redirect']}."))
    else:
        checks.append(_check("spf_all", "Sin «all» ni «redirect» al final", "warn", 20, "El registro no termina en una política: lo no listado queda como neutral.", "Termina el registro con «-all»."))
    state = {"n": 0, "fetched": 0, "problems": [], "truncated": False}
    try:
        _count_lookups(parsed, resolver, 0, state)
    except DnsError:
        state["problems"].append("no se pudo seguir algún include")
    info["lookups"], info["problems"] = state["n"], state["problems"]
    if state["n"] > SPF_LOOKUP_LIMIT:
        checks.append(_check("spf_lookups", "Dentro del límite de 10 consultas DNS", "fail", 25, f"Evaluar el registro exige {state['n']} consultas DNS; el máximo es {SPF_LOOKUP_LIMIT}. Pasado el límite, SPF falla con permerror.",
                             "Quita includes que ya no uses o reemplázalos por rangos ip4/ip6."))
    else:
        checks.append(_check("spf_lookups", "Dentro del límite de 10 consultas DNS", "ok", 0, f"Exige {state['n']} consultas DNS{' (se siguieron los include hasta el tope de la herramienta)' if state['truncated'] else ''}; el máximo es {SPF_LOOKUP_LIMIT}."))
    for p in state["problems"]:
        checks.append(_check("spf_include", "Include sin registro SPF", "warn", 5, f"{p[0].upper() + p[1:]}: ese include no aporta nada o provoca un error.", "Corrige o elimina ese include."))
    if any(m["type"] == "ptr" for m in parsed["mechanisms"]):
        checks.append(_check("spf_ptr", "Usa el mecanismo «ptr»", "warn", 5, "«ptr» está desaconsejado (RFC 7208): es lento y poco fiable.", "Reemplázalo por ip4/ip6 o include."))
    return checks, info


# ---------------------------------------------------------------- DMARC
def parse_tags(record: str) -> dict:
    out = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip()
    return out


def dmarc_records(txts: list[str]) -> list[str]:
    return [t for t in txts if re.match(r"^v=DMARC1\s*(;|$)", t.strip(), re.I)]


def _grade_dmarc(domain: str, resolver) -> tuple[list[dict], dict]:
    checks: list[dict] = []
    info = {"record": "", "records": 0, "policy": "", "inherited_from": "", "pct": 100, "rua": "", "sp": "", "adkim": "", "aspf": ""}
    recs = dmarc_records(resolver.query(f"_dmarc.{domain}", "TXT")["answers"])
    org = reg_domain(domain)
    if not recs and org != domain:
        recs = dmarc_records(resolver.query(f"_dmarc.{org}", "TXT")["answers"])
        if recs:
            info["inherited_from"] = org
    info["records"] = len(recs)
    if not recs:
        checks.append(_check("dmarc_presente", "DMARC publicado", "fail", 40, "No hay registro DMARC: el dominio no le dice a los receptores qué hacer con el correo falsificado, y el phishing que lo imita llega sin freno.",
                             f"Empieza con un TXT en _dmarc.{domain}: «v=DMARC1; p=none; rua=mailto:dmarc@{domain}» y sube la política cuando los informes estén limpios."))
        return checks, info
    if len(recs) > 1:
        checks.append(_check("dmarc_unico", "Un solo registro DMARC", "fail", 30, f"Hay {len(recs)} registros DMARC: con más de uno, los receptores lo ignoran.", "Deja un único registro «v=DMARC1; …»."))
    tags = parse_tags(recs[0])
    info.update(record=recs[0], policy=tags.get("p", "").lower(), sp=tags.get("sp", "").lower(), rua=tags.get("rua", ""), adkim=tags.get("adkim", "r"), aspf=tags.get("aspf", "r"))
    try:
        info["pct"] = int(tags.get("pct", "100"))
    except ValueError:
        info["pct"] = 100
    where = f" (heredado de {info['inherited_from']})" if info["inherited_from"] else ""
    checks.append(_check("dmarc_presente", "DMARC publicado", "ok", 0, f"Hay un registro DMARC{where}."))
    p = info["policy"]
    if p == "reject":
        checks.append(_check("dmarc_politica", "Política «reject»", "ok", 0, "Los receptores rechazan el correo que falla DMARC: es la política más fuerte."))
    elif p == "quarantine":
        checks.append(_check("dmarc_politica", "Política «quarantine»", "warn", 8, "El correo que falla DMARC va a spam. Es buena; «reject» es la meta final.", "Cuando los informes estén limpios, pasa a «p=reject»."))
    elif p == "none":
        checks.append(_check("dmarc_politica", "Política «none» (solo monitoreo)", "warn", 25, "«p=none» solo informa: no frena el correo falsificado.", "Pasa a «p=quarantine» y luego a «p=reject» cuando los informes estén limpios."))
    else:
        checks.append(_check("dmarc_politica", "Política inválida o ausente", "fail", 35, f"La etiqueta p= no tiene un valor válido ({p or 'vacía'}): el registro se ignora.", "Usa p=none, p=quarantine o p=reject."))
    if p in ("quarantine", "reject") and info["pct"] < 100:
        checks.append(_check("dmarc_pct", "Se aplica a todo el correo (pct=100)", "warn", 10, f"pct={info['pct']}: la política solo se aplica a ese porcentaje del correo; el resto pasa sin controlar.", "Sube pct a 100 cuando estés seguro."))
    if info["sp"] == "none" and p in ("quarantine", "reject"):
        checks.append(_check("dmarc_sp", "Subdominios protegidos", "warn", 5, "sp=none deja los subdominios sin protección aunque el dominio principal la tenga.", "Quita sp o usa el mismo valor que p."))
    if not info["rua"]:
        checks.append(_check("dmarc_rua", "Recibe informes agregados (rua)", "warn", 5, "Sin «rua» no recibes informes: no te enteras de quién envía correo en nombre de tu dominio.", f"Agrega «rua=mailto:dmarc@{org}»."))
    else:
        checks.append(_check("dmarc_rua", "Recibe informes agregados (rua)", "ok", 0, "Hay una dirección para los informes agregados."))
    return checks, info


# ---------------------------------------------------------------- DKIM
def _der(data: bytes, pos: int = 0) -> tuple[int, int, int]:
    """(etiqueta, inicio del contenido, longitud) de un elemento DER."""
    tag, ln = data[pos], data[pos + 1]
    pos += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln, pos = int.from_bytes(data[pos:pos + n], "big"), pos + n
    return tag, pos, ln


def rsa_bits(p_b64: str) -> int | None:
    """Tamaño aproximado de una clave RSA publicada en DKIM (None si no se puede leer o no es RSA)."""
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", p_b64), validate=False)
        _, s, _ = _der(raw)                      # SubjectPublicKeyInfo
        _, a, al = _der(raw, s)                  # AlgorithmIdentifier
        t, b, bl = _der(raw, a + al)             # BIT STRING
        if t != 0x03:
            return None
        _, c, _ = _der(raw, b + 1)               # RSAPublicKey (tras el byte de relleno)
        t, d, dl = _der(raw, c)                  # módulo
        if t != 0x02:
            return None
        mod = raw[d:d + dl].lstrip(b"\x00")
        return len(mod) * 8 - (8 - mod[0].bit_length()) if mod else None
    except (IndexError, ValueError):
        return None


def _grade_dkim(domain: str, resolver) -> tuple[list[dict], dict]:
    def probe(sel: str):
        res = resolver.query(f"{sel}._domainkey.{domain}", "TXT")
        recs = [t for t in res["answers"] if re.search(r"(^|;)\s*(v=DKIM1|p=)", t, re.I)]
        return sel, recs[0] if recs else ""
    with ThreadPoolExecutor(max_workers=6) as ex:
        found = [(s, r) for s, r in ex.map(probe, COMMON_SELECTORS) if r]
    info = {"tried": COMMON_SELECTORS, "found": []}
    checks: list[dict] = []
    for sel, rec in found:
        tags = parse_tags(rec)
        key = tags.get("p", "")
        bits = None if tags.get("k", "rsa").lower() == "ed25519" else rsa_bits(key) if key else None
        info["found"].append({"selector": sel, "revoked": not key, "bits": bits, "algorithm": tags.get("k", "rsa").lower(), "testing": "y" in tags.get("t", "").lower().split(":")})
    live = [f for f in info["found"] if not f["revoked"]]
    if not info["found"]:
        checks.append(_check("dkim_selector", "Clave DKIM encontrada", "info", 0, "No se encontró ninguna clave con los selectores más comunes. Eso NO prueba que no exista: cada proveedor usa su propio selector.",
                             "Revisa el selector real en la cabecera DKIM-Signature (campo s=) de un correo enviado por el dominio."))
    elif not live:
        checks.append(_check("dkim_selector", "Clave DKIM encontrada", "warn", 5, "Las claves encontradas están revocadas (p= vacío).", "Publica una clave vigente o elimina el registro."))
    else:
        checks.append(_check("dkim_selector", "Clave DKIM encontrada", "ok", 0, "Selectores con clave: " + ", ".join(f["selector"] for f in live) + "."))
    weak = [f for f in live if f["bits"] and f["bits"] < 1024]
    mid = [f for f in live if f["bits"] and 1024 <= f["bits"] < 2048]
    if weak:
        checks.append(_check("dkim_clave", "Claves DKIM de 2048 bits", "fail", 10, "Hay claves de menos de 1024 bits (" + ", ".join(f"{f['selector']}: ~{f['bits']}" for f in weak) + "): se pueden romper.", "Genera una clave RSA de 2048 bits y rota la actual."))
    elif mid:
        checks.append(_check("dkim_clave", "Claves DKIM de 2048 bits", "warn", 3, "Hay claves de 1024 bits (" + ", ".join(f["selector"] for f in mid) + "): aceptables hoy pero con poco margen.", "Rota a una clave RSA de 2048 bits."))
    elif live and any(f["bits"] for f in live):
        checks.append(_check("dkim_clave", "Claves DKIM de 2048 bits", "ok", 0, "Las claves RSA encontradas son de 2048 bits o más."))
    if any(f["testing"] for f in live):
        checks.append(_check("dkim_test", "DKIM fuera de modo de prueba", "warn", 3, "Hay claves con t=y (modo de prueba): los receptores no deben tratar un fallo como definitivo.", "Quita la etiqueta t=y cuando termines de probar."))
    return checks, info


# ---------------------------------------------------------------- MX y nota final
def _grade_mx(domain: str, resolver) -> tuple[dict, bool]:
    res = resolver.query(domain, "MX")
    mx = [m for m in res["answers"]]
    null_mx = len(mx) == 1 and re.match(r"^0\s*\.?$", mx[0].strip()) is not None
    return {"records": mx[:10], "null": null_mx}, bool(mx) and not null_mx


def grade_of(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def grade_domain(domain: str, resolver) -> dict:
    """Evalúa SPF, DKIM y DMARC de ``domain`` (ya validado con ``dnsdoh.clean_domain``). ``resolver.query(name, tipo)`` hace las consultas."""
    apex = resolver.query(domain, "TXT")
    if apex["status"] == 3:
        raise DomainNotFound(f"El dominio «{domain}» no existe en el DNS (NXDOMAIN).")
    spf_checks, spf = _grade_spf(domain, apex["answers"], resolver)
    dmarc_checks, dmarc = _grade_dmarc(domain, resolver)
    dkim_checks, dkim = _grade_dkim(domain, resolver)
    mx, receives = _grade_mx(domain, resolver)
    checks = spf_checks + dmarc_checks + dkim_checks
    sends_nothing = False
    if spf["record"] and not receives and spf["all"] == "-all":
        sends_nothing = not any(m["type"] in ("include", "a", "mx", "ip4", "ip6") for m in parse_spf(spf["record"])["mechanisms"])
    if sends_nothing and dmarc["policy"] == "reject":
        checks.append(_check("dominio_mudo", "Dominio que no envía ni recibe correo", "ok", 0, "No tiene MX, su SPF es «v=spf1 -all» y DMARC es reject: está bien protegido contra suplantación."))
    score = max(0, 100 - sum(c["points"] for c in checks))
    recs: list[str] = []
    for c in sorted(checks, key=lambda c: -c["points"]):
        if c["fix"] and c["status"] in ("fail", "warn", "info") and c["fix"] not in recs:
            recs.append(c["fix"])
    return {"domain": domain, "grade": grade_of(score), "score": score, "checks": checks, "spf": spf, "dmarc": dmarc, "dkim": dkim, "mx": mx,
            "recommendations": recs, "provider": apex.get("provider", ""), "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "scale": [{"grade": "A", "from": 90}, {"grade": "B", "from": 75}, {"grade": "C", "from": 60}, {"grade": "D", "from": 40}, {"grade": "F", "from": 0}],
            "limitations": ["La nota resume solo SPF, DKIM y DMARC. No evalúa MTA-STS, TLS-RPT, BIMI ni la seguridad del resto del dominio.",
                            "DKIM solo se busca con los selectores más comunes: no encontrarlo no prueba que no exista.",
                            "Los registros se leen por DNS sobre HTTPS desde un servidor público y pueden estar en caché unos minutos.",
                            "La nota es orientativa y refleja la configuración en el momento de la consulta."]}
