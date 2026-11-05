"""Verificación en DNS del remitente de un correo ya analizado: ¿lo que dicen las cabeceras coincide con lo que publica el dominio?

Usa datos del propio correo para no depender de adivinar: el selector de la firma DKIM (``s=``) y la IP que el servidor receptor evaluó
en SPF. Compara lo que el correo AFIRMA (Authentication-Results, que escribe el receptor) con lo que HOY publica el DNS. Una diferencia no
prueba una falsificación (el DNS pudo cambiar desde que llegó el mensaje), pero es justo lo que un analista debe revisar.

Solo salen consultas DNS con nombres de dominio: ni la IP, ni el correo, ni su contenido.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import spfeval
from .dnsdoh import DnsError
from .domaincheck import DomainNotFound, _check, grade_domain, parse_tags, rsa_bits

MAX_SELECTORS = 3
SPF_TEXT = dict(zip(("pass", "fail", "softfail", "neutral", "none"),
                    ("autoriza", "NO autoriza (-all)", "NO autoriza (~all)", "no se pronuncia (?all)", "no publica SPF")))


def _dkim_probe(resolver, d: str, s: str) -> dict:
    res = resolver.query(f"{s}._domainkey.{d}", "TXT")
    recs = [t for t in res["answers"] if "p=" in t.lower() or "v=dkim1" in t.lower()]
    if not recs:
        return {"d": d, "s": s, "found": False, "revoked": False, "bits": None}
    tags = parse_tags(recs[0])
    key = tags.get("p", "")
    bits = None if tags.get("k", "rsa").lower() == "ed25519" else (rsa_bits(key) if key else None)
    return {"d": d, "s": s, "found": True, "revoked": not key, "bits": bits}


def review(item: dict, resolver) -> dict:
    """Devuelve {domain, grade, score, checks, spf, dkim, ...}. Lanza DomainNotFound/DnsError si el dominio no existe o el DNS falla."""
    from_dom = (item["headers"].get("from_addr", "").rsplit("@", 1)[-1] or "").lower()
    if not from_dom:
        raise DomainNotFound("El correo no tiene un dominio de remitente que verificar.")
    sigs = (item.get("dkim_sigs") or [])[:MAX_SELECTORS]
    claimed = item.get("auth") or {}
    checks: list[dict] = []

    grade = grade_domain(from_dom, resolver, selectors=[g["s"] for g in sigs if g["d"] == from_dom])
    checks.append(_check("nota", f"Protección del dominio {from_dom}", "info", 0, f"Nota {grade['grade']} ({grade['score']}/100) por SPF, DKIM y DMARC."))
    if grade["dmarc"]["policy"] in ("", "none"):
        checks.append(_check("dmarc_none", "DMARC sin política efectiva", "warn", 0,
                             f"{from_dom} no pide rechazar ni poner en cuarentena lo que falle: cualquiera puede suplantarlo y el mensaje llega igual.",
                             "Es un riesgo del dominio, no una prueba de que este correo sea falso."))

    # ---- DKIM: ¿existe la clave de la firma que trae el correo? ------------------------------
    dkim = []
    for g in sigs:
        p = _dkim_probe(resolver, g["d"], g["s"])
        dkim.append(p)
        who = f"{g['s']}._domainkey.{g['d']}"
        if not p["found"]:
            checks.append(_check("dkim_firma", "La clave de la firma DKIM no existe", "fail", 0,
                                 f"El correo está firmado con d={g['d']} s={g['s']}, pero {who} no publica ninguna clave: esa firma no puede verificarse hoy."
                                 + (" El correo dice DKIM=pass: o el registro se retiró después, o la cabecera no es fiable." if claimed.get("dkim") == "pass" else "")))
        elif p["revoked"]:
            checks.append(_check("dkim_firma", "La clave de la firma DKIM está revocada", "fail", 0, f"{who} existe pero con p= vacío: ya no valida firmas."))
        else:
            weak = p["bits"] and p["bits"] < 1024
            checks.append(_check("dkim_firma", "La clave de la firma DKIM existe", "warn" if weak else "ok", 0,
                                 f"{who} publica una clave" + (f" RSA de ~{p['bits']} bits" if p["bits"] else "") + ("; es débil." if weak else ".")
                                 + (f" La firma es de {g['d']}, que no es el dominio visible ({from_dom}): no demuestra que el remitente sea quien dice." if g["d"] != from_dom
                                    and not from_dom.endswith("." + g["d"]) and not g["d"].endswith("." + from_dom) else "")))
    if not sigs:
        checks.append(_check("dkim_firma", "El correo no trae firma DKIM", "info", 0, "No hay cabecera DKIM-Signature: no hay clave que comprobar."))

    # ---- SPF: ¿el dominio autoriza hoy la IP que evaluó el receptor? --------------------------
    ip = item.get("spf_ip") or ""
    ip_source = "la que registró el servidor receptor"
    if not ip:
        ip, ip_source = item.get("origin_ip") or "", "el primer salto público del recorrido (puede no ser la que evaluó el receptor)"
    mailfrom = item.get("mailfrom_domain") or from_dom
    spf = None
    if ip:
        spf = spfeval.evaluate(ip, mailfrom, resolver)
        r = spf["result"]
        head = f"{ip} frente al SPF de {mailfrom} ({ip_source})"
        if r in ("pass", "fail", "softfail", "neutral", "none"):
            says = claimed.get("spf", "")
            mism = (says == "pass" and r != "pass") or (says in ("fail", "softfail") and r == "pass")
            status = "ok" if r == "pass" and not mism else "fail" if (r in ("fail", "softfail") or mism) else "warn"
            detail = f"{head}: el dominio {SPF_TEXT[r]} esa IP" + (f" (mecanismo {spf['mechanism']})." if spf["mechanism"] else ".")
            if mism:
                detail += (f" Pero las cabeceras del correo dicen SPF={says}. Esa diferencia significa que las cabeceras no son fiables, que el DNS cambió desde que llegó el mensaje "
                           "o que se evaluó otra IP: conviene comprobarlo en el servidor de correo.")
            checks.append(_check("spf_ip", "SPF frente a la IP de origen", status, 0, detail))
        else:
            checks.append(_check("spf_ip", "SPF frente a la IP de origen", "info", 0, f"{head}: no se pudo evaluar ({r}). {spf['note']}"))
    else:
        checks.append(_check("spf_ip", "SPF frente a la IP de origen", "info", 0, "El correo no trae la IP de origen (ni en las cabeceras del receptor ni en el recorrido): no se puede comprobar SPF."))

    return {"domain": from_dom, "mailfrom": mailfrom, "grade": grade["grade"], "score": grade["score"], "checks": checks, "spf": spf, "dkim": dkim,
            "ip": ip, "claimed": {k: claimed.get(k, "") for k in ("spf", "dkim", "dmarc")}, "queries": getattr(resolver, "queries", 0),
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "limitations": ["Compara con el DNS de HOY: si el dominio cambió su configuración después de que llegó el correo, puede haber diferencias legítimas.",
                            "No verifica la firma DKIM (no se tiene el cuerpo original byte a byte): comprueba que la clave exista y su tamaño.",
                            "SPF no evalúa macros, exists ni ptr; si el registro los usa, se indica."]}
