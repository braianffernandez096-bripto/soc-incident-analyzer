"""Triaje asistido por IA: una recomendación por incidente para que el analista L1/L2 la confirme o la descarte.

Principios (los mismos que el resto del proyecto):
- La severidad la fija el motor y la IA nunca la cambia. El triaje es una opinión aparte, con motivos y evidencia.
- La recomendación del motor (``baseline``) existe siempre: sin IA, o si el modelo falla o alucina, es la que se muestra.
- Toda cita a un Log_ID o IP que no exista en el archivo (o que no pertenezca al incidente) se descarta y se cuenta.
- Si el motor marca el incidente como Crítico/Alto (o con señales de abuso: varios hallazgos, IP externa) y la IA propone ser MENOS exigente, se conserva la recomendación del motor,
  se marca el conflicto y se muestra lo que sugirió la IA: bajar la guardia es una decisión humana, no del modelo.
- La decisión del analista (escalar / descartar / seguir investigando) es lo único que cierra el triaje.
"""
from __future__ import annotations

from typing import Callable

import pandas as pd

from . import ai as ai_mod
from . import detection as D

RECOMMENDATIONS = ("Escalar", "Probable falso positivo", "Falta información")
CONFIDENCE = ("Alta", "Media", "Baja")
DECISIONS = ("Escalado", "Descartado", "En investigación")
RANK = {"Escalar": 2, "Falta información": 1, "Probable falso positivo": 0}
NOTE_MAX = 500
MAX_CONSECUTIVE_FAILS = 3

TRIAGE_TOOL = {
    "name": "submit_triage",
    "description": "Entrega la recomendación de triaje del incidente para que un analista la confirme o la descarte.",
    "input_schema": {
        "type": "object",
        "properties": {
            "recommendation": {"type": "string", "enum": list(RECOMMENDATIONS),
                               "description": "Escalar = parece un ataque real que requiere respuesta; Probable falso positivo = la evidencia es compatible con actividad legítima; "
                                              "Falta información = con estos logs no se puede decidir."},
            "confidence": {"type": "string", "enum": list(CONFIDENCE)},
            "reasons": {"type": "array", "items": {"type": "string"},
                        "description": "2 a 4 motivos concretos, cada uno apoyado en hechos de la evidencia (cita Log_ID)."},
            "evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "Log_ID de la evidencia que respalda la recomendación."},
            "would_change_if": {"type": "string", "description": "Qué dato nuevo o prueba te haría cambiar de opinión (una frase concreta)."},
        },
        "required": ["recommendation", "confidence", "reasons", "evidence_ids", "would_change_if"],
    },
}

TRIAGE_PROMPT = ("Eres el primer filtro de triaje de un SOC. Un analista humano revisará tu recomendación; no decides la severidad "
                 "(la fijó el motor de reglas) ni cierras el incidente. Recomienda una de: Escalar, Probable falso positivo, Falta información. "
                 "Usa SOLO los hechos del bloque <incidente>: no inventes Log_ID, IP, cuentas ni hechos. Si la evidencia es compatible con actividad "
                 "administrativa legítima y no hay señales de abuso, dilo; si falta contexto (por ejemplo no hay resultado de un acceso), pide información. "
                 "Los motivos deben ser concretos y citar Log_ID; indica qué dato te haría cambiar de opinión.")


# --------------------------------------------------------------------------- recomendación del motor
def _incident_findings(analysis: dict, inc: dict) -> list[dict]:
    ids = set(inc["finding_ids"])
    return [f for f in analysis["findings"] if f["id"] in ids]


def _incident_evidence(analysis: dict, inc: dict) -> list[str]:
    seen: dict[str, None] = {}
    for f in _incident_findings(analysis, inc):
        for e in f["evidence_ids"]:
            seen.setdefault(e)
    return list(seen)


def baseline(analysis: dict, inc: dict) -> dict:
    """Recomendación determinista a partir de la severidad del motor y del peso de la evidencia."""
    fs = _incident_findings(analysis, inc)
    ev = _incident_evidence(analysis, inc)
    sev = inc["severity"]
    strong = len(fs) >= 2 or bool(inc["external_ips"])
    if sev == "Crítico":
        rec, conf = "Escalar", "Alta"
    elif sev == "Alto":
        rec, conf = "Escalar", "Alta" if strong and len(fs) >= 2 else "Media"
    elif sev == "Medio":
        rec, conf = "Falta información", "Media"
    else:
        rec, conf = "Probable falso positivo", "Media"
    reasons = [f"El motor clasificó el incidente como {sev} ({D.pl(len(fs), 'hallazgo', 'hallazgos')}, {D.pl(len(ev), 'evento', 'eventos')} de evidencia)."]
    for f in sorted(fs, key=lambda x: {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3}.get(x["severity"], 4))[:3]:
        why = (f.get("reasons") or [f["title"]])[0]
        cite = ", ".join(f["evidence_ids"][:3])
        reasons.append(f"{f['id']} · {f['title']}: {why}" + (f" (evidencia: {cite})" if cite else ""))
    change = {"Escalar": "Que el responsable de la cuenta o del equipo confirme que la actividad fue autorizada (cambio, tarea de mantenimiento o prueba).",
              "Falta información": "Contexto del propietario del sistema o logs adicionales (resultado de los accesos, proceso padre, tráfico asociado) que confirmen o descarten abuso.",
              "Probable falso positivo": "Cualquier evidencia de acceso exitoso, movimiento lateral o ejecución no autorizada asociada a la misma cuenta o IP."}[rec]
    return {"incident_id": inc["id"], "recommendation": rec, "confidence": conf, "reasons": reasons, "evidence_ids": ev[:6],
            "would_change_if": change, "source": "motor", "ia_sugirio": None, "conflicto": False, "difiere": False}


# --------------------------------------------------------------------------- IA
def _payload(analysis: dict, df: pd.DataFrame, inc: dict, base: dict) -> dict:
    fs = _incident_findings(analysis, inc)
    rows = ai_mod.rows_for(df, _incident_evidence(analysis, inc)[:10])
    return {
        "incidente": {"id": inc["id"], "titulo_motor": inc["title"], "severidad_motor": inc["severity"], "inicio": inc["time_start"], "fin": inc["time_end"],
                      "cuentas": inc["actor_users"], "ips_externas": inc["external_ips"], "hosts": inc["hosts"], "tacticas": inc["tactics"]},
        "hallazgos": [{"finding_id": f["id"], "regla": f["rule"], "titulo": f["title"], "severidad_motor": f["severity"],
                       "motivos_severidad": f["reasons"][:4], "mitre_orientativo": f["mitre"]} for f in fs],
        "evidencia": [ai_mod._slim_row(r) for r in rows],
        "recomendacion_del_motor": {"recomendacion": base["recommendation"], "confianza": base["confidence"]},
    }


def has_abuse_signals(analysis: dict, inc: dict) -> bool:
    """Señales de que el incidente no es ruido: gravedad Crítica/Alta, varios hallazgos relacionados, una IP externa o un hallazgo Alto/Crítico."""
    fs = _incident_findings(analysis, inc)
    return (inc["severity"] in ("Crítico", "Alto") or len(fs) >= 2 or bool(inc["external_ips"])
            or any(f["severity"] in ("Crítico", "Alto") for f in fs))


def _review(raw: dict, base: dict, allowed: set[str], ver: ai_mod.Verifier, inc: dict, protected: bool = False) -> dict:
    """Valida la respuesta del modelo. Devuelve el ítem final (con la IA o con el respaldo del motor)."""
    rec = raw.get("recommendation")
    conf = raw.get("confidence") if raw.get("confidence") in CONFIDENCE else "Baja"
    reasons = [r for r in ver.tlist(raw.get("reasons"), allowed) if len(r.split()) >= 5 and not ai_mod.is_generic(r)][:4]   # un motivo de 3 palabras no es un motivo
    ev = ver.ids_list(raw.get("evidence_ids"), allowed)[:6]
    change = ver.text(raw.get("would_change_if", ""), allowed).strip()
    if rec not in RECOMMENDATIONS or not reasons:
        return {**base, "ia_error": "respuesta del modelo inválida o sin motivos concretos"}
    if ai_mod.is_generic(change):
        change = base["would_change_if"]
    item = {"incident_id": inc["id"], "recommendation": rec, "confidence": conf, "reasons": reasons, "evidence_ids": ev,
            "would_change_if": change, "source": "ia", "ia_sugirio": None, "conflicto": False, "difiere": False}
    if (protected or inc["severity"] in ("Crítico", "Alto")) and RANK[rec] < RANK[base["recommendation"]]:
        # la IA quiere bajar la guardia en un incidente grave o con señales de abuso: se conserva el motor y se deja constancia
        kept = {**base, "conflicto": True, "ia_sugirio": {"recommendation": rec, "confidence": conf, "reasons": reasons, "would_change_if": change}}
        return kept
    item["difiere"] = rec != base["recommendation"]
    return item


def deterministic(analysis: dict) -> dict:
    items = [baseline(analysis, inc) for inc in analysis["incidents"]]
    return {"mode": "motor", "provider": "", "model": "", "items": items, "errors": [], "validation": _stats(items, None)}


def _stats(items: list[dict], ver: ai_mod.Verifier | None) -> dict:
    return {"incidentes": len(items), "con_ia": sum(i["source"] == "ia" for i in items),
            "respaldo_motor": sum(i["source"] == "motor" for i in items), "conflictos": sum(i["conflicto"] for i in items),
            "difieren": sum(i["difiere"] for i in items),
            "citas_verificadas": (ver.checked - ver.dropped_ids) if ver else 0,
            "citas_descartadas": ver.dropped_ids if ver else 0, "ips_descartadas": ver.dropped_ips if ver else 0}


def generate(analysis: dict, df: pd.DataFrame, call: Callable, provider: str = "", model: str = "") -> dict:
    """Pide una recomendación por incidente. Un fallo del modelo en un incidente deja la del motor para ese incidente."""
    ver = ai_mod.Verifier(df)
    items, errors, fails = [], [], 0
    for inc in analysis["incidents"]:
        base = baseline(analysis, inc)
        if fails >= MAX_CONSECUTIVE_FAILS:   # el proveedor dejó de responder: no esperar un tiempo de espera por cada incidente restante
            errors.append(f"{inc['id']}: omitido, el proveedor de IA dejó de responder")
            items.append(base)
            continue
        allowed = set(_incident_evidence(analysis, inc))
        text = ("Evalúa el siguiente incidente y entrega la recomendación con la herramienta indicada.\n" + TRIAGE_PROMPT
                + "\n\n<incidente>\n" + ai_mod._as_data(_payload(analysis, df, inc, base)) + "\n</incidente>")
        try:
            raw = call(TRIAGE_TOOL, text, 1500)
            fails = 0
            item = _review(raw, base, allowed, ver, inc, has_abuse_signals(analysis, inc))
            if item.get("ia_error"):
                errors.append(f"{inc['id']}: {item.pop('ia_error')}")
        except Exception as exc:   # un incidente fallido no tumba el triaje
            fails += 1
            errors.append(f"{inc['id']}: {type(exc).__name__}: {exc}")
            item = base
        items.append(item)
    stats = _stats(items, ver)
    return {"mode": "ia" if stats["con_ia"] else "motor", "provider": provider, "model": model, "items": items, "errors": errors[:10], "validation": stats}


# --------------------------------------------------------------------------- decisión del analista
def clean_note(note: str) -> str:
    return " ".join((note or "").split())[:NOTE_MAX]


def view(analysis: dict, triage: dict | None, decisions: dict) -> dict:
    """Estado completo para la interfaz y el PDF: recomendación vigente + decisión del analista por incidente."""
    t = triage or deterministic(analysis)
    items = []
    for it in t["items"]:
        items.append({**it, "decision": decisions.get(it["incident_id"])})
    done = sum(1 for i in items if i["decision"])
    return {**{k: v for k, v in t.items() if k != "items"}, "items": items,
            "resumen": {"total": len(items), "decididos": done, "pendientes": len(items) - done}}
