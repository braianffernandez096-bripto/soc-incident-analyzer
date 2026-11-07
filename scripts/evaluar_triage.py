"""Mide el triaje asistido por IA contra las etiquetas de ``sample_data/triage_esperado.json``.

Las etiquetas son criterio del autor sobre datos sintéticos (ver docs/TRIAGE.md): sirven para comparar el motor y distintos modelos,
no para afirmar una tasa de acierto en producción. En todos los casos los datos de ejemplo son ataques; no hay casos benignos reales.

Uso (no es parte del servicio):

    python scripts/evaluar_triage.py                                   # solo la recomendación del motor
    python scripts/evaluar_triage.py --provider ollama --model llama3.1:8b
    ANTHROPIC_API_KEY=... python scripts/evaluar_triage.py --provider anthropic --json resultados.json

Métricas por modelo:
- acierto: la recomendación final coincide con la esperada o con una aceptable; «exactos» cuenta solo la esperada (más exigente);
- subescalado: se esperaba «Escalar» y se entregó otra cosa (el error caro en un SOC);
- sobreescalado: se esperaba «Falta información» o «Probable falso positivo» y se entregó «Escalar»;
- conflictos: la IA quiso bajar la guardia en un incidente Crítico/Alto y se conservó la del motor;
- citas descartadas: Log_ID o IP inventados por el modelo que el verificador eliminó;
- respaldo del motor: incidentes en los que la respuesta del modelo no fue válida o el proveedor falló (tras 3 fallos seguidos se omiten los restantes).

Si Ollama se queda sin memoria, baja el contexto: `OLLAMA_NUM_CTX=8192 python scripts/evaluar_triage.py ...`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import ai as ai_mod  # noqa: E402
from backend import ai_local  # noqa: E402
from backend import triage  # noqa: E402
from backend.analysis import analyze  # noqa: E402
from backend.parser import load_events  # noqa: E402

LABELS = ROOT / "sample_data" / "triage_esperado.json"


def evaluate(items: list[dict], labels: dict, severities: dict) -> dict:
    n = ok = exact = under = over = 0
    detail = []
    for it in items:
        lab = labels.get(it["incident_id"])
        if not lab:
            continue
        exp, accept = lab["esperado"], set(lab.get("aceptable", [])) | {lab["esperado"]}
        hit = it["recommendation"] in accept
        n += 1
        ok += hit
        exact += it["recommendation"] == exp
        under += exp == "Escalar" and it["recommendation"] != "Escalar"
        over += exp != "Escalar" and it["recommendation"] == "Escalar" and "Escalar" not in accept
        detail.append({"incidente": it["incident_id"], "severidad": severities.get(it["incident_id"], ""), "esperado": exp,
                       "obtenido": it["recommendation"], "fuente": it["source"], "acierto": hit, "conflicto": it["conflicto"]})
    return {"casos": n, "aciertos": ok, "exactos": exact, "subescalado": under, "sobreescalado": over, "detalle": detail}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=("ninguno", "ollama", "anthropic"), default="ninguno")
    ap.add_argument("--model", default="")
    ap.add_argument("--archivos", nargs="*", default=[], help="evalúa solo estos archivos de sample_data (por defecto, todos los etiquetados)")
    ap.add_argument("--json", default="", help="guarda el resultado completo en este archivo")
    args = ap.parse_args()

    call, model = None, args.model
    if args.provider == "ollama":
        if not model:
            ap.error("--model es obligatorio con ollama")
        call = ai_local.make_call(model)
    elif args.provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            ap.error("define ANTHROPIC_API_KEY en el entorno (no se pasa por argumento)")
        model = model or os.environ.get("ANTHROPIC_MODEL") or ai_mod.DEFAULT_MODEL
        call = ai_mod.make_anthropic_call(key, model)

    labels = json.loads(LABELS.read_text("utf-8"))
    tot = {"casos": 0, "aciertos": 0, "exactos": 0, "subescalado": 0, "sobreescalado": 0, "conflictos": 0, "citas_descartadas": 0, "ips_descartadas": 0, "respaldo_motor": 0}
    tot_motor = {"casos": 0, "aciertos": 0, "exactos": 0, "subescalado": 0, "sobreescalado": 0}
    out = {}
    for fname, lab in labels.items():
        if fname.startswith("_") or (args.archivos and fname not in args.archivos):
            continue
        df, meta = load_events(str(ROOT / "sample_data" / fname))
        a = analyze(df, meta)
        sev = {i["id"]: i["severity"] for i in a["incidents"]}
        base = triage.deterministic(a)
        rm = evaluate(base["items"], lab, sev)
        for k in tot_motor:
            tot_motor[k] += rm[k]
        res = triage.generate(a, df, call, provider=args.provider, model=model) if call else base
        r = evaluate(res["items"], lab, sev)
        v = res["validation"]
        for k in ("casos", "aciertos", "exactos", "subescalado", "sobreescalado"):
            tot[k] += r[k]
        for k, src in (("conflictos", "conflictos"), ("citas_descartadas", "citas_descartadas"), ("ips_descartadas", "ips_descartadas"), ("respaldo_motor", "respaldo_motor")):
            tot[k] += v[src]
        out[fname] = {"motor": rm, "evaluado": r, "validacion": v, "errores": res["errors"],
                      "ia": [{"incidente": i["incident_id"], "fuente": i["source"], "recomendacion": i["recommendation"], "confianza": i["confidence"],
                              "motivos": i["reasons"], "cambiaria_si": i["would_change_if"], "conflicto": i["conflicto"], "ia_sugirio": i["ia_sugirio"]} for i in res["items"]]}
        print(f"\n{fname}: {r['aciertos']}/{r['casos']} aciertos")
        for d in r["detalle"]:
            print(f"  {d['incidente']} {d['severidad']:<8} esperado={d['esperado']:<18} obtenido={d['obtenido']:<24} [{d['fuente']}]{' CONFLICTO' if d['conflicto'] else ''}{'' if d['acierto'] else '  <-- no coincide'}")
        for i in res["items"]:   # qué quiso hacer el modelo cuando el motor lo frenó o cuando discrepó
            sug = i["ia_sugirio"] or ({"recommendation": i["recommendation"], "reasons": i["reasons"]} if i["difiere"] else None)
            if sug:
                print(f"    {i['incident_id']}: la IA sugirió «{sug['recommendation']}» — {(sug['reasons'] or [''])[0][:160]}")
        for e in res["errors"]:
            print(f"  aviso: {e}")
    print("\n== Resumen ==")
    print(f"Motor solo ........ aciertos {tot_motor['aciertos']}/{tot_motor['casos']} (exactos {tot_motor['exactos']}) · subescalado {tot_motor['subescalado']} · sobreescalado {tot_motor['sobreescalado']}")
    if call:
        print(f"{args.provider}:{model} .. aciertos {tot['aciertos']}/{tot['casos']} (exactos {tot['exactos']}) · subescalado {tot['subescalado']} · sobreescalado {tot['sobreescalado']}"
              f" · conflictos {tot['conflictos']} · citas descartadas {tot['citas_descartadas']} · IPs descartadas {tot['ips_descartadas']} · respaldo del motor {tot['respaldo_motor']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"proveedor": args.provider, "modelo": model, "total": tot, "motor": tot_motor, "archivos": out}, ensure_ascii=False, indent=1), "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
