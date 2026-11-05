"""Mide el análisis de phishing con correos reales (.eml) de una carpeta local. No es parte del servicio.

Uso con el corpus público phishing_pot (correos de phishing y spam recibidos de verdad; se analizan solo de forma estática):

    git clone --depth 1 https://github.com/rf-peixoto/phishing_pot
    python scripts/validar_correos.py phishing_pot/email --json correos.json

Para medir falsos positivos hace falta una carpeta de correo legítimo (boletines, notificaciones, correo corporativo):

    python scripts/validar_correos.py phishing_pot/email --ham /ruta/a/correo_legitimo

Qué se mide: cuántos correos reciben criticidad Medio o superior («detectados»), cuántos quedan en Bajo («sin señales»), errores de lectura,
tiempo máximo por correo y las señales más frecuentes. En el corpus de phishing no hay «verdad» por correo más allá de que todos son
indeseados, así que el resultado es una tasa de detección aproximada, no una exactitud. Con --ham la tasa de Medio o más es de falsos positivos.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import phishing  # noqa: E402

SEV = ("Crítico", "Alto", "Medio", "Bajo")


def run(files: list[Path]) -> list[dict]:
    rows = []
    for f in files:
        t0 = time.time()
        try:
            r = phishing.analyze_eml(f.read_bytes(), f.name)
            row = {"archivo": f.name, "criticidad": r["severity"], "puntaje": r["score"], "senales": [s["title"] for s in r["signals"]],
                   "urls": len(r["urls"]), "adjuntos": len(r["attachments"]), "error": ""}
        except Exception as exc:  # noqa: BLE001 - un correo ilegible cuenta como error de lectura, no como «sin señales»
            row = {"archivo": f.name, "criticidad": "error", "puntaje": 0, "senales": [], "urls": 0, "adjuntos": 0, "error": f"{type(exc).__name__}: {exc}"[:160]}
        row["segundos"] = round(time.time() - t0, 3)
        rows.append(row)
    return rows


def summarize(rows: list[dict], titulo: str) -> dict:
    n = len(rows)
    c = Counter(r["criticidad"] for r in rows)
    medio_o_mas = sum(c[k] for k in SEV[:3])
    sig = Counter(re_title(t) for r in rows for t in set(r["senales"]))
    out = {"conjunto": titulo, "correos": n, **{k: c.get(k, 0) for k in (*SEV, "error")},
           "medio_o_mas_pct": round(100 * medio_o_mas / max(1, n), 1), "alto_o_mas_pct": round(100 * (c["Crítico"] + c["Alto"]) / max(1, n), 1),
           "max_segundos": max((r["segundos"] for r in rows), default=0), "senales_top": sig.most_common(15)}
    print(f"\n== {titulo}: {n} correos ==")
    print("  " + " · ".join(f"{k}: {c.get(k, 0)}" for k in (*SEV, "error")))
    print(f"  Medio o más: {out['medio_o_mas_pct']} % · Alto o más: {out['alto_o_mas_pct']} % · tiempo máximo: {out['max_segundos']} s")
    for t, k in out["senales_top"][:10]:
        print(f"    {k:5d}  {t}")
    return out


def re_title(t: str) -> str:
    """Quita el nombre de archivo o dominio entre paréntesis para agrupar señales iguales."""
    return t.split(" (")[0][:80]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("carpeta", type=Path, help="carpeta con .eml (phishing)")
    ap.add_argument("--ham", type=Path, help="carpeta con .eml legítimos para medir falsos positivos")
    ap.add_argument("--max", type=int, default=0, help="analizar solo una muestra aleatoria de este tamaño")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--json", type=Path, help="guarda el detalle en este archivo")
    a = ap.parse_args()
    result = {}
    for key, folder in (("phishing", a.carpeta), ("legitimo", a.ham)):
        if not folder:
            continue
        files = sorted(x for x in folder.rglob("*") if x.is_file() and x.suffix.lower() in ("", ".eml", ".txt", ".msg"))
        if a.max and len(files) > a.max:
            files = random.Random(a.seed).sample(files, a.max)
        rows = run(files)
        result[key] = {"resumen": summarize(rows, key), "detalle": rows}
    if a.json:
        a.json.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
