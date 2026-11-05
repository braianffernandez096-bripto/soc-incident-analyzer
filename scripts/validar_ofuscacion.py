"""Mide la desofuscación de comandos con las pruebas públicas de Atomic Red Team (comandos reales de simulación de adversarios).

Uso (no es parte del servicio):

    git clone --depth 1 --filter=blob:none --sparse https://github.com/redcanaryco/atomic-red-team
    cd atomic-red-team && git sparse-checkout set --no-cone 'atomics/T*/T*.yaml' && cd ..
    python scripts/validar_ofuscacion.py atomic-red-team --json ofuscacion.json

Para cada comando de cmd/PowerShell se compara qué reglas lo detectan a simple vista y cuáles con la desofuscación. Mide tres cosas:
cuántos comandos ofuscados se resuelven, cuánto cambia la cobertura y qué comandos dispara la regla genérica «comando ofuscado»
(que se revisan a mano: son los candidatos a falso positivo).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import deobf, detection  # noqa: E402


def commands(root: Path):
    for f in sorted(root.glob("atomics/T*/T*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        for i, t in enumerate((doc or {}).get("atomic_tests") or []):
            ex = t.get("executor") or {}
            if ex.get("name") in ("command_prompt", "powershell") and ex.get("command"):
                yield f.parent.name, i, str(t.get("name", ""))[:90], ex["name"], str(ex["command"])


class _Row:
    Log_ID = "x"
    User = "CORP\\ana"
    Event_Description = ""


def classify(cmd: str) -> dict:
    row = _Row()
    row.Process_CommandLine = cmd
    raw = detection._match_pats(f"{row.Event_Description} {cmd}", row.User)
    res = deobf.command(cmd)
    hit = detection._match_cmd(row)
    return {"cruda": raw["key"] if raw else "", "con_desofuscacion": hit["key"] if hit else "", "tecnicas": res["techniques"],
            "revela": deobf.reveals(cmd, res)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", type=Path)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    rows = []
    for tech, i, name, shell, cmd in commands(a.root):
        c = classify(cmd[:20000])
        rows.append({"tecnica": tech, "prueba": i, "nombre": name, "shell": shell, "comando": cmd[:300], **c})
    n = len(rows)
    ofus = [r for r in rows if r["tecnicas"]]
    revela = [r for r in rows if r["revela"]]
    gana = [r for r in rows if r["con_desofuscacion"] and not r["cruda"]]
    solo_obf = [r for r in rows if r["con_desofuscacion"] == "obfuscated_cmd"]
    print(f"{n} comandos (cmd/PowerShell) de {len({r['tecnica'] for r in rows})} técnicas")
    print(f"  con alguna técnica de ofuscación resuelta: {len(ofus)}")
    print(f"  donde la ofuscación escondía un programa relevante: {len(revela)}")
    print(f"  detectados SOLO tras desofuscar: {len(gana)} ({len(solo_obf)} como «comando ofuscado» genérico)")
    for r in solo_obf:
        print(f"    - {r['tecnica']} · {r['nombre'][:50]} · {', '.join(r['tecnicas'][:2])}\n        {r['comando'][:110]!r}")
    if a.json:
        a.json.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
