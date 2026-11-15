"""Valida las reglas de detección con datasets públicos de OTRF Security-Datasets (Windows, técnica ATT&CK etiquetada).

Uso (no es parte del servicio; necesita una copia local del repositorio de datos):

    git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets
    cd Security-Datasets && git sparse-checkout set --no-cone 'datasets/atomic/_metadata/*' 'datasets/atomic/windows/*/host/*'
    python scripts/validar_datasets.py /ruta/a/Security-Datasets --json resultados.json

Segunda validación, con logs reales de SSH (Loghub, OpenSSH_2k.log de un servidor expuesto a Internet):

    python scripts/validar_datasets.py --loghub /ruta/a/loghub/OpenSSH/OpenSSH_2k.log

Se convierte cada «Failed/Accepted password» en un evento, se calcula POR SEPARADO qué IPs hicieron 3 o más fallos con huecos de
hasta 10 min entre sí y se compara con las IPs que reporta la regla de autenticación (aciertos, falsos y omitidas).

Para cada dataset de OTRF se compara la técnica ATT&CK que declara su metadato con las técnicas de los hallazgos de la app:
- ``tecnica``: algún hallazgo cita la misma técnica (o su técnica padre);
- ``tactica``: ningún hallazgo cita la técnica, pero hay uno de la misma táctica;
- ``otros``: hay hallazgos, pero de otra técnica y táctica;
- ``ninguno``: sin hallazgos.
El resultado mide cobertura frente a un adversario real, no corrección de cada regla: muchos datasets ejercitan técnicas
que la app no pretende cubrir (se reportan como «ninguno» u «otros» y se explican en docs/VALIDACION.md).

Línea base (la «vara» que corre el CI en cada cambio):

    python scripts/validar_datasets.py /ruta/Security-Datasets --loghub OpenSSH_2k.log --base tests/validation/linea_base.json
    python scripts/validar_datasets.py /ruta/Security-Datasets --loghub OpenSSH_2k.log --base tests/validation/linea_base.json --actualizar-base

Con ``--base`` compara dataset por dataset y termina con código 1 si hay una regresión: un dataset que detectaba la técnica o la táctica
baja de nivel, un dataset falla al leerse o desaparece, o SSH pierde una IP o suma un falso positivo. Los cambios que no son regresiones
(mejoras, y «ninguno» ↔ «otros», que puede ser ruido nuevo o ruido menos) se informan sin fallar. ``--actualizar-base`` fija el resultado
actual como nuevo piso, después de revisar una mejora a propósito. ``--resumen-md`` escribe la tabla para el resumen de GitHub Actions.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.analysis import analyze  # noqa: E402
from backend.parser import load_events  # noqa: E402
from backend.syslog import parse_auth_log  # noqa: E402

TACTICS = {"TA0001": "Acceso inicial", "TA0002": "Ejecución", "TA0003": "Persistencia", "TA0004": "Escalamiento de privilegios",
           "TA0005": "Evasión de defensas", "TA0006": "Acceso a credenciales", "TA0007": "Descubrimiento", "TA0008": "Movimiento lateral",
           "TA0009": "Recolección", "TA0010": "Exfiltración", "TA0011": "Comando y control", "TA0040": "Impacto"}


def read_metadata(root: Path) -> dict[str, dict]:
    """ruta relativa del zip -> {id, title, techniques:[T1053.005…], tactics:[TA0003…]} (lectura simple, sin PyYAML)."""
    out: dict[str, dict] = {}
    for f in sorted((root / "datasets/atomic/_metadata").glob("*.yaml")):
        text = f.read_text(encoding="utf-8", errors="replace")
        title = (re.search(r"^title:\s*(.+)$", text, re.M) or [None, f.stem])[1].strip()
        techs, tacs = [], []
        for m in re.finditer(r"-\s*technique:\s*(T\d+)\s*\n(?:\s+sub-technique:\s*\"?(\d+)\"?\s*\n)?((?:\s+tactics:\s*\n(?:\s+-\s*TA\d+\s*\n?)+)?)", text):
            techs.append(m.group(1) + (f".{m.group(2)}" if m.group(2) else ""))
            tacs += re.findall(r"TA\d+", m.group(3))
        for link in re.findall(r"link:\s*\S*?/(datasets/atomic/\S+?\.zip)", text, re.I):
            out[link] = {"id": f.stem, "title": title, "techniques": techs, "tactics": sorted(set(tacs))}
    return out


# ATT&CK v20 reemplazó estas técnicas (relación «revoked-by» de los datos oficiales). Los metadatos de OTRF usan los IDs anteriores;
# se traducen para compararlos con los IDs vigentes que cita la app.
RENOMBRADAS = {"T1562.002": "T1685.001", "T1562.004": "T1686"}


def parent(t: str) -> str:
    return t.split(".")[0]


def classify(expected: list[str], tactics: list[str], findings: list[dict]) -> str:
    if not findings:
        return "ninguno"
    cited = {parent(t) for f in findings for t in f["mitre"]}
    if any(parent(RENOMBRADAS.get(t, t)) in cited for t in expected):
        return "tecnica"
    names = {TACTICS.get(t, t) for t in tactics}
    if any(f["tactic"] in names for f in findings):
        return "tactica"
    return "otros"


def validate_ssh(path: Path, year: int = 2016) -> dict:
    """Valida la regla de autenticación con un log real de OpenSSH (el log no trae año: se fija uno).

    Usa el mismo lector de auth.log que la aplicación (backend/syslog.py), así que también valida esa lectura.
    """
    events, _ = parse_auth_log(path.read_text(encoding="utf-8", errors="replace"), year=year)
    df, meta = load_events(json.dumps(events).encode(), "ssh.json")
    findings = [f for f in analyze(df, meta)["findings"] if f["rule"] == "g_auth"]
    by: dict[str, list[datetime]] = collections.defaultdict(list)
    for e in events:
        if e["status"] == "failed":
            by[e["source_ip"]].append(datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
    truth = set()
    for ip, ts in by.items():
        ts.sort()
        run, best = 1, 1
        for a, b in zip(ts, ts[1:]):
            run = run + 1 if (b - a).total_seconds() <= 600 else 1
            best = max(best, run)
        if best >= 3:
            truth.add(ip)
    found = {ip for f in findings for ip in f["ips"]}
    return {"eventos": len(events), "fallos": sum(len(v) for v in by.values()), "ips_con_fallos": len(by), "ips_con_rafaga": len(truth),
            "detectadas": len(found & truth), "falsos_positivos": len(found - truth), "omitidas": len(truth - found), "hallazgos": len(findings)}


# Orden de calidad del resultado de un dataset. «error» siempre es regresión.
RANGO = {"error": -1, "ninguno": 0, "otros": 1, "tactica": 2, "tecnica": 3}
ETIQUETA = {"tecnica": "técnica", "tactica": "táctica", "otros": "otra técnica", "ninguno": "sin hallazgos", "error": "error", None: "(no está)"}


def build_base(rows: list[dict], ssh: dict | None) -> dict:
    """Lo que se guarda como línea base: el resultado de cada dataset (clave carpeta/dataset) y las cifras de SSH."""
    datasets = {f"{r['carpeta']}/{r['dataset']}": r["resultado"] for r in rows}
    return {"resumen": {k: sum(v == k for v in datasets.values()) for k in ("tecnica", "tactica", "otros", "ninguno", "error")},
            "total": len(datasets), "ssh": ssh, "datasets": dict(sorted(datasets.items()))}


def compare(base: dict, actual: dict) -> dict:
    """Compara dos líneas base. Devuelve listas de (clave, antes, ahora) y si hay regresión."""
    regresiones, mejoras, avisos = [], [], []
    b, a = base.get("datasets", {}), actual.get("datasets", {})
    for k in sorted(set(b) | set(a)):
        antes, ahora = b.get(k), a.get(k)
        if antes == ahora:
            continue
        if ahora is None or ahora == "error":
            regresiones.append((k, antes, ahora))           # desapareció o no se pudo leer: la medición dejó de valer
        elif antes is None:
            avisos.append((k, antes, ahora))                # dataset nuevo: se informa, se fija al actualizar la base
        elif RANGO[ahora] > RANGO[antes] and RANGO[ahora] >= RANGO["tactica"]:
            mejoras.append((k, antes, ahora))               # ahora acierta la técnica o la táctica
        elif RANGO[antes] >= RANGO["tactica"]:
            regresiones.append((k, antes, ahora))           # dejó de detectar la técnica o la táctica
        else:
            avisos.append((k, antes, ahora))                # ninguno ↔ otros: ruido nuevo o menos ruido; decide una persona
    ssh_b, ssh_a, ssh_problemas = base.get("ssh"), actual.get("ssh"), []
    if ssh_b:
        if not ssh_a:
            ssh_problemas.append("no se ejecutó la validación de SSH")
        else:
            if ssh_a["detectadas"] < ssh_b["detectadas"] or ssh_a["omitidas"] > ssh_b["omitidas"]:
                ssh_problemas.append(f"IPs detectadas {ssh_b['detectadas']} → {ssh_a['detectadas']} (omitidas {ssh_a['omitidas']})")
            if ssh_a["falsos_positivos"] > ssh_b["falsos_positivos"]:
                ssh_problemas.append(f"falsos positivos {ssh_b['falsos_positivos']} → {ssh_a['falsos_positivos']}")
    return {"regresiones": regresiones, "mejoras": mejoras, "avisos": avisos, "ssh": ssh_problemas,
            "falla": bool(regresiones or ssh_problemas)}


def summary_md(base: dict, actual: dict, cmp: dict) -> str:
    """Tabla en Markdown para el resumen del CI."""
    rb, ra = base.get("resumen", {}), actual["resumen"]
    out = ["## Exactitud de las reglas (OTRF + SSH real)", "",
           "**Resultado: " + ("❌ regresión" if cmp["falla"] else "✅ sin regresiones") + "**", "",
           "| Resultado | Línea base | Ahora |", "|---|---|---|"]
    for k in ("tecnica", "tactica", "otros", "ninguno", "error"):
        out.append(f"| {ETIQUETA[k].capitalize()} | {rb.get(k, 0)} | {ra.get(k, 0)} |")
    out.append(f"| **Total** | {base.get('total', 0)} | {actual['total']} |")
    s = actual.get("ssh")
    if s:
        out += ["", f"SSH real (Loghub): {s['detectadas']} de {s['ips_con_rafaga']} IPs detectadas, {s['falsos_positivos']} falsos positivos, {s['omitidas']} omitidas."]
    for titulo, clave in (("Regresiones (hacen fallar el CI)", "regresiones"), ("Mejoras", "mejoras"), ("Cambios para revisar (no fallan)", "avisos")):
        if cmp[clave]:
            out += ["", f"### {titulo}", "", "| Dataset | Antes | Ahora |", "|---|---|---|"]
            out += [f"| `{k}` | {ETIQUETA[x]} | {ETIQUETA[y]} |" for k, x, y in cmp[clave]]
    if cmp["ssh"]:
        out += ["", "### SSH", ""] + [f"- {p}" for p in cmp["ssh"]]
    if cmp["mejoras"] and not cmp["falla"]:
        out += ["", "Para fijar las mejoras como nuevo piso: `python scripts/validar_datasets.py … --actualizar-base` y subir `tests/validation/linea_base.json`."]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", type=Path, nargs="?", help="copia local de OTRF/Security-Datasets")
    ap.add_argument("--loghub", type=Path, help="OpenSSH_2k.log de Loghub (validación con SSH real)")
    ap.add_argument("--json", type=Path, help="guarda el detalle en este archivo")
    ap.add_argument("--max-zip-mb", type=float, default=40)
    ap.add_argument("--base", type=Path, help="línea base con la que comparar (falla si hay regresión)")
    ap.add_argument("--actualizar-base", action="store_true", help="guarda el resultado actual como nueva línea base")
    ap.add_argument("--resumen-md", type=Path, help="escribe la comparación en Markdown (por ejemplo, $GITHUB_STEP_SUMMARY)")
    a = ap.parse_args()
    ssh = None
    if a.loghub:
        ssh = validate_ssh(a.loghub)
        print(json.dumps(ssh, ensure_ascii=False))
        if not a.root:
            return 0
    if not a.root:
        ap.error("indica la ruta de Security-Datasets o --loghub")
    meta = read_metadata(a.root)
    rows = []
    for rel, info in sorted(meta.items()):
        z = a.root / rel
        if "/windows/" not in rel or "/host/" not in rel or not z.exists() or z.stat().st_size > a.max_zip_mb * 1e6:
            continue
        zf = zipfile.ZipFile(z)
        name = next((n for n in zf.namelist() if n.lower().endswith(".json")), None)
        if not name:
            continue
        t0 = time.time()
        try:
            df, m = load_events(zf.read(name), name)
            res = analyze(df, m)
            fs = res["findings"]
            error = ""
        except Exception as exc:  # un dataset que no se puede leer cuenta como fallo de lectura, no como «ninguno»
            df, fs, error = [], [], f"{type(exc).__name__}: {exc}"[:160]
        rows.append({"dataset": Path(rel).stem, "carpeta": Path(rel).parts[3], "id": info["id"], "titulo": info["title"], "tecnicas": info["techniques"], "tacticas": info["tactics"],
                     "eventos": len(df), "resultado": "error" if error else classify(info["techniques"], info["tactics"], fs), "error": error,
                     "hallazgos": [{"regla": f["rule"], "criticidad": f["severity"], "mitre": f["mitre"], "titulo": f["title"][:110]} for f in fs],
                     "segundos": round(time.time() - t0, 1)})
    total = len(rows)
    cuenta = {k: sum(r["resultado"] == k for r in rows) for k in ("tecnica", "tactica", "otros", "ninguno", "error")}
    print(f"{total} datasets · " + " · ".join(f"{k}: {v}" for k, v in cuenta.items()))
    if a.json:
        a.json.write_text(json.dumps({"total": total, "resumen": cuenta, "datasets": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    if not a.base:
        return 0
    actual = build_base(rows, ssh)
    if a.actualizar_base:
        a.base.parent.mkdir(parents=True, exist_ok=True)
        a.base.write_text(json.dumps(actual, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"Línea base actualizada: {a.base}")
        return 0
    base = json.loads(a.base.read_text(encoding="utf-8"))
    cmp = compare(base, actual)
    md = summary_md(base, actual, cmp)
    print(md)
    if a.resumen_md:
        with a.resumen_md.open("a", encoding="utf-8") as fh:
            fh.write(md)
    return 1 if cmp["falla"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
