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


def parent(t: str) -> str:
    return t.split(".")[0]


def classify(expected: list[str], tactics: list[str], findings: list[dict]) -> str:
    if not findings:
        return "ninguno"
    cited = {parent(t) for f in findings for t in f["mitre"]}
    if any(parent(t) in cited for t in expected):
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", type=Path, nargs="?", help="copia local de OTRF/Security-Datasets")
    ap.add_argument("--loghub", type=Path, help="OpenSSH_2k.log de Loghub (validación con SSH real)")
    ap.add_argument("--json", type=Path, help="guarda el detalle en este archivo")
    ap.add_argument("--max-zip-mb", type=float, default=40)
    a = ap.parse_args()
    if a.loghub:
        print(json.dumps(validate_ssh(a.loghub), ensure_ascii=False))
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
