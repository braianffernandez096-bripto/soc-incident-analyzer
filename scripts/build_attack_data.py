"""Rebuild backend/data/attack_techniques.json from the official MITRE ATT&CK STIX bundle.

Usage (offline, run by a maintainer when ATT&CK publishes a new version):
    git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git
    python scripts/build_attack_data.py attack-stix-data/enterprise-attack/enterprise-attack.json

Only the techniques the detection rules actually reference are kept (the app never needs the whole matrix).
The script FAILS if a referenced ID is missing, revoked or deprecated, so a stale ID cannot ship silently.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "backend" / "data" / "attack_techniques.json"
SOURCES = [ROOT / "backend" / "detection.py", ROOT / "backend" / "detection_generic.py", ROOT / "backend" / "playbook.py", ROOT / "backend" / "ai.py"]
ID_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


def referenced_ids() -> list[str]:
    found: set[str] = set()
    for src in SOURCES:
        found.update(ID_RE.findall(src.read_text(encoding="utf-8")))
    return sorted(found)


def main(bundle_path: str) -> int:
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    objs = bundle["objects"]
    collection = next(o for o in objs if o["type"] == "x-mitre-collection")
    tactics = {o["x_mitre_shortname"]: {"id": o["external_references"][0]["external_id"], "name": o["name"]}
               for o in objs if o["type"] == "x-mitre-tactic"}
    patterns: dict[str, dict] = {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                patterns[ref["external_id"]] = o
    techniques, problems = {}, []
    for tid in referenced_ids():
        o = patterns.get(tid)
        if o is None:
            problems.append(f"{tid}: not found in ATT&CK {collection['x_mitre_version']}")
        elif o.get("revoked") or o.get("x_mitre_deprecated"):
            problems.append(f"{tid}: revoked or deprecated")
        else:
            techniques[tid] = {
                "name": o["name"],
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
            }
    if problems:
        print("ERROR:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1
    used = {t for v in techniques.values() for t in v["tactics"]}
    data = {"attack_version": collection["x_mitre_version"], "domain": "enterprise-attack",
            "tactics": {k: v for k, v in tactics.items() if k in used}, "techniques": techniques}
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"OK: {len(techniques)} techniques, ATT&CK v{data['attack_version']} -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
