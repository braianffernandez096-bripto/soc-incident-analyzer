"""El arnés de evaluación del triaje y su archivo de etiquetas deben seguir coherentes con los datos de ejemplo."""
import importlib.util
import json
from pathlib import Path

from backend import triage
from backend.analysis import analyze
from backend.parser import load_events

ROOT = Path(__file__).resolve().parents[2]
LABELS = json.loads((ROOT / "sample_data" / "triage_esperado.json").read_text("utf-8"))


def test_etiquetas_cubren_exactamente_los_incidentes_de_cada_muestra():
    for fname, lab in LABELS.items():
        if fname.startswith("_"):
            continue
        df, meta = load_events(str(ROOT / "sample_data" / fname))
        ids = {i["id"] for i in analyze(df, meta)["incidents"]}
        assert set(lab) == ids, fname
        assert all(v["esperado"] in triage.RECOMMENDATIONS and set(v.get("aceptable", [])) <= set(triage.RECOMMENDATIONS) and v["criterio"] for v in lab.values())


def test_script_mide_y_cuenta_subescalado():
    spec = importlib.util.spec_from_file_location("evaluar_triage", ROOT / "scripts" / "evaluar_triage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    items = [{"incident_id": "INC-001", "recommendation": "Probable falso positivo", "source": "ia", "conflicto": False},
             {"incident_id": "INC-002", "recommendation": "Escalar", "source": "motor", "conflicto": False}]
    labels = {"INC-001": {"esperado": "Escalar"}, "INC-002": {"esperado": "Falta información"}}
    r = mod.evaluate(items, labels, {})
    assert (r["casos"], r["aciertos"], r["subescalado"], r["sobreescalado"]) == (2, 0, 1, 1)
