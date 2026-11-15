"""La «vara» de exactitud del CI: cuándo una diferencia con la línea base es regresión, mejora o un cambio para revisar.

No usa red ni los datasets: prueba la lógica de comparación de scripts/validar_datasets.py y que la línea base guardada sea coherente.
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE_FILE = ROOT / "tests" / "validation" / "linea_base.json"
SSH = {"eventos": 522, "fallos": 521, "ips_con_fallos": 24, "ips_con_rafaga": 11, "detectadas": 11, "falsos_positivos": 0, "omitidas": 0, "hallazgos": 12}


def _mod():
    spec = importlib.util.spec_from_file_location("validar_datasets", ROOT / "scripts" / "validar_datasets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = _mod()


def base(datasets, ssh=SSH):
    rows = [{"carpeta": k.split("/")[0], "dataset": k.split("/")[1], "resultado": v} for k, v in datasets.items()]
    return V.build_base(rows, ssh)


def test_sin_cambios_no_falla():
    b = base({"a/x": "tecnica", "a/y": "ninguno"})
    c = V.compare(b, b)
    assert not c["falla"] and not (c["regresiones"] or c["mejoras"] or c["avisos"])


def test_perder_la_tecnica_o_la_tactica_es_regresion():
    b = base({"a/x": "tecnica", "a/y": "tactica", "a/z": "tecnica"})
    a = base({"a/x": "tactica", "a/y": "otros", "a/z": "ninguno"})
    c = V.compare(b, a)
    assert c["falla"] and [k for k, *_ in c["regresiones"]] == ["a/x", "a/y", "a/z"]


def test_error_o_dataset_perdido_es_regresion():
    b = base({"a/x": "ninguno", "a/y": "otros"})
    a = base({"a/x": "error"})
    c = V.compare(b, a)
    assert c["falla"] and {k for k, *_ in c["regresiones"]} == {"a/x", "a/y"}


def test_subir_de_nivel_es_mejora_y_no_falla():
    b = base({"a/x": "ninguno", "a/y": "otros", "a/z": "tactica"})
    a = base({"a/x": "tecnica", "a/y": "tactica", "a/z": "tecnica"})
    c = V.compare(b, a)
    assert not c["falla"] and len(c["mejoras"]) == 3


def test_ruido_nuevo_o_menos_ruido_se_avisa_sin_fallar():
    b = base({"a/x": "ninguno", "a/y": "otros"})
    a = base({"a/x": "otros", "a/y": "ninguno", "a/nuevo": "tecnica"})
    c = V.compare(b, a)
    assert not c["falla"] and {k for k, *_ in c["avisos"]} == {"a/x", "a/y", "a/nuevo"}


def test_ssh_pierde_una_ip_o_suma_un_falso_positivo():
    b = base({"a/x": "tecnica"})
    for cambio in ({"detectadas": 10, "omitidas": 1}, {"falsos_positivos": 1}):
        c = V.compare(b, base({"a/x": "tecnica"}, {**SSH, **cambio}))
        assert c["falla"] and c["ssh"]
    assert V.compare(b, base({"a/x": "tecnica"}, None))["falla"]          # no correr SSH tampoco vale


def test_resumen_md_muestra_resultado_y_tablas():
    b = base({"a/x": "tecnica", "a/y": "ninguno"})
    a = base({"a/x": "ninguno", "a/y": "tecnica"})
    md = V.summary_md(b, a, V.compare(b, a))
    assert "❌ regresión" in md and "### Regresiones" in md and "### Mejoras" in md and "`a/x`" in md
    ok = V.summary_md(b, b, V.compare(b, b))
    assert "✅ sin regresiones" in ok and "###" not in ok


def test_la_linea_base_guardada_es_coherente():
    d = json.loads(BASE_FILE.read_text(encoding="utf-8"))
    assert d["total"] == len(d["datasets"]) == sum(d["resumen"].values())
    assert set(d["datasets"].values()) <= set(V.RANGO) and d["resumen"]["error"] == 0
    assert d["ssh"]["detectadas"] == d["ssh"]["ips_con_rafaga"] and d["ssh"]["falsos_positivos"] == 0
    assert d["resumen"]["tecnica"] >= 41                               # el piso solo sube: nunca se guarda una base peor que la publicada
