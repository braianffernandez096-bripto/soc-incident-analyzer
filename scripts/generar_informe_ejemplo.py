#!/usr/bin/env python3
"""Regenera examples/informe-ejemplo.pdf con el motor actual y (opcionalmente) el análisis con IA, cuidando cada llamada de pago.

Cada análisis con IA cuesta una llamada por incidente más una de resumen. Para no gastar de más:
  * Por defecto es un SIMULACRO: usa un modelo falso local, no toca la red y no cuesta nada. Sirve para ver que todo el recorrido funciona.
  * Con --real hace las llamadas de verdad. Antes muestra cuántas son y pide confirmación (salvo --yes).
  * Cada respuesta del modelo se guarda en disco apenas llega (--cache). Si algo falla después (maquetado, un grupo caído, cortar el script),
    al repetir se reutiliza lo ya pagado: solo se vuelve a llamar por lo que falta.
  * La clave se lee de la variable de entorno ANTHROPIC_API_KEY; no se pasa por argumento ni se imprime.

Uso:
  python3 scripts/generar_informe_ejemplo.py                       # simulacro, escribe informe-ejemplo.simulacro.pdf
  ANTHROPIC_API_KEY=... python3 scripts/generar_informe_ejemplo.py --real   # real, escribe examples/informe-ejemplo.pdf
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import ai, report  # noqa: E402
from backend.analysis import analyze  # noqa: E402
from backend.parser import load_events  # noqa: E402

SAMPLE = ROOT / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
META = {"client": "Cliente ejemplo", "analyst": "Braian Fernandez", "filename": SAMPLE.name, "title_suffix": " (ejemplo)",
        "footer": "Informe de ejemplo · Datos sintéticos · Generado automáticamente a partir de los logs del SIEM"}


def planned_calls(analysis: dict) -> int:
    """Llamadas que hará generate(): una por grupo de hallazgos (incidente u «OBS») más el resumen ejecutivo."""
    return len({f["incident_id"] or "OBS" for f in analysis["findings"]}) + 1


def _key(tool: dict, text: str, max_tokens: int) -> str:
    return hashlib.sha256(f"{tool['name']}\n{max_tokens}\n{text}".encode()).hexdigest()


class CachedCall:
    """Envuelve el modelo: guarda cada respuesta cruda en disco al recibirla y la reutiliza si el mismo pedido se repite."""

    def __init__(self, inner, path: Path | None):
        self.inner, self.path, self.lock = inner, path, threading.Lock()
        self.hits = self.misses = 0
        self.store: dict[str, dict] = {}
        if path and path.exists():
            self.store = json.loads(path.read_text("utf-8"))

    def pending(self, tool_texts: list[tuple[dict, str, int]]) -> int:
        return sum(_key(*t) not in self.store for t in tool_texts)

    def __call__(self, tool: dict, text: str, max_tokens: int) -> dict:
        k = _key(tool, text, max_tokens)
        with self.lock:
            if k in self.store:
                self.hits += 1
                return self.store[k]
        out = self.inner(tool, text, max_tokens)              # fuera del lock: los grupos corren en paralelo
        with self.lock:
            self.misses += 1
            self.store[k] = out
            if self.path:
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self.store, ensure_ascii=False), "utf-8")
                tmp.replace(self.path)                         # escritura atómica: un corte no corrompe lo ya pagado
        return out


def fake_model(tool: dict, text: str, max_tokens: int) -> dict:
    """Modelo simulado y válido (sin red, sin costo) para ensayar el recorrido completo."""
    if tool["name"] == "submit_executive_report":
        return {"executive_summary": "[SIMULACRO] Resumen ejecutivo de prueba.", "cross_incident_assessment": "[SIMULACRO] Evaluación de prueba.",
                "prioritized_actions": [{"priority": "Inmediata", "action": "[SIMULACRO] Acción de prueba.", "incident_ids": []}],
                "general_recommendations": ["[SIMULACRO] Recomendación de prueba."]}
    payload = json.loads(text.split("<analisis>")[1].split("</analisis>")[0])
    return {"incident_title": "[SIMULACRO] Incidente", "narrative": "[SIMULACRO] Narrativa de prueba.", "confidence": "Alta", "confidence_reason": "Prueba.",
            "severity": "Alto", "kill_chain": [],
            "findings": [{"finding_id": f["finding_id"], "severity": f.get("severidad_motor", "Alto"), "severity_justification": "[SIMULACRO] Prueba.",
                          "technical_explanation": "[SIMULACRO] Explicación de prueba.", "impact": "[SIMULACRO] Impacto de prueba.",
                          "investigate": ["[SIMULACRO] Paso"], "contain": ["[SIMULACRO] Paso"], "remediate": ["[SIMULACRO] Paso"]} for f in payload["hallazgos"]]}


def real_model(api_key: str, model: str | None):
    import anthropic
    client = anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=180)
    name = model or os.environ.get("ANTHROPIC_MODEL") or ai.DEFAULT_MODEL
    return lambda tool, text, mt: ai._call_tool(client, name, tool, text, mt)


def capture_prompts(analysis: dict, df) -> list[tuple[dict, str, int]]:
    """Pedidos que haría generate(), sin llamar a nadie: sirve para saber cuáles ya están en el caché."""
    seen: list[tuple[dict, str, int]] = []

    def spy(tool, text, mt):
        seen.append((tool, text, mt))
        return fake_model(tool, text, mt)

    ai.generate(analysis, df, None, call=spy)
    return seen


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--real", action="store_true", help="llama al modelo de verdad (cuesta); sin esto es un simulacro")
    ap.add_argument("--yes", action="store_true", help="no pedir confirmación")
    ap.add_argument("--cache", default="informe_ia_cache.json", help="archivo donde se guardan las respuestas pagadas (por defecto: informe_ia_cache.json)")
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", default=None, help="PDF de salida (real: examples/informe-ejemplo.pdf; simulacro: informe-ejemplo.simulacro.pdf)")
    a = ap.parse_args(argv)

    df, meta = load_events(str(SAMPLE))
    analysis = analyze(df, meta)
    n = planned_calls(analysis)
    cache = CachedCall(None, Path(a.cache) if a.real else None)
    if a.real:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            print("Falta la variable de entorno ANTHROPIC_API_KEY (no se llamó a nadie).", file=sys.stderr)
            return 2
        cache.inner = real_model(key, a.model)
        missing = cache.pending(capture_prompts(analysis, df))
        print(f"Llamadas necesarias: {n} (incidentes + resumen). Ya guardadas en el caché: {n - missing}. Faltan por pagar: {missing}.")
        if missing and not a.yes and input("¿Hacer esas llamadas reales ahora? [escribe SI para continuar] ").strip() != "SI":
            print("Cancelado. No se llamó a nadie.")
            return 1
        call, model = cache, a.model
    else:
        print(f"SIMULACRO: modelo falso local, sin red ni costo. Con --real se harían {n} llamadas (incidentes + resumen).")
        call, model = fake_model, "simulacro"
    result = ai.generate(analysis, df, None, model=model, call=call)
    if result["mode"] != "ia" or result["errors"]:
        print(f"La generación no quedó completa ({len(result['errors'])} errores): {(result['errors'] or ['sin resultados verificables'])[0][:200]}", file=sys.stderr)
        print("NO se escribió el PDF. Lo ya respondido quedó guardado en el caché: al repetir solo se llama por lo que falta.", file=sys.stderr)
        return 3
    out = Path(a.out) if a.out else (ROOT / "examples" / "informe-ejemplo.pdf" if a.real else Path("informe-ejemplo.simulacro.pdf"))
    pdf = report.build_pdf(analysis, result, df, META)
    out.write_bytes(pdf)
    v = result["validation"]
    print(f"Listo: {out} ({len(pdf) // 1024} KB). Llamadas reales hechas ahora: {cache.misses if a.real else 0} · reutilizadas del caché: {cache.hits if a.real else 0}.")
    print(f"Verificación: {v['citas_verificadas']} citas verificadas, {v['citas_descartadas']} descartadas, {v['ips_descartadas']} IP descartadas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
