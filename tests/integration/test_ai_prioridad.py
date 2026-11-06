"""La prioridad del plan de acción la fija el motor; las acciones genéricas del modelo no llegan al informe.
Casos tomados de un informe real generado con llama3.1:8b (ransomware como «Corto plazo», 3 acciones para 9 incidentes)."""
import pytest

from backend import ai
from backend import detection as D
from tests.integration.test_ai import SAMPLE, _fake_model
from backend.analysis import analyze
from backend.parser import load_events

PRIO = {"Crítico": "Inmediata", "Alto": "Corto plazo", "Medio": "Mediano plazo", "Bajo": "Mediano plazo"}


@pytest.fixture(scope="module")
def ctx():
    df, meta = load_events(str(SAMPLE))
    return df, analyze(df, meta)


def _run(ctx, actions, recs=None):
    df, a = ctx

    def model(tool, text, mt):
        if tool["name"] == "submit_executive_report":
            return {"executive_summary": "Resumen.", "cross_incident_assessment": "Varios.",
                    "prioritized_actions": actions, "general_recommendations": recs or ["Habilitar MFA en accesos remotos."]}
        return _fake_model(tool, text, mt)
    return a, ai.generate(a, df, api_key=None, call=model)


def _ent(inc):
    return (inc["hosts"] or inc["external_ips"] or [D.short_user(u) for u in inc["actor_users"]])[0]


def test_modelo_no_puede_bajar_la_prioridad_de_un_incidente_critico(ctx):
    a = ctx[1]
    crit = next(i for i in a["incidents"] if i["severity"] == "Crítico")
    _, r = _run(ctx, [{"priority": "Mediano plazo", "action": f"Aislar el equipo {_ent(crit)} y revocar sus credenciales",
                       "incident_ids": [crit["id"]]}])
    act = next(x for x in r["prioritized_actions"] if x["incident_ids"] == [crit["id"]])
    assert act["priority"] == "Inmediata"
    assert act["action"].startswith("Aislar el equipo")


def test_toda_prioridad_sale_de_la_severidad_del_motor(ctx):
    a, r = _run(ctx, [])
    sev = {i["id"]: i["severity"] for i in a["incidents"]}
    for x in r["prioritized_actions"]:
        assert x["priority"] == PRIO[max((sev[i] for i in x["incident_ids"]), key=lambda s: ["Bajo", "Medio", "Alto", "Crítico"].index(s))]


def test_accion_que_mezcla_varios_incidentes_se_descarta(ctx):
    a = ctx[1]
    crit = next(i for i in a["incidents"] if i["severity"] == "Crítico")
    otro = next(i for i in a["incidents"] if i["severity"] != "Crítico")
    _, r = _run(ctx, [{"priority": "Inmediata", "action": f"Remediar {_ent(crit)} y {_ent(otro)} en conjunto y revisar todo",
                       "incident_ids": [otro["id"], crit["id"]]}])
    assert not any(len(x["incident_ids"]) > 1 for x in r["prioritized_actions"])
    assert {x["incident_ids"][0] for x in r["prioritized_actions"]} == {i["id"] for i in a["incidents"]}


def test_accion_sin_nada_concreto_del_incidente_se_reemplaza(ctx):
    a = ctx[1]
    inc = a["incidents"][0]
    _, r = _run(ctx, [{"priority": "Inmediata", "action": "Investigar el ataque y restaurar los datos afectados", "incident_ids": [inc["id"]]}])
    act = next(x for x in r["prioritized_actions"] if x["incident_ids"] == [inc["id"]])
    assert act["action"].startswith(inc["id"] + ":")


def test_todos_los_incidentes_quedan_cubiertos_aunque_el_modelo_mencione_pocos(ctx):
    a = ctx[1]
    first = a["incidents"][0]["id"]
    _, r = _run(ctx, [{"priority": "Inmediata", "action": "Contener el equipo afectado por la intrusión", "incident_ids": [first]}])
    cubiertos = {i for x in r["prioritized_actions"] for i in x["incident_ids"]}
    assert cubiertos == {i["id"] for i in a["incidents"]}


def test_acciones_genericas_o_sin_incidente_se_reemplazan_por_la_del_motor(ctx):
    a = ctx[1]
    first = a["incidents"][0]["id"]
    _, r = _run(ctx, [
        {"priority": "Inmediata", "action": "Tomar medidas para prevenir futuros ataques", "incident_ids": [first]},
        {"priority": "Inmediata", "action": "Aislar el servidor comprometido de la red", "incident_ids": []},
        {"priority": "Inmediata", "action": "Aislar un servidor", "incident_ids": ["INC-999"]},
    ])
    assert not any("futuros ataques" in x["action"] for x in r["prioritized_actions"])
    assert not any(x["action"].startswith("Aislar") and not x["incident_ids"] for x in r["prioritized_actions"])
    assert all(x["incident_ids"] for x in r["prioritized_actions"])
    assert next(x for x in r["prioritized_actions"] if x["incident_ids"] == [first])["action"].startswith(first)


def test_plan_ordenado_de_mayor_a_menor_prioridad(ctx):
    _, r = _run(ctx, [])
    orden = [ai.PRIORITY_ORDER[x["priority"]] for x in r["prioritized_actions"]]
    assert orden == sorted(orden)


def test_recomendaciones_genericas_se_descartan(ctx):
    _, r = _run(ctx, [], recs=["Revisar y actualizar las políticas de seguridad para prevenir futuros ataques",
                              "Realizar una auditoría de seguridad", "Habilitar MFA en accesos remotos."])
    assert r["general_recommendations"] == ["Habilitar MFA en accesos remotos."]


def test_si_todas_las_recomendaciones_son_genericas_se_usan_las_del_motor(ctx):
    _, r = _run(ctx, [], recs=["Implementar medidas de seguridad"])
    assert r["general_recommendations"] and not any("medidas de seguridad" in x for x in r["general_recommendations"][:1])


@pytest.mark.parametrize("txt,esperado", [
    ("Tomar medidas para prevenir futuros ataques", True),
    ("Implementar medidas de seguridad para prevenir ataques de inyección SQL.", True),
    ("Realizar una auditoría de seguridad", True),
    ("Remediar el incidente de ransomware.", True),
    ("Revisar la configuración de seguridad del sistema y asegurarse de que esté actualizada y configurada correctamente", True),
    ("Implementar un sistema de monitoreo y respuesta a incidentes más efectivo.", True),
    ("", True),
    ("Bloquear la IP externa 198.51.100.45 en el firewall perimetral", False),
    ("Habilitar MFA", False),
    ("Restaurar los archivos desde la copia de seguridad fuera de línea", False),
])
def test_is_generic(txt, esperado):
    assert ai.is_generic(txt) is esperado


def test_plan_por_hallazgo_rellena_columnas_genericas_con_el_playbook(ctx):
    df, a = ctx
    tocados = []

    def model(tool, text, mt):
        r = _fake_model(tool, text, mt)
        if tool["name"] != "submit_executive_report":
            for fa in r["findings"][:1]:
                tocados.append(fa["finding_id"])
                fa.update(technical_explanation="Explicación técnica válida del hallazgo.", impact="Impacto válido.",
                              investigate=["Implementar medidas de seguridad para prevenir futuros ataques."],
                              contain=["Bloquear la IP de origen en el firewall perimetral."], remediate=[])
        return r
    r = ai.generate(a, df, api_key=None, call=model)
    base = ai.build_deterministic(a)["findings"]
    assert tocados
    for first in tocados:
        plan = r["findings"][first]["action_plan"]
        assert r["findings"][first]["source"] == "ia"
        assert plan["investigate"] == base[first]["action_plan"]["investigate"]
        assert plan["contain"] == ["Bloquear la IP de origen en el firewall perimetral."]
        assert plan["remediate"] == base[first]["action_plan"]["remediate"]


def test_justificacion_que_repite_la_explicacion_se_cambia_por_la_de_las_reglas(ctx):
    df, a = ctx
    tocados = []
    txt = "Se detectó una ráfaga de intentos fallidos desde una IP externa seguida de acceso exitoso."

    def model(tool, text, mt):
        r = _fake_model(tool, text, mt)
        if tool["name"] != "submit_executive_report":
            for fa in r["findings"][:1]:
                tocados.append(fa["finding_id"])
                fa.update(technical_explanation=txt, severity_justification=txt, impact="Impacto válido.")
        return r
    r = ai.generate(a, df, api_key=None, call=model)
    base = ai.build_deterministic(a)["findings"]
    assert tocados
    for first in tocados:
        assert r["findings"][first]["source"] == "ia"
        assert r["findings"][first]["severity_justification"] == base[first]["severity_justification"]


@pytest.mark.parametrize("raw,esperado", [
    ("2026-11-04 10:08:59", "10:08:59"), ("2026-11-04T10:08:59Z", "10:08:59"), ("T10:08", "10:08"), ("123:45:678", ""), ("10:08:59", "10:08:59"), ("10:08", "10:08"), ("sin hora", ""), ("", ""),
])
def test_hora_de_la_cronologia_no_se_trunca(raw, esperado):
    assert ai._clock(raw) == esperado
