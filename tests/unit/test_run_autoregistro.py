"""Claves Run: un programa instalado que se registra a sí mismo no es persistencia nueva; el resto sigue alertando.

Tomado de la medición de 24 horas en un laboratorio real (docs/VALIDACION.md 3.1). Los eventos llegan como los manda el agente de Wazuh,
con las barras invertidas duplicadas: antes de deshacer ese escapado, la regla de claves Run no veía nada en el modo Wazuh.
"""
import pandas as pd
import pytest

from backend import wazuh
from backend.analysis import analyze
from backend.detection import run_self_registration

B = "\\\\"   # una barra invertida tal como llega del agente (duplicada)
EDGE = f"C:{B}Program Files (x86){B}Microsoft{B}Edge{B}Application{B}msedge.exe"
RUN = f"HKU{B}S-1-5-21-1-2-3-1001{B}SOFTWARE{B}Microsoft{B}Windows{B}CurrentVersion{B}Run{B}"


def _ev(i, image, value, details, hours=0):
    return {"id": f"r{i}", "timestamp": f"2026-11-16T{19 + hours:02d}:02:{i:02d}.000+0000",
            "rule": {"id": "0", "level": 0, "description": "Evento sin alerta (archives)"}, "agent": {"name": "WIN-A"},
            "data": {"win": {"system": {"eventID": "13", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "WIN-A"},
                             "eventdata": {"eventType": "SetValue", "image": image, "targetObject": RUN + value, "details": details,
                                           "user": f"WIN-A{B}ana"}}}}


def _run_findings(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return [f for f in analyze(df, {"format": "wazuh"})["findings"] if f["rule"] == "persist_run"]


def test_edge_reescribiendo_su_inicio_cada_cuatro_horas_no_alerta():
    data = f'\\"{EDGE}\\" --no-startup-window --win-session-start'
    assert _run_findings([_ev(i, EDGE, "MicrosoftEdgeAutoLaunch_0A1B", data, hours=i % 4) for i in range(4)]) == []


def test_clave_run_escrita_con_reg_exe_alerta_aunque_llegue_escapada():
    """Antes del arreglo del escapado, esto no alertaba en el modo Wazuh."""
    f = _run_findings([_ev(0, f"C:{B}Windows{B}System32{B}reg.exe", "Updater", f"C:{B}Users{B}ana{B}AppData{B}Roaming{B}upd.exe")])
    assert f and f[0]["severity"] == "Alto"


@pytest.mark.parametrize("image,details", [
    # un programa de Program Files que hace arrancar otro ejecutable o un intérprete
    ("C:\\Program Files\\App\\setup.exe", '"C:\\Program Files\\App\\app.exe" /min'),
    ("C:\\Program Files\\App\\app.exe", "powershell.exe -w hidden -c iex(...)"),
    ("C:\\Program Files\\App\\app.exe", "C:\\Users\\ana\\AppData\\Local\\Temp\\x.exe"),
    # una carpeta «Program Files» falsa dentro del perfil del usuario
    ("C:\\Users\\ana\\Program Files\\App\\app.exe", '"C:\\Users\\ana\\Program Files\\App\\app.exe"'),
    # malware que se registra a sí mismo desde una ruta del usuario
    ("C:\\Users\\ana\\AppData\\Roaming\\x\\x.exe", '"C:\\Users\\ana\\AppData\\Roaming\\x\\x.exe"'),
])
def test_lo_que_no_es_autorregistro_sigue_alertando(image, details):
    assert not run_self_registration(image, details)


@pytest.mark.parametrize("details", [
    '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window',
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe --no-startup-window",
])
def test_autorregistro_con_o_sin_comillas(details):
    assert run_self_registration("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", details)
