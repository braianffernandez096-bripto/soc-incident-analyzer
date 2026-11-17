"""El agente de Wazuh escapa los campos de Windows (barras invertidas duplicadas y comillas con barra). Tomado de la medición de tareas de
administración en un laboratorio real (docs/VALIDACION.md 3.1): sin deshacerlo, Sysmon y el registro de Seguridad daban dos cuentas
distintas para la misma persona y cada comando generaba dos hallazgos."""
import pandas as pd
import pytest

from backend import wazuh
from backend.analysis import analyze

B2 = "\\\\"   # dos barras: así llega del agente


def _ev(i, eid, ed):
    channel = "Security" if eid == "4688" else "Microsoft-Windows-Sysmon/Operational"
    return {"id": f"e{eid}-{i}", "timestamp": f"2026-11-17T17:43:{10 + i:02d}.000+0000",
            "rule": {"id": "0", "level": 0, "description": "Evento sin alerta (archives)"}, "agent": {"name": "WIN-A"},
            "data": {"win": {"system": {"eventID": eid, "channel": channel, "computer": "WIN-A"}, "eventdata": ed}}}


def _findings(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return analyze(df, {"format": "wazuh"})["findings"]


@pytest.mark.parametrize("raw,clean", [
    ("C:" + B2 + "Windows" + B2 + "cmd.exe", "C:\\Windows\\cmd.exe"),
    ("WIN-A" + B2 + "ana", "WIN-A\\ana"),
    ('sc.exe create X binPath= \\"C:' + B2 + 'x.exe\\"', 'sc.exe create X binPath= "C:\\x.exe"'),
    (B2 + B2 + "*" + B2 + "C$" + B2 + "Temp", "\\\\*\\C$\\Temp"),
    ("C:\\Windows\\cmd.exe", "C:\\Windows\\cmd.exe"),          # ya normal: no se toca
    ("\\\\servidor\\recurso", "\\\\servidor\\recurso"),        # ruta UNC normal: no se toca
])
def test_deshace_el_escapado_solo_si_viene_escapado(raw, clean):
    assert wazuh._unescape(raw) == clean


def test_sysmon_y_seguridad_son_la_misma_cuenta_y_un_solo_hallazgo():
    alerts = []
    for i, c in enumerate(["whoami /all", "ipconfig /all", "systeminfo", "net user"]):
        exe = c.split()[0] + ".exe"
        alerts.append(_ev(i, "4688", {"newProcessName": "C:" + B2 + "Windows" + B2 + exe, "commandLine": c, "subjectUserName": "ana",
                                       "subjectDomainName": "WIN-A", "newProcessId": hex(0x2700 + i), "processId": "0x2668"}))
        alerts.append(_ev(i, "1", {"image": "C:" + B2 + "Windows" + B2 + exe, "commandLine": c, "user": "WIN-A" + B2 + "ana",
                                    "parentImage": "C:" + B2 + "Windows" + B2 + "cmd.exe", "processGuid": f"{{g{i}}}", "parentProcessGuid": "{p}"}))
    disc = [f for f in _findings(alerts) if f["rule"] == "cmd_discovery"]
    assert len(disc) == 1 and len(disc[0]["evidence_ids"]) == 8
