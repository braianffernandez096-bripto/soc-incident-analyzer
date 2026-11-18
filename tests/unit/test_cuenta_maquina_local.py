"""La cuenta de máquina del propio equipo («EQUIPO$») es SYSTEM local y no debe duplicar hallazgos.

Tomado de la simulación de ataque en un laboratorio real (docs/VALIDACION.md 3.2): un proceso como SYSTEM llega con dos grafías
—Sysmon «NT AUTHORITY\\SYSTEM» y el 4688 «DESKTOP-2C8LOKA$»— y cada hallazgo de comando aparecía dos veces.
"""
import pandas as pd

from backend import wazuh
from backend.analysis import analyze
from backend.detection import normalize_local_system

HOST = "DESKTOP-2C8LOKA"
CMD = r"C:\Windows\System32\cmd.exe"


def sysmon(i, image, cmd, t):
    return {"id": f"s{i}", "timestamp": t, "rule": {"id": "0", "level": 0, "description": "x"}, "agent": {"name": HOST},
            "data": {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": HOST},
                             "eventdata": {"image": image, "commandLine": cmd, "parentImage": CMD,
                                           "user": "NT AUTHORITY\\SYSTEM", "processGuid": f"{{g{i}}}", "parentProcessGuid": "{p}"}}}}


def sec4688(i, image, cmd, t):
    return {"id": f"p{i}", "timestamp": t, "rule": {"id": "0", "level": 0, "description": "x"}, "agent": {"name": HOST},
            "data": {"win": {"system": {"eventID": "4688", "channel": "Security", "computer": HOST},
                             "eventdata": {"newProcessName": image, "commandLine": cmd, "parentProcessName": CMD,
                                           "subjectUserName": f"{HOST}$", "subjectDomainName": "WORKGROUP",
                                           "newProcessId": hex(0x2700 + i), "processId": "0x2668"}}}}


def _findings(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return [f for f in analyze(df, {"format": "wazuh"})["findings"] if f["rule"] == "cmd_discovery"]


def test_system_y_cuenta_de_maquina_local_son_un_solo_hallazgo():
    cmds = ["whoami /all", "net user", "systeminfo", "ipconfig /all"]
    alerts = []
    for i, c in enumerate(cmds):
        t = f"2026-11-18T13:45:{10 + i:02d}.000+0000"
        image = rf"C:\Windows\System32\{c.split()[0]}.exe"
        alerts.append(sysmon(i, image, c, t))
        alerts.append(sec4688(i, image, c, t))
    disc = _findings(alerts)
    assert len(disc) == 1, [d["title"] for d in disc]
    assert "$" not in disc[0]["title"] and len(disc[0]["evidence_ids"]) == 8


def test_cuenta_de_maquina_de_otro_equipo_no_se_toca():
    df = pd.DataFrame([{"User": "OTRO-PC$", "Hostname": HOST}, {"User": f"{HOST}$", "Hostname": HOST},
                       {"User": "WORKGROUP\\" + HOST + "$", "Hostname": HOST}])
    out = normalize_local_system(df)
    assert list(out["User"]) == ["OTRO-PC$", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\SYSTEM"]
