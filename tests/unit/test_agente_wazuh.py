"""Las comprobaciones del propio agente de Wazuh no son reconocimiento.

Calibración tomada de la medición en un laboratorio real (docs/VALIDACION.md, 3.1): el módulo SCA del agente de Wazuh ejecuta como SYSTEM
«net user», «net1 user», «wmic useraccount … get Disabled» y «secedit /export» para evaluar el endurecimiento del equipo, cada vez que el
agente arranca. Eso disparaba «Comandos de reconocimiento». Ahora se sigue el árbol de procesos y se ignora el reconocimiento que desciende
del agente instalado en su carpeta oficial; el resto sigue alertando.
"""
from datetime import datetime, timedelta

import pandas as pd

from backend import wazuh
from backend.analysis import analyze

AGENT = r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
CMD = r"C:\Windows\System32\cmd.exe"
T0 = datetime(2026, 11, 16, 15, 37, 40)


def sysmon(i, image, cmd, parent, guid, pguid, user="NT AUTHORITY\\SYSTEM", t=0, pid="", ppid=""):
    ed = {"image": image, "commandLine": cmd, "parentImage": parent, "user": user, "processGuid": guid, "parentProcessGuid": pguid}
    if pid:
        ed.update(processId=pid, parentProcessId=ppid)
    return {"id": f"s{i}", "timestamp": (T0 + timedelta(seconds=t or i)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {"id": "61603", "level": 3, "description": "Sysmon - Process creation"}, "agent": {"name": "WIN10"},
            "data": {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "WIN10"},
                             "eventdata": ed}}}


def sec4688(i, new_name, cmd, creator, new_pid, creator_pid, t=0):
    return {"id": f"p{i}", "timestamp": (T0 + timedelta(seconds=t or i)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {"id": "60000", "level": 3, "description": "A new process has been created"}, "agent": {"name": "WIN10"},
            "data": {"win": {"system": {"eventID": "4688", "channel": "Security", "computer": "WIN10"},
                             "eventdata": {"newProcessName": new_name, "commandLine": cmd, "parentProcessName": creator, "subjectUserName": "WIN10$",
                                           "newProcessId": new_pid, "processId": creator_pid}}}}


def findings(alerts):
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return [f for f in analyze(df, {"format": "wazuh"})["findings"] if f["rule"] == "cmd_discovery"]


def sca_chain(parent=AGENT):
    """Lo que se vio en el laboratorio: agente → cmd → net → net1, y agente → cmd → wmic / secedit."""
    return [sysmon(0, CMD, "cmd.exe /c net user", parent, "{c1}", "{a0}"),
            sysmon(1, r"C:\Windows\System32\net.exe", "net user", CMD, "{n1}", "{c1}"),
            sysmon(2, r"C:\Windows\System32\net1.exe", r"C:\Windows\system32\net1 user", r"C:\Windows\System32\net.exe", "{m1}", "{n1}"),
            sysmon(3, r"C:\Windows\System32\wbem\WMIC.exe", 'wmic useraccount where (sid like "S-1-5-21-%-501") get Disabled', CMD, "{w1}", "{c2}"),
            sysmon(4, CMD, "cmd.exe /c wmic", parent, "{c2}", "{a0}"),
            sysmon(5, r"C:\Windows\System32\SecEdit.exe", r'"C:\Windows\system32\SecEdit.exe" /export /cfg C:\Windows\TEMP\secpol.cfg', CMD, "{e1}", "{c3}"),
            sysmon(6, CMD, "cmd.exe /c secedit", parent, "{c3}", "{a0}")]


def test_comprobaciones_del_agente_no_alertan_aunque_lleguen_desordenadas():
    assert findings(sca_chain()) == []


def test_mismo_nombre_en_otra_carpeta_sigue_alertando():
    assert findings(sca_chain(parent=r"C:\Users\Public\wazuh-agent.exe"))


def test_los_mismos_comandos_de_una_persona_siguen_alertando():
    alerts = [sysmon(i, r"C:\Windows\System32\net.exe", c, r"C:\Windows\explorer.exe", f"{{u{i}}}", "{x}", user="CORP\\ana")
              for i, c in enumerate(["net user", "whoami /all", "net localgroup administrators", "systeminfo"])]
    assert findings(alerts)


def test_cadena_por_numero_de_proceso_en_4688():
    alerts = [sec4688(0, CMD, "cmd.exe /c net user", AGENT, "0x1a0", "0x99"),
              sec4688(1, r"C:\Windows\System32\net.exe", "net user", CMD, "0x1b0", "0x1a0"),
              sec4688(2, r"C:\Windows\System32\net1.exe", r"C:\Windows\system32\net1 user", r"C:\Windows\System32\net.exe", "0x1c0", "0x1b0"),
              sec4688(3, r"C:\Windows\System32\whoami.exe", "whoami /all", CMD, "0x1d0", "0x1a0")]
    assert findings(alerts) == []


def test_numero_de_proceso_reutilizado_mucho_despues_no_hereda():
    alerts = [sec4688(0, CMD, "cmd.exe /c net user", AGENT, "0x1a0", "0x99"),
              # una hora después, el número 0x1a0 ya es otro proceso: lo que lance no es del agente
              *[sec4688(10 + i, r"C:\Windows\System32\net.exe", c, CMD, f"0x2{i}0", "0x1a0", t=3600 + i)
                for i, c in enumerate(["net user", "whoami /all", "net localgroup administrators", "systeminfo"])]]
    assert findings(alerts)


def test_el_agente_solo_se_exime_del_reconocimiento():
    alerts = sca_chain() + [sysmon(9, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                   "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", CMD, "{p9}", "{c1}")]
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    rules = {f["rule"] for f in analyze(df, {"format": "wazuh"})["findings"]}
    assert "cmd_encoded_ps" in rules and "cmd_discovery" not in rules


def test_cadena_que_mezcla_sysmon_decimal_y_4688_hexadecimal():
    """Lo que se vio en el laboratorio: el cmd.exe del agente lo registra Sysmon (número de proceso 6804) y a su hijo solo el 4688 (0x1a94)."""
    alerts = [sysmon(0, CMD, "cmd.exe /c net user", AGENT, "{c1}", "{a0}", pid="6804", ppid="512"),
              sec4688(1, r"C:\Windows\System32\net.exe", "net user", CMD, "0x1c00", "0x1a94"),
              sec4688(2, r"C:\Windows\System32\net1.exe", r"C:\Windows\system32\net1 user", r"C:\Windows\System32\net.exe", "0x1c10", "0x1c00"),
              sysmon(3, r"C:\Windows\System32\net1.exe", r"C:\Windows\system32\net1 user", r"C:\Windows\System32\net.exe", "{m1}", "{zz}",
                     pid="7184", ppid="7168"),
              sec4688(4, r"C:\Windows\System32\whoami.exe", "whoami /all", CMD, "0x1c20", "0x1a94")]
    assert findings(alerts) == []
