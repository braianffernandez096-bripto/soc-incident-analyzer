"""Movimiento lateral con eventos nativos de Windows: cada regla dispara con la técnica real y calla con la actividad legítima parecida.

Los eventos se arman como los exporta Windows a JSON (el formato de OTRF: «Message» con el texto del evento, más campos sueltos y el «host»
del colector) para que la prueba pase también por el parser. Al final, las mismas reglas con el formato de Wazuh.
Medición contra ataques reales: docs/VALIDACION.md (sección 2).
"""
import json
from datetime import datetime, timedelta

import pytest

from backend import wazuh
from backend.analysis import analyze
from backend.parser import load_events

T0 = datetime(2026, 11, 15, 10, 0, 0)
HOST = "WS-06.corp.local"
ATTACKER = "10.20.30.40"


def ev(eid, t, message, **extra):
    return {"@timestamp": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "EventID": eid, "Hostname": extra.pop("host", HOST),
            "host": "wec.collector.local", "Channel": extra.pop("channel", "Security"), "Message": message, **extra}


def logon(t, ip=ATTACKER, user="ana", ltype=3):
    return ev(4624, t, f"An account was successfully logged on.\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t{ltype}\r\n\r\nNew Logon:\r\n\tAccount Name:\t\t{user}\r\n"
              f"\r\nNetwork Information:\r\n\tSource Network Address:\t{ip}\r\n", IpAddress=ip, TargetUserName=user, LogonType=str(ltype))


def share(t, target, share_name="\\\\*\\IPC$", ip=ATTACKER, acct="ana", write=True):
    acc = "ReadData (or ListDirectory)\r\n\t\t\t\tWriteData (or AddFile)" if write else "ReadData (or ListDirectory)\r\n\t\t\t\tReadAttributes"
    return ev(5145, t, "A network share object was checked to see whether client can be granted desired access.\r\n\r\nSubject:\r\n"
              f"\tAccount Name:\t\t{acct}\r\n\r\nNetwork Information:\r\n\tSource Address:\t\t{ip}\r\n\r\nShare Information:\r\n"
              f"\tShare Name:\t\t{share_name}\r\n\tRelative Target Name:\t{target}\r\n\r\nAccess Request Information:\r\n\tAccesses:\t\t{acc}\r\n",
              IpAddress=ip, SubjectUserName=acct, ShareName=share_name, RelativeTargetName=target)


def proc(t, image, cmd, parent, user="CORP\\ana"):
    # Sysmon 1: el «Description» de Sysmon es la descripción del archivo, no el evento (el parser debe preferir «Message»)
    return ev(1, t, f"Process Create:\r\nImage: {image}\r\nCommandLine: {cmd}\r\nUser: {user}\r\nParentImage: {parent}\r\n",
              channel="Microsoft-Windows-Sysmon/Operational", Description="Some Windows component", Image=image, CommandLine=cmd, ParentImage=parent, User=user)


def service(t, name, binary):
    return ev(7045, t, f"A service was installed in the system.\r\n\r\nService Name:  {name}\r\nService File Name:  {binary}\r\nService Type:  user mode service\r\n",
              channel="System")


def findings(*events):
    df, meta = load_events(json.dumps(list(events)).encode(), "x.json")
    return analyze(df, meta)["findings"]


def by_rule(fs, rule):
    return [f for f in fs if f["rule"] == rule]


# ---------------------------------------------------------------- control remoto de servicios (svcctl)
def test_svcctl_desde_otro_equipo_y_servicio_nuevo_es_critico():
    fs = findings(logon(0), share(5, "svcctl"), service(20, "XYZSVC", "%COMSPEC% /C start /b powershell -enc AAAA"))
    f = by_rule(fs, "lat_svcctl")
    assert len(f) == 1 and f[0]["severity"] == "Crítico" and f[0]["mitre"] == ["T1021.002", "T1569.002"]
    assert f[0]["hosts"] == [HOST]                       # el equipo real, no el colector de logs


def test_svcctl_solo_consulta_es_alto():
    f = by_rule(findings(share(5, "svcctl")), "lat_svcctl")
    assert len(f) == 1 and f[0]["severity"] == "Alto"


@pytest.mark.parametrize("kwargs", [dict(ip="::1"), dict(ip="127.0.0.1"), dict(ip="fe80::1234:5678"), dict(acct="WS-06$")])
def test_svcctl_local_o_de_cuenta_de_maquina_no_alerta(kwargs):
    assert not by_rule(findings(share(5, "svcctl", **kwargs)), "lat_svcctl")


def test_otras_canalizaciones_ipc_no_son_svcctl():
    assert not by_rule(findings(share(5, "srvsvc"), share(6, "lsarpc")), "lat_svcctl")


# ---------------------------------------------------------------- copia de herramientas por C$ / ADMIN$
def test_escritura_de_ejecutable_en_c_dollar():
    f = by_rule(findings(share(5, "ProgramData\\tool.exe", share_name="\\\\*\\C$")), "lat_admin_write")
    assert len(f) == 1 and f[0]["mitre"] == ["T1021.002", "T1570"] and f[0]["severity"] == "Alto"


def test_dll_en_carpeta_del_sistema_lo_explica():
    f = by_rule(findings(share(5, "Windows\\System32\\evil.dll", share_name="\\\\*\\ADMIN$")), "lat_admin_write")
    assert f and any("secuestro de DLL" in r for r in f[0]["reasons"])


@pytest.mark.parametrize("target,write", [("ProgramData\\tool.exe", False), ("Users\\ana\\informe.docx", True), ("ProgramData", True)])
def test_lectura_o_documentos_en_c_dollar_no_alertan(target, write):
    assert not by_rule(findings(share(5, target, share_name="\\\\*\\C$", write=write)), "lat_admin_write")


def test_recurso_compartido_normal_no_es_administrativo():
    assert not by_rule(findings(share(5, "deploy\\tool.exe", share_name="\\\\*\\Software")), "lat_admin_write")


# ---------------------------------------------------------------- WMI
WMI = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"


def test_wmi_con_shell_y_sesion_remota_es_alto_y_lateral():
    fs = findings(logon(0), proc(10, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user backdoor P@ss /add", WMI))
    f = by_rule(fs, "lat_wmi")
    assert len(f) == 1 and f[0]["severity"] == "Alto" and f[0]["mitre"] == ["T1047"] and f[0]["category"] == "Movimiento lateral"


def test_wmi_local_con_proceso_comun_es_medio():
    f = by_rule(findings(proc(10, "C:\\Program Files\\Agent\\inventory.exe", "inventory.exe /scan", WMI)), "lat_wmi")
    assert len(f) == 1 and f[0]["severity"] == "Medio" and any("WMI local" in r for r in f[0]["reasons"])


def test_consumidor_wmi_de_script():
    f = by_rule(findings(proc(10, "C:\\Windows\\System32\\wbem\\scrcons.exe", "scrcons.exe -Embedding", "C:\\Windows\\System32\\svchost.exe")), "lat_wmi")
    assert f and "T1546.003" in f[0]["mitre"] and f[0]["severity"] == "Alto"


def test_hijos_habituales_de_wmi_no_alertan():
    fs = findings(proc(10, WMI, "wmiprvse.exe -secured -Embedding", "C:\\Windows\\System32\\svchost.exe"),
                  proc(11, "C:\\Windows\\System32\\WerFault.exe", "WerFault.exe -u -p 1234", WMI))
    assert not by_rule(fs, "lat_wmi")


# ---------------------------------------------------------------- PowerShell remoto (WinRM)
WSM = "C:\\Windows\\System32\\wsmprovhost.exe"


def test_sesion_winrm_sola_es_medio():
    f = by_rule(findings(logon(0), proc(5, WSM, "wsmprovhost.exe -Embedding", "C:\\Windows\\System32\\svchost.exe")), "lat_winrm")
    assert len(f) == 1 and f[0]["severity"] == "Medio" and f[0]["mitre"] == ["T1021.006"]


def test_winrm_con_powershell_oculto_es_alto():
    fs = findings(proc(5, WSM, "wsmprovhost.exe -Embedding", "C:\\Windows\\System32\\svchost.exe"),
                  proc(9, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -noP -sta -w 1 -enc SQBFAFgA", WSM))
    f = by_rule(fs, "lat_winrm")
    assert len(f) == 1 and f[0]["severity"] == "Alto"


# ---------------------------------------------------------------- DCOM
EXCEL = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"


def test_excel_por_dcom_tras_sesion_de_red():
    fs = findings(logon(0), proc(30, EXCEL, f'"{EXCEL}" /automation -Embedding', "C:\\Windows\\System32\\svchost.exe"))
    f = by_rule(fs, "lat_dcom")
    assert len(f) == 1 and f[0]["mitre"] == ["T1021.003"] and ATTACKER in f[0]["link_ips"]


def test_excel_por_com_sin_sesion_de_red_es_local():
    assert not by_rule(findings(proc(30, EXCEL, f'"{EXCEL}" /automation -Embedding', "C:\\Windows\\System32\\svchost.exe")), "lat_dcom")


def test_excel_abierto_por_el_usuario_no_es_dcom():
    fs = findings(logon(0), proc(30, EXCEL, f'"{EXCEL}" C:\\Users\\ana\\informe.xlsx', "C:\\Windows\\explorer.exe"))
    assert not by_rule(fs, "lat_dcom")


def test_sesion_de_red_lejana_no_se_asocia():
    fs = findings(logon(0), proc(3600, EXCEL, f'"{EXCEL}" /automation -Embedding', "C:\\Windows\\System32\\svchost.exe"))
    assert not by_rule(fs, "lat_dcom")


# ---------------------------------------------------------------- servicio remoto (estilo PsExec)
def test_servicio_con_powershell_codificado_tras_sesion_de_red_es_critico():
    fs = findings(logon(0), service(40, "Updater", "%COMSPEC% /C start /b powershell -noP -sta -w 1 -enc SQBFAFgA"))
    f = by_rule(fs, "lat_remote_service")
    assert len(f) == 1 and f[0]["severity"] == "Crítico" and f[0]["mitre"] == ["T1021.002", "T1569.002"]


def test_servicio_normal_o_sin_sesion_de_red_no_es_lateral():
    assert not by_rule(findings(logon(0), service(40, "Backup", "C:\\Program Files\\Backup\\agent.exe")), "lat_remote_service")
    assert not by_rule(findings(service(40, "Updater", "%COMSPEC% /C start /b powershell -enc AAAA")), "lat_remote_service")


# ---------------------------------------------------------------- formato de Wazuh
def _wz(eid, eventdata, channel="Security", n=0, t=0):
    return {"id": f"wz.{n}", "timestamp": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {"id": "60000", "level": 5, "description": "Windows"}, "agent": {"id": "001", "name": "WS-06"},
            "data": {"win": {"system": {"eventID": str(eid), "channel": channel, "computer": HOST}, "eventdata": eventdata}}}


def _wz_findings(alerts):
    import pandas as pd
    rows, _ = wazuh.normalize_alerts(alerts)
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return analyze(df, {"format": "wazuh"})["findings"]


def test_las_reglas_leen_el_formato_de_wazuh():
    alerts = [
        _wz(5145, {"subjectUserName": "ana", "ipAddress": ATTACKER, "shareName": "\\\\*\\IPC$", "relativeTargetName": "svcctl", "accessList": "%%4416 %%4417"}, n=1),
        _wz(5145, {"subjectUserName": "ana", "ipAddress": ATTACKER, "shareName": "\\\\*\\C$", "relativeTargetName": "ProgramData\\t.exe", "accessList": "%%4417"}, n=2, t=2),
        _wz(1, {"image": "C:\\Windows\\System32\\cmd.exe", "commandLine": "cmd.exe /c whoami", "parentImage": WMI, "user": "CORP\\ana"},
            channel="Microsoft-Windows-Sysmon/Operational", n=3, t=4),
    ]
    rules = {f["rule"] for f in _wz_findings(alerts)}
    assert {"lat_svcctl", "lat_admin_write", "lat_wmi"} <= rules
