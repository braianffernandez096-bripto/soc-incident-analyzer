"""Reglas de acceso a credenciales y persistencia basadas en Sysmon / 4662: casos de ataque y de actividad normal."""
from tests.unit.test_negativos import rules, win


def sysmon10(src, access, target="C:\\windows\\system32\\lsass.exe"):
    return dict(eid=10, src="Microsoft-Windows-Sysmon/Operational", user="",
                desc=f"Process accessed:\r\nRuleName: -\r\nSourceImage: {src}\r\nTargetImage: {target}\r\nGrantedAccess: {access}\r\n")


def sysmon13(image, target, details):
    return dict(eid=13, src="Microsoft-Windows-Sysmon/Operational", user="",
                desc=f"Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nImage: {image}\r\nTargetObject: {target}\r\nDetails: {details}\r\n")


def ev4662(account, guid):
    return dict(eid=4662, desc=f"An operation was performed on an object.\r\n\r\nSubject :\r\n\tAccount Name:\t\t{account}\r\n"
                               f"Operation:\r\n\tProperties:\t\tControl Access\r\n\t\t{{{guid}}}\r\n")


RUN = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"


def test_lsass_full_access_from_unusual_process_alerts():
    assert "cred_lsass" in rules(win([sysmon10("C:\\Users\\bob\\Downloads\\x.exe", "0x1fffff")]))


def test_lsass_access_by_routine_windows_components_is_quiet():
    rows = [sysmon10("C:\\windows\\system32\\svchost.exe", "0x1000"), sysmon10("C:\\Program Files\\VBox\\VBoxService.exe", "0x1400"),
            sysmon10("C:\\windows\\system32\\wbem\\wmiprvse.exe", "0x1410"), sysmon10("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "0x40")]
    assert not {"cred_lsass"} & set(rules(win(rows)))


def test_access_to_other_process_is_ignored():
    assert "cred_lsass" not in rules(win([sysmon10("C:\\Users\\bob\\x.exe", "0x1fffff", target="C:\\windows\\explorer.exe")]))


def test_dcsync_by_user_account_alerts():
    assert "cred_dcsync" in rules(win([ev4662("pgustavo", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")]))


def test_replication_by_domain_controller_machine_account_is_quiet():
    assert "cred_dcsync" not in rules(win([ev4662("DC-02$", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")]))


def test_unrelated_4662_is_quiet():
    assert "cred_dcsync" not in rules(win([ev4662("ana", "bf967a86-0de6-11d0-a285-00c04fd8d6c4")]))


def test_run_key_from_temp_is_high():
    case = win([sysmon13("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", RUN, "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe")])
    from backend.analysis import analyze
    from backend.parser import load_events
    f = [x for x in analyze(*load_events(*case))["findings"] if x["rule"] == "persist_run"]
    assert f and f[0]["severity"] == "Alto"


def test_run_key_from_installer_is_medium_not_silent():
    from backend.analysis import analyze
    from backend.parser import load_events
    case = win([sysmon13("C:\\Program Files\\App\\setup.exe", RUN, "C:\\Program Files\\App\\app.exe")])
    f = [x for x in analyze(*load_events(*case))["findings"] if x["rule"] == "persist_run"]
    assert f and f[0]["severity"] == "Medio"


def test_non_run_registry_write_is_quiet():
    case = win([sysmon13("C:\\windows\\system32\\lsass.exe", "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\SecureTimeLimits\\RunTime\\x", "QWORD (0x1)")])
    assert "persist_run" not in rules(case)
