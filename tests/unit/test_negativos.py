"""Pruebas negativas: actividad normal que NO debe generar hallazgos, cerca de los umbrales de cada regla.

Complementa a las pruebas con escenarios de ataque (que solo prueban que la regla dispara) y mide el lado contrario: el ruido.
Los casos marcados ``xfail(strict=True)`` son falsos positivos CONOCIDOS, medidos con datos normales (ver docs/VALIDACION.md): documentan
el comportamiento actual y, cuando se calibre la regla, la prueba pasa a verde y obliga a quitar la marca.
"""
import json
from datetime import datetime, timedelta

import pandas as pd
import pytest

from backend.analysis import analyze
from backend.parser import load_events

T0 = datetime(2026, 11, 2, 9, 0, 0)
WIN_COLS = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination", "Log_Source", "Event_Description",
            "Process_CommandLine", "Result", "Severity"]


def win(rows):
    """Export estilo SIEM de Windows (CSV) a partir de diccionarios cortos."""
    out = []
    for i, r in enumerate(rows):
        out.append(dict(Log_ID=f"E{i:05d}", Timestamp=(T0 + timedelta(seconds=r.get("t", i * 30))).strftime("%Y-%m-%d %H:%M:%S"),
                        Hostname=r.get("host", "WS-01"), Event_ID=str(r.get("eid", "4624")), User=r.get("user", "CORP\\ana"),
                        Source_IP=r.get("ip", "10.10.1.5"), Destination=r.get("dst", "DC-01"), Log_Source=r.get("src", "Security"),
                        Event_Description=r.get("desc", ""), Process_CommandLine=r.get("cmd", ""), Result=r.get("res", "Success"),
                        Severity=r.get("sev", "Informational")))
    return pd.DataFrame(out, columns=WIN_COLS).to_csv(index=False).encode(), "x.csv"


def gen(rows):
    """Export multi-fuente (JSON): cada fila (categoría, acción, estado, mensaje, opciones)."""
    out = []
    for i, (cat, action, status, msg, o) in enumerate(rows):
        out.append({"timestamp": (T0 + timedelta(seconds=o.get("t", i * 40))).strftime("%Y-%m-%dT%H:%M:%SZ"), "category": cat,
                    "user": o.get("user", "ana"), "source_ip": o.get("src", "10.0.1.5"), "destination_ip": o.get("dst", "10.0.1.50"),
                    "action": action, "status": status, "message": msg})
    return json.dumps(out).encode(), "x.json"


def rules(case):
    df, meta = load_events(*case)
    return sorted({f["rule"] for f in analyze(df, meta)["findings"]})


# ---------------------------------------------------------------- Windows
def _logons(n):
    return [dict(eid=4624, user=f"CORP\\u{i % 7}", ip=f"10.10.1.{i % 30 + 2}", desc="An account was successfully logged on") for i in range(n)]


WIN_NEGATIVE = {
    "dia_normal": win(_logons(120) + [dict(eid=7036, desc="Service entered running state", src="System") for _ in range(20)]),
    "2_fallos_externos": win([dict(eid=4625, ip="203.0.113.9", res="Failure", desc="failed") for _ in range(2)]),
    "9_fallos_internos": win([dict(eid=4625, ip="10.10.1.7", res="Failure", desc="failed", t=i * 20) for i in range(9)]),
    "fallos_espaciados": win([dict(eid=4625, ip="203.0.113.9", res="Failure", desc="failed", t=i * 700) for i in range(5)]),
    "logon_ip_privada": win([dict(eid=4624, ip="172.16.5.4"), dict(eid=4624, ip="192.168.1.9"), dict(eid=4624, ip="10.0.0.3")]),
    "privilegios_admin_interno": win([dict(eid=4624, user="CORP\\admin.ana", ip="10.10.1.9"),
                                      dict(eid=4672, user="CORP\\admin.ana", ip="10.10.1.9", desc="Special privileges assigned to new logon")]),
    "7_archivos_en_2_min": win([dict(eid=4663, desc="Accessed object", cmd=f"C:\\Docs\\f{i}.docx", t=i * 15) for i in range(7)]),
    "8_archivos_espaciados": win([dict(eid=4663, desc="Accessed object", cmd=f"C:\\Docs\\f{i}.docx", t=i * 300) for i in range(8)]),
    "share_no_sensible": win([dict(eid=5140, desc="Network share object accessed \\\\FS01\\Public")]),
    "powershell_con_script": win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="powershell.exe -File C:\\Scripts\\backup.ps1")]),
    "ping": win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="ping 8.8.8.8")]),
    "powershell_get_date": win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="powershell -NoProfile -Command Get-Date")]),
    "cmd_dir": win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="C:\\Windows\\System32\\cmd.exe /c dir")]),
    "navegador": win([dict(eid=4688, user="CORP\\ana", desc="process", cmd="C:\\Program Files\\Google\\Chrome\\chrome.exe") for _ in range(5)]),
    "hosts_coherentes": win([dict(eid=4624, host="WS-01"), dict(eid=4624, host="WS-02")]),
}


@pytest.mark.parametrize("name", WIN_NEGATIVE)
def test_windows_normal_activity_raises_nothing(name):
    assert rules(WIN_NEGATIVE[name]) == []


# ---------------------------------------------------------------- Multi-fuente (SSH, web, DNS, red, nube, Linux, endpoint)
def _web(n, msg, status="200"):
    return [("web_server", "http_request", status, msg(i), dict(user="guest", src=f"203.0.113.{i % 20 + 1}", dst="10.0.1.60")) for i in range(n)]


GEN_NEGATIVE = {
    "ssh_2_fallos_y_acceso": gen([("authentication", "ssh_login", "failed", "Invalid credentials", dict(src="203.0.113.5")),
                                  ("authentication", "ssh_login", "failed", "Invalid credentials", dict(src="203.0.113.5")),
                                  ("authentication", "ssh_login", "success", "Accepted", dict(src="203.0.113.5"))]),
    "ssh_accesos_normales": gen([("authentication", "ssh_login", "success", "Accepted publickey", dict(user=f"u{i % 4}", src=f"10.0.1.{i + 5}")) for i in range(20)]),
    "web_get_normales": gen(_web(60, lambda i: f"GET /products?page={i % 5}&sort=price")),
    "web_404_de_bots": gen([("web_server", "http_request", "404", "GET /favicon.ico", dict(user="guest", src="198.51.100.7", dst="10.0.1.60", t=i * 5)) for i in range(12)]),
    "dns_normal_y_cdn": gen([("dns", "dns_query", "resolved", f"A query for {h}", dict(user="system", src="10.0.2.55", dst="8.8.8.8"))
                             for h in ["www.google.com", "d111111abcdef8.cloudfront.net", "mail.company.com", "update.microsoft.com"] * 3]),
    "descarga_entrante_grande": gen([("network", "data_transfer", "success", "Inbound data transfer 450MB from 151.101.1.69", dict(src="151.101.1.69", dst="10.0.2.7"))]),
    "nube_llamadas_normales": gen([("cloud", "DescribeInstances", "success", "Listed instances", dict(user="ops-bot", src="198.51.100.10", dst="aws_api")) for _ in range(8)]),
    "nube_un_accessdenied": gen([("cloud", "DescribeInstances", "AccessDenied", "User not authorized", dict(user="ops-bot", src="198.51.100.10", dst="aws_api"))]),
    "linux_sudo_y_cron": gen([("process", "sudo", "success", "sudo apt update", dict(user="ana")),
                              ("process", "cron", "success", "CRON: (root) CMD (/usr/local/bin/backup.sh)", dict(user="root"))]),
    "lectura_etc_passwd": gen([("process", "file_read", "success", "Read /etc/passwd", dict(user="ana"))]),
    "adjunto_pdf_legitimo": gen([("email", "receive_email", "delivered", "Email with attachment informe_trimestral.pdf", dict(user="ana@company.com", src="93.184.216.34", dst="10.0.3.15")),
                                 ("endpoint", "file_execute", "success", "User opened informe_trimestral.pdf", dict(user="ana", src="10.0.3.15", dst="10.0.3.15"))]),
    "cpu_alta_compilacion": gen([("endpoint", "cpu_alert", "warning", "CPU utilization at 99.8% on core 0", dict(user="ci-runner", src="10.0.1.61", dst="10.0.1.61", t=i * 60)) for i in range(4)]),
    "renombrar_3_archivos": gen([("endpoint", "file_rename", "success", f"Renamed report{i}.docx to report{i}_v2.docx", dict(src="10.0.3.44", dst="10.0.3.44")) for i in range(3)]),
    "backup_crea_zips": gen([("endpoint", "file_create", "success", f"Created backup_{i}.zip", dict(user="svc_backup", src="10.0.3.44", dst="10.0.3.44")) for i in range(12)]),
    "acceso_c$_unico_de_ti": gen([("endpoint", "network_share_access", "success", "Access to C$ on 10.0.3.20", dict(user="it.admin", src="10.0.3.15", dst="10.0.3.20"))]),
}


@pytest.mark.parametrize("name", GEN_NEGATIVE)
def test_multisource_normal_activity_raises_nothing(name):
    assert rules(GEN_NEGATIVE[name]) == []


# ---------------------------------------------------------------- Falsos positivos conocidos (calibración pendiente)
KNOWN_FP = {
    "un_solo_ipconfig": (win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="ipconfig /all")]), {"cmd_discovery"}),
    "un_solo_whoami": (win([dict(eid=4688, user="CORP\\helpdesk", desc="process", cmd="whoami")]), {"cmd_discovery"}),
    "7z_de_un_usuario": (win([dict(eid=4688, user="CORP\\ana", desc="process", cmd="7z.exe a backup.7z C:\\Docs")]), {"cmd_archive_staging"}),
    "tarea_de_windows_update_como_SYSTEM": (win([dict(eid=4698, user="NT AUTHORITY\\SYSTEM",
                                                      desc="A scheduled task was created \\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan")]), {"persistence"}),
    "curl_a_repositorio_interno": (gen([("process", "process_start", "success", "curl -O http://repo.internal/tool.tar.gz",
                                         dict(user="dev", src="10.0.1.52", dst="10.0.1.52"))]), {"g_cmd"}),
}


@pytest.mark.parametrize("name", KNOWN_FP)
@pytest.mark.xfail(strict=True, reason="falso positivo conocido: la regla alerta con actividad normal (ver docs/VALIDACION.md)")
def test_known_false_positives(name):
    case, noisy = KNOWN_FP[name]
    assert not (set(rules(case)) & noisy)


# ---------------------------------------------------------------- Comportamiento intencional que conviene fijar
def test_failures_then_success_from_public_ip_is_flagged_on_purpose():
    """3 fallos + éxito desde una IP pública es justo el patrón de un ataque exitoso: se prefiere alertar (y que el analista descarte)."""
    case = win([dict(eid=4625, user="CORP\\ana", ip="203.0.113.9", res="Failure", desc="failed", t=i * 20) for i in range(3)]
               + [dict(eid=4624, user="CORP\\ana", ip="203.0.113.9", t=90)])
    assert {"brute_force", "external_logon"} <= set(rules(case))
