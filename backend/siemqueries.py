"""Consultas para el SIEM del analista (Splunk SPL y KQL de Sentinel/Defender) y reglas Sigma a partir de un hallazgo.

Sirven para **buscar lo mismo en el SIEM real** (cazar el patrón en más equipos o más tiempo) y para llevar la detección a otra plataforma.
Se generan con plantillas deterministas, sin IA y sin salir a Internet. Los nombres de campos siguen los de Splunk Add-on for Windows y de la
tabla ``SecurityEvent``/``Event`` de Sentinel; cada SIEM puede nombrarlos distinto, por eso la interfaz recuerda revisar índice y campos.

Splunk y KQL solo cubren las reglas de Windows con un equivalente directo. Para las demás fuentes (SSH, web, DNS, Linux, nube) se genera
**solo Sigma**, que usa nombres de campo estándar (``webserver``, ``dns``, ``process_creation``…) y cada SIEM traduce a los suyos. Calidad de
datos, exfiltración y comando y control (``g_exfil``, ``g_c2``) no tienen regla: dependen de flujos de red o de inteligencia de amenazas.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import timedelta

import pandas as pd

from . import detection as D
from .detection_generic import _IAM_PRIV

SYSMON_SPL = 'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
SEC_SPL = 'sourcetype="WinEventLog:Security"'
PAD = timedelta(minutes=30)
NS = uuid.UUID("6f1f0f5e-3a55-4c8e-9a41-2f6b6b7a1c01")

# --------------------------------------------------------------------------
# escapes: los valores vienen de los logs, nunca se pegan sin escapar
# --------------------------------------------------------------------------
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(v) -> str:
    return _CTRL.sub(" ", str(v)).strip()[:200]


def q(v) -> str:
    """Literal entre comillas dobles válido en SPL y en KQL."""
    return '"' + _clean(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def rx(pattern: str) -> str:
    """Una expresión regular como literal entre comillas dobles (SPL y KQL)."""
    return '"' + pattern.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ts(v) -> pd.Timestamp:
    return pd.Timestamp(v)


def _window(f: dict) -> tuple[pd.Timestamp, pd.Timestamp]:
    return _ts(f["time_start"]) - PAD, _ts(f["time_end"]) + PAD


def _spl_time(f: dict) -> str:
    a, b = _window(f)
    return f'earliest="{a:%m/%d/%Y:%H:%M:%S}" latest="{b:%m/%d/%Y:%H:%M:%S}"'


def _kql_time(f: dict) -> str:
    a, b = _window(f)
    return f"TimeGenerated between (datetime({a:%Y-%m-%d %H:%M:%S}) .. datetime({b:%Y-%m-%d %H:%M:%S}))"


def _host(f: dict) -> str:
    return (f.get("hosts") or [""])[0].split(".")[0]


def _user(f: dict) -> str:
    u = (f.get("actor_users") or f.get("users") or [""])[0]
    return u.split("\\")[-1]


def _ip(f: dict) -> str:
    return (f.get("link_ips") or f.get("ips") or [""])[0]


_LOOKAHEAD_PAIR = re.compile(r"\(\?=\[\^\\n\]\*([^()]+)\)\(\?=\[\^\\n\]\*([^()]+)\)")


def _re2(pattern: str) -> str:
    """Sigma (pySigma), Splunk y KQL usan motores RE2/PCRE sin «mirar adelante»: dos condiciones en cualquier orden, ``(?=…A)(?=…B)``, se
    reescriben como ``A…B`` o ``B…A``. La app sí usa el patrón original; esto solo cambia lo que se exporta."""
    return _LOOKAHEAD_PAIR.sub(lambda m: rf"[^\n]*(?:{m.group(1)}[^\n]*{m.group(2)}|{m.group(2)}[^\n]*{m.group(1)})", pattern)


def _cmd_regex(key: str) -> str:
    p = next((x for x in D.CMD_PATTERNS if x["key"] == key), None)
    if key == "web_service_shell":
        return r"\b(cmd|powershell|pwsh|wscript|cscript|whoami)(\.exe)?\b"
    return _re2(p["rx"].pattern) if p and p["rx"] is not None else ""


# --------------------------------------------------------------------------
# datos compartidos por Sigma, SPL y KQL
# --------------------------------------------------------------------------
LSASS_MASKS = sorted(D.LSASS_DUMP_MASKS)
LSASS_BENIGN = sorted(D.LSASS_BENIGN_SOURCES)
RUN_RE = r"\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?\\"
CMD_KEYS = {"cmd_encoded_ps": "encoded_ps", "cmd_discovery": "discovery", "cmd_archive_staging": "archive_staging",
            "cmd_anti_recovery": "anti_recovery", "cmd_cred_dump": "cred_dump", "cmd_download_cradle": "download_cradle",
            "cmd_web_service_shell": "web_service_shell", "cmd_lolbin_proxy": "lolbin_proxy", "cmd_log_tamper": "log_tamper",
            "cmd_fw_change": "fw_change", "cmd_service_binpath": "service_binpath", "cmd_logon_script": "logon_script"}


# --------------------------------------------------------------------------
# Splunk y KQL por regla
# --------------------------------------------------------------------------
def _splunk(f: dict) -> str | None:
    r, t, h, u, ip = f["rule"], _spl_time(f), _host(f), _user(f), _ip(f)
    host = f" host={q(h + '*')}" if h else ""
    if r == "brute_force":
        return (f'index=wineventlog {SEC_SPL} EventCode=4625 src_ip={q(ip)} {t}\n'
                '| stats count AS fallos dc(user) AS cuentas min(_time) AS primero max(_time) AS ultimo values(user) AS usuarios BY src_ip\n'
                '| convert ctime(primero) ctime(ultimo)')
    if r == "external_logon":
        return (f'index=wineventlog {SEC_SPL} EventCode=4624 src_ip={q(ip)} {t}\n'
                '| table _time host user Logon_Type src_ip\n| sort _time')
    if r == "privilege":
        return f'index=wineventlog {SEC_SPL} EventCode=4672 user={q("*" + u)}{host} {t}\n| table _time host user Privileges'
    if r == "lateral":
        return (f'index=wineventlog {SEC_SPL} EventCode=4624 Logon_Type=3 user={q("*" + u)}{host} {t}\n'
                '| table _time host user src_ip Workstation_Name\n| sort _time')
    if r in CMD_KEYS:
        pat = _cmd_regex(CMD_KEYS[r])
        user = f" user={q('*' + u)}" if (u and r != "cmd_web_service_shell") else ""
        return (f'index=wineventlog (EventCode=4688 OR EventCode=4104){host}{user} {t}\n'
                '| eval cmd=coalesce(Process_Command_Line, CommandLine, ScriptBlockText, Message)\n'
                f'| regex cmd={rx("(?i)" + pat)}\n| table _time host user cmd')
    if r == "cred_lsass":
        ben = ", ".join(q("*\\" + x) for x in LSASS_BENIGN)
        masks = " OR ".join(f"GrantedAccess={q(m)}" for m in LSASS_MASKS)
        return (f'index=sysmon {SYSMON_SPL} EventCode=10 TargetImage={q("*\\lsass.exe")} ({masks}){host} {t}\n'
                f'| search NOT SourceImage IN ({ben})\n| table _time host SourceImage TargetImage GrantedAccess')
    if r == "cred_dcsync":
        g = " OR ".join(f'Properties={q("*" + x + "*")}' for x in D.DCSYNC_GUIDS)
        return (f'index=wineventlog {SEC_SPL} EventCode=4662 ({g}) {t}\n'
                '| search NOT Account_Name="*$"\n| table _time host Account_Name Properties')
    if r == "kerberoast":
        return (f'index=wineventlog {SEC_SPL} EventCode=4769 Ticket_Encryption_Type=0x17 {t}\n'
                '| search NOT Service_Name="*$" NOT Service_Name="krbtgt*"\n'
                '| stats dc(Service_Name) AS servicios values(Service_Name) AS lista count BY Account_Name src_ip\n| where servicios>=3')
    if r == "persist_run":
        return (f'index=sysmon {SYSMON_SPL} EventCode=13 {host} {t}\n'
                f'| regex TargetObject={rx("(?i)" + RUN_RE)}\n| table _time host Image TargetObject Details')
    if r == "persistence":
        return (f'index=wineventlog (EventCode=4698 OR EventCode=7045){host} {t}\n'
                '| table _time host user EventCode Task_Name Service_Name Service_File_Name')
    if r == "outbound_shell":
        return (f'index=wineventlog {SEC_SPL} EventCode=5156 Direction=Outbound dest_ip={q(ip)}{host} {t}\n'
                '| table _time host Application src_ip dest_ip dest_port')
    if r == "sensitive_share":
        return (f'index=wineventlog (EventCode=5140 OR EventCode=5145){host} user={q("*" + u)} {t}\n'
                '| stats count values(Share_Name) AS recursos BY user src_ip host')
    if r == "mass_access":
        return (f'index=wineventlog {SEC_SPL} EventCode=4663 user={q("*" + u)}{host} {t}\n'
                '| bin _time span=2m\n| stats dc(Object_Name) AS archivos BY _time host user\n| where archivos>=8')
    return None


def _kql(f: dict) -> str | None:
    r, t, h, u, ip = f["rule"], _kql_time(f), _host(f), _user(f), _ip(f)
    comp = f'\n| where Computer startswith {q(h)}' if h else ""
    if r == "brute_force":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4625 and IpAddress == {q(ip)}\n'
                '| summarize Fallos=count(), Cuentas=dcount(TargetUserName), Primero=min(TimeGenerated), Ultimo=max(TimeGenerated),\n'
                '            Usuarios=make_set(TargetUserName, 20) by IpAddress')
    if r == "external_logon":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4624 and IpAddress == {q(ip)}\n'
                '| project TimeGenerated, Computer, TargetUserName, LogonType, IpAddress\n| order by TimeGenerated asc')
    if r == "privilege":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4672 and SubjectUserName =~ {q(u)}{comp}\n'
                '| project TimeGenerated, Computer, SubjectUserName, PrivilegeList')
    if r == "lateral":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4624 and LogonType == 3 and TargetUserName =~ {q(u)}{comp}\n'
                '| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName\n| order by TimeGenerated asc')
    if r in CMD_KEYS:
        pat = _cmd_regex(CMD_KEYS[r])
        user = f'\n| where Account endswith {q(chr(92) + u)}' if (u and r != "cmd_web_service_shell") else ""
        return ('union\n  (SecurityEvent | where EventID == 4688 | extend Cmd = CommandLine),\n'
                '  (Event | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104 | extend Cmd = RenderedDescription, Account = UserName)\n'
                f'| where {t}{comp}{user}\n| where Cmd matches regex {rx("(?i)" + pat)}\n| project TimeGenerated, Computer, Account, Cmd')
    if r == "cred_lsass":
        ben = "|".join(re.escape(x) for x in LSASS_BENIGN)
        return ('Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID == 10\n'
                f'| where {t}{comp}\n'
                '| extend Src = extract(@"(?i)SourceImage:\\s*(\\S+)", 1, RenderedDescription),\n'
                '         Mask = tolower(extract(@"(?i)GrantedAccess:\\s*(\\S+)", 1, RenderedDescription))\n'
                '| where RenderedDescription matches regex @"(?i)TargetImage:\\s*\\S*\\\\lsass\\.exe"\n'
                f'| where Mask in ({", ".join(q(m) for m in LSASS_MASKS)})\n'
                f'| where not(Src matches regex {rx("(?i)\\\\(" + ben + ")$")})\n| project TimeGenerated, Computer, Src, Mask')
    if r == "cred_dcsync":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4662\n'
                f'| where Properties has_any ({", ".join(q(x) for x in D.DCSYNC_GUIDS)})\n'
                '| where SubjectUserName !endswith "$"\n| project TimeGenerated, Computer, SubjectUserName, Properties')
    if r == "kerberoast":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4769 and TicketEncryptionType == "0x17"\n'
                '| where ServiceName !endswith "$" and ServiceName !startswith "krbtgt"\n'
                '| summarize Servicios=dcount(ServiceName), Lista=make_set(ServiceName, 20), Tickets=count() by TargetUserName, IpAddress\n| where Servicios >= 3')
    if r == "persist_run":
        return ('Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID == 13\n'
                f'| where {t}{comp}\n| where RenderedDescription matches regex {rx("(?i)TargetObject:.*" + RUN_RE)}\n'
                '| project TimeGenerated, Computer, RenderedDescription')
    if r == "persistence":
        return ('union\n  (SecurityEvent | where EventID == 4698 | extend Detalle = tostring(EventData)),\n'
                '  (Event | where EventID == 7045 | extend Detalle = RenderedDescription)\n'
                f'| where {t}{comp}\n| project TimeGenerated, Computer, EventID, Detalle')
    if r == "outbound_shell":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 5156 and DestAddress == {q(ip)}{comp}\n'
                '| project TimeGenerated, Computer, Application, SourceAddress, DestAddress, DestPort')
    if r == "sensitive_share":
        return (f'SecurityEvent\n| where {t}\n| where EventID in (5140, 5145) and SubjectUserName =~ {q(u)}{comp}\n'
                '| summarize Accesos=count(), Recursos=make_set(ShareName, 20) by SubjectUserName, IpAddress, Computer')
    if r == "mass_access":
        return (f'SecurityEvent\n| where {t}\n| where EventID == 4663 and SubjectUserName =~ {q(u)}{comp}\n'
                '| summarize Archivos=dcount(ObjectName) by bin(TimeGenerated, 2m), Computer, SubjectUserName\n| where Archivos >= 8')
    return None


# --------------------------------------------------------------------------
# Sigma
# --------------------------------------------------------------------------
def _y(obj, ind: int = 0) -> str:
    pad = "  " * ind
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:\n{_y(v, ind + 1)}")
            else:
                out.append(f"{pad}{k}: {_y(v)}")
        return "\n".join(out)
    if isinstance(obj, list):
        out = []
        for v in obj:
            if isinstance(v, dict):
                body = _y(v, ind + 1).split("\n")
                out.append(f"{pad}- {body[0].lstrip()}" + ("\n" + "\n".join(body[1:]) if len(body) > 1 else ""))
            else:
                out.append(f"{pad}- {_y(v)}")
        return "\n".join(out)
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return str(obj)
    return json.dumps(str(obj), ensure_ascii=False)


def _tags(mitre: list[str]) -> list[str]:
    return ["attack." + t.lower() for t in mitre]


def _sigma_specs() -> dict[str, dict]:
    specs: dict[str, dict] = {}
    titles = {
        "cmd_encoded_ps": ("PowerShell codificado u ofuscado", "high", ["T1059.001", "T1027"]),
        "cmd_discovery": ("Comandos de reconocimiento de cuentas y recursos", "low", ["T1087", "T1069", "T1135"]),
        "cmd_archive_staging": ("Compresión de datos antes de sacarlos (staging)", "medium", ["T1560.001", "T1074.001"]),
        "cmd_anti_recovery": ("Eliminación de copias de sombra", "critical", ["T1490"]),
        "cmd_cred_dump": ("Volcado de credenciales por línea de comandos", "critical", ["T1003"]),
        "cmd_download_cradle": ("Descarga y ejecución de código remoto", "high", ["T1105", "T1059.001"]),
        "cmd_lolbin_proxy": ("Ejecución mediante un programa de confianza (mshta, cmstp, InstallUtil…)", "high", ["T1218", "T1220"]),
        "cmd_log_tamper": ("Auditoría o registro de eventos desactivado o alterado", "high", ["T1685.001", "T1685.005"]),
        "cmd_fw_change": ("Regla de firewall que abre el tráfico entrante o lo desactiva", "medium", ["T1686"]),
        "cmd_service_binpath": ("Servicio creado o modificado desde la línea de comandos", "medium", ["T1543.003"]),
        "cmd_logon_script": ("Script de inicio de sesión (UserInitMprLogonScript)", "high", ["T1037.001"]),
    }
    for rule, (title, level, mitre) in titles.items():
        pat = _cmd_regex(CMD_KEYS[rule])
        if not pat:
            continue
        specs[rule] = dict(title=title, level=level, mitre=mitre, logsource={"category": "process_creation", "product": "windows"},
                           detection={"selection": {"CommandLine|re": "(?i)" + pat}, "condition": "selection"},
                           fields=["CommandLine", "Image", "User", "ParentImage"],
                           desc=f"{title}. Generada por SOC Incident Analyzer a partir de la regla «{rule}».")
    specs["cred_lsass"] = dict(
        title="Acceso a la memoria de LSASS por un proceso no habitual", level="critical", mitre=["T1003.001"],
        logsource={"category": "process_access", "product": "windows"},
        detection={"selection": {"TargetImage|endswith": "\\lsass.exe", "GrantedAccess": LSASS_MASKS},
                   "filter_windows": {"SourceImage|endswith": [("\\" + x) for x in LSASS_BENIGN]},
                   "condition": "selection and not filter_windows"},
        fields=["SourceImage", "TargetImage", "GrantedAccess"], desc="Un proceso fuera de los componentes habituales abre lsass.exe con permisos de lectura de memoria.")
    specs["cred_dcsync"] = dict(
        title="DCSync: derechos de replicación usados por una cuenta de usuario", level="critical", mitre=["T1003.006"],
        logsource={"product": "windows", "service": "security"},
        detection={"selection": {"EventID": 4662, "Properties|contains": list(D.DCSYNC_GUIDS)},
                   "filter_machine": {"SubjectUserName|endswith": "$"}, "condition": "selection and not filter_machine"},
        fields=["SubjectUserName", "Properties"], desc="Solo los controladores de dominio (cuentas de máquina) deberían pedir estos derechos.")
    specs["kerberoast"] = dict(
        title="Kerberoasting: tickets de servicio RC4 solicitados en ráfaga", level="high", mitre=["T1558.003"],
        logsource={"product": "windows", "service": "security"},
        detection={"selection": {"EventID": 4769, "TicketEncryptionType": "0x17"},
                   "filter_machine": {"ServiceName|endswith": "$"}, "filter_krbtgt": {"ServiceName|startswith": "krbtgt"},
                   "condition": "selection and not filter_machine and not filter_krbtgt"},
        fields=["TargetUserName", "ServiceName", "IpAddress"], falsepositives=["Aplicaciones antiguas que solo soportan RC4; se distingue por la ráfaga hacia varios servicios"],
        desc="Una cuenta pide tickets de servicio con RC4 hacia varios servicios de usuario. Combínala con un conteo por cuenta (≥3 servicios en 10 min).")
    specs["persist_run"] = dict(
        title="Valor nuevo en las claves Run/RunOnce", level="medium", mitre=["T1547.001"],
        logsource={"category": "registry_set", "product": "windows"},
        detection={"selection": {"TargetObject|re": "(?i)" + RUN_RE}, "condition": "selection"},
        fields=["Image", "TargetObject", "Details"], falsepositives=["Instaladores legítimos de software"],
        desc="Programa de inicio automático agregado al registro.")
    specs["persistence"] = dict(
        title="Tarea programada o servicio nuevo", level="medium", mitre=["T1053.005", "T1543.003"],
        logsource={"product": "windows", "service": "security"},
        detection={"selection_task": {"EventID": 4698}, "filter_windows_tasks": {"SubjectUserName|endswith": "SYSTEM", "TaskName|startswith": "\\Microsoft\\Windows\\"},
                   "condition": "selection_task and not filter_windows_tasks"},
        fields=["TaskName", "SubjectUserName"], falsepositives=["Software que crea tareas propias al instalarse"],
        desc="Creación de una tarea programada (4698) fuera de las propias de Windows. Los servicios nuevos (7045) van en el registro System.")
    specs["external_logon"] = dict(
        title="Inicio de sesión de red o RDP desde una IP pública", level="medium", mitre=["T1078"],
        logsource={"product": "windows", "service": "security"},
        detection={"selection": {"EventID": 4624, "LogonType": [3, 10]},
                   "filter_private": {"IpAddress|cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]},
                   "filter_empty": {"IpAddress": "-"},
                   "condition": "selection and not filter_private and not filter_empty"},
        fields=["TargetUserName", "IpAddress", "LogonType"], falsepositives=["Usuarios remotos legítimos con VPN o RDP expuesto"],
        desc="Autenticación exitosa desde fuera de las redes privadas.")
    specs["privilege"] = dict(
        title="Privilegios especiales asignados a un inicio de sesión", level="low", mitre=["T1078", "T1134"],
        logsource={"product": "windows", "service": "security"},
        detection={"selection": {"EventID": 4672, "PrivilegeList|contains": ["SeDebugPrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege"]},
                   "condition": "selection"},
        fields=["SubjectUserName", "PrivilegeList"], falsepositives=["Cuentas administrativas en uso normal; conviene combinarla con un origen externo"],
        desc="Muy ruidosa por sí sola: úsala para correlacionar, no como alerta aislada.")

    # ---- otras fuentes: solo Sigma (campos estándar de Sigma; el SIEM los traduce a los suyos) -----------------------------------------
    def add(rule, title, level, mitre, logsource, detection, desc, fields=(), fp=None):
        specs[rule] = dict(title=title, level=level, mitre=mitre, logsource=logsource, detection=detection, fields=list(fields), desc=desc)
        if fp:
            specs[rule]["falsepositives"] = fp

    add("g_auth", "Fallo de autenticación SSH (sshd)", "low", ["T1110.001", "T1110.003"],
        {"product": "linux", "service": "sshd"},
        {"selection": ["Failed password for", "Invalid user", "authentication failure"], "condition": "selection"},
        "Cada fallo de inicio de sesión por SSH. Un solo fallo es normal: la detección de fuerza bruta o password spraying es el conteo "
        "(3 o más fallos desde la misma IP en 10 minutos) y, sobre todo, un acceso exitoso desde esa IP después de los fallos.",
        ["Message"], ["Usuarios que se equivocan de clave; revisa la IP de origen y si hubo un acceso exitoso posterior"])
    add("g_web", "Petición web con patrones de ataque (SQL, rutas, XSS, Log4Shell, webshell)", "medium", ["T1190"],
        {"category": "webserver"},
        {"selection": {"cs-uri-query|contains": [
            "union select", "' or '", " or 1=1", "or%201=1", "%27%20or%20", "information_schema", "sleep(", "; drop ",
            "../", "..%2f", "%2e%2e%2f", "/etc/passwd", "win.ini",
            "<script", "%3cscript", "javascript:", "onerror=",
            "${jndi:", "cmd=", "/bin/sh", "/bin/bash", "exec("]}, "condition": "selection"},
        "Peticiones HTTP con los mismos patrones que usa la app: inyección SQL, recorrido de rutas, XSS, Log4Shell y ejecución de comandos. "
        "Una ráfaga desde la misma IP y una respuesta 200 aumentan la confianza; un solo intento suele ser un escáner.",
        ["c-ip", "cs-uri-stem", "cs-uri-query", "sc-status"], ["Escáneres de vulnerabilidades autorizados; pruebas del propio equipo"])
    add("g_dns_tunnel", "Consulta DNS con un subdominio largo y aleatorio (posible túnel DNS)", "medium", ["T1071.004"],
        {"category": "dns"},
        {"selection": {"query|re": "(?i)(^|\\.)[a-z0-9]{6,}[0-9][a-z0-9]{5,}(\\.[a-z0-9-]+){2,}$"}, "condition": "selection"},
        "Una etiqueta de 12 o más caracteres alfanuméricos con al menos un dígito, delante del dominio (la app además mide la entropía, que Sigma no puede calcular). "
        "Un solo nombre así es normal; un túnel DNS genera muchos: cuenta 5 o más consultas distintas al mismo dominio desde el mismo host.",
        ["query", "src_ip"], ["Servicios de antivirus o CDN que consultan nombres con hash; valida el dominio"])
    add("g_mining", "Minería de criptomonedas (xmrig, stratum, pools)", "high", ["T1496.001"],
        {"category": "process_creation", "product": "linux"},
        {"selection_img": {"Image|endswith": ["/xmrig", "/minerd", "/cpuminer"]},
         "selection_cmd": {"CommandLine|contains": ["stratum+tcp://", "stratum+ssl://", "--donate-level", "pool.minexmr", "xmrig"]},
         "condition": "1 of selection_*"},
        "Proceso o línea de comandos típicos de un minero. Suele ir acompañado de CPU al ~100 % sostenida y de conexiones a un pool.",
        ["Image", "CommandLine", "User"], ["Minería autorizada por la organización (poco habitual)"])
    add("g_privesc", "Lectura de archivos de credenciales en Linux", "medium", ["T1003.008", "T1552.001"],
        {"category": "process_creation", "product": "linux"},
        {"selection_img": {"Image|endswith": ["/cat", "/less", "/more", "/head", "/tail", "/cp", "/base64", "/xxd"]},
         "selection_file": {"CommandLine|contains": ["/etc/shadow", "/etc/sudoers", "id_rsa", ".aws/credentials"]},
         "condition": "selection_img and selection_file"},
        "Un usuario lee o copia archivos con contraseñas o claves. Es más grave si viene después de un cambio a root (SUID).",
        ["Image", "CommandLine", "User"], ["Administración legítima; valida el usuario y el momento"])
    add("g_persistence_linux", "Persistencia en Linux: cron o claves SSH autorizadas", "medium", ["T1098.004", "T1053.003"],
        {"category": "process_creation", "product": "linux"},
        {"selection": {"CommandLine|contains": ["| crontab -", "/etc/cron.d/", "/etc/crontab", "authorized_keys"]}, "condition": "selection"},
        "Una tarea cron nueva o una clave agregada a authorized_keys permiten volver a entrar aunque cambien la contraseña.",
        ["Image", "CommandLine", "User"], ["Gestión de claves y tareas por el administrador o por herramientas de configuración"])
    add("g_ransomware", "Ransomware: nota de rescate o archivos cifrados", "critical", ["T1486"],
        {"category": "file_event"},
        {"selection_note": {"TargetFilename|contains": ["HOW_TO_DECRYPT", "README_RECOVER", "DECRYPT_INSTRUCTIONS", "RANSOM"]},
         "selection_ext": {"TargetFilename|endswith": [".locked", ".encrypted", ".lockbit", ".crypt"]},
         "condition": "1 of selection_*"},
        "Creación de una nota de rescate o de archivos con extensión de cifrado. Combínala con la eliminación de copias de seguridad (regla de vssadmin).",
        ["TargetFilename", "Image"], ["Software de cifrado legítimo que use esas extensiones"])
    add("g_phishing", "Ejecución de un adjunto con doble extensión", "high", ["T1204.002", "T1036.007"],
        {"category": "process_creation", "product": "windows"},
        {"selection": {"Image|re": "(?i)\\.(pdf|docx?|xlsx?|jpe?g|png|txt)\\.(exe|scr|js|vbs|bat|cmd|ps1|lnk|hta)$"}, "condition": "selection"},
        "Un archivo que parece un documento (factura.pdf.exe) se ejecuta como programa: señal típica de adjunto de phishing abierto por la víctima.",
        ["Image", "CommandLine", "ParentImage", "User"], ["Muy poco habitual en uso legítimo"])
    add("g_cmd", "Comandos sospechosos: bypass de PowerShell y descargas", "high", ["T1059.001", "T1105"],
        {"category": "process_creation", "product": "windows"},
        {"selection": {"CommandLine|contains": ["-ExecutionPolicy Bypass", "-EncodedCommand", "DownloadString", "Invoke-WebRequest", "IEX(",
                                                "certutil -urlcache", "bitsadmin /transfer"]}, "condition": "selection"},
        "Línea de comandos con las técnicas más comunes de ejecución y descarga. Para variantes más específicas usa las reglas de PowerShell codificado y de descarga.",
        ["CommandLine", "Image", "User", "ParentImage"], ["Scripts de administración que usan Bypass; valida el origen"])
    add("g_share_probe", "Sondeo de recursos compartidos administrativos (IPC$, C$, ADMIN$)", "low", ["T1135", "T1021.002"],
        {"product": "windows", "service": "security"},
        {"selection": {"EventID": 5145, "ShareName|endswith": ["\\IPC$", "\\C$", "\\ADMIN$"]}, "condition": "selection"},
        "Accesos a recursos administrativos. Muy ruidosa por sí sola: es sospechosa cuando una misma cuenta o IP los toca en varios equipos en poco tiempo.",
        ["SubjectUserName", "IpAddress", "ShareName"], ["Herramientas de administración y de inventario"])
    add("g_cloud", "Cambios de permisos, credenciales o registros en la nube (AWS CloudTrail)", "high", ["T1098", "T1078.004"],
        {"product": "aws", "service": "cloudtrail"},
        {"selection": {"eventName": list(_IAM_PRIV)}, "condition": "selection"},
        "Creación de claves, cambios de políticas y apagado de registros. Si la plataforma es Azure o GCP, adapta los nombres de evento.",
        ["eventName", "userIdentity.arn", "sourceIPAddress"], ["Cambios de IAM autorizados; valida la identidad y el momento"])
    return specs


_SPECS = _sigma_specs()

# Reglas con al menos una consulta (la interfaz solo ofrece el botón en estas)
SUPPORTED = frozenset({"brute_force", "external_logon", "privilege", "lateral", "cred_lsass", "cred_dcsync", "persist_run", "persistence",
                       "outbound_shell", "sensitive_share", "mass_access", "kerberoast", *CMD_KEYS})


# Reglas con Sigma pero sin consulta Splunk/KQL (otras fuentes: SSH, web, DNS, Linux, nube)
SIGMA_ONLY = frozenset({"g_auth", "g_web", "g_dns_tunnel", "g_mining", "g_privesc", "g_persistence", "g_ransomware", "g_phishing", "g_cmd",
                        "g_share_probe", "g_cloud"})
ALL_SUPPORTED = SUPPORTED | SIGMA_ONLY


def sigma_rule(rule: str) -> str | None:
    """Regla Sigma (YAML) de un tipo de hallazgo, o None si no hay equivalente. Para fuerza bruta incluye la regla de correlación."""
    if rule == "brute_force":
        base_id = str(uuid.uuid5(NS, "brute_force_base"))
        base = {"title": "Fallo de inicio de sesión (4625)", "id": base_id, "name": "soc_ia_logon_failure", "status": "experimental",
                "description": "Base para detectar fuerza bruta: cada fallo de autenticación en Windows.", "author": "SOC Incident Analyzer",
                "tags": _tags(["T1110"]), "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"}, "level": "informational"}
        corr = {"title": "Fuerza bruta o password spraying desde una misma IP", "id": str(uuid.uuid5(NS, "brute_force_corr")), "status": "experimental",
                "description": "3 o más fallos desde la misma IP en 10 minutos (umbral de la app para IP externas; para internas usa 10).",
                "author": "SOC Incident Analyzer", "tags": _tags(["T1110", "T1110.003"]),
                "correlation": {"type": "event_count", "rules": ["soc_ia_logon_failure"], "group-by": ["IpAddress"], "timespan": "10m",
                                "condition": {"gte": 3}}, "level": "medium"}
        return _y(base) + "\n---\n" + _y(corr) + "\n"
    if rule == "g_persistence":     # una sola regla de la app cubre Linux (cron, claves SSH) y Windows (Run, tareas): se exportan todas
        return "---\n".join(sigma_rule(r) for r in ("g_persistence_linux", "persist_run", "persistence"))
    s = _SPECS.get(rule)
    if not s:
        return None
    doc = {"title": s["title"], "id": str(uuid.uuid5(NS, rule)), "status": "experimental", "description": s["desc"],
           "author": "SOC Incident Analyzer", "tags": _tags(s["mitre"]), "logsource": s["logsource"], "detection": s["detection"],
           "fields": s["fields"], "falsepositives": s.get("falsepositives", ["Administración legítima; valida el contexto"]), "level": s["level"]}
    return _y(doc) + "\n"


def queries_for(finding: dict) -> dict | None:
    """Consultas del hallazgo, o None si su regla no tiene equivalente directo."""
    spl, kql, sig = _splunk(finding), _kql(finding), sigma_rule(finding["rule"])
    if not (spl or kql or sig):
        return None
    return {"splunk": spl, "kql": kql, "sigma": sig}


def sigma_bundle(findings: list[dict]) -> tuple[str, int]:
    """Todas las reglas Sigma distintas de los hallazgos de la sesión, en un único YAML multi-documento."""
    docs, seen = [], set()
    for f in findings:
        if f["rule"] in seen:
            continue
        seen.add(f["rule"])
        s = sigma_rule(f["rule"])
        if s:
            docs.append(s)
    return "---\n".join(docs), len(docs)
