"""Motor de detección determinista + correlación de incidentes.

Principio de diseño (rigor analítico): TODO hallazgo sale de reglas que se
evalúan sobre las filas del Excel y cita sus Log_ID como evidencia. La IA no
detecta nada: solo explica y redacta sobre lo que este módulo encontró.

Convenciones
- "Externa" = IP que no es RFC1918/loopback/link-local. Ojo: los rangos de
  documentación (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) se tratan como
  externos a propósito (Python los marca como "privados", lo que sería un error
  para este análisis).
- Las marcas de tiempo del export no traen zona horaria; se usan tal cual.
"""
from __future__ import annotations

import ipaddress
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import timedelta
from typing import Callable

import pandas as pd

SEV_ORDER = {"Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}
SEV_NAMES = {v: k for k, v in SEV_ORDER.items()}

TACTIC_ORDER = [
    "Acceso a credenciales", "Acceso inicial", "Ejecución", "Persistencia",
    "Escalamiento de privilegios", "Descubrimiento", "Movimiento lateral",
    "Recolección", "Comando y control", "Exfiltración", "Impacto",
    "Calidad de datos / SIEM",
]

CATEGORIES = [
    "Fuerza bruta", "Inicios sospechosos", "Escalamiento", "Comandos y procesos",
    "Movimiento lateral", "Otras anomalías",
]

CONFIG = {
    "brute_external_min_failures": 3,
    "brute_internal_min_failures": 10,
    "brute_cluster_gap_s": 600,
    "post_bruteforce_success_window_s": 1800,
    "mass_access_min_files": 8,
    "mass_access_gap_s": 120,
    "exfil_min_requests": 5,
    "exfil_alto_bytes": 20_000_000,
    "exfil_critico_bytes": 100_000_000,
    "web_min_requests": 10,
    "web_cluster_gap_s": 300,
    "command_cluster_gap_s": 900,
    # Calibración (docs/VALIDACION.md): un comando suelto de administración no es un hallazgo; la repetición o un contexto raro, sí.
    "discovery_min_commands": 3,
    "staging_min_commands": 3,
    "kerberoast_min_services": 3,   # tickets de servicio RC4 a ≥3 servicios distintos de una cuenta en la ventana
    "kerberoast_window_s": 600,
}

ADMIN_RE = re.compile(r"admin|root", re.I)
SERVICE_RE = re.compile(r"svc|service|backup|sql|iis", re.I)
WEB_SVC_USER_RE = re.compile(r"apppool|w3wp|\biis\b|nginx|apache|httpd|tomcat|www-data", re.I)
SHELL_RE = re.compile(r"\b(cmd|powershell|pwsh|bash|sh|wscript|cscript|whoami)(\.exe)?\b", re.I)
SENSITIVE_RE = re.compile(r"(finance|financ|legal|payroll|nomina|rrhh|\bhr\b|confidential|budget|secret)", re.I)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7",
)]
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s;\"'<>|]+|\\\\[\w.\-]+\\[\w$.\\\-*]+")


# --------------------------------------------------------------------------
# utilidades
# --------------------------------------------------------------------------
def ip_of(text: str) -> str:
    m = IP_RE.search(str(text or ""))
    return m.group(1) if m else ""


def is_external(value: str) -> bool:
    ip = ip_of(value) or str(value or "").strip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def short_user(u: str) -> str:
    return str(u or "").split("\\")[-1]


def is_admin_like(u: str) -> bool:
    return bool(ADMIN_RE.search(short_user(u)))


def norm_host(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def bump(sev: str, n: int = 1) -> str:
    return SEV_NAMES[min(4, SEV_ORDER[sev] + n)]


def max_sev(sevs) -> str:
    return SEV_NAMES[max((SEV_ORDER[s] for s in sevs), default=1)]


def fts(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def hhmmss(ts) -> str:
    return pd.Timestamp(ts).strftime("%H:%M:%S")


def fmt_dur(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds} s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m} min {s} s" if s else f"{m} min"
    h, m = divmod(m, 60)
    return f"{h} h {m} min"


def _groups(df, keys):
    """groupby seguro: un DataFrame vacío (p. ej. un export sin eventos 4672) no debe romper la regla."""
    return iter(()) if df.empty else df.groupby(keys)


def pl(n: int, sing: str, plur: str) -> str:
    """'1 cuenta' / '8 cuentas'."""
    return f"{n} {sing if n == 1 else plur}"


def fmt_int(n: int) -> str:
    return f"{int(n):,}".replace(",", ".")


def fmt_dec(x: float, nd: int = 1) -> str:
    return f"{x:,.{nd}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def fmt_mb(b: int) -> str:
    return f"{fmt_dec(b / 1_000_000, 1)} MB"


def trunc(s: str, n: int = 160) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def clusters(df: pd.DataFrame, gap_s: int) -> list[pd.DataFrame]:
    """Parte un DataFrame ordenado por tiempo en grupos con huecos <= gap_s."""
    if df.empty:
        return []
    df = df.sort_values("Timestamp")
    out, start, prev = [], 0, None
    ts = list(df["Timestamp"])
    for i, t in enumerate(ts):
        if prev is not None and (t - prev).total_seconds() > gap_s:
            out.append(df.iloc[start:i])
            start = i
        prev = t
    out.append(df.iloc[start:])
    return out


def median_gap(df: pd.DataFrame) -> float | None:
    ts = list(df.sort_values("Timestamp")["Timestamp"])
    gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
    return statistics.median(gaps) if gaps else None


# --------------------------------------------------------------------------
# modelo
# --------------------------------------------------------------------------
@dataclass
class Finding:
    rule: str
    title: str
    category: str
    tactic: str
    mitre: list[str]
    severity: str
    reasons: list[str]
    explanation: str
    time_start: str
    time_end: str
    hosts: list[str]
    users: list[str]
    ips: list[str]
    actor_users: list[str]
    link_ips: list[str]
    evidence_ids: list[str]
    metrics: dict
    iocs: list[dict]
    id: str = ""
    incident_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class State:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.findings: list[Finding] = []
        self.compromised: dict[str, dict] = {}   # usuario -> {ip, log_id, ts}
        self.brute: list[dict] = []              # ráfagas de fuerza bruta detectadas
        self.claimed: set[str] = set()           # Log_ID ya asignados a un hallazgo de acceso a archivos
        self.rule_hits: Counter = Counter()


def _ioc(type_: str, value: str, note: str = "") -> dict:
    return {"type": type_, "value": value, "note": note}


def _mk(st: State, rule: str, title: str, category: str, tactic: str, mitre: list[str],
        severity: str, reasons: list[str], explanation: str, rows: pd.DataFrame, *,
        actor_ips=(), actor_users=(), link_ips=None, metrics=None, iocs=None, hosts=None) -> Finding:
    rows = rows.sort_values(["Timestamp", "Log_ID"]).drop_duplicates("Log_ID")
    users = [u for u in dict.fromkeys(rows["User"]) if u and u != "-"]
    # sin columna Hostname (otros SIEM) el activo afectado lo informa la regla (p. ej. su IP)
    hosts = list(dict.fromkeys(h for h in rows["Hostname"] if h)) or [h for h in dict.fromkeys(hosts or []) if h]
    ips = list(dict.fromkeys(i for i in rows["Source_IP"] if i))
    actor_ips = [i for i in dict.fromkeys(actor_ips) if i]
    f = Finding(
        rule=rule, title=title, category=category, tactic=tactic, mitre=mitre,
        severity=severity, reasons=reasons, explanation=explanation,
        time_start=fts(rows["Timestamp"].min()), time_end=fts(rows["Timestamp"].max()),
        hosts=hosts, users=users, ips=ips,
        actor_users=[u for u in dict.fromkeys(actor_users) if u and u != "-"],
        link_ips=list(dict.fromkeys(list(actor_ips) + list(link_ips or []))),
        evidence_ids=list(rows["Log_ID"]), metrics=metrics or {}, iocs=iocs or [],
    )
    st.findings.append(f)
    st.rule_hits[rule] += 1
    return f


# --------------------------------------------------------------------------
# reglas
# --------------------------------------------------------------------------
def rule_brute_force(st: State) -> None:
    d = st.df
    fails = d[d["Event_ID"] == "4625"]
    for ip, g in _groups(fails, "Source_IP"):
        if not ip:
            continue
        ext = is_external(ip)
        for c in clusters(g, CONFIG["brute_cluster_gap_s"]):
            n = len(c)
            if not ((ext and n >= CONFIG["brute_external_min_failures"])
                    or (not ext and n >= CONFIG["brute_internal_min_failures"])):
                continue
            users = list(dict.fromkeys(c["User"]))
            per_user = Counter(c["User"])
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            window_end = t1 + timedelta(seconds=CONFIG["post_bruteforce_success_window_s"])
            succ = d[(d["Source_IP"] == ip) & (d["Event_ID"] == "4624")
                     & (d["Timestamp"] >= t0) & (d["Timestamp"] <= window_end)]
            rdp = c["Event_Description"].str.contains(r"LogonType=10|RDP", case=False, regex=True).any()
            spray = len(users) >= 3
            gap = median_gap(c)
            dur = (t1 - t0).total_seconds()
            origin = "externa" if ext else "interna"

            sev = "Alto" if (n >= CONFIG["brute_internal_min_failures"] or spray or len(succ)) else "Medio"
            reasons = [f"{n} fallos de autenticación (4625) desde la IP {origin} {ip} en {fmt_dur(dur)}."]
            if spray:
                reasons.append(f"Afecta a {len(users)} cuentas distintas (patrón de password spraying).")
            if ext:
                reasons.append("El origen es una IP externa a las redes privadas (RFC1918).")
            if len(succ):
                reasons.append(f"Tras la ráfaga hubo {pl(len(succ), 'inicio de sesión exitoso', 'inicios de sesión exitosos')} "
                               f"desde la misma IP ({', '.join(succ['Log_ID'])}).")
            else:
                reasons.append("No se observaron inicios de sesión exitosos desde esa IP.")

            if spray:
                pattern = (f"El patrón (muchas cuentas con pocos intentos cada una, {fmt_dec(gap, 0)} s de mediana entre intentos) "
                           f"es característico de password spraying (T1110.003).")
            else:
                pattern = (f"Todos los intentos apuntan a la cuenta {users[0]}"
                           f"{' mediante RDP (LogonType=10)' if rdp else ''}; es consistente con fuerza bruta contra una "
                           f"cuenta (T1110.001).")
            succ_txt = (f" Posteriormente se registró {pl(len(succ), 'inicio de sesión exitoso', 'inicios de sesión exitosos')} desde esa IP: "
                        + "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}, {r.User} en {r.Hostname})" for r in succ.itertuples())
                        + ".") if len(succ) else " No se observaron inicios de sesión exitosos desde esa IP."
            expl = (f"Se registraron {n} intentos fallidos de autenticación (Event ID 4625) originados en la IP {origin} {ip} "
                    f"entre {hhmmss(t0)} y {hhmmss(t1)} ({fmt_dur(dur)}), dirigidos a {pl(len(users), 'cuenta', 'cuentas')} "
                    f"({', '.join(short_user(u) for u in users)}) sobre {', '.join(dict.fromkeys(c['Hostname']))}. "
                    f"{pattern}{succ_txt}")
            title = ("Password spraying" if spray else "Fuerza bruta" + (" por RDP" if rdp else "")) + f" desde {ip}"
            _mk(st, "brute_force", title, "Fuerza bruta", "Acceso a credenciales",
                ["T1110.003"] if spray else ["T1110.001"], sev, reasons, expl, c,
                actor_ips=[ip],
                metrics={"intentos_fallidos": n, "cuentas_objetivo": len(users),
                         "intentos_por_cuenta": dict(per_user), "ventana_s": round(dur),
                         "mediana_entre_intentos_s": gap, "exitos_posteriores": list(succ["Log_ID"]),
                         "ip_origen": ip, "origen_externo": ext},
                iocs=[_ioc("IP", ip, "Origen de la ráfaga de autenticaciones fallidas")])
            st.brute.append({"ip": ip, "start": t0, "end": t1, "n": n})


def rule_external_logon(st: State) -> None:
    d = st.df
    s = d[(d["Event_ID"] == "4624") & d["Source_IP"].map(is_external)]
    for (ip, user), g in _groups(s, ["Source_IP", "User"]):
        for c in clusters(g, 900):
            first = c.iloc[0]
            t0 = c["Timestamp"].min()
            rdp = c["Event_Description"].str.contains(r"LogonType=10|RDP", case=False, regex=True).any()
            prior = [b for b in st.brute if b["ip"] == ip and timedelta(0) <= t0 - b["end"] <= timedelta(minutes=60)]
            on_dc = any(re.match(r"(?i)dc", h) for h in c["Hostname"])
            sev = "Alto"
            reasons = [f"Inicio de sesión exitoso (4624) de {user} desde la IP externa {ip}."]
            if prior:
                b = prior[0]
                reasons.append(f"Ocurre {fmt_dur((t0 - b['end']).total_seconds())} después de {b['n']} fallos desde la misma IP.")
            if rdp:
                reasons.append("Se trata de un acceso remoto por RDP (LogonType=10) desde Internet.")
            if on_dc:
                reasons.append("El host destino es un controlador de dominio.")
            if is_admin_like(user):
                sev = "Crítico"
                reasons.append("La cuenta es administrativa (nombre 'admin'): su compromiso otorga control amplio.")
            expl = (f"A las {hhmmss(t0)} la cuenta {user} inició sesión correctamente en {first.Hostname} desde la IP externa "
                    f"{ip} ({first.Log_ID}). "
                    + (f"Este acceso sigue a una ráfaga de {prior[0]['n']} fallos de autenticación desde la misma IP "
                       f"({fmt_dur((t0 - prior[0]['end']).total_seconds())} antes), lo que indica que las credenciales fueron "
                       f"obtenidas por adivinación (T1110) y luego usadas como cuenta válida (T1078)."
                       if prior else "No hay ráfaga previa de fallos desde esa IP en el export; el origen externo ya es anómalo para una cuenta corporativa.")
                    + (" El acceso fue por RDP (T1021.001)." if rdp else ""))
            f = _mk(st, "external_logon", f"Inicio de sesión exitoso de {short_user(user)} desde IP externa {ip}",
                    "Inicios sospechosos", "Acceso inicial", ["T1078"] + (["T1021.001"] if rdp else []), sev,
                    reasons, expl, c, actor_ips=[ip], actor_users=[user],
                    metrics={"ip_origen": ip, "usuario": user, "tras_fuerza_bruta": bool(prior), "rdp": bool(rdp)},
                    iocs=[_ioc("IP", ip, "IP externa con sesión exitosa"), _ioc("Cuenta", user, "Cuenta usada desde IP externa")])
            st.compromised.setdefault(user, {"ip": ip, "log_id": first.Log_ID, "ts": t0})


def rule_privilege(st: State) -> None:
    d = st.df
    p = d[d["Event_ID"] == "4672"]
    sel = p[p["Source_IP"].map(is_external)]
    extra = []
    for r in p.itertuples():
        comp = st.compromised.get(r.User)
        if comp and r.Log_ID not in set(sel["Log_ID"]) and timedelta(0) <= r.Timestamp - comp["ts"] <= timedelta(minutes=30):
            extra.append(r.Log_ID)
    if extra:
        sel = pd.concat([sel, p[p["Log_ID"].isin(extra)]])
    for (user, ip), g in _groups(sel, ["User", "Source_IP"]):
        for c in clusters(g, 900):
            r = c.iloc[0]
            sev = "Crítico" if is_admin_like(user) else "Alto"
            comp = st.compromised.get(user)
            reasons = [f"Se asignaron privilegios especiales (4672) a {user} en {r.Hostname}."]
            if is_external(ip):
                reasons.append(f"El inicio de sesión proviene de la IP externa {ip}.")
            if comp:
                reasons.append(f"La cuenta ya aparece comprometida (acceso externo {comp['log_id']}).")
            if is_admin_like(user):
                reasons.append("La cuenta es administrativa.")
            expl = (f"A las {hhmmss(r.Timestamp)} se registró el Event ID 4672 (privilegios especiales asignados a un nuevo inicio de "
                    f"sesión) para {user} en {r.Hostname}, con origen {ip} ({r.Log_ID}). Este evento indica que la sesión recibió "
                    f"privilegios sensibles (p. ej. SeDebugPrivilege, SeBackupPrivilege); combinado con un origen externo "
                    f"sugiere uso de la cuenta con privilegios elevados por parte de un tercero (T1078, escalamiento).")
            _mk(st, "privilege", f"Asignación de privilegios especiales a {short_user(user)} desde {ip}",
                "Escalamiento", "Escalamiento de privilegios", ["T1078", "T1134"], sev, reasons, expl, c,
                actor_ips=[ip] if is_external(ip) else [], actor_users=[user],
                metrics={"usuario": user, "host": r.Hostname, "ip_origen": ip},
                iocs=[_ioc("Cuenta", user, "Cuenta con privilegios especiales tras acceso externo")])


# -- comandos y procesos ----------------------------------------------------
CMD_PATTERNS = [
    dict(key="anti_recovery", tactic="Impacto", base="Crítico", mitre=["T1490"],
         label="Eliminación de copias de sombra (anti-recuperación)",
         rx=re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete|bcdedit.*recoveryenabled\s+no|wmic.*shadowcopy\s+delete", re.I),
         why="Borrar las copias de sombra impide restaurar archivos y es un paso típico previo a ransomware."),
    dict(key="cred_dump", tactic="Acceso a credenciales", base="Crítico", mitre=["T1003"],
         label="Volcado de credenciales",
         rx=re.compile(r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs\.dll.*minidump|ntdsutil|ntds\.dit|\bdumpert\b|nanodump|secretsdump"
                       r"|esentutl(\.exe)?[\"']?\s+.*/y\s+.*(ntds|\\sam\b|\\system\b|\\security\b|shadowcopy)"
                       r"|reg(\.exe)?[\"']?\s+save\s+hklm\\(sam|security|system)", re.I),
         why="Extraer credenciales de memoria o del registro permite movimiento lateral y persistencia."),
    dict(key="web_service_shell", tactic="Ejecución", base="Crítico", mitre=["T1505.003", "T1190"],
         label="Shell iniciada por el servicio web", rx=None,
         why="Un proceso web (IIS) que lanza cmd.exe/powershell es un indicador clásico de webshell o RCE."),
    dict(key="encoded_ps", tactic="Ejecución", base="Alto", mitre=["T1059.001", "T1027"],
         label="PowerShell con comando codificado",
         rx=re.compile(r"powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\b", re.I),
         why="-EncodedCommand oculta el contenido del script y es muy usado para evadir controles."),
    dict(key="download_cradle", tactic="Ejecución", base="Alto", mitre=["T1105", "T1059"],
         label="Descarga/ejecución remota de código",
         rx=re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|certutil.*-urlcache|bitsadmin.*/transfer", re.I),
         why="Descargar y ejecutar contenido remoto es un patrón de entrega de malware."),
    dict(key="archive_staging", tactic="Recolección", base="Alto", mitre=["T1560.001", "T1074.001"],
         label="Compresión de datos (staging)",
         rx=re.compile(r"(?:^|[\s\\/\"'])(tar|7z|7za|rar|winrar|zip)(\.exe)?[\"']?\s+[^\n]*?\.(zip|7z|rar|tar|gz)\b|compress-archive", re.I),
         why="Agrupar y comprimir archivos suele preceder a su exfiltración."),
    dict(key="discovery", tactic="Descubrimiento", base="Medio", mitre=["T1087", "T1069", "T1135"],
         label="Comandos de reconocimiento",
         rx=re.compile(r"\b(whoami|systeminfo|ipconfig|nltest|quser|tasklist)\b|net1?(\.exe)?\s+(view|user|group|localgroup|share|use)\b|get-localgroupmember|get-smbshare|get-aduser|get-adgroupmember|get-netcomputer", re.I),
         why="Enumerar usuarios, grupos y recursos compartidos es la fase de reconocimiento posterior al acceso."),
]


DISCOVERY_DIRECTORY_RE = re.compile(r"\bnltest\b|net1?(\.exe)?\s+(view|user|group|localgroup|share|use)\b|get-localgroupmember|get-smbshare|get-aduser|get-adgroupmember|get-netcomputer", re.I)


def _match_cmd(row) -> dict | None:
    text = f"{row.Event_Description} {row.Process_CommandLine}"
    for p in CMD_PATTERNS:
        if p["key"] == "web_service_shell":
            if WEB_SVC_USER_RE.search(row.User) and SHELL_RE.search(text):
                return p
        elif p["rx"].search(text):
            return p
    return None


def rule_commands(st: State) -> None:
    d = st.df
    cand = d[(d["Event_ID"].isin(["4688", "4104", "4103", "1"]) | (d["Log_Source"] == "PowerShell"))
             & ~d["Log_Source"].isin(["IIS", "Proxy"])]
    hits = []
    for r in cand.itertuples():
        p = _match_cmd(r)
        if p:
            hits.append((p["key"], r.Hostname, r.User, r.Log_ID))
    if not hits:
        return
    key_by_id = {h[3]: h[0] for h in hits}
    sub = d[d["Log_ID"].isin(key_by_id)].copy()
    sub["_key"] = sub["Log_ID"].map(key_by_id)
    pat = {p["key"]: p for p in CMD_PATTERNS}
    for (key, host, user), g in _groups(sub, ["_key", "Hostname", "User"]):
        p = pat[key]
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            ext = c["Source_IP"].map(is_external).any()
            # Calibración: un comando de administración suelto (ipconfig, whoami) no es un hallazgo; la ráfaga o el origen externo sí.
            # Solo se exime la enumeración de cuentas/grupos/recursos del dominio (net user /domain, nltest, Get-AD*): un comando así ya es señal.
            if (key == "discovery" and not ext and len(c) < CONFIG["discovery_min_commands"]
                    and not c["Process_CommandLine"].map(lambda x: bool(DISCOVERY_DIRECTORY_RE.search(x))).any()):
                continue
            sev = bump(p["base"], 1) if (ext and p["base"] != "Crítico") else p["base"]
            cmds = [trunc(x, 140) for x in c["Process_CommandLine"] if x] or [trunc(x, 140) for x in c["Event_Description"]]
            reasons = [f"Coincide con el patrón «{p['label']}»: {p['why']}"]
            if ext:
                reasons.append(f"La actividad se origina en la IP externa {c[c['Source_IP'].map(is_external)].iloc[0].Source_IP}.")
            parent = c["Event_Description"].str.extract(r"parent=([\w.\\-]+)")[0].dropna()
            if len(parent):
                reasons.append(f"Proceso padre: {parent.iloc[0]}.")
            if key == "web_service_shell":
                reasons.append(f"La cuenta {user} es la identidad del servicio web.")
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            listing = "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}): {trunc(r.Process_CommandLine or r.Event_Description, 120)}"
                                for r in c.itertuples())
            expl = (f"En {host}, la cuenta {user} ejecutó {pl(len(c), 'comando', 'comandos')} con el patrón «{p['label']}» entre {hhmmss(t0)} y "
                    f"{hhmmss(t1)}: {listing}. {p['why']}")
            paths = sorted({m for s in list(c["Process_CommandLine"]) for m in PATH_RE.findall(s)})
            # si la columna de comando es solo un proceso (p. ej. 4104), lo relevante está en la descripción (script block)
            shown = [(r.Process_CommandLine if (" " in r.Process_CommandLine or not r.Event_Description) else r.Event_Description)
                     for r in c.itertuples()]
            iocs = [_ioc("Comando", trunc(x, 200), p["label"]) for x in dict.fromkeys(shown) if x]
            iocs += [_ioc("Ruta/archivo", pth, p["label"]) for pth in paths]
            ext_ips = [i for i in c["Source_IP"] if is_external(i)]
            if ext_ips:
                iocs.append(_ioc("IP", ext_ips[0], "Origen externo de la actividad"))
            title = f"{p['label']} en {host} ({short_user(user)})"
            cat = "Comandos y procesos"
            metrics = {"comandos": len(c), "host": host, "usuario": user, "ejemplos": cmds[:5]}
            if key == "archive_staging":
                blob_c = " ".join(c["Process_CommandLine"])
                odd_place = bool(re.search(r"\\(ProgramData|Temp|Users\\Public)\\|/tmp/|\s-p\S", blob_c, re.I))
                if not (ext or odd_place or len(c) >= CONFIG["staging_min_commands"]):
                    metrics["_sin_corroborar"] = True   # se descarta al final si ninguna otra regla lo respalda (p. ej. salida a Internet)
            _mk(st, f"cmd_{key}", title, cat, p["tactic"], p["mitre"], sev, reasons, expl, c,
                actor_ips=ext_ips[:1], actor_users=[user], metrics=metrics, iocs=iocs)


def prune_uncorroborated(st: State) -> int:
    """Descarta los hallazgos marcados como `_sin_corroborar` que ninguna otra regla respaldó. Se llama tras todas las reglas."""
    keep = [f for f in st.findings if not (f.metrics.get("_sin_corroborar") and not f.metrics.get("_corroborado"))]
    n = len(st.findings) - len(keep)
    for f in keep:   # marcas internas: no deben salir en el informe ni en el prompt de la IA
        f.metrics.pop("_sin_corroborar", None)
        f.metrics.pop("_corroborado", None)
    st.findings[:] = keep
    return n


def rule_lateral(st: State) -> None:
    d = st.df
    s = d[d["Event_ID"].isin(["4624", "4625"])].copy()
    s["_src"] = s["Event_Description"].str.extract(r"source=([A-Za-z0-9_.\-]+)")[0]
    s = s[s["_src"].notna() & (s["_src"].map(norm_host) != s["Hostname"].map(norm_host))]
    for (user, src, dst), g in _groups(s, ["User", "_src", "Hostname"]):
        for c in clusters(g, 900):
            ok = c[c["Event_ID"] == "4624"]
            ko = c[c["Event_ID"] == "4625"]
            lt = c["Event_Description"].str.extract(r"LogonType=(\d+)")[0].dropna()
            lt = lt.iloc[0] if len(lt) else "?"
            comp = st.compromised.get(user)
            sev = "Crítico" if (comp or is_admin_like(user)) else "Alto"
            reasons = [f"Autenticación de red ({'LogonType=' + lt}) en {dst} originada en otro host del entorno ({src})."]
            if len(ko):
                reasons.append(f"Hubo {pl(len(ko), 'intento fallido', 'intentos fallidos')} en la misma secuencia, señal de prueba de credenciales.")
            if comp:
                reasons.append(f"La cuenta {user} ya estaba comprometida (acceso externo {comp['log_id']}).")
            elif is_admin_like(user):
                reasons.append("La cuenta es administrativa.")
            expl = (f"La cuenta {user} se autenticó contra {dst} usando como origen el host {src} "
                    f"(LogonType={lt}, red). Registros: "
                    + "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}, {'éxito' if r.Event_ID == '4624' else 'fallo'})" for r in c.itertuples())
                    + f". El salto {src} -> {dst} con una cuenta ya vista en actividad sospechosa en {src} es consistente con "
                      f"movimiento lateral mediante recursos compartidos de administración (T1021.002) con cuentas válidas (T1078).")
            _mk(st, "lateral", f"Movimiento lateral de {short_user(user)}: {src} -> {dst}", "Movimiento lateral",
                "Movimiento lateral", ["T1021.002", "T1078"], sev, reasons, expl, c,
                actor_users=[user],
                metrics={"usuario": user, "origen": src, "destino": dst, "logon_type": lt,
                         "fallos": int(len(ko)), "exitos": int(len(ok))},
                iocs=[_ioc("Host", dst, f"Destino de movimiento lateral desde {src}"),
                      _ioc("Cuenta", user, "Cuenta usada para el salto")])


def _share_label(text: str) -> str:
    m = SENSITIVE_RE.search(text)
    return m.group(1).lower() if m else ""


def rule_mass_access(st: State) -> None:
    d = st.df
    files = d[(d["Event_ID"] == "4663") & d["Process_CommandLine"].str.contains(r"File access:", case=False, regex=True)]
    for (user, host), g in _groups(files, ["User", "Hostname"]):
        for c in clusters(g, CONFIG["mass_access_gap_s"]):
            n = len(c)
            if n < CONFIG["mass_access_min_files"]:
                continue
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            names = [re.sub(r"^File access:\s*", "", x) for x in c["Process_CommandLine"]]
            nums = [int(m.group(1)) for x in names if (m := re.search(r"(\d+)\.\w+$", x))]
            sequential = len(nums) == n and nums == list(range(nums[0], nums[0] + n))
            share = _share_label(" ".join(c["Destination"]) + " " + " ".join(names))
            # eventos de recurso compartido del mismo usuario/recurso cerca de la ráfaga
            d_near = d[(d["User"] == user) & d["Event_ID"].isin(["5140", "5145"])
                       & (d["Timestamp"] >= t0 - timedelta(minutes=5)) & (d["Timestamp"] <= t1 + timedelta(minutes=5))
                       & d["Destination"].str.contains(share or "@@", case=False, regex=False)]
            rows = pd.concat([c, d_near])
            st.claimed |= set(rows["Log_ID"])
            dur = max((t1 - t0).total_seconds(), 1)
            comp = st.compromised.get(user)
            reasons = [f"{n} accesos a archivos (4663) por {user} en {fmt_dur(dur)} (~{fmt_dec(n / dur * 60, 1)} archivos/min)."]
            if sequential:
                reasons.append(f"Los nombres siguen una numeración consecutiva ({names[0].split(chr(92))[-1]} … {names[-1].split(chr(92))[-1]}), "
                               f"típica de recorrido automatizado y no de uso humano.")
            if share:
                reasons.append(f"El recurso afectado es de contenido sensible ({share}).")
            sev = "Alto"
            expl = (f"Entre {hhmmss(t0)} y {hhmmss(t1)} la cuenta {user} accedió a {n} archivos en {host} "
                    f"({names[0]} … {names[-1]}), a razón de ~{fmt_dec(n / dur * 60, 1)} por minuto"
                    + (", con numeración consecutiva" if sequential else "")
                    + ". Un barrido de este tipo es consistente con recolección de datos desde un recurso compartido (T1039) "
                      "previa a cifrado o exfiltración.")
            _mk(st, "mass_access", f"Acceso masivo a archivos por {short_user(user)} en {host}", "Otras anomalías",
                "Recolección", ["T1039", "T1005"], sev, reasons, expl, rows, actor_users=[user],
                metrics={"archivos": n, "ventana_s": round(dur), "archivos_por_min": round(n / dur * 60, 1),
                         "numeracion_consecutiva": sequential, "recurso": share, "usuario": user, "host": host},
                iocs=[_ioc("Ruta/archivo", names[0], "Primer archivo del barrido"),
                      _ioc("Ruta/archivo", names[-1], "Último archivo del barrido")])


def rule_sensitive_share(st: State) -> None:
    d = st.df
    sh = d[d["Event_ID"].isin(["5140", "5145"]) & ~d["Log_ID"].isin(st.claimed)].copy()
    text = sh["Destination"] + " " + sh["Event_Description"] + " " + sh["Process_CommandLine"]
    sh["_label"] = text.map(_share_label)
    sh = sh[sh["_label"] != ""]
    for (user, label), g in _groups(sh, ["User", "_label"]):
        for c in clusters(g, 900):
            comp = st.compromised.get(user)
            ext = c["Source_IP"].map(is_external).any()
            high = c["Severity"].str.lower().isin(["high", "critical", "alto", "crítico"]).any()
            sev = "Alto" if (comp or ext or high) else "Medio"
            r0 = c.iloc[0]
            paths = sorted({m for s in (list(c["Destination"]) + list(c["Event_Description"])) for m in PATH_RE.findall(s)})
            files = sorted({m.group(0) for s in c["Event_Description"] if (m := re.search(r"[\w\\]+\.\w{2,5}\b", s))})
            reasons = [f"Acceso a un recurso compartido de contenido sensible ('{label}') por {user}."]
            if comp:
                reasons.append(f"La cuenta ya figura como comprometida ({comp['log_id']}).")
            if high:
                reasons.append("El propio SIEM marcó al menos un evento como High.")
            if not (comp or ext or high):
                reasons.append("Por sí solo es un acceso de lectura; su relevancia depende del contexto de las demás evidencias del incidente.")
            expl = (f"La cuenta {user} accedió al recurso '{label}' en {r0.Hostname} ("
                    + "; ".join(f"{r.Log_ID} {hhmmss(r.Timestamp)}: {trunc(r.Destination or r.Event_Description, 90)}" for r in c.itertuples())
                    + "). El acceso a repositorios financieros/legales es de alto valor para un atacante (T1039).")
            _mk(st, "sensitive_share", f"Acceso a recurso sensible '{label}' por {short_user(user)}", "Otras anomalías",
                "Recolección", ["T1039"], sev, reasons, expl, c, actor_users=[user],
                metrics={"usuario": user, "recurso": label, "eventos": int(len(c))},
                iocs=[_ioc("Ruta/archivo", p, "Recurso sensible accedido") for p in paths[:4]])


def rule_exfil_proxy(st: State) -> None:
    d = st.df
    px = d[(d["Log_Source"] == "Proxy") | (d["Event_ID"] == "PROXY_ACCESS")].copy()
    if px.empty:
        return
    px["_bytes"] = pd.to_numeric(px["Process_CommandLine"].str.extract(r"bytes_out=(\d+)")[0], errors="coerce").fillna(0).astype(int)
    px["_dest"] = px["Destination"].map(ip_of)
    px["_post"] = px["Event_Description"].str.contains("POST", case=False)
    px = px[px["_post"] & px["_dest"].map(is_external)]
    for (user, host, dest), g in _groups(px, ["User", "Hostname", "_dest"]):
        for c in clusters(g, 600):
            n, total = len(c), int(c["_bytes"].sum())
            if n < CONFIG["exfil_min_requests"] or total < CONFIG["exfil_alto_bytes"] // 4:
                continue
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            dur = (t1 - t0).total_seconds()
            gap = median_gap(c)
            sev = "Crítico" if total >= CONFIG["exfil_critico_bytes"] else ("Alto" if total >= CONFIG["exfil_alto_bytes"] else "Medio")
            prev = st.df[(st.df["User"] == user) & (st.df["Hostname"] == host)
                         & st.df["Process_CommandLine"].str.contains(r"\.(?:7z|zip|rar)\b", case=False, regex=True)
                         & (st.df["Timestamp"] < t0) & (st.df["Timestamp"] >= t0 - timedelta(minutes=15))]
            reasons = [f"{n} peticiones HTTPS POST hacia la IP externa {dest} sumando {fmt_int(total)} bytes ({fmt_mb(total)}) en {fmt_dur(dur)}."]
            if gap:
                reasons.append(f"Cadencia regular (mediana {fmt_dec(gap, 0)} s entre peticiones), propia de una transferencia automatizada.")
            if len(prev):
                lag = (t0 - prev["Timestamp"].max()).total_seconds()
                reasons.append(f"Se inicia {fmt_dur(lag)} después de un comando de compresión ({prev.iloc[-1].Log_ID}) del mismo usuario y host.")
            uris = list(c["Process_CommandLine"].str.extract(r"uri=(\S+)")[0].dropna())
            expl = (f"Desde {host}, la cuenta {user} envió {n} POST salientes a {dest}:443 entre {hhmmss(t0)} y {hhmmss(t1)} "
                    f"({fts(t0)[:10]}), con un total de {fmt_int(total)} bytes ({fmt_mb(total)}; {fmt_dec(total / 1048576, 1)} MiB). "
                    f"Las URIs ({uris[0] if uris else '?'} … {uris[-1] if uris else '?'}) indican subidas por sesiones numeradas"
                    + (f" y la transferencia comenzó {fmt_dur((t0 - prev['Timestamp'].max()).total_seconds())} después de comprimir datos" if len(prev) else "")
                    + ". Es consistente con exfiltración de datos por HTTPS (T1041).")
            _mk(st, "exfil_proxy", f"Posible exfiltración de {fmt_mb(total)} desde {host} hacia {dest}", "Otras anomalías",
                "Exfiltración", ["T1041"], sev, reasons, expl, c, actor_users=[user], link_ips=[dest],
                metrics={"peticiones": n, "bytes_totales": total, "mb_totales": round(total / 1_000_000, 1),
                         "ventana_s": round(dur), "mediana_entre_peticiones_s": gap, "destino": f"{dest}:443",
                         "usuario": user, "host": host},
                iocs=[_ioc("IP", dest, "Destino de la transferencia saliente"),
                      _ioc("URL/URI", f"https://{dest}/upload/session/N", "Patrón de subida")])


def rule_outbound(st: State) -> None:
    d = st.df
    fw = d[((d["Log_Source"] == "Firewall") | (d["Event_ID"] == "5156")) & ~d["Log_Source"].isin(["Proxy"])].copy()
    fw["_dest"] = fw["Destination"].map(ip_of)
    fw = fw[fw["_dest"].map(is_external)]
    for (user, host, dest), g in _groups(fw, ["User", "Hostname", "_dest"]):
        for c in clusters(g, 900):
            r0 = c.iloc[0]
            text = f"{r0.Event_Description} {r0.Process_CommandLine}"
            shell = bool(SHELL_RE.search(text)) or bool(re.search(r"process=\S*(powershell|cmd|wscript|mshta|rundll32)", text, re.I))
            comp = st.compromised.get(user)
            prior_stage = [f for f in st.findings if f.rule == "cmd_archive_staging" and user in f.users and host in f.hosts
                           and 0 <= (pd.Timestamp(r0.Timestamp) - pd.Timestamp(f.time_end)).total_seconds() <= 900]
            sev = "Alto"
            reasons = [f"Conexión saliente permitida de {host} hacia la IP externa {dest}."]
            if shell:
                sev = "Crítico"
                reasons.append("La conexión la inició un intérprete de comandos (powershell/cmd), no un navegador ni un servicio esperado.")
            if comp:
                reasons.append(f"La cuenta {user} ya figura como comprometida ({comp['log_id']}).")
            for pf in prior_stage:
                pf.metrics["_corroborado"] = True
            if prior_stage:
                lag = (pd.Timestamp(r0.Timestamp) - pd.Timestamp(prior_stage[0].time_end)).total_seconds()
                reasons.append(f"Ocurre {fmt_dur(lag)} después de comprimir datos en el mismo host.")
            expl = (f"A las {hhmmss(r0.Timestamp)} {host} abrió una conexión saliente a {dest} ({trunc(r0.Event_Description, 120)}) "
                    f"bajo la cuenta {user} ({r0.Log_ID}). " + ("Al venir de powershell.exe y tras el staging de datos, es consistente con envío de datos o "
                                                                  "canal de comando y control sobre HTTPS (T1071.001/T1041)." if shell else
                                                                  "Conviene validar si el destino es legítimo."))
            _mk(st, "outbound_shell", f"Conexión saliente a IP externa {dest} desde {host}", "Otras anomalías",
                "Comando y control", ["T1071.001", "T1041"], sev, reasons, expl, c, actor_users=[user], link_ips=[dest],
                metrics={"destino": r0.Destination, "host": host, "usuario": user, "proceso_shell": shell},
                iocs=[_ioc("IP", dest, "Destino externo de conexión iniciada por shell")])


def rule_persistence(st: State) -> None:
    d = st.df
    p = d[d["Event_ID"].isin(["4698", "7045"])]
    # Calibración: las tareas propias de Windows creadas por SYSTEM (\Microsoft\Windows\...) son mantenimiento normal.
    p = p[~(p["User"].str.contains(r"SYSTEM$", case=False, regex=True, na=False)
            & (p["Event_ID"] == "4698")
            & p["Event_Description"].str.contains(r"\\Microsoft\\Windows\\", regex=True, na=False))]
    for (host, user), g in _groups(p, ["Hostname", "User"]):
        for c in clusters(g, 1800):
            blob = " ".join(c["Event_Description"] + " " + c["Process_CommandLine"])
            images = []
            for r in c.itertuples():  # por fila: si no, los valores de filas distintas se pegan entre sí
                images += [m.strip() for m in re.findall(r"(?:ImagePath|Action)=([^;]+)", r.Process_CommandLine)]
            # binario/script real = última ruta de la cadena (p. ej. "powershell.exe -File C:\...\x.ps1" -> x.ps1)
            targets = []
            for im in images:
                paths = PATH_RE.findall(im)
                targets.append(paths[-1] if paths else im)
            base = [m.group(0) for t in targets if (m := re.search(r"[\w.\-]+\.(?:exe|ps1|bat|dll|vbs)$", t, re.I))]
            suspicious_path = bool(re.search(r"\\(ProgramData|Temp|Users\\Public|AppData)\\", blob, re.I))
            t0 = c["Timestamp"].min()
            execs = d[d["Process_CommandLine"].apply(lambda s: any(b.lower() in s.lower() for b in base if b.lower().endswith(".exe")) if s else False)
                      & (d["Event_ID"] == "4688") & (d["Timestamp"] >= t0)]
            execs = execs[(execs["Hostname"] == host)]
            rows = pd.concat([c, execs])
            gap = median_gap(execs) if len(execs) > 1 else None
            periodic = False
            if len(execs) >= 3:
                gaps = [(b - a).total_seconds() for a, b in zip(execs["Timestamp"], execs["Timestamp"].iloc[1:])]
                periodic = (max(gaps) - min(gaps)) <= max(5, 0.05 * statistics.median(gaps))
            sev = "Alto" if (suspicious_path or len(execs)) else "Medio"
            reasons = [f"{user} creó persistencia en {host}: " + ", ".join(
                f"{'tarea programada' if r.Event_ID == '4698' else 'servicio'} ({r.Log_ID})" for r in c.itertuples()) + "."]
            if suspicious_path:
                reasons.append("El binario/script reside en una ruta no estándar y escribible (ProgramData).")
            if re.search(r"update|helper|microsoft\\windows", blob, re.I):
                reasons.append("Los nombres imitan componentes legítimos de Windows (enmascaramiento, T1036).")
            if len(execs):
                reasons.append(f"El binario se ejecutó {len(execs)} veces tras instalarse"
                               + (f", cada {fmt_dur(gap)} de forma periódica (comportamiento tipo beacon)." if periodic and gap else "."))
            if not is_admin_like(user) and user not in ("", "-"):
                reasons.append(f"Una cuenta no administrativa ({short_user(user)}) realizó una operación privilegiada en un servidor.")
            names = re.findall(r"(?:TaskName|ServiceName)=([^;]+)", blob)
            expl = (f"En {host}, {user} creó mecanismos de persistencia: "
                    + "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}): {trunc(r.Process_CommandLine or r.Event_Description, 150)}" for r in c.itertuples())
                    + (f". Después, {', '.join(sorted({b for b in base if b.lower().endswith('.exe')}))} se ejecutó {len(execs)} veces ({', '.join(execs['Log_ID'])})"
                       + (f", a intervalos regulares de {fmt_dur(gap)}" if periodic and gap else "") if len(execs) else "")
                    + ". La combinación de tarea programada + servicio nuevo en ProgramData con nombres de apariencia legítima apunta a "
                      "persistencia (T1053.005, T1543.003) y enmascaramiento (T1036.004).")
            iocs = [_ioc("Ruta/archivo", t, "Binario/script de persistencia") for t in dict.fromkeys(targets)]
            iocs += [_ioc("Servicio/Tarea", n.strip(), "Nombre usado para persistencia") for n in names]
            _mk(st, "persistence", f"Persistencia en {host} mediante tarea programada y servicio", "Otras anomalías",
                "Persistencia", ["T1053.005", "T1543.003", "T1036.004"], sev, reasons, expl, rows, actor_users=[user],
                metrics={"host": host, "usuario": user, "ejecuciones": int(len(execs)), "intervalo_s": gap,
                         "periodico": periodic, "imagenes": targets}, iocs=iocs)


# --- Acceso a credenciales / persistencia por Sysmon y 4662 (calibradas contra OTRF, ver docs/VALIDACION.md) ---
LSASS_BENIGN_SOURCES = {"svchost.exe", "vboxservice.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsm.exe",
                        "msmpeng.exe", "mssense.exe", "collectguestlogs.exe", "wmiprvse.exe", "smss.exe", "sense.exe"}
# Máscaras que permiten leer la memoria (PROCESS_ALL_ACCESS y variantes de mimikatz/procdump/comsvcs). 0x1000/0x1400/0x1410/0x40 son rutina de Windows.
LSASS_DUMP_MASKS = {"0x1fffff", "0x1f3fff", "0x1f0fff", "0x143a", "0x1010", "0x1038", "0x1418"}
DCSYNC_GUIDS = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
RUNKEY_RE = re.compile(r"\\Software\\(?:Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\\", re.I)


def _field(text: str, name: str) -> str:
    m = re.search(rf"^\s*{name}:\s*(.+?)\s*$", text, re.I | re.M)
    return m.group(1).strip() if m else ""


def rule_cred_lsass(st: State) -> None:
    d = st.df
    s = d[d["Event_ID"] == "10"]
    rows = []
    for r in s.itertuples():
        t = r.Event_Description
        if not _field(t, "TargetImage").lower().endswith("lsass.exe"):
            continue
        src = _field(t, "SourceImage")
        if src.rsplit("\\", 1)[-1].lower() in LSASS_BENIGN_SOURCES:
            continue
        if _field(t, "GrantedAccess").lower() not in LSASS_DUMP_MASKS:
            continue
        rows.append((r.Log_ID, src))
    if not rows:
        return
    src_by_id = dict(rows)
    sub = s[s["Log_ID"].isin(src_by_id)].copy()
    sub["_src"] = sub["Log_ID"].map(src_by_id)
    for (host, src), g in _groups(sub, ["Hostname", "_src"]):
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            masks = sorted({_field(x, "GrantedAccess") for x in c["Event_Description"]})
            exe = src.rsplit("\\", 1)[-1]
            reasons = [f"{exe} abrió lsass.exe con permisos de lectura de memoria ({', '.join(masks)}); es lo que hacen mimikatz, procdump o comsvcs.dll para extraer credenciales.",
                       "El proceso no está entre los componentes habituales de Windows que acceden a LSASS."]
            expl = (f"En {host}, {src} accedió a la memoria de lsass.exe ({pl(len(c), 'evento', 'eventos')} Sysmon 10, {hhmmss(c['Timestamp'].min())}). "
                    "Con esos permisos se puede volcar la memoria y obtener hashes y contraseñas (T1003.001).")
            _mk(st, "cred_lsass", f"Acceso a la memoria de LSASS por {exe} en {host}", "Comandos y procesos", "Acceso a credenciales",
                ["T1003.001"], "Crítico", reasons, expl, c, hosts=[host],
                metrics={"host": host, "proceso": src, "permisos": masks, "eventos": len(c)},
                iocs=[_ioc("Ruta/archivo", src, "Proceso que leyó la memoria de LSASS")])


def rule_cred_dcsync(st: State) -> None:
    d = st.df
    s = d[d["Event_ID"] == "4662"]
    rows = []
    for r in s.itertuples():
        t = r.Event_Description.lower()
        if not any(g in t for g in DCSYNC_GUIDS):
            continue
        acct = _field(r.Event_Description, "Account Name") or r.User
        if not acct or acct.endswith("$"):       # los controladores de dominio replican entre sí con cuentas de máquina
            continue
        rows.append((r.Log_ID, acct))
    if not rows:
        return
    acct_by_id = dict(rows)
    sub = s[s["Log_ID"].isin(acct_by_id)].copy()
    sub["_acct"] = sub["Log_ID"].map(acct_by_id)
    for (host, acct), g in _groups(sub, ["Hostname", "_acct"]):
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            reasons = [f"La cuenta {acct} solicitó derechos de replicación de directorio (DS-Replication-Get-Changes) sobre el dominio.",
                       "Solo los controladores de dominio (cuentas de máquina) deberían hacerlo; es la técnica DCSync."]
            expl = (f"En {host}, la cuenta de usuario {acct} ejerció derechos de replicación del directorio ({pl(len(c), 'evento', 'eventos')} 4662). "
                    "Un atacante con esos derechos puede extraer los hashes de todas las cuentas del dominio, incluido krbtgt (T1003.006).")
            _mk(st, "cred_dcsync", f"Posible DCSync por {acct} contra {host}", "Comandos y procesos", "Acceso a credenciales",
                ["T1003.006"], "Crítico", reasons, expl, c, actor_users=[acct], hosts=[host],
                metrics={"host": host, "usuario": acct, "eventos": len(c)})


def rule_persist_run(st: State) -> None:
    d = st.df
    s = d[d["Event_ID"] == "13"]
    rows = []
    for r in s.itertuples():
        t = r.Event_Description
        target = _field(t, "TargetObject")
        if not RUNKEY_RE.search(target):
            continue
        rows.append((r.Log_ID, target, _field(t, "Image"), _field(t, "Details")))
    if not rows:
        return
    info = {x[0]: x for x in rows}
    sub = s[s["Log_ID"].isin(info)].copy()
    for (host,), g in _groups(sub, ["Hostname"]):
        for c in clusters(g, 1800):
            det = [info[i] for i in c["Log_ID"]]
            risky = any(re.search(r"\\(Temp|Users\\Public|ProgramData|AppData)\\|powershell|cmd\.exe|wscript|mshta|rundll32|reg\.exe", x[2] + " " + x[3], re.I) for x in det)
            sev = "Alto" if risky else "Medio"
            reasons = [f"Se creó una entrada de inicio automático en {det[0][1].split(chr(92) + 'Run')[0].split('Microsoft')[-1].strip(chr(92)) or 'Run'}\\Run: {trunc(det[0][3], 100)}."]
            if risky:
                reasons.append("El ejecutable reside en una ruta escribible por el usuario o lo escribió un intérprete de comandos.")
            expl = (f"En {host}, {det[0][2] or 'un proceso'} añadió {pl(len(c), 'valor', 'valores')} a las claves Run/RunOnce (Sysmon 13): "
                    + "; ".join(f"{x[1].rsplit(chr(92), 1)[-1]} = {trunc(x[3], 90)}" for x in det[:4]) + ". Se ejecutará en cada inicio de sesión (T1547.001).")
            _mk(st, "persist_run", f"Persistencia por clave Run en {host}", "Otras anomalías", "Persistencia", ["T1547.001"], sev, reasons, expl, c, hosts=[host],
                metrics={"host": host, "valores": [x[1] for x in det][:6], "imagenes": sorted({x[2] for x in det if x[2]})[:4]},
                iocs=[_ioc("Ruta/archivo", trunc(x[3], 200), "Valor de la clave Run") for x in det[:6] if x[3]])


def rule_kerberoast(st: State) -> None:
    """Kerberoasting (T1558.003): una cuenta pide tickets de servicio con cifrado RC4 (0x17) para varios servicios de usuario."""
    d = st.df
    s = d[d["Event_ID"] == "4769"]
    rows = []
    for r in s.itertuples():
        t = r.Event_Description
        if _field(t, "Ticket Encryption Type").lower() != "0x17":
            continue
        svc = _field(t, "Service Name")
        if not svc or svc.endswith("$") or svc.lower().startswith("krbtgt"):   # cuentas de máquina y krbtgt usan RC4 sin ser señal
            continue
        acct = (_field(t, "Account Name") or r.User).split("@")[0]
        if not acct or acct.endswith("$"):
            continue
        rows.append((r.Log_ID, acct, svc))
    if not rows:
        return
    info = {x[0]: x for x in rows}
    sub = s[s["Log_ID"].isin(info)].copy()
    sub["_acct"] = sub["Log_ID"].map(lambda i: info[i][1])
    for (host, acct), g in _groups(sub, ["Hostname", "_acct"]):
        for c in clusters(g, CONFIG["kerberoast_window_s"]):
            svcs = list(dict.fromkeys(info[i][2] for i in c["Log_ID"]))
            if len(svcs) < CONFIG["kerberoast_min_services"]:
                continue
            ips = [i for i in dict.fromkeys(c["Source_IP"]) if i]
            reasons = [f"{acct} pidió tickets de servicio con cifrado RC4 (0x17) para {len(svcs)} servicios distintos en {fmt_dur((c['Timestamp'].max() - c['Timestamp'].min()).total_seconds())}: {', '.join(svcs[:6])}.",
                       "Un usuario normal pide pocos tickets y con AES; pedirlos en ráfaga con RC4 permite descifrar la contraseña de las cuentas de servicio sin conexión (Kerberoasting)."]
            expl = (f"En {host}, la cuenta {acct} solicitó {pl(len(c), 'ticket', 'tickets')} Kerberos (4769) con cifrado RC4 para {len(svcs)} cuentas de servicio "
                    f"({', '.join(svcs[:6])}). Un atacante usa esos tickets para crackear las contraseñas de las cuentas de servicio fuera de línea (T1558.003).")
            _mk(st, "kerberoast", f"Posible Kerberoasting por {acct} ({len(svcs)} servicios)", "Inicios sospechosos", "Acceso a credenciales",
                ["T1558.003"], "Alto", reasons, expl, c, actor_users=[acct], hosts=[host],
                metrics={"host": host, "usuario": acct, "servicios": svcs[:10], "tickets": len(c), "ips": ips[:3]},
                iocs=[_ioc("Cuenta", s_, "Cuenta de servicio con ticket RC4 solicitado") for s_ in svcs[:8]])


def rule_web_attack(st: State) -> None:
    d = st.df
    w = d[(d["Log_Source"] == "IIS") | (d["Event_ID"] == "HTTP_ACCESS")]
    for ip, g in _groups(w, "Source_IP"):
        for c in clusters(g, CONFIG["web_cluster_gap_s"]):
            n = len(c)
            if n < CONFIG["web_min_requests"]:
                continue
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            dur = (t1 - t0).total_seconds()
            gap = median_gap(c)
            status = Counter(c["Result"])
            uris = Counter(c["Process_CommandLine"])
            probe = c[c["Process_CommandLine"].str.contains(r"cmd=|\.aspx\?|\.\./|union\s+select|<script", case=False, regex=True)]
            host = c.iloc[0].Hostname
            rce = d[(d["Hostname"] == host) & (d["Source_IP"] == ip) & (d["Event_ID"] == "4688")
                    & d["User"].str.contains(WEB_SVC_USER_RE) & (d["Timestamp"] > t1) & (d["Timestamp"] <= t1 + timedelta(minutes=10))]
            sev = "Crítico" if len(rce) else "Alto"
            uri_txt = ", ".join(f"{u} x{k}" for u, k in uris.most_common(6))
            st_txt = ", ".join(f"HTTP {s}: {k}" for s, k in sorted(status.items()))
            reasons = [f"{n} peticiones HTTP desde {ip} en {fmt_dur(dur)}"
                       + (f" (una cada {fmt_dec(gap, 0)} s, cadencia automatizada)." if gap else ".")]
            if len(probe):
                first_probe = probe.iloc[0]
                reasons.append(f"{len(probe)} peticiones con patrón de webshell/inyección (p. ej. {first_probe.Process_CommandLine}); "
                               f"la primera ({first_probe.Log_ID}) devolvió HTTP {first_probe.Result}.")
            reasons.append(f"Respuestas: {st_txt}; abundantes 5xx/4xx indican sondeo de recursos.")
            if len(rce):
                reasons.append(f"Segundos después el servicio web ejecutó un proceso hijo ({', '.join(rce['Log_ID'])}): posible ejecución remota de comandos.")
            expl = (f"Desde la IP externa {ip} se enviaron {n} peticiones a {host} entre {hhmmss(t0)} y {hhmmss(t1)}: {uri_txt}. "
                    f"Estados: {st_txt}. "
                    + (f"Las peticiones a /uploads/*.aspx con el parámetro cmd= (primera: {probe.iloc[0].Log_ID}, HTTP {probe.iloc[0].Result}) "
                       f"corresponden al patrón de uso de una webshell (T1505.003). " if len(probe) else "")
                    + "Además se enumeran /admin/, /api/v1/export y se repite /login?user=admin, lo que sugiere reconocimiento y "
                      "adivinación de acceso (T1190, T1110)." )
            iocs = [_ioc("IP", ip, "Origen del ataque web")]
            iocs += [_ioc("URL/URI", u, f"Solicitada {k} veces") for u, k in uris.most_common(8)]
            _mk(st, "web_attack", f"Ataque web contra {host} desde {ip}", "Otras anomalías", "Acceso inicial",
                ["T1190", "T1505.003"], sev, reasons, expl, c, actor_ips=[ip],
                metrics={"peticiones": n, "ventana_s": round(dur), "mediana_entre_peticiones_s": gap,
                         "estados": {str(k): int(v) for k, v in status.items()},
                         "uris": dict(uris), "posible_rce": bool(len(rce)), "host": host}, iocs=iocs)


def rule_dataquality(st: State) -> None:
    d = st.df
    # 1) alias de nombre de host
    groups = defaultdict(set)
    for h in set(d["Hostname"]) - {""}:
        groups[norm_host(h)].add(h)
    for key, names in groups.items():
        if len(names) > 1:
            cnt = {h: int((d["Hostname"] == h).sum()) for h in sorted(names)}
            rows = d[d["Hostname"].isin(names)].groupby("Hostname").head(3)   # ejemplos de cada grafía
            _mk(st, "dq_host_alias", f"Nombres de host inconsistentes: {' / '.join(sorted(names))}", "Otras anomalías",
                "Calidad de datos / SIEM", [], "Bajo",
                [f"El mismo equipo aparece con {len(names)} grafías ({', '.join(f'{h}: {n} eventos' for h, n in cnt.items())})."],
                f"Los eventos usan variantes del mismo nombre ({', '.join(sorted(names))}). Si no se normalizan, las correlaciones por host "
                f"se fragmentan y pueden ocultar actividad. No se interpretó como actividad maliciosa: es un problema de normalización del SIEM.",
                rows, metrics={"variantes": cnt}, iocs=[])
    # 2) Log_Source incoherente con el Event ID
    bad = d[(d["Event_ID"] == "7036") & (d["Log_Source"] != "System")]
    if len(bad):
        _mk(st, "dq_logsource", "Evento 7036 registrado con fuente distinta de 'System'", "Otras anomalías",
            "Calidad de datos / SIEM", [], "Bajo",
            [f"{len(bad)} evento(s) 7036 (Service Control Manager) figuran con Log_Source='{bad.iloc[0].Log_Source}'."],
            f"El Event ID 7036 pertenece al registro System, pero {', '.join(bad['Log_ID'])} aparece como '{bad.iloc[0].Log_Source}'. "
            f"Puede ser un error de parseo o una inserción de eventos; se recomienda verificarlo en el origen.",
            bad, metrics={"eventos": list(bad["Log_ID"])}, iocs=[])
    # 3) cuentas con nombres parecidos (mismas letras reordenadas)
    users = sorted({short_user(u) for u in d["User"]} - {"", "-"})
    by_letters = defaultdict(list)
    for u in users:
        k = "".join(sorted(re.sub(r"[^a-z0-9]", "", u.lower())))
        if len(k) >= 6:
            by_letters[k].append(u)
    for k, names in by_letters.items():
        if len(names) > 1:
            full = [u for u in set(d["User"]) if short_user(u) in names]
            rows = d[d["User"].isin(full)].groupby("User").head(2)
            cnt = {n: int(d["User"].map(short_user).eq(n).sum()) for n in names}
            _mk(st, "dq_account_lookalike", f"Cuentas con nombres casi idénticos: {' / '.join(names)}", "Otras anomalías",
                "Calidad de datos / SIEM", [], "Bajo",
                [f"Existen {len(names)} cuentas con las mismas letras en distinto orden ({', '.join(f'{n}: {c} eventos' for n, c in cnt.items())})."],
                f"Se observan las cuentas {', '.join(names)}, que difieren solo por el orden de sus componentes. Puede ser una convención "
                f"de nombres legítima o una cuenta creada para confundir a los analistas (T1036). Los logs no permiten decidir cuál: "
                f"conviene validar en Active Directory quién creó cada una y cuándo.",
                rows, actor_users=[u for u in full], metrics={"cuentas": cnt}, iocs=[])


def rule_underclassification(st: State) -> None:
    d = st.df
    skip = {"dq_host_alias", "dq_logsource", "dq_account_lookalike"}
    ev_ids = {i for f in st.findings if f.rule not in skip for i in f.evidence_ids}
    ev = d[d["Log_ID"].isin(ev_ids)]
    info = ev[ev["Severity"].str.lower().isin(["informational", "info", "informativo", "low", "bajo"])]
    if len(ev) == 0 or len(info) == 0:
        return
    per_rule = Counter()
    for f in st.findings:
        if f.rule in skip:
            continue
        per_rule[f.title] = sum(1 for i in f.evidence_ids if i in set(info["Log_ID"]))
    top = [(t, n) for t, n in per_rule.most_common() if n][:6]
    _mk(st, "siem_underclass", f"El SIEM clasificó como 'Informational' {len(info)} eventos que forman parte de incidentes",
        "Otras anomalías", "Calidad de datos / SIEM", [], "Medio",
        [f"{len(info)} de {len(ev)} eventos usados como evidencia ({fmt_dec(len(info) / len(ev) * 100, 0)} %) tienen Severity=Informational en el export."],
        f"De los {len(ev)} eventos que sustentan los hallazgos, {len(info)} fueron clasificados por el SIEM como Informational, por lo que "
        f"no habrían generado una alerta prioritaria. Ejemplos por hallazgo: " + "; ".join(f"{t} ({n})" for t, n in top) +
        ". Se recomienda ajustar las reglas de correlación/severidad del SIEM para cubrir estos comportamientos.",
        info.head(40), metrics={"eventos_informational": int(len(info)), "eventos_evidencia": int(len(ev)), "top": top}, iocs=[])


RULES: list[tuple[str, str, Callable[[State], None]]] = [
    ("brute_force", "Fuerza bruta / password spraying: ráfagas de 4625 desde una misma IP", rule_brute_force),
    ("external_logon", "Inicio de sesión exitoso (4624) desde IP externa", rule_external_logon),
    ("privilege", "Privilegios especiales (4672) asociados a origen externo o cuenta comprometida", rule_privilege),
    ("persistence", "Persistencia: tareas programadas (4698) y servicios nuevos (7045)", rule_persistence),
    ("cmd", "Comandos/procesos sospechosos (PowerShell codificado, reconocimiento, compresión, vssadmin, shell del servicio web…)", rule_commands),
    ("cred_lsass", "Acceso a la memoria de LSASS (Sysmon 10) por procesos no habituales", rule_cred_lsass),
    ("cred_dcsync", "DCSync: derechos de replicación de directorio (4662) usados por una cuenta de usuario", rule_cred_dcsync),
    ("persist_run", "Persistencia en claves Run/RunOnce (Sysmon 13)", rule_persist_run),
    ("kerberoast", "Kerberoasting: ráfaga de tickets de servicio RC4 (4769) de una misma cuenta", rule_kerberoast),
    ("lateral", "Movimiento lateral: autenticación en un host con origen en otro host (source=…)", rule_lateral),
    ("mass_access", "Acceso masivo/secuencial a archivos (4663)", rule_mass_access),
    ("sensitive_share", "Acceso a recursos compartidos sensibles (5140/5145)", rule_sensitive_share),
    ("exfil_proxy", "Exfiltración: ráfaga de POST al proxy hacia IP externa", rule_exfil_proxy),
    ("outbound_shell", "Conexión saliente a IP externa iniciada por shell/proceso inusual", rule_outbound),
    ("web_attack", "Ataque web: ráfagas HTTP con patrones de webshell/enumeración", rule_web_attack),
    ("dataquality", "Calidad de datos: hosts con distintas grafías, fuente de log incoherente, cuentas similares", rule_dataquality),
    ("siem_underclass", "Brecha del SIEM: evidencias de incidentes clasificadas como Informational", rule_underclassification),
]


# --------------------------------------------------------------------------
# correlación en incidentes
# --------------------------------------------------------------------------
INCIDENT_EXCLUDED_RULES = {"dq_host_alias", "dq_logsource", "dq_account_lookalike", "siem_underclass"}


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _incident_title(fs: list[Finding]) -> str:
    generic = detection_generic.incident_title(fs)
    if generic:
        return generic
    rules = {f.rule for f in fs}
    host = lambda r: next((f.hosts[0] for f in fs if f.rule == r and f.hosts), "")
    users = [u for f in fs for u in f.actor_users]
    user = short_user(Counter(users).most_common(1)[0][0]) if users else ""
    if "web_attack" in rules or "cmd_web_service_shell" in rules:
        rce = "cmd_web_service_shell" in rules
        return f"Ataque web contra {host('web_attack') or 'el servidor web'}" + (" con ejecución remota de comandos" if rce else "")
    if "exfil_proxy" in rules:
        return f"Exfiltración de datos desde {host('exfil_proxy')} ({user})"
    if "persistence" in rules:
        return f"Persistencia en {host('persistence')} por la cuenta {user}"
    if "lateral" in rules:
        extra = " y exfiltración" if "outbound_shell" in rules else ""
        return f"Compromiso de la cuenta {user} por acceso externo, movimiento lateral{extra}"
    if "cmd_anti_recovery" in rules or "mass_access" in rules:
        return f"Recolección masiva y eliminación de copias de sombra por {user}"
    if "external_logon" in rules and "brute_force" in rules:
        return f"Password spraying con compromiso de la cuenta {user}"
    return "Actividad sospechosa correlacionada"


def _ukey(user: str) -> str:
    """CORP\\mflores, mflores y mflores@corp.example son la misma cuenta (fuentes distintas la escriben distinto)."""
    return short_user(user).split("@")[0].lower()


def correlate(st: State) -> tuple[list[dict], list[Finding]]:
    fs = [f for f in st.findings if f.rule not in INCIDENT_EXCLUDED_RULES]
    uf = _UF(len(fs))
    for i, a in enumerate(fs):
        for j in range(i + 1, len(fs)):
            b = fs[j]
            share_ip = set(a.link_ips) & set(b.link_ips)
            share_user = {_ukey(u) for u in a.actor_users} & {_ukey(u) for u in b.actor_users}
            if share_ip or share_user:
                uf.union(i, j)
    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(fs):
        groups[uf.find(i)].append(f)
    ordered = sorted(groups.values(), key=lambda g: min(f.time_start for f in g))
    incidents = []
    for n, g in enumerate(ordered, 1):
        iid = f"INC-{n:03d}"
        g.sort(key=lambda f: (f.time_start, -SEV_ORDER[f.severity]))
        for f in g:
            f.incident_id = iid
        users = list(dict.fromkeys(u for f in g for u in f.actor_users))
        ips = list(dict.fromkeys(i for f in g for i in f.link_ips if is_external(i)))
        hosts = list(dict.fromkeys(h for f in g for h in f.hosts))
        tactics = [t for t in TACTIC_ORDER if t in {f.tactic for f in g}]
        sev = max_sev(f.severity for f in g)
        incidents.append({
            "id": iid, "title": _incident_title(g), "severity": sev,
            "time_start": min(f.time_start for f in g), "time_end": max(f.time_end for f in g),
            "finding_ids": [], "_findings": g, "actor_users": users, "external_ips": ips, "hosts": hosts,
            "tactics": tactics, "mitre": sorted({t for f in g for t in f.mitre}),
            "evidence_count": len({e for f in g for e in f.evidence_ids}),
        })
    others = [f for f in st.findings if f.rule in INCIDENT_EXCLUDED_RULES]
    return incidents, others


def build_hypotheses(incidents: list[dict]) -> list[dict]:
    """Relaciones ENTRE incidentes que los logs sugieren pero no prueban."""
    out = []
    # recursos sensibles compartidos
    res = defaultdict(set)
    for inc in incidents:
        for f in inc["_findings"]:
            if f.rule in ("mass_access", "sensitive_share") and f.metrics.get("recurso"):
                res[f.metrics["recurso"]].add(inc["id"])
    for label, ids in res.items():
        if len(ids) > 1:
            ids = sorted(ids)
            times = {i: next(x for x in incidents if x["id"] == i) for i in ids}
            spans = "; ".join(
                i + ": " + times[i]["time_start"][11:16] + "-" + times[i]["time_end"][11:16] for i in ids)
            out.append({
                "id": f"H-{len(out) + 1:02d}", "confidence": "Baja", "incidents": ids,
                "statement": (f"Los incidentes {', '.join(ids)} tocan el mismo recurso sensible '{label}' "
                              f"({spans}), "
                              f"pero con cuentas, IP de origen y hosts distintos."),
                "basis": "Coincidencia de recurso objetivo. Ningún evento enlaza directamente las cuentas o los hosts de ambos incidentes.",
            })
    # IPs externas en el mismo /24
    by24 = defaultdict(lambda: defaultdict(set))
    for inc in incidents:
        for ip in inc["external_ips"]:
            try:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                continue
            by24[net][ip].add(inc["id"])
    for net, ipmap in by24.items():
        incs = sorted({i for s in ipmap.values() for i in s})
        if len(ipmap) > 1 and len(incs) > 1:
            out.append({
                "id": f"H-{len(out) + 1:02d}", "confidence": "Baja", "incidents": incs,
                "statement": f"Las IP externas {', '.join(sorted(ipmap))} comparten el segmento {net} y aparecen en incidentes distintos ({', '.join(incs)}).",
                "basis": "Coincidencia de red /24. No prueba una infraestructura común; puede ser casualidad o un artefacto del rango usado.",
            })
    return out


# Reglas para eventos que no son de Windows (SSH, web, DNS, correo, nube…). Se importa al final porque usa las
# utilidades de este módulo.
from . import detection_generic  # noqa: E402

RULES.extend(detection_generic.RULES)
