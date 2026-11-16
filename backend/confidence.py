"""Confianza de cada hallazgo y evidencia en contra.

La **criticidad** dice cuánto daño haría si es real; la **confianza** dice qué tan probable es que sea actividad maliciosa real y no un
falso positivo. Son ejes distintos: un «Crítico» puede tener confianza baja (por ejemplo, una sola línea que coincide con un patrón) y un
«Medio» puede ser casi seguro. Este módulo no cambia la criticidad ni qué se detecta.

El cálculo es determinista y se explica entero:

1. **Punto de partida según el tipo de señal** (``BASE``): Alta para señales que casi nunca son legítimas (lectura de LSASS, DCSync,
   coincidencia con inteligencia de amenazas…), Media para comportamientos que también hace un administrador, Baja para heurísticas y
   observaciones de calidad de datos. En puntos: Alta 6, Media 4, Baja 2.
2. **Ajustes** a favor (+) y en contra (−), cada uno con su motivo legible: corroboración por otra detección independiente (+2), origen
   externo (+1), origen interno en reglas de origen (−1), cuenta de servicio o de máquina (−1), cuenta de administración haciendo una tarea
   de administración (−1), un solo evento (−1), y ajustes propios de cada regla a partir de sus métricas.
3. **Resultado:** 6 o más puntos = Alta; 4 o 5 = Media; 3 o menos = Baja.

La medición de si esto separa bien los aciertos del ruido está en docs/VALIDACION.md.
"""
from __future__ import annotations

import re
from datetime import timedelta

import pandas as pd

from . import detection as D

POINTS = {"Alta": 6, "Media": 4, "Baja": 2}
LEVELS = ("Baja", "Media", "Alta")
ORDER = {"Alta": 3, "Media": 2, "Baja": 1, "": 0}
BASIS = {"Alta": "Punto de partida alto: este tipo de señal casi nunca es legítimo.",
         "Media": "Punto de partida medio: este comportamiento también lo produce actividad legítima; depende del contexto.",
         "Baja": "Punto de partida bajo: es una señal débil por sí sola (por ejemplo, comandos de reconocimiento que también usa soporte técnico)."}

# Punto de partida por regla. Lo no listado parte de Media.
_ALTA = {"cred_lsass", "cred_dcsync", "kerberoast", "outbound_shell", "defense_registry", "ctx_misp", "ctx_feed",
         "cmd_anti_recovery", "cmd_cred_dump", "cmd_web_service_shell", "g_ransomware", "g_mining", "lat_dcom", "lat_remote_service"}
_BAJA = {"cmd_discovery", "siem_underclass", "dq_account_lookalike", "dq_host_alias", "dq_logsource"}
BASE = {**{r: "Alta" for r in _ALTA}, **{r: "Baja" for r in _BAJA}}

# Observaciones que no son indicios de ataque: no cuentan como corroboración ni se ajustan.
OBSERVATIONS = {"siem_underclass", "dq_account_lookalike", "dq_host_alias", "dq_logsource"}
WEAK = OBSERVATIONS | {"cmd_discovery"}
# Señales que valen con un solo evento (no se descuenta «un solo evento»).
SINGLE_OK = _ALTA | {"persist_run", "persistence", "external_logon", "privilege", "cmd_encoded_ps", "cmd_download_cradle",
                     "cmd_obfuscated_cmd", "cmd_lolbin_proxy", "cmd_log_tamper", "lat_svcctl", "lat_admin_write", "lat_winrm", "lat_wmi",
                     "g_phishing", "g_privesc", "g_exfil", "ctx_cve", "lateral", "cmd_logon_script", "cmd_service_binpath", "cmd_fw_change"}
# Reglas donde el origen de red es el actor (una IP interna es motivo de duda; una pública, de certeza).
ORIGIN_RULES = {"brute_force", "g_auth", "web_attack", "g_web", "privilege", "lateral"}
# Reglas donde la cuenta es quien actúa (y no la víctima, como en la fuerza bruta).
ACTOR_RULES = {"persistence", "persist_run", "privilege", "mass_access", "sensitive_share", "exfil_proxy", "lat_wmi", "lat_winrm",
               "g_cmd", "g_persistence", "g_persistence_linux"} | {r for r in ("cmd_discovery", "cmd_encoded_ps", "cmd_download_cradle", "cmd_obfuscated_cmd",
               "cmd_lolbin_proxy", "cmd_log_tamper", "cmd_fw_change", "cmd_service_binpath", "cmd_logon_script", "cmd_archive_staging")}
# Tareas que forman parte del trabajo de un administrador.
ADMIN_TASKS = {"persistence", "privilege", "cmd_fw_change", "cmd_service_binpath", "cmd_log_tamper", "cmd_logon_script",
               "lat_winrm", "lat_wmi", "lat_svcctl", "lat_admin_write"}
SERVICE_RE = re.compile(r"^(?:svc|sa)[_.\-]|[_.\-]svc$|service|^system$|healthmailbox|\$$", re.I)
ODD_PATH = re.compile(r"\\(?:ProgramData|Temp|Users\\Public|AppData|PerfLogs)\\|^\\\\", re.I)


def _ts(s: str):
    try:
        return pd.Timestamp(s)
    except (TypeError, ValueError):
        return None


def _num(v) -> float:
    """Valor numérico de una métrica. Algunas reglas guardan la lista de eventos (por ejemplo, «exitos_posteriores»): cuenta sus elementos."""
    if isinstance(v, (list, tuple, set, dict)):
        return float(len(v))
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _rule_specific(f: D.Finding) -> list[tuple[int, str]]:
    """Ajustes propios de cada regla, a partir de sus métricas. Cada uno: (puntos, motivo)."""
    m, r, out = f.metrics or {}, f.rule, []
    if r in ("brute_force", "g_auth"):
        intentos, cuentas = _num(m.get("intentos_fallidos")), _num(m.get("cuentas_objetivo"))
        if _num(m.get("exitos_posteriores")):
            out.append((2, "Después de los fallos hubo un inicio de sesión exitoso desde el mismo origen."))
        if intentos >= 50:
            out.append((1, f"Volumen alto: {int(intentos)} intentos fallidos."))
        if cuentas >= 3:
            out.append((1, f"Probó {int(cuentas)} cuentas distintas (patrón de rociado de contraseñas)."))
        med = m.get("mediana_entre_intentos_s")
        if med is not None and _num(med) <= 2:
            out.append((1, "Ritmo de máquina: los intentos llegan con segundos o menos de diferencia."))
        if intentos and intentos < 15 and cuentas <= 1 and not _num(m.get("exitos_posteriores")):
            out.append((-1, "Pocos intentos sobre una sola cuenta: también lo produce un usuario que olvidó su contraseña o un servicio con una clave vieja."))
    elif r == "external_logon":
        if m.get("tras_fuerza_bruta"):
            out.append((2, "El acceso llegó después de una fuerza bruta desde el mismo origen."))
        if m.get("rdp"):
            out.append((1, "Es un acceso por escritorio remoto (RDP) desde Internet."))
    elif r == "lateral" and _num(m.get("exitos")):
        out.append((1, "La autenticación entre equipos tuvo éxito."))
    elif r == "lat_svcctl" and _num(m.get("servicios_nuevos")):
        out.append((2, "En la misma ventana se instaló un servicio nuevo en el equipo."))
    elif r == "lat_admin_write" and m.get("carpeta_sistema"):
        out.append((1, "El archivo se escribió en una carpeta del sistema o de programas."))
    elif r in ("lat_wmi", "lat_winrm"):
        if m.get("origen_red"):
            out.append((1, "Hubo un inicio de sesión de red cercano: la ejecución vino de otro equipo."))
        else:
            out.append((-1, "No hay inicio de sesión de red cercano: puede ser administración local."))
        if m.get("oculto"):
            out.append((2, "Ejecutó PowerShell oculto o codificado dentro de la sesión remota."))
        if m.get("consumidor_wmi"):
            out.append((1, "Se activó un consumidor de eventos WMI con script."))
    elif r in ("persistence", "persist_run"):
        imgs = " ".join(map(str, m.get("imagenes") or []))
        if imgs and ODD_PATH.search(imgs):
            out.append((1, "El programa que queda persistente está en una carpeta escribible por usuarios o en un recurso de red."))
        if m.get("periodico"):
            out.append((1, "Se ejecuta de forma periódica y regular, como una baliza."))
    elif r.startswith("cmd_") and _num(m.get("comandos")) >= 3:
        out.append((1, f"El patrón se repitió en {int(_num(m.get('comandos')))} comandos."))
    elif r == "exfil_proxy" and _num(m.get("mb_totales")) >= 100:
        out.append((1, f"Volumen de salida alto: {int(_num(m.get('mb_totales')))} MB."))
    elif r in ("web_attack", "g_web") and (m.get("posible_rce") or m.get("consulta_sensible_posterior")):
        out.append((2, "Hay señales de que el ataque web tuvo efecto (ejecución de comandos o consulta sensible posterior)."))
    elif r == "g_ransomware":
        if m.get("nota_de_rescate"):
            out.append((2, "Apareció una nota de rescate."))
        if m.get("copias_borradas"):
            out.append((1, "Se borraron las copias de sombra."))
    elif r == "mass_access" and m.get("numeracion_consecutiva"):
        out.append((1, "Los archivos se recorrieron en orden consecutivo, como lo haría un script."))
    elif r == "g_c2" and _num(m.get("conexiones")) >= 20:
        out.append((1, f"{int(_num(m.get('conexiones')))} conexiones al mismo destino."))
    elif r == "ctx_cve":
        out.append((-1, "Indica software vulnerable, no que alguien lo haya explotado."))
    return out


def _corroboration(f: D.Finding, others: list[D.Finding]) -> list[tuple[int, str]]:
    """+2 si otra detección **independiente** (otra regla y ningún evento en común) apunta al mismo equipo en ±2 h o al mismo actor."""
    if f.rule in OBSERVATIONS:
        return []
    ev, t0, t1 = set(f.evidence_ids), _ts(f.time_start), _ts(f.time_end)
    actor_ips = {i for i in f.link_ips if i}
    actors = {u.lower() for u in f.actor_users if u}
    hits, intel = [], []
    for g in others:
        if g is f or g.rule == f.rule or g.rule in WEAK or ev & set(g.evidence_ids):
            continue
        same_actor = bool(actor_ips & set(g.link_ips)) or bool(actors & {u.lower() for u in g.actor_users if u})
        same_host = False
        if set(f.hosts) & set(g.hosts) and t0 is not None and t1 is not None:
            g0, g1 = _ts(g.time_start), _ts(g.time_end)
            same_host = g0 is not None and g1 is not None and g0 <= t1 + timedelta(hours=2) and g1 >= t0 - timedelta(hours=2)
        if same_actor or same_host:
            (intel if g.rule.startswith("ctx_") else hits).append(g.title)
    out = []
    if intel:
        out.append((2, "El actor coincide con inteligencia de amenazas: " + "; ".join(dict.fromkeys(intel[:2])) + "."))
    if hits:
        names = list(dict.fromkeys(hits))
        out.append((2, f"Otra detección independiente (sin eventos en común) apunta al mismo equipo o actor: {'; '.join(names[:2])}"
                       + (f" y {len(names) - 2} más" if len(names) > 2 else "") + "."))
    return out


def assess(f: D.Finding, others: list[D.Finding]) -> None:
    """Completa confidence, confidence_score, confidence_basis, confidence_for y confidence_against del hallazgo."""
    base = BASE.get(f.rule, "Media")
    if f.rule in OBSERVATIONS:
        f.confidence, f.confidence_score, f.confidence_for, f.confidence_against = "Baja", POINTS["Baja"], [], []
        f.confidence_basis = "Es una observación sobre la calidad o la clasificación de los datos, no un indicio de ataque."
        return
    f.confidence_basis = BASIS[base]
    adj: list[tuple[int, str]] = []
    adj += _corroboration(f, others)
    if f.rule in ORIGIN_RULES:
        ips = [i for i in f.link_ips if i]
        if any(D.is_external(i) for i in ips):
            adj.append((1, "El origen es una IP pública."))
        elif ips:
            adj.append((-1, "El origen es una IP interna: puede ser un equipo mal configurado, un escáner autorizado o administración."))
    accounts = [u for u in (f.actor_users or f.users) if u and u != "-"]
    if f.rule in ACTOR_RULES and accounts:
        if all(SERVICE_RE.search(D.short_user(u)) for u in accounts):
            adj.append((-1, "La cuenta es de servicio o de máquina: puede ser un proceso automático; verificar si es su comportamiento habitual."))
        elif f.rule in ADMIN_TASKS and all(D.is_admin_like(u) for u in accounts):
            adj.append((-1, "Lo hizo una cuenta de administración y es una tarea propia de su trabajo: confirmar que estaba planificada."))
    if len(f.evidence_ids) == 1 and f.rule not in SINGLE_OK:
        adj.append((-1, "Se apoya en un solo evento."))
    adj += _rule_specific(f)

    score = POINTS[base] + sum(p for p, _ in adj)
    f.confidence = "Alta" if score >= 6 else "Media" if score >= 4 else "Baja"
    f.confidence_score = score
    f.confidence_for = [t for p, t in adj if p > 0]
    f.confidence_against = [t for p, t in adj if p < 0]


def assess_all(findings: list[D.Finding]) -> None:
    for f in findings:
        assess(f, findings)
