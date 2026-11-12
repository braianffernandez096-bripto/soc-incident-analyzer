"""Alertas de Wazuh -> esquema del motor.

Wazuh entrega **alertas** (JSON) con la regla que saltó, el agente y los datos del evento. El motor de este proyecto trabaja con **eventos**
(columnas ``Log_ID``, ``Timestamp``, ``Hostname``, ``Event_ID``…). Este módulo hace de traductor y nada más: no decide criticidades ni habla con
la red. Lo que no sabe interpretar lo conserva como contexto (aparece en la línea de tiempo y en las evidencias) y se cuenta, para que el analista
vea cuánto del flujo se entendió.

Qué entiende hoy:

* **Windows** (canal de eventos, Sysmon y PowerShell): ``data.win.system.eventID`` + ``data.win.eventdata``. Se reconstruye la descripción con
  líneas ``Campo: valor``, que es el formato que ya leen las reglas del motor (``TargetImage``, ``GrantedAccess``, ``LogonType``…).
* **Linux** (``sshd`` y ``sudo``): se lee el ``full_log`` con el mismo lector que usa el ``auth.log`` de la app.
* **Cualquier otra alerta**: se conserva con su descripción, su identificador de regla y sus técnicas MITRE.

Los datos del evento son **no confiables** (los controla quien genera el log): se recortan, se les quitan los caracteres de control y la interfaz
los escapa al mostrarlos, como con cualquier archivo cargado.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone

from . import syslog as syslog_mod
from .parser import load_events

MAX_ALERTS_PER_CALL = 200
MAX_FIELD = 300
MAX_DESC = 2000
MAX_CMD = 2000

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EMPTY = {"", "-", "null", "none", "n/a"}

# Wazuh: nivel de la regla (0-15) -> etiqueta de severidad del SIEM (el motor la usa para detectar la «brecha del SIEM»)
def severity_from_level(level) -> str:
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "Informational"
    if n >= 12:
        return "Critical"
    if n >= 10:
        return "High"
    if n >= 7:
        return "Medium"
    if n >= 4:
        return "Low"
    return "Informational"


def _clean(v, limit: int = MAX_FIELD) -> str:
    if v is None:
        return ""
    s = _CTRL.sub(" ", str(v)).strip()
    return s[:limit]


def _g(d, *path):
    """Lectura segura de d[a][b][c]; devuelve '' si algo del camino falta o no es un dict."""
    for k in path:
        if not isinstance(d, dict):
            return ""
        d = d.get(k, "")
    return d if d is not None else ""


def _ip(v) -> str:
    s = _clean(v, 64)
    if s.lower() in _EMPTY:
        return ""
    try:
        if ipaddress.ip_address(s).is_unspecified:        # «0.0.0.0» y «::» significan «sin dato», no una dirección real
            return ""
    except ValueError:
        pass
    return s


def _val(v, limit: int = MAX_FIELD) -> str:
    s = _clean(v, limit)
    return "" if s.lower() in _EMPTY else s


def _timestamp(raw) -> str | None:
    """Wazuh escribe ``2026-11-12T12:34:56.789+0000``. Se devuelve ISO-8601 con zona para que el lector del motor lo pase a UTC."""
    s = _clean(raw, 64)
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d):?(\d\d)|(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z", s)
    if not m:
        return None
    if m.group(1):
        return f"{m.group(1)}{m.group(2) or ''}{m.group(3)}:{m.group(4)}"
    return f"{m.group(5)}{m.group(6) or ''}+00:00"


# ---------------------------------------------------------------- Windows

def _title(key: str) -> str:
    return key[:1].upper() + key[1:]


def _win_log_source(channel: str) -> str:
    c = channel.lower()
    if "sysmon" in c:
        return "Sysmon"
    if "powershell" in c:
        return "PowerShell"
    if c in ("security", "system", "application"):
        return c.capitalize()
    return _clean(channel.rsplit("/", 1)[-1], 40) or "Windows"


def _win_user(ed: dict, eid: str) -> str:
    # 4624/4625/4776...: la cuenta que intenta entrar es la «target»; en el resto manda la «subject»
    if eid in ("4624", "4625", "4648", "4768", "4769", "4771", "4776"):
        name, dom = _val(ed.get("targetUserName")), _val(ed.get("targetDomainName"))
    else:
        name, dom = _val(ed.get("subjectUserName")), _val(ed.get("subjectDomainName"))
    if not name:
        name, dom = _val(ed.get("user")), ""
    if not name:
        name = _val(ed.get("targetUserName")) or _val(ed.get("subjectUserName"))
    return f"{dom}\\{name}" if (dom and name and "\\" not in name) else name


def _win_row(alert: dict, win: dict, rule: dict) -> dict:
    system, ed = win.get("system") or {}, win.get("eventdata") or {}
    if not isinstance(system, dict):
        system = {}
    if not isinstance(ed, dict):
        ed = {}
    eid = _clean(system.get("eventID"), 12)
    lines = [_clean(rule.get("description"), 200)]
    for k, v in ed.items():
        sv = _val(v, 400)
        if sv and isinstance(k, str):
            lines.append(f"{_title(_clean(k, 60))}: {sv}")
    lt = _val(ed.get("logonType"), 4)
    if lt:
        lines.append(f"LogonType={lt}")
    ws = _val(ed.get("workstationName"), 80)
    if eid in ("4624", "4625") and ws:
        lines.append(f"source={re.sub(r'[^A-Za-z0-9_.-]', '', ws)}")
    sev_val = _clean(system.get("severityValue"), 20).upper()
    if sev_val == "AUDIT_FAILURE" or eid in ("4625", "4771"):
        result = "Failure"
    else:
        result = "Success"
    cmd = _val(ed.get("commandLine") or ed.get("scriptBlockText") or ed.get("newProcessName") or ed.get("image"), MAX_CMD)
    return {
        "Event_ID": eid,
        "Log_Source": _win_log_source(_clean(system.get("channel"), 80)),
        "User": _win_user(ed, eid),
        "Source_IP": _ip(ed.get("ipAddress") or ed.get("sourceIp") or ed.get("sourceAddress")),
        "Destination": _val(ed.get("destinationIp") or ed.get("destAddress") or ed.get("shareName") or ed.get("targetServerName")),
        "Event_Description": "\n".join(lines)[:MAX_DESC],
        "Process_CommandLine": cmd,
        "Result": result,
        "_host": _val(system.get("computer"), 120),
    }


# ---------------------------------------------------------------- Linux

def _linux_row(alert: dict, rule: dict, ts_iso: str) -> dict | None:
    full = _clean(alert.get("full_log"), 2000)
    if not full:
        return None
    when = datetime.fromisoformat(ts_iso).astimezone(timezone.utc).replace(tzinfo=None)
    events, _ = syslog_mod.parse_auth_log(full, year=when.year, now=when)
    if not events:
        return None
    ev = events[0]
    return {
        "Event_ID": ev["action"], "Log_Source": ev["category"], "User": _val(ev["user"]), "Source_IP": _ip(ev["source_ip"]),
        "Destination": "", "Event_Description": _clean(ev["message"], MAX_DESC), "Process_CommandLine": "",
        "Result": ev["status"], "_host": "",
    }


# ---------------------------------------------------------------- genérico

def _generic_row(alert: dict, rule: dict) -> dict:
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    ids = mitre.get("id") if isinstance(mitre.get("id"), list) else []
    desc = _clean(rule.get("description"), 300)
    extra = []
    if ids:
        extra.append("MITRE: " + ", ".join(_clean(i, 20) for i in ids[:6]))
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    for key in ("srcuser", "dstuser", "url", "protocol", "id"):
        if _val(data.get(key)):
            extra.append(f"{_title(key)}: {_val(data.get(key), 200)}")
    src = _ip(data.get("srcip") or data.get("src_ip"))
    dst = _ip(data.get("dstip") or data.get("dest_ip"))
    return {
        "Event_ID": f"wazuh_regla_{_clean(rule.get('id'), 12) or '0'}",
        "Log_Source": _val(_g(alert, "decoder", "name"), 40) or "Wazuh",
        "User": _val(data.get("dstuser") or data.get("srcuser")),
        "Source_IP": src,
        "Destination": dst,
        "Event_Description": "\n".join([desc] + extra)[:MAX_DESC],
        "Process_CommandLine": "",
        "Result": "alert",
        "_host": "",
    }


# ---------------------------------------------------------------- entrada

def normalize_alert(alert) -> tuple[dict | None, str]:
    """Una alerta de Wazuh -> (fila canónica, tipo) o (None, motivo del descarte)."""
    if not isinstance(alert, dict):
        return None, "no_es_objeto"
    rule = alert.get("rule")
    if not isinstance(rule, dict):
        return None, "sin_regla"
    ts = _timestamp(alert.get("timestamp"))
    if not ts:
        return None, "sin_fecha_valida"
    win = _g(alert, "data", "win")
    kind = "otro"
    row = None
    if isinstance(win, dict) and _g(win, "system", "eventID") not in ("", None):
        row, kind = _win_row(alert, win, rule), "windows"
    else:
        row = _linux_row(alert, rule, ts)
        kind = "linux_auth" if row else "otro"
    if row is None:
        row = _generic_row(alert, rule)
    host = _val(_g(alert, "agent", "name"), 120) or row.pop("_host", "") or _val(_g(alert, "agent", "id"), 40) or "wazuh"
    row.pop("_host", None)
    aid = _clean(alert.get("id"), 64)
    if not aid:
        return None, "sin_id"
    row.update(Log_ID=aid, Timestamp=ts, Hostname=host, Severity=severity_from_level(rule.get("level")))
    return row, kind


def normalize_alerts(alerts: list) -> tuple[list[dict], dict]:
    rows, stats = [], {"recibidas": len(alerts), "windows": 0, "linux_auth": 0, "otro": 0, "descartadas": 0, "motivos": {}}
    for a in alerts:
        row, kind = normalize_alert(a)
        if row is None:
            stats["descartadas"] += 1
            stats["motivos"][kind] = stats["motivos"].get(kind, 0) + 1
            continue
        stats[kind] += 1
        rows.append(row)
    return rows, stats


def rows_to_frame(rows: list[dict]):
    """Filas canónicas -> (DataFrame del motor, metadatos), por el mismo camino que un JSON cargado a mano."""
    return load_events(json.dumps(rows, ensure_ascii=False).encode("utf-8"), "wazuh-alertas.json")
