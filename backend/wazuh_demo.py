"""Modo demo del panel de Wazuh: reproduce una secuencia de ataque de ejemplo, sin necesitar un Wazuh real.

Se activa con ``WAZUH_DEMO=on`` (y solo si ``WAZUH_INGEST`` está apagado: una instalación con Wazuh de verdad nunca mezcla alertas inventadas con las reales).
Las alertas se generan aquí con el formato que entrega ``integratord`` y entran por el mismo camino que las reales: traductor, ventana en memoria,
motor de reglas y aviso. No hay IA ni red de por medio y los datos son ficticios (documentación RFC 5737: ``203.0.113.0/24`` y ``198.51.100.0/24``).

La historia se cuenta por etapas, separadas ``WAZUH_DEMO_SECONDS`` segundos (20 por defecto), para ver cómo el caso crece y cómo sube la severidad:

1. Fuerza bruta contra ``admin`` desde una IP pública.
2. La misma IP entra con éxito.
3. La cuenta pide privilegios de depuración y lee la memoria de ``lsass.exe``.
4. Persistencia: un valor nuevo en la clave ``Run`` apuntando a ``ProgramData``.
5. Ruido de fondo: intentos de SSH contra un servidor Linux (severidad media, va al resumen).
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

log = logging.getLogger("soc.wazuh.demo")

LABEL = "🧪 DEMO · "
ATTACKER = "203.0.113.50"
SSH_SCANNER = "198.51.100.9"
HOST = "WS-01"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def interval() -> int:
    try:
        v = int(os.environ.get("WAZUH_DEMO_SECONDS", "").strip() or 20)
    except ValueError:
        v = 20
    return max(1, min(300, v))


def _ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}+0000"


def _win(run: str, n: int, t: datetime, eid: str, ed: dict, *, ch: str = "Security", level: int = 5, sev: str = "AUDIT_FAILURE", desc: str = "Windows") -> dict:
    return {"id": f"demo.{run}.{n}", "timestamp": _ts(t), "rule": {"id": "60122", "level": level, "description": desc},
            "agent": {"id": "001", "name": HOST},
            "data": {"win": {"system": {"eventID": eid, "channel": ch, "computer": f"{HOST}.corp.local", "severityValue": sev}, "eventdata": ed}}}


def _ssh(run: str, n: int, t: datetime) -> dict:
    return {"id": f"demo.{run}.{n}", "timestamp": _ts(t), "rule": {"id": "5760", "level": 5, "description": "sshd: authentication failed"},
            "agent": {"id": "002", "name": "linux-1"}, "decoder": {"name": "sshd"},
            "full_log": f"{t.strftime('%b %d %H:%M:%S')} linux-1 sshd[1042]: Failed password for root from {SSH_SCANNER} port 4242 ssh2"}


def stages(now: datetime | None = None, run: str | None = None) -> list[tuple[str, list[dict]]]:
    """Las etapas de la historia. Las horas se calculan respecto de ``now`` para que el panel muestre actividad reciente."""
    now = (now or datetime.now(timezone.utc)).replace(tzinfo=timezone.utc)
    run = run or str(int(now.timestamp()))
    logon = {"targetUserName": "admin", "targetDomainName": "CORP", "ipAddress": ATTACKER, "logonType": "3"}
    out: list[tuple[str, list[dict]]] = []

    # los desfases (segundos respecto de ``now``) ordenan la historia: fallos, acceso, privilegios, lsass, persistencia
    def t(offset: int) -> datetime:
        return now + timedelta(seconds=offset)

    out.append(("Fuerza bruta contra admin", [_win(run, i, t(i - 30), "4625", logon, desc="Logon failure - unknown user or bad password") for i in range(12)]))
    out.append(("Acceso exitoso desde la misma IP pública",
                [_win(run, 20, t(-16), "4624", logon, sev="AUDIT_SUCCESS", level=3, desc="Logon success")]))
    out.append(("Privilegios de depuración y lectura de lsass", [
        _win(run, 30, t(-12), "4672", {"subjectUserName": "admin", "subjectDomainName": "CORP", "privilegeList": "SeDebugPrivilege"},
             sev="AUDIT_SUCCESS", desc="Special privileges assigned to new logon"),
        _win(run, 31, t(-8), "10", {"sourceImage": "C:\\Windows\\Temp\\svchelper.exe", "targetImage": "C:\\Windows\\system32\\lsass.exe", "grantedAccess": "0x1fffff"},
             ch=SYSMON, level=12, desc="Sysmon: process accessed lsass.exe")]))
    out.append(("Persistencia en la clave Run", [
        _win(run, 40, t(-4), "13", {"image": "C:\\Windows\\Temp\\svchelper.exe", "eventType": "SetValue",
                                    "targetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper",
                                    "details": "C:\\ProgramData\\Microsoft\\svchelper.exe"},
             ch=SYSMON, level=10, sev="AUDIT_SUCCESS", desc="Sysmon: registry value set")]))
    out.append(("Ruido: intentos de SSH contra un servidor Linux", [_ssh(run, 50 + i, t(i - 10)) for i in range(8)]))
    return out


def replay(live, cycle: Callable[[], bool], every: int | None = None, *, sleep: Callable[[float], None] = time.sleep,
           now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> int:
    """Envía las etapas una a una y corre un ciclo de análisis tras cada una. Devuelve cuántas etapas envió."""
    wait = interval() if every is None else every
    sent = 0
    run = str(int(now().timestamp()))
    for i, name in enumerate(n for n, _ in stages(now(), run)):
        if i:
            sleep(wait)
        _, alerts = stages(now(), run)[i]
        res = live.ingest(alerts)
        log.info("wazuh_demo stage=%d name=%s accepted=%d", i + 1, name, res["accepted"])
        try:
            cycle()
        except Exception:          # una etapa que falla no debe frenar la historia ni tumbar el hilo
            log.exception("wazuh_demo_cycle_failed")
        sent += 1
    return sent
