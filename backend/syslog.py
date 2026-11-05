"""Lectura de ``auth.log`` / ``secure`` de Linux (syslog en texto) y conversión al esquema multi-fuente de la app.

Entiende los dos formatos de fecha habituales (``Nov  2 09:00:01`` de syslog clásico y ``2026-11-02T09:00:01+00:00`` de rsyslog/journald)
y estos eventos: sshd (contraseña/clave aceptada o fallida, usuario inválido) y sudo (intentos fallidos y comandos ejecutados).
El resto de líneas se ignora y se cuenta, para avisar cuánto del archivo se pudo interpretar.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

CLASSIC = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)"
ISO = r"(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
HEAD = re.compile(rf"^(?:{CLASSIC}|{ISO})\s+(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
SSH_FAIL = re.compile(r"^Failed (?P<method>\w[\w-]*) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")
SSH_OK = re.compile(r"^Accepted (?P<method>\w[\w-]*) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")
SUDO_FAIL = re.compile(r"^(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts?|authentication failure)")
SUDO_CMD = re.compile(r"^(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
MAX_LINE = 2000


def looks_like_syslog(text: str) -> bool:
    """Al menos 3 de las primeras 20 líneas no vacías tienen la cabecera de syslog (evita confundir un CSV con un log)."""
    seen = hits = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        seen += 1
        hits += bool(HEAD.match(line[:MAX_LINE]))
        if seen >= 20:
            break
    return hits >= 3 and hits >= seen * 0.6


def _when(m: re.Match, year: int, now: datetime) -> datetime:
    if m.group("iso"):
        s = m.group("iso").replace("Z", "+00:00")
        d = datetime.fromisoformat(s if re.search(r"[+-]\d\d:?\d\d$", s) else s + "+00:00")
        return d.astimezone(timezone.utc).replace(tzinfo=None)
    mon, day, hms = m.group("ts").split()
    d = datetime.strptime(f"{year} {MONTHS[mon]} {int(day)} {hms}", "%Y %m %d %H:%M:%S")
    return d.replace(year=year - 1) if d > now + timedelta(days=1) else d     # syslog no trae año: nunca en el futuro


def parse_auth_log(text: str, year: int | None = None, now: datetime | None = None) -> tuple[list[dict], dict]:
    """Devuelve (eventos en el esquema multi-fuente, estadísticas de lectura)."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    year = year or now.year
    events, lines, ignored = [], 0, 0
    for line in text.splitlines():
        if not line.strip():
            continue
        lines += 1
        m = HEAD.match(line[:MAX_LINE])
        if not m:
            ignored += 1
            continue
        prog, msg, host = m.group("prog"), m.group("msg"), m.group("host")
        ev = None
        if prog.startswith("sshd"):
            # «Invalid user X from…» se ignora: el mismo intento ya aparece como «Failed password for invalid user», y contarlo dos veces duplicaría los fallos
            for rx, status in ((SSH_FAIL, "failed"), (SSH_OK, "success")):
                s = rx.match(msg)
                if s:
                    ev = dict(category="authentication", action="ssh_login", status=status, user=s.group("user"), source_ip=s.group("ip"),
                              message=msg[:300])
                    break
        elif prog == "sudo":
            s = SUDO_FAIL.match(msg)
            if s:
                ev = dict(category="authentication", action="sudo", status="failed", user=s.group("user"), source_ip="", message=msg[:300])
            else:
                s = SUDO_CMD.match(msg)
                if s:
                    ev = dict(category="process", action="sudo_command", status="success", user=s.group("user"), source_ip="",
                              message=f"sudo como {s.group('target')}: {s.group('cmd')[:300]}")
        if not ev:
            ignored += 1
            continue
        ev.update(timestamp=_when(m, year, now).strftime("%Y-%m-%dT%H:%M:%SZ"), hostname=host, destination_ip="")
        events.append(ev)
    return events, {"lines": lines, "events": len(events), "ignored": ignored}
