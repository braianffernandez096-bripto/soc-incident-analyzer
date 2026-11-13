"""Avisos a Telegram (opcional, apagado por defecto).

Telegram es un servicio en la nube y los mensajes de un bot **no** van cifrados de extremo a extremo, así que por defecto el aviso lleva lo mínimo
para que el analista sepa qué mirar en el panel: severidad, recomendación del motor, tipo de hallazgo (genérico, p. ej. «Fuerza bruta»), cantidad de
eventos, hora (UTC), táctica y técnica MITRE y un enlace. **No** incluye usuarios, IPs, comandos, rutas ni logs. El nombre del equipo solo se agrega si
lo pides con ``TELEGRAM_INCLUDE_HOST=1``.

``TELEGRAM_DETAIL=full`` es una opción **explícita** para quien acepta que esos datos pasen por Telegram: suma el título del hallazgo, el equipo, las
cuentas y las IPs. Sigue sin incluir comandos, rutas ni logs.

Variables: ``TELEGRAM_BOT_TOKEN`` y ``TELEGRAM_CHAT_ID`` (sin ellas no se envía nada), ``APP_BASE_URL`` (para el enlace), ``TELEGRAM_INCLUDE_HOST`` y
``TELEGRAM_DETAIL``. El token nunca se escribe en los registros.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Callable

import httpx

log = logging.getLogger("soc.notify")

API = "https://api.telegram.org/bot{token}/sendMessage"
MAX_LINES = 10
EMOJI = {"Crítico": "🔴", "Alto": "🟠", "Medio": "🟡", "Bajo": "🟢"}
REC = {"Crítico": "Escalar", "Alto": "Escalar", "Medio": "Falta información", "Bajo": "Probable falso positivo"}
_SAFE = re.compile(r"[^\w .\-]", re.UNICODE)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _plain(s: str, n: int = 60) -> str:
    return _SAFE.sub("", str(s or ""))[:n].strip()


_WINDOWS = {"brute_force", "external_logon", "privilege", "persistence", "persist_run", "defense_registry", "cred_lsass", "cred_dcsync",
            "kerberoast", "lateral", "mass_access", "sensitive_share", "exfil_proxy", "outbound_shell"}


def source_label(f: dict) -> str:
    """Tipo de origen del hallazgo (genérico, sin datos del entorno): sirve para distinguir p. ej. fuerza bruta de Windows de la de SSH."""
    rule = str(f.get("rule") or "")
    proto = _plain((f.get("metrics") or {}).get("protocolo", ""), 12)
    if rule == "g_auth":
        return proto or "Autenticación"
    if rule in _WINDOWS or rule.startswith("cmd_"):
        return "Windows"
    return {"web_attack": "IIS/Web", "g_web": "Web", "ctx_cve": "Vulnerabilidad", "ctx_misp": "MISP", "ctx_feed": "Feed", "g_dns_tunnel": "DNS", "g_cloud": "Cloud"}.get(rule, "")


def _text(s, n: int = 160) -> str:
    """Texto con más libertad (modo ``full``): solo se quitan los caracteres de control y se recorta."""
    return _CTRL.sub(" ", str(s or "")).strip()[:n]


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, *, include_host: bool = False, base_url: str = "",
                 post: Callable | None = None, timeout: float = 10.0, full: bool = False):
        self._token, self.chat_id = token, chat_id
        self.include_host, self.base_url, self.full = include_host, base_url.rstrip("/"), full
        self._post, self._timeout = post, timeout

    @classmethod
    def from_env(cls, post: Callable | None = None) -> "TelegramNotifier | None":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat:
            return None
        base = os.environ.get("APP_BASE_URL", "").strip()
        if base and not re.match(r"^https?://", base, re.I):
            base = ""
        return cls(token, chat, include_host=os.environ.get("TELEGRAM_INCLUDE_HOST", "").strip().lower() in ("1", "true", "yes"),
                   base_url=base, post=post, full=os.environ.get("TELEGRAM_DETAIL", "").strip().lower() == "full")

    # -- formato ---------------------------------------------------------------------------------
    def line(self, f: dict) -> str:
        sev = f.get("severity", "")
        head = f"{EMOJI.get(sev, '⚪')} {REC.get(sev, 'Revisar')} · {sev}"
        tech = ", ".join(_plain(m, 14) for m in (f.get("mitre") or [])[:2])
        detail = _plain(f.get("tactic", "")) + (f" · {tech}" if tech else "")
        n = len(f.get("evidence_ids") or [])
        when = str(f.get("time_start") or "")[11:16]
        src = source_label(f)
        cat = _plain(f.get("category", ""), 40) + (f" ({src})" if src else "")
        what = " · ".join(x for x in (cat, f"{n} evento(s)" if n else "", f"{when} UTC" if when else "") if x)
        lines = [head]
        if self.full and f.get("title"):
            lines.append("   " + _text(f["title"]))
        if what:
            lines.append("   " + what)
        host = ""
        if (self.include_host or self.full) and f.get("hosts"):
            host = " · Equipo: " + (_text(", ".join(f["hosts"][:3]), 80) if self.full else _plain(f["hosts"][0], 40))
        lines.append(f"   {detail}{host}".rstrip())
        if self.full:
            who = ", ".join(list(f.get("actor_users") or f.get("users") or [])[:3])
            ips = ", ".join((f.get("ips") or [])[:3])
            extra = " · ".join(x for x in (f"Cuentas: {_text(who, 80)}" if who else "", f"IP: {_text(ips, 80)}" if ips else "") if x)
            if extra:
                lines.append("   " + extra)
        return "\n".join(lines)

    def format(self, findings: list[dict], title: str) -> str:
        lines = [self.line(f) for f in findings[:MAX_LINES]]
        extra = len(findings) - MAX_LINES
        body = "\n".join(lines) + (f"\n… y {extra} más." if extra > 0 else "")
        tail = f"\nPanel: {self.base_url}" if self.base_url else "\nAbre el panel de la app para ver el detalle."
        return f"{title}\n{body}{tail}"

    # -- envío -----------------------------------------------------------------------------------
    def send(self, text: str) -> bool:
        """Devuelve True si Telegram aceptó el mensaje. Nunca lanza: un fallo de aviso no debe frenar el análisis."""
        payload = {"chat_id": self.chat_id, "text": text[:3800], "disable_web_page_preview": True}
        try:
            if self._post:
                return bool(self._post(API.replace("{token}", "oculto"), payload))
            r = httpx.post(API.format(token=self._token), json=payload, timeout=self._timeout, follow_redirects=False, trust_env=False)
            ok = r.status_code == 200
            if not ok:
                log.warning("telegram_rejected status=%s", r.status_code)
            return ok
        except Exception as exc:       # red caída, DNS, tiempo de espera…
            log.warning("telegram_failed error=%s", type(exc).__name__)
            return False
