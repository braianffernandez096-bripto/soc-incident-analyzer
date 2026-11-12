"""Avisos a Telegram (opcional, apagado por defecto).

Telegram es un servicio en la nube y los mensajes de un bot **no** van cifrados de extremo a extremo, así que el aviso lleva lo mínimo para que el
analista sepa que debe mirar el panel: severidad, recomendación del motor, táctica y técnica MITRE y un enlace. **No** incluye usuarios, IPs,
comandos, rutas ni logs. El nombre del equipo solo se agrega si lo pides con ``TELEGRAM_INCLUDE_HOST=1``.

Variables: ``TELEGRAM_BOT_TOKEN`` y ``TELEGRAM_CHAT_ID`` (sin ellas no se envía nada), ``APP_BASE_URL`` (para el enlace) y ``TELEGRAM_INCLUDE_HOST``.
El token nunca se escribe en los registros.
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


def _plain(s: str, n: int = 60) -> str:
    return _SAFE.sub("", str(s or ""))[:n].strip()


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, *, include_host: bool = False, base_url: str = "",
                 post: Callable | None = None, timeout: float = 10.0):
        self._token, self.chat_id = token, chat_id
        self.include_host, self.base_url = include_host, base_url.rstrip("/")
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
                   base_url=base, post=post)

    # -- formato ---------------------------------------------------------------------------------
    def line(self, f: dict) -> str:
        sev = f.get("severity", "")
        head = f"{EMOJI.get(sev, '⚪')} {REC.get(sev, 'Revisar')} · {sev}"
        tech = ", ".join(_plain(m, 14) for m in (f.get("mitre") or [])[:2])
        detail = _plain(f.get("tactic", "")) + (f" · {tech}" if tech else "")
        host = ""
        if self.include_host and f.get("hosts"):
            host = " · Equipo: " + _plain(f["hosts"][0], 40)
        return f"{head}\n   {detail}{host}".rstrip()

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
