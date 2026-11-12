"""Modo Wazuh en vivo (opcional, apagado por defecto): acumula alertas, las analiza y avisa de lo nuevo.

Se activa con ``WAZUH_INGEST=on`` y una clave ``WAZUH_INGEST_TOKEN`` de 16 caracteres o más. Sin eso el endpoint ni existe.

* Las alertas llegan una a una (``integratord`` de Wazuh) y se guardan en una **ventana en memoria** (por defecto 24 h y 5.000 filas). No se escribe nada en
  disco: al reiniciar el servicio la ventana empieza vacía.
* Un ciclo de análisis corre cada ``WAZUH_ANALYZE_SECONDS`` (60 por defecto) **solo si llegaron alertas nuevas**. Es el mismo motor de siempre: la criticidad
  la fijan las reglas y no interviene ninguna IA.
* Cada hallazgo nuevo se avisa una sola vez. Crítico y Alto salen en el ciclo; Medio y Bajo se juntan en un resumen cada ``WAZUH_DIGEST_MINUTES`` (60).
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import deque
from typing import Callable

from . import wazuh as W

log = logging.getLogger("soc.wazuh")

IMMEDIATE = {"Crítico", "Alto"}
SKIP_RULES = {"siem_underclass", "dq_host_alias", "dq_logsource", "dq_account_lookalike"}   # observaciones sobre la calidad de los datos, no amenazas
MAX_SEEN = 5000
MIN_TOKEN = 16


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        v = default
    return max(lo, min(hi, v))


def enabled() -> bool:
    return os.environ.get("WAZUH_INGEST", "").strip().lower() in ("1", "true", "yes", "on")


def token() -> str:
    return os.environ.get("WAZUH_INGEST_TOKEN", "").strip()


def usable() -> bool:
    """Activo y con una clave decente: sin clave el endpoint queda cerrado, no abierto."""
    return enabled() and len(token()) >= MIN_TOKEN


def fingerprint(f: dict) -> str:
    key = "|".join([f.get("rule", ""), ",".join(sorted(f.get("hosts") or [])), ",".join(sorted(f.get("actor_users") or [])),
                    ",".join(sorted(f.get("ips") or [])), str(f.get("time_start", ""))])
    return hashlib.sha256(key.encode()).hexdigest()[:20]


class LiveState:
    def __init__(self, *, max_rows: int | None = None, window_hours: int | None = None, digest_minutes: int | None = None,
                 notifier=None, clock: Callable[[], float] = time.time):
        self.max_rows = max_rows or _int_env("WAZUH_MAX_ROWS", 5000, 100, 20000)
        self.window = (window_hours or _int_env("WAZUH_WINDOW_HOURS", 24, 1, 168)) * 3600
        self.digest_secs = (digest_minutes or _int_env("WAZUH_DIGEST_MINUTES", 60, 1, 1440)) * 60
        self.notifier, self.clock = notifier, clock
        self.lock = threading.Lock()
        self._rows: deque = deque()            # (llegada, fila)
        self._ids: set[str] = set()
        self._dirty = False
        self._seen: dict[str, float] = {}
        self._digest: list[dict] = []
        self._last_digest = clock()
        self.received = 0
        self.stats = {"windows": 0, "linux_auth": 0, "otro": 0, "descartadas": 0}
        self.updated: float | None = None
        self.latest: tuple | None = None       # (DataFrame, metadatos, análisis) del último ciclo

    # -- entrada --------------------------------------------------------------------------------
    def ingest(self, alerts: list) -> dict:
        rows, st = W.normalize_alerts(alerts)
        now = self.clock()
        added = dup = 0
        with self.lock:
            for r in rows:
                if r["Log_ID"] in self._ids:
                    dup += 1
                    continue
                self._rows.append((now, r))
                self._ids.add(r["Log_ID"])
                added += 1
            self._evict(now)
            if added:
                self._dirty = True
            self.received += st["recibidas"]
            for k in self.stats:
                self.stats[k] += st.get(k, 0)
        return {"accepted": added, "duplicates": dup, "skipped": st["descartadas"], "reasons": st["motivos"]}

    def _evict(self, now: float) -> None:
        while self._rows and (now - self._rows[0][0] > self.window or len(self._rows) > self.max_rows):
            _, old = self._rows.popleft()
            self._ids.discard(old["Log_ID"])

    def snapshot(self) -> list[dict]:
        with self.lock:
            self._evict(self.clock())
            return [r for _, r in self._rows]

    @property
    def size(self) -> int:
        with self.lock:
            self._evict(self.clock())
            return len(self._rows)

    # -- ciclo ----------------------------------------------------------------------------------
    def run_cycle(self, analyze_fn: Callable) -> bool:
        """Analiza la ventana si hay algo nuevo. ``analyze_fn(df, meta)`` es el motor. El resultado queda en ``latest``."""
        with self.lock:
            dirty, self._dirty = self._dirty, False
        self._maybe_digest()
        if not dirty:
            return False
        rows = self.snapshot()
        if not rows:
            return False
        try:
            df, meta = W.rows_to_frame(rows)
            analysis = analyze_fn(df, meta)
        except Exception:
            log.exception("wazuh_cycle_failed")
            with self.lock:
                self._dirty = True        # reintentar en el ciclo siguiente
            return False
        self.updated = self.clock()
        self.latest = (df, meta, analysis)
        self._notify(analysis)
        return True

    # -- avisos ---------------------------------------------------------------------------------
    def _notify(self, analysis: dict) -> None:
        now = self.clock()
        fresh = []
        for f in analysis.get("findings", []):
            if f.get("rule") in SKIP_RULES:
                continue
            fp = fingerprint(f)
            if fp in self._seen:
                continue
            self._seen[fp] = now
            fresh.append(f)
        while len(self._seen) > MAX_SEEN:
            self._seen.pop(next(iter(self._seen)))
        if not fresh or not self.notifier:
            return
        urgent = [f for f in fresh if f.get("severity") in IMMEDIATE]
        self._digest += [f for f in fresh if f.get("severity") not in IMMEDIATE]
        if urgent:
            self.notifier.send(self.notifier.format(urgent, f"🛡️ Wazuh · {len(urgent)} hallazgo(s) nuevo(s) para revisar"))

    def _maybe_digest(self) -> None:
        now = self.clock()
        if not self.notifier or not self._digest or now - self._last_digest < self.digest_secs:
            return
        batch, self._digest, self._last_digest = self._digest, [], now
        self.notifier.send(self.notifier.format(
            batch, f"🛡️ Wazuh · resumen: {len(batch)} hallazgo(s) de severidad media o baja (posibles falsos positivos, revisar)"))

    def status(self) -> dict:
        return {"enabled": True, "rows": self.size, "received": self.received, "interpreted": dict(self.stats),
                "updated": self.updated, "has_analysis": self.latest is not None, "telegram": bool(self.notifier),
                "window_hours": self.window // 3600, "max_rows": self.max_rows}
