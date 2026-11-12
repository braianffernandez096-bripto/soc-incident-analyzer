#!/usr/bin/env python3
"""Integración de Wazuh con SOC Incident Analyzer: reenvía cada alerta al endpoint ``/api/wazuh/alerts``.

Wazuh (integratord) lo invoca así:  custom-soc-analyzer <archivo_alerta.json> <api_key> <hook_url>
``api_key`` es el valor de ``WAZUH_INGEST_TOKEN`` del analyzer y ``hook_url`` la dirección del endpoint.
Solo usa la biblioteca estándar. Si el analyzer no responde, escribe el motivo en el registro de integraciones y sale con error: Wazuh sigue
funcionando igual (la alerta ya quedó guardada en su propio índice).
"""
import json
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 10
RETRIES = 2


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):      # nunca seguir redirecciones: la clave viaja en un encabezado
        return None


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("uso: custom-soc-analyzer <archivo_alerta.json> <api_key> <hook_url>", file=sys.stderr)
        return 2
    alert_file, api_key, url = argv[1], argv[2], argv[3]
    if not url.lower().startswith(("http://", "https://")):
        print("hook_url debe empezar con http:// o https://", file=sys.stderr)
        return 2
    try:
        with open(alert_file, "rb") as fh:
            alert = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"no pude leer la alerta: {type(exc).__name__}", file=sys.stderr)
        return 2
    body = json.dumps(alert).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Wazuh-Token": api_key})
    opener = urllib.request.build_opener(_NoRedirect)
    for attempt in range(RETRIES + 1):
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                return 0 if 200 <= resp.status < 300 else 1
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 404, 413):          # reintentar no lo arregla
                print(f"el analyzer rechazó la alerta (HTTP {exc.code})", file=sys.stderr)
                return 1
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        if attempt < RETRIES:
            time.sleep(1 + attempt)
    print("el analyzer no respondió; la alerta no se reenvió", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
