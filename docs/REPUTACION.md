# Reputación de IP y dominios (VirusTotal y AbuseIPDB)

Volver al [README](../README.md).

Opcional. En la pestaña **Indicadores (IoC)**, el botón **Consultar reputación** enriquece los indicadores externos con VirusTotal (cuántos motores los marcan como maliciosos) y AbuseIPDB (puntaje de confianza de abuso y reportes de los últimos 90 días). El resultado aparece en la tabla de IoC y en una sección del informe PDF.

- **Tú decides qué sale.** Antes de consultar, la app muestra la lista exacta de indicadores que se enviarán y los que se omiten, con el motivo. Solo viajan IP públicas y dominios; nunca IP internas, cuentas, equipos, comandos ni contenido de los logs.

- **Las IP de documentación (RFC 5737) no se consultan**, porque no tienen reputación real. El export de ejemplo usa solo esas, así que allí no hay nada que enviar; hay una casilla para incluirlas únicamente si quieres probar que tu clave funciona.

- **No cambia la criticidad.** La reputación es contexto para el analista; el motor de reglas sigue decidiendo.

- **Claves gratuitas:** crea una cuenta en [VirusTotal](https://www.virustotal.com) y otra en [AbuseIPDB](https://www.abuseipdb.com) y define `VT_API_KEY` y `ABUSEIPDB_API_KEY` en `.env`, o pégalas en la interfaz (solo se usan en esa consulta). Con una sola de las dos funciona igual (AbuseIPDB solo consulta IP; los dominios van solo a VirusTotal).

- **Límites del plan gratuito:** VirusTotal permite 4 consultas por minuto y 500 por día, así que la app consulta una cada ~15 s (25 indicadores como máximo por consulta, ~6 min). AbuseIPDB permite 1.000 por día. Si una clave es rechazada o se agota la cuota, esa consulta se detiene con un aviso. Con un plan de pago puedes ajustar el tope y los intervalos con `INTEL_MAX_INDICATORS` (25), `INTEL_VT_INTERVAL` (15.5 s) e `INTEL_ABUSE_INTERVAL` (0.3 s) en el archivo `.env`; los valores por defecto respetan el plan gratuito.
