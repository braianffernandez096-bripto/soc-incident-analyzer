# Privacidad: qué datos salen de tu equipo

Volver al [README](../README.md).

La app corre en tu equipo y no envía telemetría. Solo salen datos si tú activas una de estas tres funciones:

| Función | Qué se envía | A quién |
|---|---|---|
| **Redacción con IA** (botón en la pestaña Informe, requiere clave de Anthropic) | Por incidente y hallazgo: título, criticidad, métricas, explicación del motor y las **filas de evidencia** (`Log_ID`, fecha, equipo, usuario, IP de origen y destino, origen del log, descripción del evento y línea de comandos recortadas, resultado y severidad). También el resumen del conjunto (cantidad de eventos, ventana de tiempo, IP externas). **No** se envían el nombre del cliente ni del analista, ni el archivo completo. | Anthropic |
| **Consulta DNS** (botones «Evaluar» en Evaluar dominio y «Comprobar registro» en Dominios parecidos) | Solo **nombres de dominio**, por DNS sobre HTTPS (nunca el correo, sus enlaces ni sus adjuntos). Se desactiva con `DNS_LOOKUPS=off`. | Cloudflare (si falla, Google) |
| **Reputación** (botón en Indicadores (IoC) o en Phishing, requiere clave de VirusTotal o AbuseIPDB) | Solo las IP públicas, dominios y, en phishing, el hash SHA-256 de los adjuntos, que ves y confirmas en pantalla. Nunca IP internas, cuentas, equipos ni comandos. | VirusTotal y AbuseIPDB |

Las filas de evidencia pueden contener nombres de usuario, equipos y direcciones IP reales. Antes de activar la IA de Anthropic, asegúrate de tener permiso para compartir esos datos con un tercero; sin la clave de Anthropic, el informe se genera por reglas y no sale nada. Con **Ollama** en tu propio equipo (`127.0.0.1`) los datos no salen de él; la pantalla avisa si Ollama está en otro equipo, y en ese caso los datos viajan hasta esa dirección.
