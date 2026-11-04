# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [Sin publicar]

## [1.0.0] - 2026-11-03

### Añadido
- Análisis de logs de SIEM en Excel (`.xlsx`, `.xlsm`), CSV/TSV y JSON/NDJSON (incluye respuestas de Elasticsearch y exportaciones de Splunk), con detección de separador, codificación y zona horaria.
- Motor de reglas determinista: fuerza bruta y password spraying, inicios de sesión externos, escalamiento de privilegios, comandos sospechosos, movimiento lateral, acceso masivo a archivos, exfiltración, persistencia, ataques web y calidad de datos. Cada hallazgo cita sus `Log_ID` y justifica la criticidad.
- Correlación de hallazgos en incidentes, con mapeo orientativo a MITRE ATT&CK.
- Informe técnico en PDF y redacción opcional con IA (Claude), verificada contra los datos del archivo.
- Reputación opcional de IP y dominios públicos con VirusTotal y AbuseIPDB, con confirmación previa de lo que se envía.
- Verificación del archivo subido por contenido: rechazo de ejecutables disfrazados, aviso de macros, objetos incrustados, vínculos externos e inyección de fórmulas.
- Clave de acceso opcional (`APP_ACCESS_TOKEN`).
- Docker (multi-stage, usuario sin privilegios, solo lectura), `Makefile`, integración continua con pruebas, `bandit`, `pip-audit` y Trivy, y dependencias con versión exacta y hash.
- Suite de pruebas unitarias, de integración y e2e.

### Seguridad
- Documentación interactiva de la API desactivada por defecto.
- Identificadores de sesión de 128 bits y cabeceras de seguridad adicionales.
- El nombre del cliente y del analista viaja en el cuerpo de una petición POST y no en la URL.
