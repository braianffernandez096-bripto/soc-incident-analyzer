# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [Sin publicar]

## [1.2.0] - 2026-11-04

### Añadido
- Botón **Probar con datos de ejemplo** en la pantalla de inicio: analiza el export sintético incluido en el repositorio sin tener que elegir un archivo (`POST /api/sample`; el archivo es fijo en el servidor).

### Cambiado
- Cabecera más compacta: las siete pestañas caben en una sola fila, y el tema y el movimiento se agrupan en el menú **Ajustes**. En pantallas pequeñas las pestañas se desplazan.
- Panel: los incidentes se muestran en una cuadrícula de tres columnas.
- Matriz ATT&CK en cuadrícula adaptable: se ven todas las tácticas sin desplazamiento horizontal.
- Plurales corregidos en la interfaz («1 hallazgo», «1 evento»).
- Capturas del README renovadas, con la pantalla de inicio y el rechazo de un archivo falso.
- README: requisito explícito de Python 3.12.
- Pantalla de inicio más limpia: título, zona de carga y «hasta 25 MB». El detalle de formatos y columnas esperadas pasa a «¿Cómo funciona?», con un enlace desde la zona de carga.
- Títulos neutros: la pestaña Incidentes vuelve a llamarse «Incidentes» y la sección 3 del PDF, «Relación entre incidentes». Se quitan los restos del enunciado del reto.

## [1.1.0] - 2026-11-03

### Añadido
- MITRE ATT&CK completo: nombre oficial y enlace de cada técnica en hallazgos y en el PDF, pestaña **ATT&CK** con la matriz por táctica y exportación de una capa para ATT&CK Navigator.
- Datos oficiales de ATT&CK Enterprise v20.0 incluidos en `backend/data/`, con `scripts/build_attack_data.py` para regenerarlos. Las pruebas comprueban que todas las técnicas citadas por las reglas existen y no están obsoletas.

### Cambiado
- Pruebas automáticas: Trivy se ejecuta como contenedor (la descarga de su binario fallaba en el CI) y Dependabot deja de proponer cambios de Python y de las dependencias bloqueadas con hash.

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
