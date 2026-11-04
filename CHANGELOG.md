# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [Sin publicar]

## [1.3.0] - 2026-11-04

### Añadido
- README: apartados «Qué problema resuelve y para quién» y «Cómo se desarrolló»; la insignia de cobertura ahora la genera Codecov desde el CI en lugar de un valor escrito a mano.
- Reglas para exports que no son de Windows (`backend/detection_generic.py`): fuerza bruta y spraying por SSH/RDP/Kerberos, ataques web, exfiltración, phishing, comando y control, persistencia, sondeo de recursos compartidos, ransomware, minería, escalamiento SUID, túnel DNS y abuso de identidades cloud, con su plan de acción. Los incidentes mezclan hallazgos de Windows y de otras fuentes.
- Segundo ejemplo `sample_data/logs_multifuente.json` (100 eventos) con pruebas; el ejemplo de Windows sigue dando 25 hallazgos y 6 incidentes.
- Ejemplo `sample_data/SIEM_Logs_500_Eventos` (500 eventos, `.csv`, `.xlsx` y `.json`): 7 incidentes de fuentes mixtas y 3 señuelos, con pruebas.
- 12 técnicas ATT&CK nuevas en los datos oficiales (ahora 40, v20.0).
- Un JSON guardado línea por línea en una hoja de cálculo (`.csv`/`.xlsx`) se reconstruye; si faltan líneas sueltas se lee lo disponible y se avisa. Si no se puede reconstruir, el mensaje lo explica.
- Cualquier contenedor JSON con una lista de eventos con fecha se reconoce (por ejemplo `logs_database`), no solo `events`/`logs`/`records`.
- Los archivos sin `Event_ID` pueden usar `action` como código de evento y `category` como fuente del log.
- Fondo animado en la pantalla de inicio (barrido de radar, anillos y red de nodos en un `<canvas>`, `frontend/bg.js`). Solo se anima en el inicio, usa los colores del tema, respeta **Movimiento: reducido** y `prefers-reduced-motion`, y se pausa si la pestaña no está visible.

### Corregido
- La correlación trata `CORP\\mflores`, `mflores` y `mflores@dominio` como la misma cuenta, así que un EDR o un correo y los eventos de Windows se unen en un solo incidente.
- El aviso de limitaciones nombraba cuentas del archivo de ejemplo (`backupsvc`, `rrojas`, `helpdesk`) aunque los datos fueran otros.

### Cambiado
- Se quita «Analista SOC N2» de la cabecera, del analista por defecto del informe («Analista SOC») y del rol que se le da a la IA («analista SOC senior»).
- Se quita el texto sobre el export de ejemplo de la pantalla de inicio; el botón **Probar con datos de ejemplo** sigue disponible.

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
