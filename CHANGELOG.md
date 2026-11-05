# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [Sin publicar]

### Añadido
- README: capturas nuevas del análisis de correos (carga, resultados, homógrafos, remitente esperado, informe PDF), de la ayuda y de los dos tipos de captcha; la captura de inicio ahora muestra las pestañas «Análisis de logs» y «Phishing».
- **«¿Cómo funciona?» con dos secciones** (Análisis de logs y Phishing): se abre en la que corresponde a la pantalla actual. La guía para guardar un correo como `.eml` pasó de la pantalla de carga a la sección de Phishing, y el campo «Remitente esperado» ya no trae una dirección de ejemplo.
- **Ataques homógrafos en el módulo de phishing** (`backend/homograph.py`): alfabetos mezclados en una misma palabra (a latina/cirílica, o griega), «I» mayúscula por «l» minúscula, cifras por letras, `rn`/`m`, caracteres invisibles y de dirección, dominios escritos solo con letras que imitan las latinas, dominios IDN y `xn--` decodificados. Se revisan el remitente, el Reply-To, el Return-Path, el nombre visible y los dominios de los enlaces. Desglose carácter por carácter (código Unicode, nombre y alfabeto) en la interfaz y en el PDF; el PDF muestra los caracteres fuera de Latin-1 como `[U+XXXX]` en vez de glifos faltantes.
- **Remitente esperado** (campo opcional al subir): compara carácter por carácter y señala la letra cambiada. Si se ve igual pero no es la misma, el correo es Crítico. También se comparan entre sí remitente, Reply-To, Return-Path y la dirección del nombre visible, y el dominio del remitente contra el del destinatario.
- 5 correos de ejemplo nuevos (`sample_data/correos/06`–`10`: «I» mayúscula, «a» cirílica en el dominio y en el usuario, dominio con `rn` que imita al del destinatario, y un legítimo con tildes que no debe alertar). El botón de ejemplos ya no está limitado a 5 archivos.
- **Captcha de rompecabezas deslizante** (segundo tipo del captcha local): escena generada con figuras, hueco real y hueco señuelo, pieza que se arrastra con ratón, dedo o teclado; tolerancia de 6 px y control básico de que el arrastre sea un movimiento. `CAPTCHA_TYPE=imagenes|rompecabezas|aleatorio` (por defecto `aleatorio`).
- **Captcha local opcional** (`CAPTCHA=on`, apagado por defecto) para las subidas de logs y de correos. Tipo imágenes: 6 imágenes, hay que marcar las 3 que muestran la misma figura (pueden estar giradas 0°, 90°, 180° o 270°, con color, fondo y ruido al azar). 16 figuras originales de dispositivos y animales (`backend/captcha_assets/`, regenerables con `scripts/build_captcha_assets.py`). Sin terceros ni internet; respuesta solo en el servidor; un intento por desafío; pase de un solo uso, de segundos y ligado a la IP (cada análisis pide su captcha; mirar resultados no); límite de fallos por IP; modal accesible (teclado, Esc). Los datos de ejemplo no lo piden.
- Módulo de phishing (`backend/phishing.py`, pestaña **Phishing**): análisis estático de correos `.eml` (hasta 5 de 5 MB). Encabezados y suplantación, SPF/DKIM/DMARC, enlaces engañosos (IP, acortadores, punycode, dominios parecidos a una marca, texto distinto del destino, formularios), adjuntos (doble extensión, ejecutables disfrazados, macros, comprimidos con contraseña o con ejecutables, PDF con contenido activo, hash SHA-256), veredicto con puntaje, «Qué verificar», acciones y técnicas ATT&CK. No se abre ningún enlace ni se ejecuta ningún adjunto; las URL se muestran «defangeadas».
- Reputación de phishing: dominios, IP y hash SHA-256 de adjuntos con VirusTotal y AbuseIPDB, con la misma confirmación previa. Nunca se envían archivos, direcciones de correo ni URL completas.
- Informe en PDF de correos. El análisis de correos y el de logs son independientes en la interfaz: la pestaña Phishing solo aparece fuera de un análisis de logs, y los correos ya no se agregan al informe de logs.
- Ejemplos `sample_data/correos/` (4 maliciosos y 1 legítimo) y 67 pruebas nuevas, con casos positivos y negativos por señal.
- ATT&CK: técnicas de phishing y suplantación en los datos oficiales (48 técnicas, v20.0).

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
