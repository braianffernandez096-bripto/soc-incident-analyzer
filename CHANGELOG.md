# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [Sin publicar]

### Añadido (punto 3b: ofuscación)
- **URLs ofuscadas** (`backend/deobf.py`): se normalizan antes de analizarlas. IP escrita en decimal (`http://3232235777`), hexadecimal, octal o abreviada, e IPv4 dentro de IPv6; `%XX` en el host o en varias capas; caracteres invisibles y entidades HTML numéricas que esconden el esquema (`jav&#x09;ascript:`); barras invertidas. El correo muestra la dirección real que interpreta el navegador y suma una señal de ofuscación.
- **Redirecciones abiertas y enlaces envueltos:** si la URL lleva otro destino dentro de un parámetro (`?url=…`), ese destino también se analiza. Los reescritores de enlaces corporativos (Safe Links, Proofpoint…) se siguen sin generar ruido.
- **Comandos ofuscados en los logs** (regla `cmd_obfuscated_cmd`, T1027.010): se quitan `^`, acentos graves, comillas intercaladas, concatenaciones, `.Replace()`, `[char]`, `-join` y `FromBase64String`, y se vuelven a pasar las reglas. Solo cuenta si la ofuscación **escondía** un comando relevante; un `ipconfig` o una concatenación normal no alertan. Si lo oculto coincide con otra regla (por ejemplo una descarga), esa regla dispara con el comando limpio y sube un nivel.
- **HTML ofuscado** (`backend/htmlscan.py`), en el cuerpo del correo y en adjuntos `.html`/`.svg`: HTML smuggling (Blob + descarga + datos incrustados, T1027.006, Crítico), JavaScript ofuscado (`eval`, `atob`, `unescape`, `fromCharCode`, `\x`, bloques Base64 largos), `meta refresh`, enlaces con entidades numéricas y texto oculto o caracteres de ancho cero en volumen. Se decodifican los literales (sin ejecutar nada) y las URL que esconden pasan a ser IOC.
- ATT&CK: 56 técnicas en 31 reglas (T1027.006, T1027.010, T1059.007 y T1140 nuevas).
- Límites documentados en `docs/VALIDACION.md` (sección 5): no se ejecuta código, así que lo que se arma en tiempo de ejecución no se ve. La validación con OTRF y Loghub no cambia (20/3/27/57 y 11/11).

### Añadido (punto 3: phishing)
- **Decodificador de `-EncodedCommand`** (`backend/psdecode.py`): acepta todas las grafías de la opción (`-e`, `-ec`, `-enc`…), decodifica el Base64 UTF-16, revisa una capa más de compresión (con tope de tamaño contra bombas de descompresión) y marca lo que hace el comando (descarga, IEX, oculta la ventana, intenta desactivar AMSI…). En los hallazgos de logs se muestra el contenido, se extraen sus URL e IP como indicadores y, si descarga algo de una URL externa, sube un nivel la criticidad.
- **Comandos en el cuerpo de un correo («ClickFix»)**: un `powershell -enc …` o un `irm … | iex` en el texto se marca como Crítico (T1059.001, T1204.004) y se muestra decodificado.
- **Verificar el remitente en DNS** (`backend/senderreview.py`, `backend/spfeval.py`): botón opcional en cada correo. Usa el selector DKIM de la propia firma y la IP que registró el servidor receptor; evalúa SPF de verdad contra el DNS actual (ip4, ip6, a, mx, include, redirect, límite de 10 consultas); comprueba que exista la clave de la firma y su tamaño; y compara todo con lo que dicen las cabeceras. Incluido en el PDF de phishing. Solo salen nombres de dominio.
- «Evaluar dominio» ahora busca primero el selector DKIM del propio correo; el análisis de SPF entiende `mx/24` y `a/28`.

### Añadido (punto 2: consultas y fuentes)
- **Consultas para el SIEM** (`backend/siemqueries.py`): cada hallazgo de Windows con equivalente directo muestra la consulta de Splunk (SPL), la de Microsoft Sentinel/Defender (KQL) y la regla Sigma, con IP, cuenta, equipo y ventana (±30 min) ya rellenos y botón de copiar. Endpoint `GET /api/sessions/{id}/findings/{fid}/queries` y descarga de todas las reglas Sigma de la sesión (`/sigma.yml`, botón en Hallazgos). Los valores de los logs se escapan para que no puedan salirse de las comillas de la consulta.
- **Lectura de `auth.log` / `secure` de Linux** (`backend/syslog.py`): se sube el archivo tal cual (fecha clásica o ISO; el año se infiere y nunca queda en el futuro). Se interpretan sshd (contraseña/clave aceptada o fallida) y sudo (fallos y comandos); el resto se ignora y se avisa cuántas líneas. Ejemplo en `sample_data/auth_log_ejemplo.txt`. La validación con SSH real ahora usa este mismo lector (sigue 11 de 11 IPs, 0 falsos positivos).
- **Kerberoasting** (evento 4769, T1558.003): una cuenta que pide tickets RC4 (0x17) para 3 o más servicios de usuario en 10 minutos. Excluye cuentas de máquina y krbtgt. En OTRF dispara en 1 dataset (el de Kerberoasting) y en ninguno de los otros 106: misma técnica 19 → 20.
- Pass-the-hash queda sin regla a propósito (ver docs/VALIDACION.md).

### Cambiado (calibración, punto 1b)
- **Menos ruido:** un `ipconfig`, `whoami` o `tasklist` suelto ya no genera «Comandos de reconocimiento» (se necesitan ≥3 en el mismo grupo o un origen externo; la enumeración de dominio como `net user` o `nltest` sigue alertando sola); la compresión de datos aislada (`7z a x.7z`) se descarta salvo origen externo, ruta temporal/ProgramData, contraseña, ≥3 comandos o conexión saliente posterior; las tareas de Windows creadas por SYSTEM (`\Microsoft\Windows\…`) ya no se reportan como persistencia.
- Volcado de credenciales: ahora detecta `reg.exe" save HKLM\sam` entre comillas, `esentutl` sobre SAM/NTDS, `ntds.dit`, Dumpert, NanoDump, lsadump y secretsdump. La regla de compresión ya no confunde un `curl` a un archivo `.tar.gz` con un archivado.

### Añadido (calibración, punto 1b)
- **Tres reglas nuevas para Windows/Sysmon:** acceso a la memoria de LSASS por procesos no habituales (Sysmon 10, T1003.001), DCSync (4662 con derechos de replicación de una cuenta que no es de máquina, T1003.006) y persistencia en claves Run/RunOnce (Sysmon 13, T1547.001), con guía de respuesta.
- Resultado medido sobre los mismos 107 datasets de OTRF: misma técnica **13 → 19**, misma táctica 2 → 3, «otra técnica» 39 → 27 (por menos ruido). Los 5 falsos positivos conocidos pasan a pruebas normales; se agregan pruebas de que la calibración no apaga la detección real.

### Añadido
- **Validación de las reglas con datos externos** (`docs/VALIDACION.md`, `scripts/validar_datasets.py`): SSH real de Loghub (11 de 11 IPs atacantes detectadas, sin falsos positivos) y 107 ataques de Windows de OTRF Security-Datasets con su técnica ATT&CK (línea base: 13 con la técnica correcta, 39 con otra, 53 sin hallazgos), con los huecos de cobertura priorizados.
- **Pruebas negativas** (`tests/unit/test_negativos.py`): 30 casos de actividad normal que no deben generar hallazgos y 5 falsos positivos medidos (calibrados después, ver arriba).
- Cobertura ATT&CK documentada (ahora 50 técnicas en 29 reglas) y lista de técnicas sin cobertura.

## [1.4.0] - 2026-11-05

### Añadido
- README: capturas nuevas del recorrido, el puntaje explicado y los dominios parecidos; se actualizaron las de la carga, los resultados y la ayuda de phishing.
- README: sección «Demostración» con GIF del análisis de logs, el análisis de phishing, la evaluación de dominios, los dominios parecidos y los informes PDF.
- **Cabeceras pegadas** como alternativa al `.eml`: se pega el origen del mensaje (se quita el resumen que antepone Gmail) y se analizan remitente, autenticación y recorrido; sin cuerpo no se evalúan enlaces ni adjuntos, y se avisa.
- **Recorrido del correo** (`Received`): línea de tiempo del origen al destino con hora UTC, TLS y retraso entre saltos; señales de bajo peso por horas fuera de orden, retrasos largos, fecha que no coincide y recorridos inusualmente largos. Nuevo ejemplo `sample_data/correos/11_recorrido_anomalo.eml`.
- **Puntaje con factores visibles**: desglose por categoría, tope y señal, con los umbrales de criticidad, en la interfaz y en el PDF.
- **Evaluar dominio** (`backend/domaincheck.py`): SPF, DKIM y DMARC leídos por DNS sobre HTTPS (`backend/dnsdoh.py`, sin dependencias nuevas) con nota de A a F y descuentos visibles.
- **Dominios parecidos** (`backend/lookalikes.py`): variantes de typosquatting con la tabla de confundibles de los homógrafos; comprobación opcional de registro (hasta 60) y descarga .txt/.csv.
- Privacidad: las consultas DNS son opcionales, solo envían nombres de dominio, tienen límite de peticiones y captcha (si está activo) y se desactivan con `DNS_LOOKUPS=off`.
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
