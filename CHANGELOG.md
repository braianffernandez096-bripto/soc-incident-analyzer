# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [1.10.3] - 2026-11-07

### Añadido: informe HTML en el análisis de phishing
- Botón **Descargar informe HTML** junto al del PDF en Phishing → Correos (`POST /api/phishing/{id}/report.html`; cliente y analista van en el cuerpo, no en la URL).
- Un único archivo que se abre sin conexión, con el mismo contenido que el PDF de phishing (resumen por criticidad, señales, autenticación, recorrido, verificación DNS, cálculo del puntaje, homógrafos, enlaces defangeados, adjuntos, qué verificar, acciones y reputación si se consultó), con el diseño glass, tema claro/oscuro, secciones desplegables y versión imprimible.
- Mismas garantías que el informe de logs: todo dato del correo se escapa, sin estilos ni manejadores en línea y con su propia CSP por hash (sin red).
- El ensamblado del documento (CSS, JS con anime.js y CSP) pasó a una función común para ambos informes.
- Pruebas: contenido, archivo sin recursos externos y CSP coincidente, campos hostiles, reputación, endpoint (404, solo POST, PDF intacto) y un e2e que lo descarga y lo abre sin errores.

### Documentación: demostraciones nuevas en GIF
- Los seis GIF del README se rehicieron con el diseño nuevo (glass y animaciones): análisis de logs, phishing, evaluar dominio, dominios parecidos y los informes HTML de logs y de phishing. Se recortaron la barra del navegador y la ventana de la VM, y se dejaron en bucle.
- Se eliminaron las 22 capturas PNG de `img/` (eran del diseño anterior) y la galería `docs/CAPTURAS.md`; el README ya no tiene la sección «Capturas». El informe PDF de ejemplo sigue en `examples/`.

## [1.10.2] - 2026-11-07

### Cambiado: glass en toda la app y modo claro cómodo
- El estilo glass y las animaciones (anime.js) se aplican a **todas** las pantallas: Panel, Incidentes, Hallazgos, ATT&CK, Eventos, Indicadores, Informe, inicio y Phishing. Encabezado translúcido, entrada escalonada al cambiar de pestaña y filas de tabla en cascada (no se repite al filtrar).
- El fondo «aurora» pasa a ser un único elemento fijo a **pantalla completa** (antes se recortaba al contenido). En los inicios se muestra el radar, con un vidrio suave que no lo tapa.
- **Modo claro cómodo**: fondo gris azulado en lugar de blanco puro, texto de alto contraste (principal 14:1, secundario 7:1), bordes y sombras definidos, tablas casi opacas con filas alternadas.
- Corregidos dos problemas de contraste: el filtro seleccionado de Hallazgos y la etiqueta «Reglas del motor» en oscuro.
- «Reducir movimiento» también quita el desenfoque del encabezado y de las tablas.
- Pruebas e2e: aurora a pantalla completa en las 7 pestañas, filtro legible, y contraste/blanco puro del tema claro.

## [1.10.1] - 2026-11-07

### Cambiado: pantalla de inicio y Phishing con el mismo estilo glass
- La pantalla de inicio y las tres herramientas de Phishing (Correos, Evaluar dominio, Dominios parecidos) usan vidrio esmerilado, entrada escalonada con anime.js y pestañas en negrita; Phishing suma el fondo «aurora».
- Rendimiento: desenfoque más liviano, el fondo animado se pausa cuando la pestaña está oculta y con «reducir movimiento» se quitan el desenfoque y la aurora (útil en equipos o máquinas virtuales sin aceleración gráfica). La entrada animada solo se repite al cambiar de pantalla, no en cada redibujado.
- Pruebas e2e nuevas para el inicio y Phishing, con y sin movimiento.

## [1.10.0] - 2026-11-07

### Cambiado: Panel con estilo «glass» y animaciones (anime.js)
- Pestañas de navegación en **negrita**; el encabezado se acomoda para que «Informe» no se corte.
- Panel con paneles de vidrio esmerilado y fondo «aurora» (claro/oscuro), anillos de proporción en los indicadores y entrada animada de números, dona, barras, tarjetas y línea de tiempo.
- La dona de criticidad filtra el panel: atenúa los casos sin hallazgos de esa criticidad y los de la línea de tiempo, y ofrece ir a Hallazgos con ese filtro.
- Al hacer clic en una tarjeta de incidente o en una fila de la línea de tiempo se despliega el detalle del caso sin salir del Panel, con acceso a «Abrir en Incidentes».
- Cursor de hora al pasar el mouse sobre la línea de tiempo.
- anime.js 3.2.2 (MIT) se sirve desde `frontend/vendor/` (sin CDN, compatible con la CSP). Las animaciones son opcionales: con «reducir movimiento» o sin la librería todo se ve completo y de inmediato.
- Pruebas e2e nuevas: pestañas en negrita, filtro de la dona, detalle desplegable, cursor de hora y panel sin movimiento. Corregido el conteo de pruebas en README y docs/DESARROLLO.md.

## [1.9.0] - 2026-11-07

### Añadido: informe HTML descargable
- Botón **Descargar informe HTML** junto al del PDF (`POST /api/sessions/{id}/report.html`; los nombres de cliente y analista van en el cuerpo, no en la URL).
- Un único archivo que se abre sin conexión, con el mismo contenido que el PDF: resumen, metodología, incidentes con cronología, evidencia y plan de acción, observaciones, IoC con filtro, reputación, triaje y decisiones del analista, y correos sospechosos.
- Gráficos SVG (criticidad y eventos por ventana, apilados por criticidad), diseño «glass» claro/oscuro adaptado al celular, secciones desplegables y versión imprimible.
- Animaciones con anime.js 3.2.2 (MIT) incluido en el archivo, sin CDN. Son opcionales: respeta «reducir movimiento» y el informe se ve completo sin JavaScript.
- Seguridad: todo dato de logs, IA o correos se escapa; sin estilos ni manejadores en línea; el informe lleva su propia CSP (script y estilo por hash, sin red).
- Pruebas: contenido igual al PDF, archivo sin recursos externos, CSP coincidente con el script real, logs/IA/correos/cliente hostiles y un e2e que descarga el archivo y lo abre sin errores.

## [1.8.0] - 2026-11-07

### Añadido: OpenAI y Gemini como proveedores de IA
- Nuevo módulo `backend/ai_cloud.py`: adaptadores para OpenAI (Chat Completions con llamada a función) y Gemini (`generateContent`) con la misma interfaz que Claude y Ollama. Sirven para el informe y para el triaje.
- Selector de proveedor en las pestañas Informe e Incidentes: clave propia (variable de entorno o campo de la interfaz, enviada por cabecera `X-Provider-Key`, sin guardarse) y modelo editable con sugerencias. `OPENAI_MODEL` y `GEMINI_MODEL` fijan el modelo por defecto.
- Seguridad: direcciones fijas en el servidor (sin SSRF), nombre de modelo validado, sin proxies ni redirecciones, errores por código HTTP sin repetir la respuesta del proveedor, reintentos ante 429/5xx.
- `/api/health` y la carga de archivos informan qué proveedores tienen clave en el servidor (`ai_keys`), nunca la clave. `GET /api/ai/providers` lista también OpenAI y Gemini.
- Documentación: `docs/PROVEEDORES-IA.md`; README, `.env.example` y `docs/PRIVACIDAD.md` actualizados.
- Probado con servidores simulados; no se contrastó con las APIs reales.

## [1.7.2] - 2026-11-07

### Cambiado: lectura del informe en modo reglas
- El resumen ejecutivo agrega «Qué atender primero» con los tres incidentes más graves y qué contener en cada uno (IP externas, cuentas o equipo).
- Plurales corregidos («1 medio», «1 hallazgo enlazado», «requiere» / «requieren»).
- La sección «Alcance y metodología» lista solo las reglas que generaron hallazgos e indica cuántas se evaluaron.
- Si el archivo no trae nombre de host, el informe dice «sin dato de host» en lugar de contar un equipo vacío.
- El gráfico de eventos por ventana muestra varias etiquetas de hora aunque haya pocas ventanas.
- La hora de la decisión del analista se guarda en la zona horaria de su navegador (por ejemplo `2026-11-06 23:10 (UTC-03:00)`) y no en UTC.

## [1.7.1] - 2026-11-06

### Documentado: cuándo usar IA local y cuándo un modelo de mayor calidad
- README, `docs/IA-LOCAL.md` y avisos en la interfaz (pestañas Informe e Incidentes) recomiendan un modelo de mayor calidad, como Claude, para el informe formal y el triaje; Ollama queda como apoyo, práctica y uso sin conexión. Se documenta lo medido con llama3.1:8b y que aún no se midió su capacidad de reconocer un falso positivo real.

### Cambiado: triaje con modelos pequeños
- El prompt del triaje exige evidencia positiva para «Probable falso positivo» y aclara que lo que no aparece en el recorte de evidencia no prueba que no ocurrió. La evidencia enviada pasa de 10 a 14 eventos por incidente.
- Si los motivos de un «Probable falso positivo» se apoyan solo en ausencias o hipótesis, se trata como «Falta información» (confianza Baja).
- Si el proveedor de IA falla 3 veces seguidas, se omiten los incidentes restantes (usan la recomendación del motor) en lugar de esperar el tiempo de espera de cada uno.
- `scripts/evaluar_triage.py` muestra qué sugirió la IA en cada conflicto, guarda los motivos en el `.json` y acepta `--archivos`.

## [1.7.0] - 2026-11-06

### Añadido: higiene del repositorio
- `CONTRIBUTING.md` con las reglas del proyecto, cómo preparar el entorno y la lista previa a un pull request.
- Plantillas de issues (error, falso positivo o detección omitida, mejora) con enlace al reporte privado de vulnerabilidades, y plantilla de pull request.
- El CI genera un **SBOM** de la imagen en formato CycloneDX (Trivy, misma versión fijada) y lo publica como artefacto de cada ejecución.
- `INTEL_MAX_INDICATORS`, `INTEL_VT_INTERVAL` e `INTEL_ABUSE_INTERVAL` quedan documentadas en `.env.example` y `docs/REPUTACION.md`.

### Cambiado: protección extra del triaje
- La IA tampoco puede bajar la recomendación de un incidente con señales de abuso (varios hallazgos, IP externa o un hallazgo Alto/Crítico), aunque el motor lo haya clasificado como Medio: se conserva la del motor y se marca el conflicto.


### Añadido: triaje asistido por IA con decisión del analista
- En la pestaña Incidentes, cada incidente trae una recomendación de triaje (**Escalar**, **Probable falso positivo** o **Falta información**) con confianza, motivos que citan `Log_ID` y «qué me haría cambiar de opinión». Sin IA la da el motor; con IA (Claude u Ollama, desde el panel de la misma pestaña) la propone el modelo.
- La severidad sigue siendo del motor. Si la IA propone ser menos exigente en un incidente Crítico o Alto, se conserva la recomendación del motor y se marca el **conflicto**. Se descartan los `Log_ID` e IP inventados, los motivos genéricos y las respuestas inválidas (ese incidente queda con la del motor).
- El analista registra su decisión (Escalado, Descartado o En investigación) con una nota; aparece en el PDF junto con la recomendación de IA.
- Nuevo `scripts/evaluar_triage.py` y `sample_data/triage_esperado.json` para medir un modelo (aciertos, subescalado, sobreescalado, conflictos, citas descartadas). Las etiquetas son criterio del autor sobre datos sintéticos; ver `docs/TRIAGE.md`.
- Nuevos `backend/triage.py` y endpoints `GET /api/sessions/{id}/triage`, `POST …/triage/ai` y `POST …/triage/{incidente}/decision`. Sin dependencias nuevas. 23 pruebas nuevas (1.109 en total).

### Añadido: reglas Sigma para Linux, web, DNS y nube
- Los hallazgos de SSH, ataque web, túnel DNS, minería, lectura de credenciales en Linux, persistencia (cron, claves SSH y también Windows), ransomware, phishing con doble extensión, comandos sospechosos, sondeo de recursos compartidos y cambios de IAM en la nube ahora ofrecen una regla **Sigma** en «Buscar en tu SIEM» y en la descarga de reglas de la pestaña Hallazgos. Son solo Sigma (sin Splunk ni KQL), con campos estándar. No tienen regla la exfiltración ni el comando y control.
- Las reglas se convierten sin error con pySigma (backend Splunk) y se prueban contra las evidencias de los ejemplos; esa prueba detectó que el regex de túnel DNS no cubría subdominios de dos niveles, y se corrigió.

### Corregido: regla de firewall (Windows) en Sigma, Splunk y KQL
- El patrón de «regla de firewall que abre el tráfico entrante o lo desactiva» usaba «mirar adelante» (`(?=…)`), que los motores de Sigma y de KQL no admiten, y pySigma lo rechazaba. Ahora se exporta con un patrón equivalente sin ese operador; la detección de la app no cambia.

## [1.6.0] - 2026-11-06

### Añadido: IA local con Ollama
- En la pestaña Informe se puede elegir **IA local (Ollama)** además de Claude, con un modelo instalado en Ollama: sin clave, sin costo y, si Ollama corre en el mismo equipo, sin enviar datos a terceros. Claude funciona exactamente igual que antes.
- Mismas garantías: la criticidad la decide el motor, el verificador descarta `Log_ID` e IP inventados y, si el modelo falla, el informe sale por reglas. La dirección de Ollama (`OLLAMA_HOST`) solo la define el servidor; se pide un contexto de 16.384 tokens (`OLLAMA_NUM_CTX`) para que no recorte la evidencia.
- La prioridad del plan de acción (sección 7) la fija el motor según la criticidad del incidente (Crítico → Inmediata, Alto → Corto plazo, Medio/Bajo → Mediano plazo); el modelo ya no puede bajarla. Una prueba real con un modelo local de 8B había dejado un ransomware en «Corto plazo».
- Todo incidente queda cubierto en el plan de acción: si el modelo no lo menciona, entra la acción concreta de las reglas.
- Se descartan las acciones y recomendaciones genéricas del modelo («tomar medidas para prevenir futuros ataques»); en el plan por hallazgo, la columna genérica o vacía se completa con el plan de las reglas. En el plan de acción, la acción del modelo solo se usa si se refiere a un único incidente y nombra algo concreto de él (IP, equipo, cuenta o indicador); si no, entra la acción de las reglas. Una justificación de criticidad que repite la explicación técnica se reemplaza por la de las reglas.
- Cronología: la hora ya no se corta ni se pierde cuando el modelo devuelve la fecha completa (también con formato ISO «…T10:08:59Z»). PDF: el Log_ID no se parte en dos líneas y «1 host» en singular.
- Tiempo de espera por consulta configurable (`OLLAMA_TIMEOUT`, 60 minutos por defecto): una prueba real con un modelo de 8B en una VM de 2 procesadores mostró consultas de más de 15 minutos con incidentes grandes.
- Nuevo `backend/ai_local.py`, endpoint `GET /api/ai/providers` y parámetros `provider` y `model` en `POST /api/sessions/{id}/ai`. 36 pruebas nuevas con un servidor Ollama simulado y una prueba de navegador. Sin dependencias nuevas. 21 pruebas nuevas (1.107 en total).

### Corregido: números de los ejemplos en la documentación
- `docs/FORMATOS.md` atribuía al ejemplo de 500 eventos el resultado del de 100 (15 hallazgos y 9 incidentes). Ahora: `logs_multifuente.json` produce 15 hallazgos en 9 incidentes y `SIEM_Logs_500_Eventos` 28 hallazgos en 7 incidentes.

### Cambiado: README aún más corto
- El README pasa de 364 a unas 235 líneas. Formatos de entrada y datos de ejemplo, la galería de capturas, IA local con Ollama, reputación y privacidad se movieron, completos, a `docs/FORMATOS.md`, `docs/CAPTURAS.md`, `docs/IA-LOCAL.md`, `docs/REPUTACION.md` y `docs/PRIVACIDAD.md`; el README deja un resumen y el enlace a cada uno. No se eliminó información.

### Cambiado: README más corto
- El README pasa de 411 a unas 345 líneas (de 5.900 a 3.400 palabras): «Cómo funciona», el detalle del análisis de correos, «Si algo falla», «Pruebas», «Seguridad» y «Estructura» se resumen y su texto completo está en `docs/DESARROLLO.md`. No se eliminó información.

### Corregido: calibración con correo legítimo de bancos y empresas
- Con 19 correos reales (Banco Galicia, Naranja X, Personal Pay, Gobierno, boletines) hubo 6 falsos positivos; ahora 0. Causas: dominios propios del banco (`galicia.ar`, cobranzas) que no figuraban, enlaces de rastreo de emBlue y las palabras «billetera» y «tokens» tomadas por cebo de criptoactivos (ahora solo cuentan junto a un verbo de reclamar, validar, migrar o conectar).

### Añadido: letras de otro alfabeto dentro de las palabras del mensaje
- Nueva señal (Alto) cuando 3 o más palabras del cuerpo mezclan letras latinas con cirílicas o griegas que se ven iguales. Detecta un phishing real enviado desde un servicio de encuestas legítimo, que ahora sale Crítico.

### Corregido: calibración del phishing con el corpus público de SpamAssassin
- **Marca por subdominio:** `applecore…` ya no se toma por «imita a Apple»; la marca debe ir sola o con palabras típicas de suplantación (`login`, `secure`, `verify`…).
- **`mailto:` con entidades HTML:** ya no se marca como enlace ofuscado; sigue alertando si se oculta un enlace web.
- Medición completa tras las calibraciones: phishing_pot 86,4 % Medio o más y 62,5 % Alto o más (antes 87,7 % / 64,9 %: ya no se llama «imitación de Google/Microsoft» al phishing alojado en sitios legítimos de esas empresas). Los 20 correos reales siguen en 0 de 20. Detalle en `docs/VALIDACION.md` (sección 3b).

### Añadido: evasión de defensas y persistencia por línea de comandos
- **Programas de confianza (LOLBins)** (`cmd_lolbin_proxy`, T1218.x y T1220): `mshta` con JavaScript, VBScript, URL o `.hta`; `cmstp /s … .inf`; `hh.exe` con un `.chm` de una ruta de usuario; `control.exe` o `rundll32` con un `.cpl` de ProgramData, Temp o del usuario; InstallUtil sobre un `.dll` o `.exe` de esas rutas; `Register-CimProvider -Path`; y `wmic … /format:` con una hoja XSL remota. El hallazgo cita la técnica concreta de cada uno.
- **Auditoría o registro de eventos alterado** (`cmd_log_tamper`, T1685.001 y T1685.005): `wevtutil cl` o `set-log` que cambia la ruta o lo desactiva, `auditpol` que desactiva o borra, `sc config eventlog`, `Stop-Service EventLog`, `Clear-EventLog` y el apagado de la línea de comandos de los procesos (`ProcessCreationIncludeCmdLine_Enabled = 0`). El uso normal (`wevtutil sl … /ms:`, `auditpol /set … :enable`, activar la línea de comandos) no alerta.
- **Registro de eventos desactivado en el registro de Windows** (`defense_registry`, Sysmon 13): `EventLog\Start = 4` y la línea de comandos apagada. Sube a Crítico si lo escribió un programa de una ruta de usuario.
- **Firewall abierto o desactivado** (`cmd_fw_change`, T1686, Medio), **servicio creado o modificado** (`cmd_service_binpath`, T1543.003, Medio; sube a Alto si apunta a un intérprete o a una ruta de usuario) y **script de inicio de sesión** (`cmd_logon_script`, T1037.001, Alto). Todas con playbook, consulta Splunk/KQL y regla Sigma.
- **Medido con datos externos:** de los 107 ataques de OTRF, «misma técnica» pasa de 20 a 41 y «sin hallazgos» de 57 a 37. Sin falsos positivos nuevos medidos: los logs de ejemplo dan lo mismo y las pruebas negativas con el uso normal de esos programas siguen en verde. Detalle y límites en `docs/VALIDACION.md`.

### Cambiado
- **ATT&CK v20:** 68 técnicas en 32 reglas. MITRE reemplazó T1562.002, T1562.004 y T1070.001 por T1685.001, T1686 y T1685.005; la app cita los vigentes y `scripts/validar_datasets.py` traduce los identificadores anteriores de OTRF antes de comparar.
- Los títulos de comandos ya no muestran paréntesis vacíos cuando el log no trae usuario.
- `docs/VALIDACION.md`: corregidas dos cifras desactualizadas (Loghub: 522 eventos y 24 IP; la tabla de ATT&CK ya no omite T1204.004) y documentado qué huecos se descartan a propósito (movimiento lateral por red, credenciales en memoria, inyección de procesos).

## [1.5.0] - 2026-11-05

### Añadido: pruebas de navegador, inyección de prompts y regeneración segura del informe
- **Pruebas de navegador** (`tests/e2e/test_ui.py`, Playwright + Chromium): cargan un export, recorren panel, hallazgos y filtros, descargan el PDF, analizan correos de phishing (crítico y legítimo, y un enlace escrito con entidades HTML) y comprueban que un log con `<img onerror>` y `<script>` se muestra como texto y no se ejecuta. Fallan si aparece cualquier error de JavaScript o violación de la política CSP. Se saltan solas si no hay Chromium instalado.
- **Inyección de prompts en la capa de IA** (`tests/integration/test_prompt_injection.py`): logs con instrucciones («ignora lo anterior», `</analisis>`, etiquetas falsas) no apagan la detección ni cierran el bloque de datos; un modelo que obedece la inyección (baja severidades, inventa IP y Log_ID, mete `<img src="file:///…">` o `javascript:`) no cambia la criticidad del motor, sus citas inventadas se descartan y el PDF no genera enlaces activos.
- **Endurecimiento** (`backend/ai.py`): el JSON que se envía al modelo escapa `<` y `>` (`\u003c`, `\u003e`), así un valor de un log no puede cerrar el bloque `<analisis>` ni imitar una instrucción. El modelo lo lee igual.
- **Regenerar el informe de ejemplo sin gastar de más** (`scripts/generar_informe_ejemplo.py`): simulacro sin red ni costo por defecto; con `--real` muestra cuántas llamadas hará y pide confirmación; cada respuesta del modelo se guarda en disco al llegar y, si algo falla, al repetir solo se llama por lo que falta; no escribe un PDF incompleto. La clave se lee de `ANTHROPIC_API_KEY`.
- `build_pdf` acepta un pie y un sufijo de título opcionales (para el informe de ejemplo).
- 913 pruebas, cobertura 95,6 %.

### Validación con datos reales
- **Phishing real:** `scripts/validar_correos.py` analiza los 12.864 correos de phishing_pot: Medio o más 87,7 %, Alto o más 64,9 %, 0,11 s de media. Comprobado con 11.364 correos no usados para ajustar (87,6 % / 64,8 %). Resultados y límites en `docs/VALIDACION.md` (sección 3b).
- **Correo legítimo real:** con 20 correos reales (boletines, LinkedIn, GitHub, cursos) los falsos positivos pasaron de 14 de 20 a 0 de 20. Con DMARC en «pass» ya no suman las desalineaciones de SPF/DKIM, Message-ID y Return-Path; el rastreo de clics del propio remitente o de servicios de envío conocidos deja de contar como engaño (salvo si el enlace habla de pagos, cuentas o inicio de sesión); el relleno invisible de los boletines ya no se toma por ofuscación. A cambio, la detección sobre el corpus de phishing baja de 92,2 % a 87,7 % (spam comercial que solo se marcaba por señales débiles).
- **Comandos ofuscados:** `scripts/validar_ofuscacion.py` mide el desofuscador con 1.360 comandos de Atomic Red Team.
- **Corregido a partir de esos datos:** un correo con un enlace como `http://[placeholder_1]/` hacía fallar todo el análisis (ahora se marca como enlace inválido); los emoji con selector de variación y las plantillas `{{{ … }}}` ya no se toman por ofuscación; el desofuscador ya no daña los escapes `` `r`n `` de PowerShell y entiende el operador `-f` de Invoke-Obfuscation.
- **Nuevas señales:** marcas muy suplantadas (criptoactivos, seguridad, bancos y mensajería) en el nombre visible, selectores de variación y marcas combinantes ocultas, estafas de adelanto de pago sin enlaces y cebos de reclamo o validación de criptoactivos.
- Pendiente: ampliar la muestra de correo legítimo (corporativo, bancario, otros rubros); 20 correos de una sola bandeja son pocos.

### Añadido: ofuscación
- **URLs ofuscadas** (`backend/deobf.py`): se normalizan antes de analizarlas. IP escrita en decimal (`http://3232235777`), hexadecimal, octal o abreviada, e IPv4 dentro de IPv6; `%XX` en el host o en varias capas; caracteres invisibles y entidades HTML numéricas que esconden el esquema (`jav&#x09;ascript:`); barras invertidas. El correo muestra la dirección real que interpreta el navegador y suma una señal de ofuscación.
- **Redirecciones abiertas y enlaces envueltos:** si la URL lleva otro destino dentro de un parámetro (`?url=…`), ese destino también se analiza. Los reescritores de enlaces corporativos (Safe Links, Proofpoint…) se siguen sin generar ruido.
- **Comandos ofuscados en los logs** (regla `cmd_obfuscated_cmd`, T1027.010): se quitan `^`, acentos graves, comillas intercaladas, concatenaciones, `.Replace()`, `[char]`, `-join` y `FromBase64String`, y se vuelven a pasar las reglas. Solo cuenta si la ofuscación **escondía** un comando relevante; un `ipconfig` o una concatenación normal no alertan. Si lo oculto coincide con otra regla (por ejemplo una descarga), esa regla dispara con el comando limpio y sube un nivel.
- **HTML ofuscado** (`backend/htmlscan.py`), en el cuerpo del correo y en adjuntos `.html`/`.svg`: HTML smuggling (Blob + descarga + datos incrustados, T1027.006, Crítico), JavaScript ofuscado (`eval`, `atob`, `unescape`, `fromCharCode`, `\x`, bloques Base64 largos), `meta refresh`, enlaces con entidades numéricas y texto oculto o caracteres de ancho cero en volumen. Se decodifican los literales (sin ejecutar nada) y las URL que esconden pasan a ser IOC.
- ATT&CK: 56 técnicas en 31 reglas (T1027.006, T1027.010, T1059.007 y T1140 nuevas).
- Límites documentados en `docs/VALIDACION.md` (sección 5): no se ejecuta código, así que lo que se arma en tiempo de ejecución no se ve. La validación con OTRF y Loghub no cambia (20/3/27/57 y 11/11).

### Añadido: phishing
- **Decodificador de `-EncodedCommand`** (`backend/psdecode.py`): acepta todas las grafías de la opción (`-e`, `-ec`, `-enc`…), decodifica el Base64 UTF-16, revisa una capa más de compresión (con tope de tamaño contra bombas de descompresión) y marca lo que hace el comando (descarga, IEX, oculta la ventana, intenta desactivar AMSI…). En los hallazgos de logs se muestra el contenido, se extraen sus URL e IP como indicadores y, si descarga algo de una URL externa, sube un nivel la criticidad.
- **Comandos en el cuerpo de un correo («ClickFix»)**: un `powershell -enc …` o un `irm … | iex` en el texto se marca como Crítico (T1059.001, T1204.004) y se muestra decodificado.
- **Verificar el remitente en DNS** (`backend/senderreview.py`, `backend/spfeval.py`): botón opcional en cada correo. Usa el selector DKIM de la propia firma y la IP que registró el servidor receptor; evalúa SPF de verdad contra el DNS actual (ip4, ip6, a, mx, include, redirect, límite de 10 consultas); comprueba que exista la clave de la firma y su tamaño; y compara todo con lo que dicen las cabeceras. Incluido en el PDF de phishing. Solo salen nombres de dominio.
- «Evaluar dominio» ahora busca primero el selector DKIM del propio correo; el análisis de SPF entiende `mx/24` y `a/28`.

### Añadido: consultas y fuentes
- **Consultas para el SIEM** (`backend/siemqueries.py`): cada hallazgo de Windows con equivalente directo muestra la consulta de Splunk (SPL), la de Microsoft Sentinel/Defender (KQL) y la regla Sigma, con IP, cuenta, equipo y ventana (±30 min) ya rellenos y botón de copiar. Endpoint `GET /api/sessions/{id}/findings/{fid}/queries` y descarga de todas las reglas Sigma de la sesión (`/sigma.yml`, botón en Hallazgos). Los valores de los logs se escapan para que no puedan salirse de las comillas de la consulta.
- **Lectura de `auth.log` / `secure` de Linux** (`backend/syslog.py`): se sube el archivo tal cual (fecha clásica o ISO; el año se infiere y nunca queda en el futuro). Se interpretan sshd (contraseña/clave aceptada o fallida) y sudo (fallos y comandos); el resto se ignora y se avisa cuántas líneas. Ejemplo en `sample_data/auth_log_ejemplo.txt`. La validación con SSH real ahora usa este mismo lector (sigue 11 de 11 IPs, 0 falsos positivos).
- **Kerberoasting** (evento 4769, T1558.003): una cuenta que pide tickets RC4 (0x17) para 3 o más servicios de usuario en 10 minutos. Excluye cuentas de máquina y krbtgt. En OTRF dispara en 1 dataset (el de Kerberoasting) y en ninguno de los otros 106: misma técnica 19 → 20.
- Pass-the-hash queda sin regla a propósito (ver docs/VALIDACION.md).

### Cambiado: calibración
- **Menos ruido:** un `ipconfig`, `whoami` o `tasklist` suelto ya no genera «Comandos de reconocimiento» (se necesitan ≥3 en el mismo grupo o un origen externo; la enumeración de dominio como `net user` o `nltest` sigue alertando sola); la compresión de datos aislada (`7z a x.7z`) se descarta salvo origen externo, ruta temporal/ProgramData, contraseña, ≥3 comandos o conexión saliente posterior; las tareas de Windows creadas por SYSTEM (`\Microsoft\Windows\…`) ya no se reportan como persistencia.
- Volcado de credenciales: ahora detecta `reg.exe" save HKLM\sam` entre comillas, `esentutl` sobre SAM/NTDS, `ntds.dit`, Dumpert, NanoDump, lsadump y secretsdump. La regla de compresión ya no confunde un `curl` a un archivo `.tar.gz` con un archivado.

### Añadido: calibración
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
