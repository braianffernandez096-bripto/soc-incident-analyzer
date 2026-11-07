# Detalle técnico

Material que estaba en el README y se movió acá para que la portada sea corta. No se quitó nada: el README enlaza a cada parte.

Contenido: [Cómo funciona](#cómo-funciona-detalle) · [Análisis de correos](#análisis-de-correos-phishing-detalle) · [Si algo falla](#si-algo-falla) · [Pruebas](#pruebas) · [Seguridad](#seguridad-detalle) · [Estructura](#estructura)

## Cómo funciona (detalle)

1. **Motor de reglas determinista** (`backend/detection.py`): fuerza bruta y password spraying, inicios de sesión externos, escalamiento de privilegios, comandos y procesos sospechosos, movimiento lateral, acceso masivo a archivos, exfiltración, persistencia, acceso a LSASS, DCSync, Kerberoasting, claves Run, programas de confianza del sistema usados para ejecutar código (mshta, cmstp, InstallUtil…), apagado del registro de eventos y del firewall, ataques web y problemas de calidad de datos.

2. Cada hallazgo cita los `Log_ID` que lo sustentan y explica por qué tiene esa criticidad. Además de los eventos de Windows (por Event ID), `backend/detection_generic.py` cubre exports de otras fuentes que traen una acción y un mensaje en lugar de Event IDs numéricos: fuerza bruta y password spraying por SSH/RDP/Kerberos, ataques web (inyección SQL, rutas, XSS), exfiltración, phishing con adjuntos de doble extensión, comando y control, persistencia, ransomware, minería de criptomonedas, escalamiento SUID en Linux, túneles DNS y abuso de identidades cloud (IAM).

3. **Correlación**: los hallazgos se agrupan en incidentes cuando comparten IP externa o cuenta de actor. Compartir host o recurso no fusiona incidentes; queda como hipótesis de confianza baja.

4. **IA (Claude u Ollama local)** (`backend/ai.py` y `backend/ai_local.py`): redacta la narrativa, la explicación técnica, el impacto y el plan de acción de cada incidente a partir de los hallazgos ya detectados. No puede cambiar la criticidad. Un verificador descarta cualquier `Log_ID` o IP que no exista en el archivo. Sin API key, o si la IA falla, el informe se genera con plantillas deterministas. Con Ollama solo cambia la llamada al modelo (`ai_local.make_call`); la dirección de Ollama se define únicamente en el servidor (`OLLAMA_HOST`), el nombre del modelo debe estar instalado y no se siguen redirecciones ni se usan proxies del entorno.

5. **PDF** (`backend/report.py`): resumen ejecutivo, hallazgos, evidencia, criticidad y justificación, impacto, plan de acción (investigar, contener, remediar) y recomendaciones generales.

6. **Reputación (opcional)** (`backend/intel.py`): consulta en VirusTotal y AbuseIPDB las IP y dominios públicos que tú confirmes. Ver [REPUTACION.md](REPUTACION.md).

7. **MITRE ATT&CK** (`backend/attack.py`): cada técnica sugerida por un hallazgo se muestra con su nombre oficial y un enlace a attack.mitre.org. La pestaña **ATT&CK** agrupa las técnicas por táctica en una matriz y permite descargar una capa `.json` para [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Los datos son los oficiales de MITRE (v20.0), incluidos en `backend/data/` y validados contra las reglas por las pruebas. No se consulta Internet.

8. **Consultas para tu SIEM** (`backend/siemqueries.py`): cada hallazgo con equivalente directo ofrece el botón **Buscar en tu SIEM**. Los de Windows muestran la consulta de **Splunk (SPL)**, la de **Microsoft Sentinel/Defender (KQL)** y la regla **Sigma**; los de otras fuentes (SSH, servidor web, DNS, Linux y nube) muestran **solo Sigma**, con campos estándar que cada SIEM traduce a los suyos, con la IP, la cuenta, el equipo y la ventana del hallazgo ya rellenos. La pestaña Hallazgos descarga además todas las reglas Sigma de la sesión en un `.yml`. Son plantillas deterministas (sin IA, sin Internet) y los valores del log se escapan para que no puedan alterar la consulta; cada SIEM nombra índices y campos a su manera, así que hay que revisarlos. Las reglas Sigma de otras fuentes cubren autenticación SSH, ataques web, túnel DNS, minería, lectura de credenciales y persistencia en Linux, ransomware, phishing con doble extensión, comandos sospechosos, sondeo de recursos compartidos y cambios de IAM en la nube. No tienen regla la exfiltración, el comando y control (dependen de flujos de red o de inteligencia de amenazas) ni la calidad de datos. Las reglas se comprueban con la librería oficial pySigma cuando está instalada (`pip install pysigma pysigma-backend-splunk`) y contra las evidencias de los ejemplos.

9. **Phishing** (`backend/phishing.py`): la pestaña **Phishing** analiza correos `.eml` (hasta 5, 5 MB cada uno). Revisa remitente, Reply-To y suplantación de marcas; SPF, DKIM y DMARC; enlaces engañosos (IP en vez de dominio, acortadores, punycode, dominios casi idénticos a una marca, texto distinto del destino); **ataques homógrafos** (letras de otro alfabeto o «I» por «l» que se ven iguales, con desglose carácter por carácter); y adjuntos (doble extensión, ejecutables disfrazados, macros, comprimidos con contraseña, hash SHA-256). También detecta comandos que el correo pide copiar y ejecutar (la técnica «ClickFix»): un `powershell -enc …` en el cuerpo se **decodifica** y se muestra qué hace (descargas, ocultamiento, desactivar el antimalware), con sus URL e IP como indicadores. Da un veredicto con puntaje, las señales que lo sustentan, **qué verificar** y acciones sugeridas. Es análisis estático: no se abre ningún enlace ni se ejecuta ningún adjunto.

10. **Verificar el remitente en DNS** (opcional, botón en cada correo): usa el selector de la propia firma DKIM del correo y la IP que registró el servidor receptor para comprobar, con el DNS de hoy, si el dominio autoriza esa IP en SPF (se evalúa el registro de verdad: `ip4`, `ip6`, `a`, `mx`, `include`, `redirect`, con el límite de 10 consultas), si existe la clave de la firma y qué política DMARC tiene, y lo compara con lo que dicen las cabeceras. Una diferencia (por ejemplo, la cabecera dice `SPF=pass` pero el dominio no autoriza esa IP) no prueba una falsificación, porque el DNS pudo cambiar, pero es justo lo que hay que revisar. Solo salen nombres de dominio por DNS sobre HTTPS; ni la IP ni el contenido del correo. No evalúa macros SPF, `exists` ni `ptr`, y no verifica la firma DKIM en sí (falta el mensaje original byte a byte): comprueba que la clave exista y su tamaño.

## Análisis de correos (phishing, detalle)

En la pestaña **Phishing** (disponible desde el inicio, sin cargar logs) sube uno o varios `.eml`, o pulsa **Probar con correos de ejemplo** (`sample_data/correos/`: 8 maliciosos, entre ellos 4 con homógrafos, 1 con un recorrido anómalo y 2 legítimos que no deben alertar). Para obtener un `.eml`: en Outlook, Thunderbird o Gmail guarda el correo como `.eml` o usa «Descargar mensaje». Los `.msg` no se admiten. Si no puedes exportarlo, **pega las cabeceras** (el «origen del mensaje») en el cuadro de la pantalla de carga: se analizan remitente, autenticación y recorrido, pero sin cuerpo no hay enlaces ni adjuntos.

- **Ataques homógrafos.** Detecta direcciones y dominios que se ven iguales a otros pero no lo son: la «a» cirílica (U+0430) en lugar de la «a» latina (U+0061), la «I» mayúscula en lugar de la «l» minúscula (`banco.universaI@…` contra `banco.universal@…`), cifras por letras (`0`/`o`, `1`/`l`), `rn` por `m` y caracteres invisibles. Para cada remitente muestra el **desglose carácter por carácter** (código Unicode, nombre y alfabeto, con el carácter sospechoso resaltado), también en el PDF.
- Si escribes el **remitente esperado** al subir el correo, compara carácter por carácter y dice exactamente qué letra cambió. También compara el remitente con el Reply-To, el Return-Path, la dirección escrita en el nombre visible y el dominio del destinatario, y revisa los dominios de los enlaces (también los escritos en `xn--`). Los nombres con tilde (`josé@empresa.com`) o escritos por completo en otro alfabeto no alertan.

- **Recorrido del correo.** Los saltos `Received` se ordenan del origen al destino, con hora UTC, protocolo/TLS y retraso entre servidores. Se marcan horas fuera de orden, retrasos de 6 h o más, una fecha que no encaja con el recorrido y recorridos inusualmente largos. Son señales de **bajo peso** (1 punto): el atacante puede inventar los `Received` que añade su servidor, y solo los de tu propia infraestructura son fiables.

- **Puntaje con factores visibles.** «¿Cómo se calculó el puntaje?» muestra qué sumó cada señal, los topes por categoría (por ejemplo, Adjunto máx. 14) y los umbrales de criticidad. También va en el PDF.

- **Evaluar dominio (SPF/DKIM/DMARC).** Pestaña **Evaluar dominio**: lee los registros DNS públicos y da una nota de A a F con descuentos fijos y visibles (sin SPF −35, `+all` −35, DMARC ausente −40, `p=none` −25, más de 10 consultas DNS en SPF −25, claves DKIM de menos de 2048 bits…) y cómo corregir cada falla. DKIM solo se busca con los selectores más comunes: no encontrarlo no prueba que no exista.

- **Dominios parecidos.** Pestaña **Dominios parecidos**: genera variantes de typosquatting de una marca (letras parecidas, homógrafos IDN con su forma `xn--`, letras intercambiadas u omitidas, teclas vecinas, otras terminaciones, palabras como `login`) y permite descargar la lista (.txt o .csv) para vigilar o bloquear. Generarla es local; la comprobación de cuáles están registradas es opcional (hasta 60 dominios) y consulta el DNS.

- **Seguro por diseño.** El archivo se lee solo como texto: no se renderiza el HTML, no se abre ningún enlace y no se extrae ni se ejecuta ningún adjunto (de un ZIP solo se lee la lista de nombres). Las URL se muestran «defangeadas» (`hxxps://sitio[.]com`) para que no sean enlaces activos.

- **Determinista.** Cada señal tiene un peso fijo y la criticidad sale de la suma; no interviene la IA. Los casos negativos (correo legítimo, enlaces oficiales, PDF real, SPF/DKIM/DMARC alineados) tienen pruebas propias.

- **Qué verificar.** Cada correo trae los pasos de un analista L1 (confirmar con el remitente por otro canal, buscar clics en el proxy y el DNS, detonar el adjunto en una sandbox, buscar el mismo correo en otros buzones) y las acciones de contención.

- **Reputación opcional.** Con tus claves de VirusTotal y AbuseIPDB y tu confirmación, se consultan dominios, IP y el **hash SHA-256** de los adjuntos. Nunca se envían el archivo, el correo, las direcciones de correo ni las URL completas.

- **Informe.** Se descarga un PDF propio del análisis de correos. El análisis de correos y el de logs son independientes: al analizar un archivo de logs no aparece la pestaña Phishing, y al analizar correos no se mezclan con los logs. Para cambiar de uno a otro usa «Cargar otro».

- **Límites.** Las cabeceras SPF/DKIM/DMARC las escribe el servidor que recibió el correo: si el `.eml` viene de otra fuente pueden estar ausentes o ser falsas. Los pesos son orientativos y el veredicto es una ayuda para el triage, no una prueba. Sin una dirección de referencia (la que escribes como «remitente esperado» u otra del mismo correo) la app no puede saber cuál es la legítima: el desglose está para que la compares tú con el contacto real. La tabla de caracteres confundibles es curada (los casos prácticos), no la base completa de Unicode.

## Si algo falla

| Mensaje | Causa | Solución |
|---|---|---|
| `Formato no soportado` | La extensión no es `.xlsx`, `.xlsm`, `.csv`, `.tsv`, `.txt`, `.log`, `.json`, `.jsonl` o `.ndjson`. | Exporta o guarda el archivo en uno de esos formatos. |
| `No encontré una fila de cabecera reconocible` | Las columnas no tienen nombres reconocibles. | Usa nombres como `Timestamp`, `Event_ID`, `Hostname`, `User`, `Source_IP` (ver *Formatos de entrada*). |
| `…pero su contenido es un ejecutable / un ZIP / …` | El archivo está renombrado y no es lo que dice su extensión. | Vuelve a exportarlo desde el SIEM. Si no esperabas ese contenido, no lo abras. |
| `El archivo supera el límite de 25 MB` o `el máximo soportado es 100.000 filas` | Export demasiado grande. | Divídelo por rango de fechas. |
| `No hay API key de Anthropic` | Falta la clave para la redacción con IA. | Defínela en `.env` (`ANTHROPIC_API_KEY`) o pégala en la pestaña Informe. Sin ella el informe sale por reglas. |
| `VirusTotal rechazó la clave` / `AbuseIPDB rechazó la clave` | Clave inválida o inactiva. | Copia de nuevo la clave desde tu cuenta. |
| `No hay indicadores públicos para consultar` | Todas las IP son internas o de documentación. | Es lo esperado con el archivo de ejemplo; usa la casilla de prueba o un export con IP públicas. |
| `Acceso no autorizado` | La instancia tiene `APP_ACCESS_TOKEN`. | Introduce la clave de acceso. |
| `Demasiadas solicitudes` | Límite de peticiones por IP. | Espera un minuto. |
| `No matching distribution found for httpcore2` (o `httpx2`) | Tu Python es anterior a 3.11 (por ejemplo, 3.10 en Ubuntu 22.04). | Instala Python 3.12 (`sudo add-apt-repository ppa:deadsnakes/ppa`, `sudo apt install python3.12 python3.12-venv`), borra `.venv` y recréalo con `python3.12 -m venv .venv`. |
| `address already in use` | El puerto 8000 está ocupado. | `make stop`, o inicia con `--port 8001`. |

## Pruebas

```bash
pip install --require-hashes -r requirements-dev.lock      # pytest, cobertura, bandit y pip-audit
python -m pytest                                           # ~1.200 pruebas
python -m pytest --cov=backend --cov-report=term-missing   # con cobertura (95 %)
```

Atajos con `make` (Linux/macOS/WSL): `make install`, `make test`, `make test-cov`, `make lint`, `make audit` (bandit + pip-audit), `make start`, `make stop`, `make logs`. Con `make help` ves la lista completa.

- `tests/unit/`: motor de detección contra el Excel de ejemplo, límites del parser, formatos de entrada (CSV, TSV, JSON, NDJSON, codificaciones y zonas horarias), verificación de archivos (tipo real por contenido, macros, inyección de fórmulas) datos de MITRE ATT&CK (todas las técnicas que citan las reglas existen y siguen vigentes, matriz y capa de Navigator), análisis de correos (señales positivas y negativas, límites y casos hostiles), homógrafos (alfabetos mezclados, I/l, casos legítimos con tildes que no deben alertar) y captcha (respuesta solo en el servidor, un intento, caducidad, pase de un solo uso).

- `tests/integration/`: API con entradas hostiles (archivo falso, markup en celdas y portada, 413, 429, cabeceras), clave de acceso (401 en todas las rutas protegidas, fuerza bruta), capa de IA y consultas de reputación con servidores simulados (las pruebas no usan red ni claves) el botón de datos de ejemplo, el módulo de phishing (PDF, reputación y remitente esperado) y el captcha de imágenes y de rompecabezas.

- `tests/e2e/`: arranca el servidor real; `test_smoke.py` recorre carga, análisis y PDF por API, y `test_ui.py` maneja un navegador real (Playwright + Chromium: `pip install playwright && playwright install chromium`; si falta, se salta) para el flujo de logs, el PDF, el phishing y una prueba de que un log con HTML/JS no se ejecuta.
- `tests/integration/test_triaje.py` y `tests/unit/test_evaluar_triage.py`: triaje con modelos simulados (honesto, con `Log_ID` inventados, que baja la guardia, que devuelve basura o falla), decisiones del analista, API y coherencia de las etiquetas de evaluación.
- `tests/integration/test_ai_ollama.py`: IA local contra un servidor Ollama simulado (estado y modelos, dirección válida, JSON roto y reintento, errores legibles, caída del servidor con respaldo por reglas, la API sin clave, y que el navegador no pueda cambiar la dirección ni el modelo).
- `tests/integration/test_prompt_injection.py`: logs con instrucciones inyectadas y un modelo simulado que las obedece; comprueba que la criticidad sigue siendo la del motor, que lo inventado se descarta y que el PDF no genera enlaces activos.

- `tests/unit/test_negativos.py`: 35 casos de actividad normal (30 sin ruido y 5 falsos positivos medidos y ya calibrados) que no deben alertar, cerca de los umbrales de cada regla, más pruebas de que la calibración no apaga la detección real.

- `tests/unit/test_evasion_defensas.py`: programas de confianza (mshta, cmstp, InstallUtil…), registro de eventos y auditoría, firewall, servicios y script de inicio de sesión, con comandos de ataque tomados de OTRF y el uso normal de esos mismos programas, que no debe alertar.

- `tests/unit/test_reglas_credenciales.py`: acceso a LSASS (Sysmon 10), DCSync (4662), claves Run (Sysmon 13) y Kerberoasting (4769), con casos de ataque y de actividad normal.

- `tests/unit/test_casos_reales.py`: casos tomados de correos y comandos públicos reales (el fallo de las plantillas sin rellenar, marcas cripto, caracteres invisibles, estafas sin enlaces, ofuscación con `-f`), con los casos normales que no deben alertar.

- `tests/unit/test_ofuscacion.py`: ofuscación de URLs (IP numérica, `%XX`), comandos (`^`, acentos graves, `+`, `[char]`) y HTML (smuggling, `atob`, `meta refresh`, texto oculto), con sus casos normales que no deben alertar.

- `tests/unit/test_psdecode.py`: decodificación de `-EncodedCommand` (todas las grafías de la opción, una capa de compresión, bomba de descompresión, correos con ClickFix). `tests/unit/test_spf_remitente.py`: evaluación de SPF (mecanismos, prefijos, límite de 10 consultas, bucles) y verificación del remitente con DNS simulado.

- `tests/unit/test_siemqueries.py`: consultas Splunk/KQL y Sigma (YAML válido, entidades y ventana, y valores hostiles que no pueden escapar de las comillas). `tests/unit/test_sigma_otras_fuentes.py`: Sigma de SSH, web, DNS, Linux y nube (YAML válido, etiquetas ATT&CK, coincidencia con las evidencias de los ejemplos y no marcar tráfico normal). `tests/unit/test_syslog.py`: lectura de `auth.log` (fechas clásicas e ISO, año inferido, sudo, errores claros).

## Seguridad (detalle)

- Las claves (Anthropic, VirusTotal, AbuseIPDB) viven en `.env` (excluido de Git) o se pegan en la interfaz; nunca se guardan, se registran ni se devuelven al navegador.

- **Inyección de prompts (capa de IA):** los logs se envían al modelo como datos no confiables y se escapan `<` y `>` para que un valor no pueda cerrar el bloque de datos ni imitar una instrucción. Aunque un modelo obedeciera una instrucción escondida en un log, no puede cambiar la criticidad (la decide el motor de reglas), sus IP y `Log_ID` inventados se descartan y su texto se escapa en pantalla y en el PDF. Lo comprueban `tests/integration/test_prompt_injection.py` y las pruebas de navegador.

- Todo dato del archivo se escapa antes de mostrarse y antes de entrar al PDF. La interfaz aplica una CSP estricta (`script-src 'self'`); los estilos en línea están permitidos porque la interfaz los usa, un riesgo aceptado que no permite ejecutar scripts.

- Límites: 25 MB de subida (lectura acotada), 300 MB descomprimidos, 100.000 filas y límite de peticiones por IP.
  
- **Verificación del archivo subido:** el tipo se decide por su contenido, no por la extensión (un ejecutable renombrado a `.xlsx` se rechaza). En los Excel se avisa de macros VBA, objetos incrustados, vínculos externos y conexiones de datos, y se rechazan los que traen declaraciones XML peligrosas o rutas internas sospechosas. También se avisa de celdas con inyección de fórmulas. La app **nunca ejecuta ni evalúa** el archivo, y esto es un primer filtro, no un antivirus: "sin avisos" no significa "archivo seguro".

- **Captcha opcional (`CAPTCHA=on`):** antes de analizar un archivo de logs o un `.eml`, la persona resuelve un captcha **local**: no usa servicios de terceros, no necesita internet ni claves. Hay dos tipos y el servidor sortea uno en cada desafío (`CAPTCHA_TYPE=imagenes`, `rompecabezas` o `aleatorio`, el valor por defecto). **Imágenes:** marcar las 3 de 6 que muestran la misma figura (dispositivos de red y animales, giradas y con color, fondo y ruido al azar).

- **Rompecabezas:** deslizar una pieza hasta el hueco de la imagen (ratón, dedo o flechas del teclado); se acepta con unos píxeles de tolerancia y se comprueba, de forma básica, que el arrastre sea un movimiento y no un salto. La respuesta solo vive en el servidor, cada desafío admite un intento y caduca, y cada análisis pide su propio captcha (el pase es de un solo uso y dura segundos; ver los resultados no depende de ningún tiempo). Está apagado por defecto (en tu VM no estorba) y no protege los datos de ejemplo. Frena bots genéricos, no a un atacante dirigido: no sustituye a la clave de acceso. Las figuras son originales y se regeneran con `python scripts/build_captcha_assets.py`.

- **Clave de acceso opcional:** define `APP_ACCESS_TOKEN` (se recomiendan 16 caracteres o más) y toda la API exige `Authorization: Bearer <clave>`; la interfaz la pide al entrar. Es una sola clave compartida, no un sistema de usuarios, y debe servirse detrás de HTTPS. Sin ella, la app no tiene login: úsala en local.

- La documentación interactiva de la API (`/docs`) está desactivada por defecto (`ENABLE_DOCS=1` la activa).

- Docker: imagen multi-stage con dependencias verificadas por hash, usuario sin privilegios, sistema de archivos de solo lectura, sin capacidades (`cap_drop: ALL`) y `no-new-privileges`.

- Integración continua: pruebas con cobertura mínima, pruebas de navegador (Playwright), `bandit`, `pip-audit` y Trivy sobre la imagen.

- Alcance, límites y cómo reportar una vulnerabilidad: [SECURITY.md](../SECURITY.md).

## Estructura

```
backend/      parser, reglas de detección, correlación, análisis de correos (.eml) y de homógrafos, captcha local, IA, reputación (VirusTotal/AbuseIPDB), MITRE ATT&CK, informe PDF y API (FastAPI)
scripts/      build_attack_data.py regenera backend/data/ desde los datos oficiales de MITRE; build_captcha_assets.py regenera las figuras del captcha; validar_datasets.py mide las reglas con datasets públicos; validar_correos.py y validar_ofuscacion.py miden phishing y desofuscación con correos y comandos reales; generar_informe_ejemplo.py regenera el PDF de ejemplo cuidando las llamadas de pago a la IA (simulacro por defecto, caché en disco y confirmación; uso de mantenimiento)
docs/         VALIDACION.md: método y resultados de la validación de las reglas
frontend/     interfaz web sin build (HTML, CSS y JS; fuentes IBM Plex locales)
sample_data/  exports de ejemplo (Windows en Excel/CSV/NDJSON, multi-fuente en JSON, SIEM de 500 eventos y un auth.log de Linux) y correos .eml de ejemplo
tests/        unit, integration y e2e
Makefile      atajos: install, start, stop, test, test-cov, lint, audit, logs, backup, clean
requirements*.lock  dependencias con versión exacta y hash (requirements*.txt son los rangos de origen)
SECURITY.md, CHANGELOG.md  política de seguridad y registro de cambios
examples/     informe técnico de ejemplo en PDF
img/gif/      demostraciones en GIF del README
Dockerfile, docker-compose.yml y .github/workflows/tests.yml (imagen y pruebas automáticas)
```
