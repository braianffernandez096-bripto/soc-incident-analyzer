# SOC Incident Analyzer

![Python](https://img.shields.io/badge/python-3.12-blue) [![Tests](https://github.com/braianffernandez096-bripto/soc-incident-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/braianffernandez096-bripto/soc-incident-analyzer/actions/workflows/tests.yml) [![Cobertura](https://codecov.io/gh/braianffernandez096-bripto/soc-incident-analyzer/branch/main/graph/badge.svg)](https://codecov.io/gh/braianffernandez096-bripto/soc-incident-analyzer) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

Aplicación web para análisis de logs. Recibe el export de un SIEM (Excel, CSV/TSV o JSON/NDJSON), detecta indicadores de compromiso, correlaciona los eventos en incidentes, clasifica la criticidad (Crítico / Alto / Medio / Bajo) y genera el informe técnico en PDF.

## Qué problema resuelve y para quién

Un SIEM entrega miles de eventos y el analista tiene que decidir cuáles importan, cómo se relacionan y qué hacer primero.
Esta herramienta toma el export de un SIEM (Excel, CSV o JSON) y lo convierte en incidentes ordenados por criticidad, cada uno con las evidencias que lo sustentan.
Cada hallazgo se mapea a MITRE ATT&CK y trae un plan de acción (investigar, contener, remediar) y un informe técnico en PDF.
Está pensada para analistas SOC de nivel 1 y estudiantes que practican triage, y para quien quiera ver cómo se correlacionan los eventos sin montar un SIEM completo.
El análisis, los incidentes, MITRE ATT&CK y el informe en PDF funcionan sin Internet y sin costo, porque las reglas son deterministas y el informe usa plantillas. La redacción con IA es opcional: requiere tu propia clave de API de Anthropic (servicio de pago por uso) y solo mejora la redacción, nunca cambia la criticidad.

## Cómo se desarrolló

Proyecto personal de Braian Fernandez, hecho para practicar el análisis de incidentes. Lo desarrollé con ayuda de un asistente de IA (Claude, de Anthropic): yo definí qué debía detectar y cómo, revisé cada cambio, probé la aplicación con logs propios y decidí qué entra en el repositorio; el asistente escribió gran parte del código y de las pruebas. Por eso las decisiones de seguridad (la IA no puede cambiar la criticidad, los datos se tratan como no confiables) están cubiertas por pruebas automáticas y el historial de cambios está en el [CHANGELOG](CHANGELOG.md).

## Cómo funciona

1. **Motor de reglas determinista** (`backend/detection.py`): fuerza bruta y password spraying, inicios de sesión externos, escalamiento de privilegios, comandos y procesos sospechosos, movimiento lateral, acceso masivo a archivos, exfiltración, persistencia, ataques web y problemas de calidad de datos. Cada hallazgo cita los `Log_ID` que lo sustentan y explica por qué tiene esa criticidad. Además de los eventos de Windows (por Event ID), `backend/detection_generic.py` cubre exports de otras fuentes que traen una acción y un mensaje en lugar de Event IDs numéricos: fuerza bruta y password spraying por SSH/RDP/Kerberos, ataques web (inyección SQL, rutas, XSS), exfiltración, phishing con adjuntos de doble extensión, comando y control, persistencia, ransomware, minería de criptomonedas, escalamiento SUID en Linux, túneles DNS y abuso de identidades cloud (IAM).

2. **Correlación**: los hallazgos se agrupan en incidentes cuando comparten IP externa o cuenta de actor. Compartir host o recurso no fusiona incidentes; queda como hipótesis de confianza baja.

3. **IA (Claude)** (`backend/ai.py`): redacta la narrativa, la explicación técnica, el impacto y el plan de acción de cada incidente a partir de los hallazgos ya detectados. No puede cambiar la criticidad. Un verificador descarta cualquier `Log_ID` o IP que no exista en el archivo. Sin API key, o si la IA falla, el informe se genera con plantillas deterministas.

4. **PDF** (`backend/report.py`): resumen ejecutivo, hallazgos, evidencia, criticidad y justificación, impacto, plan de acción (investigar, contener, remediar) y recomendaciones generales.

5. **Reputación (opcional)** (`backend/intel.py`): consulta en VirusTotal y AbuseIPDB las IP y dominios públicos que tú confirmes. Ver [más abajo](#reputación-de-ip-y-dominios-virustotal-y-abuseipdb).

6. **MITRE ATT&CK** (`backend/attack.py`): cada técnica sugerida por un hallazgo se muestra con su nombre oficial y un enlace a attack.mitre.org. La pestaña **ATT&CK** agrupa las técnicas por táctica en una matriz y permite descargar una capa `.json` para [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Los datos son los oficiales de MITRE (v20.0), incluidos en `backend/data/` y validados contra las reglas por las pruebas. No se consulta Internet.

7. **Phishing** (`backend/phishing.py`): la pestaña **Phishing** analiza correos `.eml` (hasta 5, 5 MB cada uno). Revisa remitente, Reply-To y suplantación de marcas; SPF, DKIM y DMARC; enlaces engañosos (IP en vez de dominio, acortadores, punycode, dominios casi idénticos a una marca, texto distinto del destino); **ataques homógrafos** (letras de otro alfabeto o «I» por «l» que se ven iguales, con desglose carácter por carácter); y adjuntos (doble extensión, ejecutables disfrazados, macros, comprimidos con contraseña, hash SHA-256). Da un veredicto con puntaje, las señales que lo sustentan, **qué verificar** y acciones sugeridas. Es análisis estático: no se abre ningún enlace ni se ejecuta ningún adjunto.

## Formatos de entrada

| Formato | Extensiones | Detalles |
|---|---|---|
| Excel | `.xlsx`, `.xlsm` | Usa la hoja con más filas; detecta la fila de cabecera aunque haya títulos encima. |
| CSV / TSV | `.csv`, `.tsv`, `.txt`, `.log` | Detecta el separador (`,` `;` tab `\|`) y la codificación (UTF-8, UTF-16, Windows-1252). |
| JSON | `.json` | Arreglo de eventos, contenedores como `{"events": [...]}` (o cualquier otro nombre: se elige la lista que tiene fecha) y respuestas de Elasticsearch/OpenSearch (`hits.hits[]._source`). |
| NDJSON | `.jsonl`, `.ndjson` | Un evento por línea; también el formato de exportación de Splunk (`{"result": {...}}`). |

- **Columnas:** se reconocen por nombre aunque cambien mayúsculas, acentos o idioma (`Descripción`, `hostname`, `Equipo`…) y los campos anidados típicos de Elastic ECS / Winlogbeat (`@timestamp`, `host.name`, `winlog.event_id`, `source.ip`, `user.name`, `process.command_line`…). Solo son indispensables `Timestamp` y `Event_ID`; lo que falte queda vacío y se informa. Si el archivo no trae `Event_ID` pero sí `action` (o `event_type`), se usa como código de evento, y `category` pasa a ser la fuente del log.

- **Marcas de tiempo:** si traen zona horaria (`Z`, `+02:00`) o son epoch (segundos, milisegundos…), se convierten a UTC y el informe lo declara. Si no la traen, se usan tal cual.

- **Log_ID:** si no existe, se generan identificadores `ROW-00001…` estables.

- Un `.txt` o `.log` que contenga JSON se detecta por su contenido. Si un JSON se guardó línea por línea en una hoja de cálculo (`.csv` o `.xlsx`), se reconstruye; si le faltan líneas sueltas se lee lo que haya y se avisa.

## Resultado con el Excel de ejemplo

`sample_data/SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx` (715 eventos, ~6 h; también en `.csv` y `.ndjson`, con el mismo resultado) produce **25 hallazgos** agrupados en **6 incidentes**:

| ID | Incidente | Criticidad |
|---|---|---|
| INC-001 | Password spraying con compromiso de la cuenta `mgarcia` | Alto |
| INC-002 | Compromiso de la cuenta `admin` por acceso externo, movimiento lateral y exfiltración | Crítico |
| INC-003 | Recolección masiva y eliminación de copias de sombra por `backupsvc` | Crítico |
| INC-004 | Exfiltración de datos desde WS-018 (`rrojas`) | Crítico |
| INC-005 | Persistencia en APP-SRV01 por la cuenta `helpdesk` | Alto |
| INC-006 | Ataque web contra WEB-01 con ejecución remota de comandos | Crítico |

Las IP y los datos del ejemplo son sintéticos (rangos de documentación RFC 5737).

`sample_data/logs_multifuente.json` (100 eventos de SSH, web, base de datos, DNS, correo, endpoint y nube) es un segundo ejemplo, y `sample_data/SIEM_Logs_500_Eventos.{csv,xlsx,json}` (500 eventos de un día con Windows, Linux, web, proxy, DNS, correo, EDR y nube) un tercero con 7 incidentes y señuelos que no deben alertar, sin Event IDs de Windows: produce **15 hallazgos** agrupados en **9 incidentes** (fuerza bruta SSH con compromiso de `admin`, ataque web con exfiltración, phishing con movimiento lateral, ransomware, escalamiento SUID, túnel DNS, abuso de identidad cloud, password spraying y minería).

## Capturas

**Inicio: carga del archivo o prueba con datos de ejemplo**

![Pantalla de inicio con la zona de carga y el botón de datos de ejemplo](img/Inicio.png)

**Panel: resumen e incidentes detectados**

![Panel con las tarjetas de incidentes y la línea de tiempo](img/Dashboard.png)

**Panel: actividad, hallazgos por criticidad e IP con más movimiento**

![Actividad de la ventana analizada, hallazgos por criticidad e IP](img/Metricas.png)

**Incidentes: secuencia de eventos con el `Log_ID` que respalda cada paso** (INC-002)

![Incidente INC-002 con su secuencia de eventos](img/INC-002.png)

**Hallazgos: explicación técnica, criticidad, impacto y plan de acción**

![Hallazgo con explicación, impacto y plan de acción en tres columnas](img/Seccion-Hallazgos.png)

**ATT&CK: técnicas sugeridas por los hallazgos, agrupadas por táctica, con descarga de la capa para Navigator**

![Matriz MITRE ATT&CK por táctica](img/Matriz-ATTACK.png)

**Eventos: los 715 registros originales, con marca de los ligados a incidentes**

![Tabla de eventos con filtros](img/Eventos.png)

**Indicadores de compromiso (IoC)**

![Tabla de indicadores de compromiso](img/IOCs.png)

**Informe: datos de portada, redacción con IA y descarga del PDF**

![Pantalla del informe técnico](img/Informe.png)

**Verificación del archivo: un PNG renombrado a `.csv` se rechaza por su contenido, no por su extensión**

![Mensaje de rechazo al subir una imagen renombrada como CSV](img/Archivo-rechazado.png)

**Informe técnico generado**

[Ver el informe de ejemplo en PDF](examples/informe-ejemplo.pdf) (29 páginas: resumen ejecutivo, 6 incidentes, hallazgos con evidencia, plan de acción y recomendaciones). El nombre del cliente es ficticio.

## Instalación y ejecución (Ubuntu 24.04)

**Requiere Python 3.12 o superior** (Ubuntu 24.04 ya lo trae). En Ubuntu 22.04 la versión del sistema es 3.10 y la instalación falla; mira *Si algo falla*.

```bash
# 1. Dependencias del sistema
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git make

# 2. Clonar el repositorio
git clone https://github.com/braianffernandez096-bripto/soc-incident-analyzer.git
cd soc-incident-analyzer

# 3. Entorno virtual e instalación
python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock      # versiones exactas, verificadas por hash

# 4. (Opcional) claves: Anthropic para la redacción con IA (de pago); VirusTotal y AbuseIPDB para reputación
cp .env.example .env
nano .env                       # ANTHROPIC_API_KEY=...  VT_API_KEY=...  ABUSEIPDB_API_KEY=...

# 5. Iniciar la aplicación
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Abre http://127.0.0.1:8000, sube el export del SIEM (puedes usar cualquiera de los de `sample_data/`, o pulsar **Probar con datos de ejemplo** para verlo sin buscar ningún archivo), revisa el análisis y descarga el informe en la pestaña **Informe**. Si no definiste la clave en `.env`, puedes pegarla ahí; solo se usa durante esa sesión.

En Windows, la activación del entorno es `.venv\Scripts\activate`.

### Con Docker

Si prefieres no instalar Python, con Docker y Docker Compose alcanza:

```bash
git clone https://github.com/braianffernandez096-bripto/soc-incident-analyzer.git
cd soc-incident-analyzer
cp .env.example .env            # opcional: tus claves (Anthropic, VirusTotal, AbuseIPDB)
docker compose up --build
```

Abre http://127.0.0.1:8000. El puerto queda publicado solo en tu equipo (`127.0.0.1`) porque la app no tiene login. La imagen corre con un usuario sin privilegios y no incluye tu `.env`: las claves se pasan como variables de entorno.

## Análisis de correos (phishing)

En la pestaña **Phishing** (disponible desde el inicio, sin cargar logs) sube uno o varios `.eml`, o pulsa **Probar con correos de ejemplo** (`sample_data/correos/`: 8 maliciosos, entre ellos 4 con homógrafos, y 2 legítimos que no deben alertar). Para obtener un `.eml`: en Outlook, Thunderbird o Gmail guarda el correo como `.eml` o usa «Descargar mensaje». Los `.msg` no se admiten.

- **Ataques homógrafos.** Detecta direcciones y dominios que se ven iguales a otros pero no lo son: la «a» cirílica (U+0430) en lugar de la «a» latina (U+0061), la «I» mayúscula en lugar de la «l» minúscula (`banco.universaI@…` contra `banco.universal@…`), cifras por letras (`0`/`o`, `1`/`l`), `rn` por `m` y caracteres invisibles. Para cada remitente muestra el **desglose carácter por carácter** (código Unicode, nombre y alfabeto, con el carácter sospechoso resaltado), también en el PDF. Si escribes el **remitente esperado** al subir el correo, compara carácter por carácter y dice exactamente qué letra cambió. También compara el remitente con el Reply-To, el Return-Path, la dirección escrita en el nombre visible y el dominio del destinatario, y revisa los dominios de los enlaces (también los escritos en `xn--`). Los nombres con tilde (`josé@empresa.com`) o escritos por completo en otro alfabeto no alertan.
- **Seguro por diseño.** El archivo se lee solo como texto: no se renderiza el HTML, no se abre ningún enlace y no se extrae ni se ejecuta ningún adjunto (de un ZIP solo se lee la lista de nombres). Las URL se muestran «defangeadas» (`hxxps://sitio[.]com`) para que no sean enlaces activos.
- **Determinista.** Cada señal tiene un peso fijo y la criticidad sale de la suma; no interviene la IA. Los casos negativos (correo legítimo, enlaces oficiales, PDF real, SPF/DKIM/DMARC alineados) tienen pruebas propias.
- **Qué verificar.** Cada correo trae los pasos de un analista L1 (confirmar con el remitente por otro canal, buscar clics en el proxy y el DNS, detonar el adjunto en una sandbox, buscar el mismo correo en otros buzones) y las acciones de contención.
- **Reputación opcional.** Con tus claves de VirusTotal y AbuseIPDB y tu confirmación, se consultan dominios, IP y el **hash SHA-256** de los adjuntos. Nunca se envían el archivo, el correo, las direcciones de correo ni las URL completas.
- **Informe.** Se descarga un PDF propio del análisis de correos. El análisis de correos y el de logs son independientes: al analizar un archivo de logs no aparece la pestaña Phishing, y al analizar correos no se mezclan con los logs. Para cambiar de uno a otro usa «Cargar otro».
- **Límites.** Las cabeceras SPF/DKIM/DMARC las escribe el servidor que recibió el correo: si el `.eml` viene de otra fuente pueden estar ausentes o ser falsas. Los pesos son orientativos y el veredicto es una ayuda para el triage, no una prueba. Sin una dirección de referencia (la que escribes como «remitente esperado» u otra del mismo correo) la app no puede saber cuál es la legítima: el desglose está para que la compares tú con el contacto real. La tabla de caracteres confundibles es curada (los casos prácticos), no la base completa de Unicode.

## Reputación de IP y dominios (VirusTotal y AbuseIPDB)

Opcional. En la pestaña **Indicadores (IoC)**, el botón **Consultar reputación** enriquece los indicadores externos con VirusTotal (cuántos motores los marcan como maliciosos) y AbuseIPDB (puntaje de confianza de abuso y reportes de los últimos 90 días). El resultado aparece en la tabla de IoC y en una sección del informe PDF.

- **Tú decides qué sale.** Antes de consultar, la app muestra la lista exacta de indicadores que se enviarán y los que se omiten, con el motivo. Solo viajan IP públicas y dominios; nunca IP internas, cuentas, equipos, comandos ni contenido de los logs.

- **Las IP de documentación (RFC 5737) no se consultan**, porque no tienen reputación real. El export de ejemplo usa solo esas, así que allí no hay nada que enviar; hay una casilla para incluirlas únicamente si quieres probar que tu clave funciona.

- **No cambia la criticidad.** La reputación es contexto para el analista; el motor de reglas sigue decidiendo.

- **Claves gratuitas:** crea una cuenta en [VirusTotal](https://www.virustotal.com) y otra en [AbuseIPDB](https://www.abuseipdb.com) y define `VT_API_KEY` y `ABUSEIPDB_API_KEY` en `.env`, o pégalas en la interfaz (solo se usan en esa consulta). Con una sola de las dos funciona igual (AbuseIPDB solo consulta IP; los dominios van solo a VirusTotal).

- **Límites del plan gratuito:** VirusTotal permite 4 consultas por minuto y 500 por día, así que la app consulta una cada ~15 s (25 indicadores como máximo por consulta, ~6 min). AbuseIPDB permite 1.000 por día. Si una clave es rechazada o se agota la cuota, esa consulta se detiene con un aviso.

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
python -m pytest                                           # 555 pruebas
python -m pytest --cov=backend --cov-report=term-missing   # con cobertura (95 %)
```

Atajos con `make` (Linux/macOS/WSL): `make install`, `make test`, `make test-cov`, `make lint`, `make audit` (bandit + pip-audit), `make start`, `make stop`, `make logs`. Con `make help` ves la lista completa.

- `tests/unit/`: motor de detección contra el Excel de ejemplo, límites del parser, formatos de entrada (CSV, TSV, JSON, NDJSON, codificaciones y zonas horarias), verificación de archivos (tipo real por contenido, macros, inyección de fórmulas) datos de MITRE ATT&CK (todas las técnicas que citan las reglas existen y siguen vigentes, matriz y capa de Navigator), análisis de correos (señales positivas y negativas, límites y casos hostiles), homógrafos (alfabetos mezclados, I/l, casos legítimos con tildes que no deben alertar) y captcha (respuesta solo en el servidor, un intento, caducidad, pase de un solo uso).

- `tests/integration/`: API con entradas hostiles (archivo falso, markup en celdas y portada, 413, 429, cabeceras), clave de acceso (401 en todas las rutas protegidas, fuerza bruta), capa de IA y consultas de reputación con servidores simulados (las pruebas no usan red ni claves) el botón de datos de ejemplo, el módulo de phishing (PDF, reputación y remitente esperado) y el captcha de imágenes y de rompecabezas.

- `tests/e2e/`: arranca el servidor real y recorre carga, análisis y PDF.

## Privacidad: qué datos salen de tu equipo

La app corre en tu equipo y no envía telemetría. Solo salen datos si tú activas una de estas dos funciones:

| Función | Qué se envía | A quién |
|---|---|---|
| **Redacción con IA** (botón en la pestaña Informe, requiere clave de Anthropic) | Por incidente y hallazgo: título, criticidad, métricas, explicación del motor y las **filas de evidencia** (`Log_ID`, fecha, equipo, usuario, IP de origen y destino, origen del log, descripción del evento y línea de comandos recortadas, resultado y severidad). También el resumen del conjunto (cantidad de eventos, ventana de tiempo, IP externas). **No** se envían el nombre del cliente ni del analista, ni el archivo completo. | Anthropic |
| **Reputación** (botón en Indicadores (IoC) o en Phishing, requiere clave de VirusTotal o AbuseIPDB) | Solo las IP públicas, dominios y, en phishing, el hash SHA-256 de los adjuntos, que ves y confirmas en pantalla. Nunca IP internas, cuentas, equipos ni comandos. | VirusTotal y AbuseIPDB |

Las filas de evidencia pueden contener nombres de usuario, equipos y direcciones IP reales. Antes de activar la IA, asegúrate de tener permiso para compartir esos datos con un tercero; sin la clave de Anthropic, el informe se genera por reglas y no sale nada.

## Seguridad

- Las claves (Anthropic, VirusTotal, AbuseIPDB) viven en `.env` (excluido de Git) o se pegan en la interfaz; nunca se guardan, se registran ni se devuelven al navegador.

- Todo dato del archivo se escapa antes de mostrarse y antes de entrar al PDF. La interfaz aplica una CSP estricta (`script-src 'self'`); los estilos en línea están permitidos porque la interfaz los usa, un riesgo aceptado que no permite ejecutar scripts.

- Límites: 25 MB de subida (lectura acotada), 300 MB descomprimidos, 100.000 filas y límite de peticiones por IP.
  
- **Verificación del archivo subido:** el tipo se decide por su contenido, no por la extensión (un ejecutable renombrado a `.xlsx` se rechaza). En los Excel se avisa de macros VBA, objetos incrustados, vínculos externos y conexiones de datos, y se rechazan los que traen declaraciones XML peligrosas o rutas internas sospechosas. También se avisa de celdas con inyección de fórmulas. La app **nunca ejecuta ni evalúa** el archivo, y esto es un primer filtro, no un antivirus: "sin avisos" no significa "archivo seguro".

- **Captcha opcional (`CAPTCHA=on`):** antes de analizar un archivo de logs o un `.eml`, la persona resuelve un captcha **local**: no usa servicios de terceros, no necesita internet ni claves. Hay dos tipos y el servidor sortea uno en cada desafío (`CAPTCHA_TYPE=imagenes`, `rompecabezas` o `aleatorio`, el valor por defecto). **Imágenes:** marcar las 3 de 6 que muestran la misma figura (dispositivos de red y animales, giradas y con color, fondo y ruido al azar). **Rompecabezas:** deslizar una pieza hasta el hueco de la imagen (ratón, dedo o flechas del teclado); se acepta con unos píxeles de tolerancia y se comprueba, de forma básica, que el arrastre sea un movimiento y no un salto. La respuesta solo vive en el servidor, cada desafío admite un intento y caduca, y cada análisis pide su propio captcha (el pase es de un solo uso y dura segundos; ver los resultados no depende de ningún tiempo). Está apagado por defecto (en tu VM no estorba) y no protege los datos de ejemplo. Frena bots genéricos, no a un atacante dirigido: no sustituye a la clave de acceso. Las figuras son originales y se regeneran con `python scripts/build_captcha_assets.py`.
- **Clave de acceso opcional:** define `APP_ACCESS_TOKEN` (se recomiendan 16 caracteres o más) y toda la API exige `Authorization: Bearer <clave>`; la interfaz la pide al entrar. Es una sola clave compartida, no un sistema de usuarios, y debe servirse detrás de HTTPS. Sin ella, la app no tiene login: úsala en local.

- La documentación interactiva de la API (`/docs`) está desactivada por defecto (`ENABLE_DOCS=1` la activa).

- Docker: imagen multi-stage con dependencias verificadas por hash, usuario sin privilegios, sistema de archivos de solo lectura, sin capacidades (`cap_drop: ALL`) y `no-new-privileges`.

- Integración continua: pruebas con cobertura mínima, `bandit`, `pip-audit` y Trivy sobre la imagen.

- Alcance, límites y cómo reportar una vulnerabilidad: [SECURITY.md](SECURITY.md).

## Límites

- Si las marcas de tiempo no traen zona horaria, se usan tal cual; si la traen, se convierten a UTC.

- Los rangos 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 (documentación) se tratan como externos.

- El mapeo MITRE ATT&CK es orientativo: indica técnicas consistentes con la evidencia, no prueba su uso, y no cambia la criticidad. La reputación de IP es opcional y orientativa; no hay geolocalización propia.

- Los archivos de sesión viven en memoria (máx. 10) y se pierden al reiniciar el servidor.

## Estructura

```
backend/      parser, reglas de detección, correlación, análisis de correos (.eml) y de homógrafos, captcha local, IA, reputación (VirusTotal/AbuseIPDB), MITRE ATT&CK, informe PDF y API (FastAPI)
scripts/      build_attack_data.py regenera backend/data/ desde los datos oficiales de MITRE; build_captcha_assets.py regenera las figuras del captcha (uso de mantenimiento)
frontend/     interfaz web sin build (HTML, CSS y JS; fuentes IBM Plex locales)
sample_data/  exports de ejemplo (Windows en Excel/CSV/NDJSON, multi-fuente en JSON y SIEM de 500 eventos) y correos .eml de ejemplo
tests/        unit, integration y e2e
Makefile      atajos: install, start, stop, test, test-cov, lint, audit, logs, backup, clean
requirements*.lock  dependencias con versión exacta y hash (requirements*.txt son los rangos de origen)
SECURITY.md, CHANGELOG.md  política de seguridad y registro de cambios
examples/     informe técnico de ejemplo en PDF
img/          capturas del README
Dockerfile, docker-compose.yml y .github/workflows/tests.yml (imagen y pruebas automáticas)
```

## Licencia

MIT. Las fuentes IBM Plex conservan su licencia (`frontend/vendor/fonts/LICENSE-IBM-Plex.txt`).
