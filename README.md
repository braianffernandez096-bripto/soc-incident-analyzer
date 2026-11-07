# SOC Incident Analyzer

![Python](https://img.shields.io/badge/python-3.12-blue) [![Tests](https://github.com/braianffernandez096-bripto/soc-incident-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/braianffernandez096-bripto/soc-incident-analyzer/actions/workflows/tests.yml) [![Cobertura](https://codecov.io/gh/braianffernandez096-bripto/soc-incident-analyzer/branch/main/graph/badge.svg)](https://codecov.io/gh/braianffernandez096-bripto/soc-incident-analyzer) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

Aplicación web para análisis de logs. Recibe el export de un SIEM (Excel, CSV/TSV o JSON/NDJSON), detecta indicadores de compromiso, correlaciona los eventos en incidentes, clasifica la criticidad (Crítico / Alto / Medio / Bajo) y genera el informe técnico en PDF.

## Qué problema resuelve y para quién

Un SIEM entrega miles de eventos y el analista tiene que decidir cuáles importan, cómo se relacionan y qué hacer primero.
Esta herramienta toma el export de un SIEM (Excel, CSV o JSON) y lo convierte en incidentes ordenados por criticidad, cada uno con las evidencias que lo sustentan.
Cada hallazgo se mapea a MITRE ATT&CK y trae un plan de acción (investigar, contener, remediar) y un informe técnico en PDF.

Está pensada para analistas SOC y estudiantes que practican triage, y para quien quiera ver cómo se correlacionan los eventos sin montar un SIEM completo.
El análisis, los incidentes, MITRE ATT&CK y el informe en PDF funcionan sin Internet y sin costo, porque las reglas son deterministas y el informe usa plantillas. La redacción con IA es opcional: puedes usar tu propia clave de API de Anthropic, OpenAI o Gemini (servicios de pago por uso) o un modelo local con Ollama, sin costo y sin enviar datos a terceros. Solo mejora la redacción, nunca cambia la criticidad.

## Cómo se desarrolló

Proyecto personal, hecho para practicar el análisis de incidentes. Lo desarrollé con ayuda de un asistente de IA (Claude, de Anthropic): yo definí qué debía detectar y cómo, revisé cada cambio, probé la aplicación con logs propios y decidí qué entra en el repositorio; el asistente escribió gran parte del código y de las pruebas. Por eso las decisiones de seguridad (la IA no puede cambiar la criticidad, los datos se tratan como no confiables) están cubiertas por pruebas automáticas y el historial de cambios está en el [CHANGELOG](CHANGELOG.md).

## Cómo funciona

1. **Motor de reglas determinista** (`backend/detection.py`, `detection_generic.py`): fuerza bruta y password spraying, movimiento lateral, escalamiento de privilegios, persistencia, LSASS, DCSync, Kerberoasting, exfiltración, evasión de defensas, ataques web y más; para Windows (por Event ID) y para otras fuentes (SSH, web, DNS, cloud).

2. Cada hallazgo cita los `Log_ID` que lo sustentan y explica por qué tiene esa criticidad.

3. **Correlación**: los hallazgos se agrupan en incidentes cuando comparten IP externa o cuenta de actor.

4. **IA (Claude, OpenAI, Gemini u Ollama local)** (`backend/ai.py`, `backend/ai_cloud.py`, `backend/ai_local.py`, opcional): solo redacta; no puede cambiar la criticidad y un verificador descarta lo inventado. Se elige el proveedor en la pestaña Informe. Sin clave ni Ollama, el informe usa plantillas.

5. **PDF** (`backend/report.py`): resumen ejecutivo, hallazgos, evidencia, impacto, plan de acción y recomendaciones.
6. **Informe HTML** (`backend/report_html.py`): el mismo contenido en un solo archivo que se abre sin conexión, con gráficos y animaciones (ver [Informe HTML](#informe-html)).

6. **Reputación (opcional)** (`backend/intel.py`): VirusTotal y AbuseIPDB, solo con tu confirmación. Ver [más abajo](#reputación-de-ip-y-dominios-virustotal-y-abuseipdb) y [docs/REPUTACION.md](docs/REPUTACION.md).

7. **MITRE ATT&CK** (`backend/attack.py`): técnicas con nombre oficial, matriz por táctica y capa para ATT&CK Navigator. Sin Internet.

8. **Consultas para tu SIEM** (`backend/siemqueries.py`): Splunk (SPL), Sentinel (KQL) y reglas Sigma para los hallazgos de Windows; para SSH, web, DNS, Linux y nube, reglas Sigma.

9. **Phishing** (`backend/phishing.py`): análisis estático de `.eml` (remitente, SPF/DKIM/DMARC, enlaces, homógrafos, adjuntos, ClickFix) con veredicto y puntaje.

10. **Verificar el remitente en DNS** (opcional): comprueba SPF, clave DKIM y política DMARC con el DNS de hoy y lo compara con las cabeceras.

Detalle de cada punto en [docs/DESARROLLO.md](docs/DESARROLLO.md#cómo-funciona-detalle).

## Formatos de entrada

Acepta Excel (`.xlsx`, `.xlsm`), CSV/TSV, JSON, NDJSON (también el formato de Splunk y las respuestas de Elasticsearch/OpenSearch) y `auth.log` de Linux en texto. Reconoce las columnas por nombre aunque cambie el idioma o el esquema (incluido Elastic ECS), y solo exige `Timestamp` y `Event_ID`. Tabla de formatos, columnas, marcas de tiempo y cada ejemplo de `sample_data/`: [docs/FORMATOS.md](docs/FORMATOS.md).

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

Las IP y los datos del ejemplo son sintéticos (rangos de documentación RFC 5737). Hay otros ejemplos con distintas fuentes (SSH, web, DNS, nube, correo) en [docs/FORMATOS.md](docs/FORMATOS.md#datos-de-ejemplo).

## Demostración

**Análisis de logs: del export del SIEM al panel, los incidentes, los hallazgos y el informe**

![Recorrido por el análisis de logs: panel, incidentes, hallazgos, eventos, indicadores e informe](img/gif/logs-demo.gif)

**Phishing: análisis de correos de ejemplo, detalle con homógrafos y descarga del informe**

![Recorrido por el análisis de phishing: carga, tabla de correos, detalle del correo y desglose de caracteres](img/gif/phishing-demo.gif)

**Evaluar dominio: nota de A a F con lo que resta cada comprobación (SPF, DKIM y DMARC)**

![Evaluación de un dominio con su nota y la tabla de comprobaciones](img/gif/dominio-demo.gif)

**Dominios parecidos: variantes de typosquatting y comprobación de cuáles están registradas**

![Generación de variantes de un dominio y comprobación de registro en el DNS](img/gif/parecidos-demo.gif)

<details>
<summary>Ver los informes PDF generados (logs y phishing)</summary>

![Informe técnico en PDF del análisis de logs](img/gif/informe-logs.gif)

![Informe en PDF del análisis de correos, con recorrido y puntaje](img/gif/informe-phishing.gif)

</details>

## Capturas

**Panel: resumen e incidentes detectados**

![Panel con las tarjetas de incidentes y la línea de tiempo](img/Dashboard.png)

Galería completa (incidentes, hallazgos, ATT&CK, eventos, IoC, informe, análisis de correos y captcha): [docs/CAPTURAS.md](docs/CAPTURAS.md). Informe técnico de ejemplo: [ver el PDF](examples/informe-ejemplo.pdf) (29 páginas; el nombre del cliente es ficticio).

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

# 4. (Opcional) claves: Anthropic para la redacción con IA (de pago); VirusTotal y AbuseIPDB para reputación. Para IA local sin clave, instala Ollama y un modelo (ver [IA local](#ia-local-con-ollama-opcional))
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

En la pestaña **Phishing** (disponible desde el inicio, sin cargar logs) sube uno o varios `.eml`, o pulsa **Probar con correos de ejemplo** (`sample_data/correos/`: 8 maliciosos, entre ellos 4 con homógrafos, 1 con un recorrido anómalo y 2 legítimos que no deben alertar). Para obtener un `.eml`: en Outlook, Thunderbird o Gmail guarda el correo como `.eml` o usa «Descargar mensaje». Los `.msg` no se admiten. Si no puedes exportarlo, **pega las cabeceras** (el «origen del mensaje») en el cuadro de la pantalla de carga.

Es análisis estático y determinista: no se abre ningún enlace ni se ejecuta ningún adjunto, y las URL se muestran «defangeadas». Incluye ataques homógrafos con desglose carácter por carácter, remitente esperado, recorrido `Received`, puntaje con factores visibles, evaluación de dominio (SPF/DKIM/DMARC) y dominios parecidos. Todo el detalle, con sus límites, está en [docs/DESARROLLO.md](docs/DESARROLLO.md#análisis-de-correos-phishing-detalle).

## Triaje asistido por IA (opcional)

Cada incidente trae una recomendación (**Escalar**, **Probable falso positivo** o **Falta información**) con motivos, confianza y «qué me haría cambiar de opinión»; el analista registra su decisión y una nota, que va al PDF. La severidad la fija siempre el motor y, si la IA quiere ser menos exigente en un incidente Crítico o Alto, se conserva la del motor y se marca el conflicto. Incluye un script para medir modelos. Detalle y límites: [docs/TRIAGE.md](docs/TRIAGE.md).

## Informe HTML

Junto al PDF, en la pestaña **Informe** está **Descargar informe HTML**: un único archivo que se abre con doble clic en cualquier navegador, sin conexión y sin instalar nada. Trae el mismo contenido que el PDF (resumen, incidentes con evidencia y plan de acción, IoC, reputación, triaje y decisiones del analista, correos sospechosos) más:

- gráficos SVG (criticidad, eventos por ventana de 10 minutos con cada criticidad) y animaciones con [anime.js](https://animejs.com/) 3.2.2 incluido dentro del archivo (sin CDN);
- diseño «glass» con modo claro y oscuro (sigue al sistema y se puede cambiar), adaptado al celular;
- incidentes y hallazgos desplegables, filtro de indicadores y versión imprimible (botón «Imprimir / PDF»: se abre todo y se quitan los efectos);
- las animaciones son opcionales: sin JavaScript o con «reducir movimiento» activado el informe se ve completo y quieto.

El análisis de **Phishing** tiene su propio **Descargar informe HTML** (junto al PDF, en Phishing → Correos): el mismo contenido que su PDF, con el mismo diseño y las mismas garantías de seguridad.

Seguridad: todo dato del archivo analizado, de la IA o de un correo se escapa al generar el HTML, y el propio informe lleva una política CSP que solo permite su script y su estilo (por hash) y ninguna conexión: aunque algo se escapara mal, el navegador no ejecutaría código. Como cualquier informe con datos del cliente, compártelo solo con quien corresponda.

## Otros proveedores de IA: OpenAI y Gemini (opcional)

Además de Claude, en las pestañas **Informe** e **Incidentes** puedes elegir **OpenAI** o **Gemini (Google)** con tu propia clave (`OPENAI_API_KEY`, `GEMINI_API_KEY` en `.env`, o pegada en el campo, que se usa solo en esa consulta y no se guarda). Las garantías son las mismas que con Claude: el motor fija la criticidad, el verificador descarta lo inventado y, si el proveedor falla, queda el informe por reglas. Las direcciones de los servicios están fijas en el servidor (el navegador no puede indicar otra URL) y los mensajes de error no repiten lo que responde el proveedor. Los nombres de modelo cambian seguido: hay uno por defecto y puedes escribir otro en el campo o fijarlo con `OPENAI_MODEL` / `GEMINI_MODEL`. Detalle en [docs/PROVEEDORES-IA.md](docs/PROVEEDORES-IA.md).

## IA local con Ollama (opcional)

Alternativa a Claude para quien no quiere pagar ni enviar datos a un tercero: en la pestaña **Informe** eliges **IA local (Ollama)** y uno de los modelos instalados (`ollama pull llama3.1:8b`). Mismas garantías que con Claude: la criticidad y la prioridad del plan de acción las fija el motor y el verificador descarta lo inventado. **Recomendación:** un modelo local pequeño (como llama3.1:8b) sirve como apoyo y para practicar, pero puede equivocarse al redactar y al recomendar el triaje; para el informe formal y el triaje con IA se aconseja un modelo de mayor calidad, como Claude (ver [docs/IA-LOCAL.md](docs/IA-LOCAL.md#cuándo-usar-cada-uno)). Sin GPU, un modelo de 8B tarda minutos por consulta. Configuración (`OLLAMA_HOST`, `OLLAMA_NUM_CTX`, `OLLAMA_TIMEOUT`), Docker y tiempos medidos: [docs/IA-LOCAL.md](docs/IA-LOCAL.md).

## Reputación de IP y dominios (VirusTotal y AbuseIPDB)

Opcional. El botón **Consultar reputación** enriquece los indicadores externos con VirusTotal y AbuseIPDB. Antes de consultar ves la lista exacta de lo que se enviará: solo IP públicas y dominios, nunca IP internas, cuentas ni contenido de los logs. No cambia la criticidad. Claves gratuitas, límites y detalle: [docs/REPUTACION.md](docs/REPUTACION.md).

## Si algo falla

Los mensajes de error más comunes (formato no soportado, cabecera no reconocida, archivo renombrado, límites de tamaño, claves rechazadas, Python anterior a 3.11, puerto ocupado) están con su causa y solución en [docs/DESARROLLO.md](docs/DESARROLLO.md#si-algo-falla). Si usas Ubuntu 22.04, necesitas Python 3.12: la tabla explica cómo instalarlo.

## Pruebas

```bash
pip install --require-hashes -r requirements-dev.lock      # pytest, cobertura, bandit y pip-audit
python -m pytest                                           # ~1.200 pruebas
python -m pytest --cov=backend --cov-report=term-missing   # con cobertura (95 %)
```

Atajos con `make` (Linux/macOS/WSL): `make install`, `make test`, `make test-cov`, `make lint`, `make audit` (bandit + pip-audit), `make start`, `make stop`, `make logs`. Con `make help` ves la lista completa.

Hay pruebas unitarias, de integración (API con entradas hostiles, capa de IA con modelo simulado, inyección de prompts) y de extremo a extremo con un navegador real (Playwright), además de casos de actividad normal que no deben alertar. Qué cubre cada archivo: [docs/DESARROLLO.md](docs/DESARROLLO.md#pruebas).

## Validación de las reglas

Las reglas se midieron con datos que no escribí yo. Método, resultados y límites en [docs/VALIDACION.md](docs/VALIDACION.md):

- **SSH real (Loghub):** de 11 IPs que atacaron con fuerza bruta, la app detectó las 11, sin falsos positivos.

- **107 ataques de Windows (OTRF Security-Datasets):** la técnica correcta en 41 (antes de calibrar: 13), otra técnica en 26 y ninguna en 37; la cobertura es limitada y está documentada.

- **Phishing real (12.864 correos de phishing_pot):** 86,4 % con criticidad Medio o más y 62,5 % Alto o más (86,3 % y 62,4 % en los 11.362 correos no usados para ajustar). Correo legítimo: 0 falsos positivos en 39 correos reales (muestra pequeña).

- **Tráfico normal:** 35 casos de actividad corriente sin hallazgos.

Se pueden repetir con `scripts/validar_datasets.py`.

## Privacidad: qué datos salen de tu equipo

La app corre en tu equipo y no envía telemetría. Solo salen datos si tú activas una de estas funciones:

| Función | Qué se envía | A quién |
|---|---|---|
| **Redacción con IA de Anthropic** (requiere clave) | Título, criticidad, métricas y filas de evidencia de cada hallazgo (puede incluir usuarios, equipos e IP reales); no el nombre del cliente ni el archivo completo | Anthropic |
| **Consulta DNS** (Evaluar dominio, Dominios parecidos) | Solo nombres de dominio, por DNS sobre HTTPS; `DNS_LOOKUPS=off` la desactiva | Cloudflare (si falla, Google) |
| **Reputación** (requiere clave) | Solo IP públicas, dominios y hash SHA-256 de adjuntos, que confirmas en pantalla | VirusTotal y AbuseIPDB |

Con **Ollama** en tu propio equipo los datos no salen de él. Antes de activar la IA de un proveedor externo (Anthropic, OpenAI o Google), asegúrate de tener permiso para compartir esos datos con un tercero. Detalle completo: [docs/PRIVACIDAD.md](docs/PRIVACIDAD.md).

## Seguridad

- Las claves (Anthropic, VirusTotal, AbuseIPDB) viven en `.env` (excluido de Git) o se pegan en la interfaz; nunca se guardan, se registran ni se devuelven al navegador.

- **Datos del archivo no confiables:** se escapan antes de mostrarse y de entrar al PDF, la CSP es estricta (`script-src 'self'`), el tipo del archivo se decide por su contenido y la app nunca ejecuta lo que sube el usuario.

- **Capa de IA:** los logs viajan como datos no confiables; aunque un modelo obedeciera una instrucción escondida, no puede cambiar la criticidad y lo inventado se descarta (lo comprueban pruebas automáticas).

- **Opcionales:** clave de acceso (`APP_ACCESS_TOKEN`), captcha local (`CAPTCHA=on`) y documentación de la API desactivada por defecto.

- **Contenedor y CI:** imagen sin privilegios, de solo lectura y con dependencias verificadas por hash; el CI corre pruebas, navegador, `bandit`, `pip-audit` y Trivy, y publica un SBOM (CycloneDX) de la imagen.

- Detalle: [docs/DESARROLLO.md](docs/DESARROLLO.md#seguridad-detalle). Alcance, límites y cómo reportar una vulnerabilidad: [SECURITY.md](SECURITY.md). Para colaborar: [CONTRIBUTING.md](CONTRIBUTING.md).

## Límites

- Si las marcas de tiempo no traen zona horaria, se usan tal cual; si la traen, se convierten a UTC.

- Los rangos 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 (documentación) se tratan como externos.

- El mapeo MITRE ATT&CK es orientativo: indica técnicas consistentes con la evidencia, no prueba su uso, y no cambia la criticidad. La reputación de IP es opcional y orientativa; no hay geolocalización propia.

- Los archivos de sesión viven en memoria (máx. 10) y se pierden al reiniciar el servidor.

## Estructura

```
backend/      parser, reglas de detección, correlación, phishing, IA, reputación, MITRE ATT&CK, informe PDF y API (FastAPI)
frontend/     interfaz web sin build (HTML, CSS y JS)
tests/        unit, integration y e2e
scripts/      validación con datasets públicos y regeneración de datos
sample_data/  exports y correos .eml de ejemplo
docs/         detalle: DESARROLLO, FORMATOS, CAPTURAS, IA-LOCAL, REPUTACION, PRIVACIDAD y VALIDACION
```

Árbol completo, con scripts y archivos de configuración: [docs/DESARROLLO.md](docs/DESARROLLO.md#estructura).

## Licencia

MIT. Las fuentes IBM Plex conservan su licencia (`frontend/vendor/fonts/LICENSE-IBM-Plex.txt`). anime.js 3.2.2 (MIT, © Julian Garnier) va incluido en el informe HTML y en el Panel: `backend/assets/ANIME-LICENSE.md` y `frontend/vendor/ANIME-LICENSE.md`.
