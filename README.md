# SOC Incident Analyzer

![Python](https://img.shields.io/badge/python-3.12-blue) ![Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen) ![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

Aplicación web para el reto final del Bootcamp Analista SOC Nivel 2. Recibe el Excel exportado de un SIEM, detecta indicadores de compromiso, correlaciona los eventos en incidentes, clasifica la criticidad (Crítico / Alto / Medio / Bajo) y genera el informe técnico en PDF.

## Cómo funciona

1. **Motor de reglas determinista** (`backend/detection.py`): fuerza bruta y password spraying, inicios de sesión externos, escalamiento de privilegios, comandos y procesos sospechosos, movimiento lateral, acceso masivo a archivos, exfiltración, persistencia, ataques web y problemas de calidad de datos. Cada hallazgo cita los `Log_ID` que lo sustentan y explica por qué tiene esa criticidad.
2. **Correlación**: los hallazgos se agrupan en incidentes cuando comparten IP externa o cuenta de actor. Compartir host o recurso no fusiona incidentes; queda como hipótesis de confianza baja.
3. **IA (Claude)** (`backend/ai.py`): redacta la narrativa, la explicación técnica, el impacto y el plan de acción de cada incidente a partir de los hallazgos ya detectados. No puede cambiar la criticidad. Un verificador descarta cualquier `Log_ID` o IP que no exista en el Excel. Sin API key, o si la IA falla, el informe se genera con plantillas deterministas.
4. **PDF** (`backend/report.py`): resumen ejecutivo, hallazgos, evidencia, criticidad y justificación, impacto, plan de acción (investigar, contener, remediar) y recomendaciones generales.

## Resultado con el Excel de ejemplo

`sample_data/SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx` (715 eventos, ~6 h) produce **25 hallazgos** agrupados en **6 incidentes**:

| ID | Incidente | Criticidad |
|---|---|---|
| INC-001 | Password spraying con compromiso de la cuenta `mgarcia` | Alto |
| INC-002 | Compromiso de `admin` por acceso externo, movimiento lateral y exfiltración | Crítico |
| INC-003 | Recolección masiva y borrado de shadow copies por `backupsvc` | Crítico |
| INC-004 | Exfiltración de datos desde WS-018 (`rrojas`) | Crítico |
| INC-005 | Persistencia en APP-SRV01 por la cuenta `helpdesk` | Alto |
| INC-006 | Ataque web contra WEB-01 con ejecución remota de comandos | Crítico |

Las IP y los datos del ejemplo son sintéticos (rangos de documentación RFC 5737).

## Instalación y ejecución (Ubuntu 24.04)

```bash
# 1. Dependencias del sistema
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git

# 2. Clonar el repositorio
git clone https://github.com/TU_USUARIO/soc-incident-analyzer.git
cd soc-incident-analyzer

# 3. Entorno virtual e instalación
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. (Opcional) clave de Anthropic para el análisis con IA
cp .env.example .env
nano .env                       # ANTHROPIC_API_KEY=...

# 5. Iniciar la aplicación
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Abre http://127.0.0.1:8000, sube el Excel exportado del SIEM (puedes usar el de `sample_data/`), revisa el análisis y descarga el informe en la pestaña **Informe**. Si no definiste la clave en `.env`, puedes pegarla ahí; solo se usa durante esa sesión.

En Windows, la activación del entorno es `.venv\Scripts\activate`.

## Pruebas

```bash
python -m pytest                                           # 47 pruebas
python -m pytest --cov=backend --cov-report=term-missing   # con cobertura (93 %)
```

- `tests/unit/`: motor de detección contra el Excel de ejemplo y límites del parser.
- `tests/integration/`: API con entradas hostiles (archivo falso, markup en celdas y portada, 413, 429, cabeceras) y capa de IA con un servidor simulado.
- `tests/e2e/`: arranca el servidor real y recorre carga, análisis y PDF.

## Seguridad

- La clave de Anthropic vive en `.env` (excluido de Git) o se pega en la interfaz; nunca se guarda ni se registra.
- Todo dato del Excel se escapa antes de mostrarse y antes de entrar al PDF. La interfaz aplica una CSP estricta (`script-src 'self'`).
- Límites: 25 MB de subida (lectura acotada), 300 MB descomprimidos, 100.000 filas y límite de peticiones por IP.
- La app no tiene login: úsala en local. Si la expones en red, ponla detrás de un proxy con autenticación.

## Límites

- Las marcas de tiempo del export no traen zona horaria; se usan tal cual.
- Los rangos 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 (documentación) se tratan como externos.
- El mapeo MITRE ATT&CK es orientativo. No hay reputación de IP ni geolocalización.
- Los archivos de sesión viven en memoria (máx. 10) y se pierden al reiniciar el servidor.

## Estructura

```
backend/      parser, reglas de detección, correlación, IA, informe PDF y API (FastAPI)
frontend/     interfaz web sin build (HTML, CSS y JS; fuentes IBM Plex locales)
sample_data/  Excel de ejemplo
tests/        unit, integration y e2e
```

## Licencia

MIT. Las fuentes IBM Plex conservan su licencia (`frontend/vendor/fonts/LICENSE-IBM-Plex.txt`).
