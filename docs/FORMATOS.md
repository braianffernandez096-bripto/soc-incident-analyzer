# Formatos de entrada y datos de ejemplo

Material que estaba en el README. Volver al [README](../README.md).

## Formatos de entrada

| Formato | Extensiones | Detalles |
|---|---|---|
| Excel | `.xlsx`, `.xlsm` | Usa la hoja con más filas; detecta la fila de cabecera aunque haya títulos encima. |
| CSV / TSV | `.csv`, `.tsv`, `.txt`, `.log` | Detecta el separador (`,` `;` tab `\|`) y la codificación (UTF-8, UTF-16, Windows-1252). |
| JSON | `.json` | Arreglo de eventos, contenedores como `{"events": [...]}` (o cualquier otro nombre: se elige la lista que tiene fecha) y respuestas de Elasticsearch/OpenSearch (`hits.hits[]._source`). |
| NDJSON | `.jsonl`, `.ndjson` | Un evento por línea; también el formato de exportación de Splunk (`{"result": {...}}`). |
| auth.log / secure | `.log`, `.txt` | Syslog de Linux en texto (fecha clásica o ISO). Se leen los eventos de `sshd` (contraseña o clave aceptada/fallida) y de `sudo`; el resto de líneas se ignora y se avisa cuántas. Ejemplo: `sample_data/auth_log_ejemplo.txt`. Si el archivo no tiene extensión, agrégale `.log`. |

- **Columnas:** se reconocen por nombre aunque cambien mayúsculas, acentos o idioma (`Descripción`, `hostname`, `Equipo`…) y los campos anidados típicos de Elastic ECS / Winlogbeat (`@timestamp`, `host.name`, `winlog.event_id`, `source.ip`, `user.name`, `process.command_line`…). Solo son indispensables `Timestamp` y `Event_ID`; lo que falte queda vacío y se informa. Si el archivo no trae `Event_ID` pero sí `action` (o `event_type`), se usa como código de evento, y `category` pasa a ser la fuente del log.

- **Marcas de tiempo:** si traen zona horaria (`Z`, `+02:00`) o son epoch (segundos, milisegundos…), se convierten a UTC y el informe lo declara. Si no la traen, se usan tal cual.

- **Log_ID:** si no existe, se generan identificadores `ROW-00001…` estables.

- Un `.txt` o `.log` que contenga JSON se detecta por su contenido. Si un JSON se guardó línea por línea en una hoja de cálculo (`.csv` o `.xlsx`), se reconstruye; si le faltan líneas sueltas se lee lo que haya y se avisa.

## Datos de ejemplo

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
