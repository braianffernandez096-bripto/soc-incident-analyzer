# Solución de problemas

Volver al [README](../README.md). Los comandos usan el nombre de contenedor `soc-incident-analyzer-analyzer-1`; puede cambiar con el nombre de tu carpeta (`docker ps`).

## No puedo abrir la aplicación

El contenedor publica el puerto solo en `127.0.0.1:8000` del servidor. Si lo abres desde otra máquina, hace falta un túnel SSH:

```
ssh -L 8000:127.0.0.1:8000 usuario@IP-DEL-SERVIDOR
```
y abrir `http://localhost:8000`. Primero comprueba que el contenedor está sano: `docker ps` debe decir `(healthy)`; si no, `docker logs --tail 30 soc-incident-analyzer-analyzer-1`.

## Wazuh: no llegan alertas

| Síntoma | Causa y solución |
|---|---|
| En los registros del analizador solo hay `GET /api/health` y ningún `POST /api/wazuh/alerts` | El contenedor salió de la red de Wazuh (pasa al recrearlo con `docker compose up -d` a secas). Comprueba: `docker inspect soc-incident-analyzer-analyzer-1 --format "{{json .NetworkSettings.Networks}}"` debe incluir `single-node_default`. Arreglo: `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --force-recreate`. |
| El manager no dice `Enabling integration for: 'custom-soc-analyzer'` | Permisos incorrectos (`root:wazuh` y `750`) o `ossec.conf` editado fuera del contenedor. Ver [WAZUH.md](WAZUH.md). |
| `401` al enviar | `api_key` de la integración distinta de `WAZUH_INGEST_TOKEN`. |
| `404` al enviar | `WAZUH_INGEST` no está en `on` o el token tiene menos de 16 caracteres (el endpoint queda cerrado). |
| Llegan alertas pero no hay hallazgo de fuerza bruta | El `<level>` es demasiado alto: con 7 o más solo llega la alerta agregada. Usa 5 (o 3). |
| El agente de Windows figura `Disconnected` (por ejemplo tras reiniciar la VM) | En esa máquina, PowerShell como administrador: `Restart-Service WazuhSvc`. Comprueba con `agent_control -l` en el manager. |

## Telegram: no llega el aviso

- Comprueba `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID` en el `.env` y que el contenedor los recibió (`docker exec … env | grep -c TELEGRAM`).
- Los hallazgos Crítico y Alto avisan al instante; Medio y Bajo, en un resumen horario.
- Un hallazgo ya avisado no se repite salvo que **suba de severidad**.
- Espera hasta un minuto: el análisis automático corre cada 60 segundos si hay alertas nuevas.

## MISP

| Síntoma | Causa y solución |
|---|---|
| `Authentication failed … API enabled user` (HTTP 403) | La clave está mal copiada (distingue mayúsculas; revisa `l`/`I`/`1`, `O`/`0`) o el rol no tiene *Auth key access*. Compara `grep ^MISP_KEY .env` con la clave original. |
| `CERTIFICATE_VERIFY_FAILED … self-signed certificate` | Certificado autofirmado: agrega `MISP_VERIFY=0` (o `MISP_CA` con tu CA) y recrea el contenedor. |
| `KeyError: 'MISP_URL'` | La variable no llegó al contenedor: falta en el `.env` o el contenedor no se recreó con la versión nueva (`git pull` y `docker compose up -d --build`). |
| No aparece el usuario en el selector de *Add authentication key* | Crea la clave desde la cuenta del propio usuario (*My profile* → *Auth keys*). |
| No hay hallazgo aunque el indicador existe | Prueba la consulta sin filtros: `docker exec … python -c "import os,httpx;h={'Authorization':os.environ['MISP_KEY'],'Accept':'application/json'};u=os.environ['MISP_URL']+'/attributes/restSearch';f=lambda b:len(httpx.post(u,json={**b,'returnFormat':'json','value':'203.0.113.50'},headers=h,verify=False).json().get('response',{}).get('Attribute',[]));print('sin filtros',f({}),'solo to_ids',f({'to_ids':1}),'to_ids+warninglist',f({'to_ids':1,'enforceWarninglist':True}))"`. `0` sin filtros: el evento no está guardado o es de otra organización. `0` solo con `to_ids`: falta marcar «For Intrusion Detection System». `0` solo con la lista de advertencia: MISP descarta ese valor (por ejemplo, rangos de documentación); usa una IP que no esté en esas listas. |

Guía completa: [MISP.md](MISP.md).

## KEV y EPSS

| Síntoma | Causa y solución |
|---|---|
| `python -m backend.context --refresh` da `error` | El contenedor no sale a Internet (proxy o firewall) o las URL cambiaron (`CONTEXT_KEV_URL`, `CONTEXT_EPSS_URL`). Mientras tanto se usa la copia anterior, si existe. |
| No hay hallazgo de CVE | El texto del evento debe mencionar el CVE; el CVE debe estar en KEV o tener EPSS ≥ 10 %; y no debe figurar como corregido (`Solved`). Prueba con [`ejemplo_cve.csv`](../sample_data/ejemplo_cve.csv). |
| El contexto se ve vacío tras reiniciar | La caché vive en `/tmp/context` (sin persistencia): se vuelve a descargar sola en segundo plano; fuerza la descarga con el comando de arriba. |
| Wazuh no genera alertas de vulnerabilidades | En la imagen Docker oficial de Wazuh 4.14 el módulo viene desactivado (`<vulnerability-detection><enabled>no`) y no emitió alertas en las pruebas. El cruce se prueba con `ejemplo_cve.csv` o enviando una alerta con el formato de Wazuh. |

## Probar con los archivos de ejemplo

- [`sample_data/ejemplo_cve.csv`](../sample_data/ejemplo_cve.csv): Log4Shell en dos equipos (con KEV activo: **Crítico**), PAN-OS y una fila ya corregida (no genera hallazgo).
- [`sample_data/ejemplo_misp.csv`](../sample_data/ejemplo_misp.csv): conexiones a `203.0.113.50`; requiere cargar ese indicador en tu MISP ([MISP.md](MISP.md), paso 7).

## Feed propio

| Síntoma | Causa y solución |
|---|---|
| `feed` en `/api/context/status` sin indicadores | `FEED_PATH` debe apuntar dentro de `/feed` y el archivo estar en `./feed/`; recrea el contenedor tras editar el `.env`. |
| Un indicador no dispara | Puede haber vencido (`expira` o `fecha` + `FEED_TTL_DAYS`) o su `tipo` no coincide con el valor. |

## Contexto desde el Indexer

| Síntoma | Causa y solución |
|---|---|
| No aparece el botón «Ver contexto en Wazuh» | Falta `WAZUH_INDEXER_URL`, `_USER` o `_PASSWORD`, o la URL no empieza con `http(s)://`. |
| «El Indexer rechazó la clave» | Usuario o contraseña distintos (se distinguen mayúsculas); revisa el `.env`. |
| «No se pudo conectar» | El contenedor no está en la red de Wazuh (recrea con los dos compose) o el certificado es autofirmado y falta `WAZUH_INDEXER_VERIFY=0`. |
| Solo salen alertas, ningún evento crudo | Hace falta `<logall_json>yes</logall_json>` **y** `archives: enabled: true` en Filebeat (ver `docs/WAZUH.md`); con `curl …/wazuh-archives-*/_count` en `0` falta el segundo. |
| Los eventos crudos no son los del hallazgo | Se muestran solo los que no generaron alerta, en ±90 s y los más relacionados primero; ajusta `WAZUH_INDEXER_RAW_WINDOW_SEC` y `WAZUH_INDEXER_RAW_MAX`. |

