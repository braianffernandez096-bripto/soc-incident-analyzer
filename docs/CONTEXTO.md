# Contexto de amenazas: CISA KEV, EPSS y tu MISP

Todo es **opcional y está apagado por defecto**. Sin configurar nada, el analizador se comporta exactamente igual que antes.

| Fuente | Qué aporta | Qué sale de tu red |
|---|---|---|
| **CISA KEV** | Si un CVE está siendo **explotado en ataques reales** (y si se usó en ransomware). | Nada: se descarga el catálogo completo y se cruza en local. |
| **EPSS** (FIRST) | Probabilidad estimada (0–100 %) de que un CVE se explote en los próximos 30 días. | Nada: igual, archivo completo y cruce local. |
| **Tu MISP** | Si una IP o un hash de los eventos figura como indicador en tu plataforma. | Solo la consulta a la URL de **tu** MISP. |

La criticidad la sigue fijando el motor de reglas con umbrales explícitos; la IA no la cambia. KEV/EPSS son contexto para **priorizar**, no un reemplazo de CVSS: un CVE que no está en KEV no es «seguro».

## 1. CISA KEV + EPSS

En el `.env` del servidor:

```
CONTEXT_ENABLED=on
```

Reinicia el contenedor. La primera vez descarga dos archivos públicos (KEV ≈ 1 MB, EPSS ≈ 5 MB comprimido) en segundo plano y los refresca cada 24 h (`CONTEXT_REFRESH_HOURS`). Si la descarga falla se sigue usando la copia anterior; sin datos, la regla simplemente no dispara.

Para comprobar la descarga y el formato desde tu red:

```
sudo docker exec soc-incident-analyzer-analyzer-1 python -m backend.context --refresh
```

Debe mostrar `kev: ok (… registros)` y `epss: ok (… registros)`, y una línea con CVE-2021-44228 (Log4Shell). Estado: `GET /api/context/status`.

### Cómo decide

| Situación | Severidad |
|---|---|
| CVE en KEV con uso conocido en ransomware | Crítico |
| CVE en KEV | Alto |
| Sin KEV, EPSS ≥ 70 % | Alto |
| Sin KEV, EPSS ≥ 10 % | Medio |
| Resto, o vulnerabilidad ya corregida (`Solved`) | sin hallazgo |

Funciona con cualquier log que mencione un CVE. Con Wazuh, el módulo de detección de vulnerabilidades genera alertas con el CVE, el paquete y el estado; llegan al analizador si su nivel alcanza el `<level>` de la integración (ver [WAZUH.md](WAZUH.md)). Los hallazgos Alto o Crítico se avisan por Telegram como cualquier otro.

## 2. Tu MISP

En el `.env` (la clave **solo** aquí; nunca en el chat ni en GitHub):

```
MISP_URL=https://IP-DE-TU-MISP
MISP_KEY=clave-de-api-de-un-usuario-de-lectura
MISP_VERIFY=0        # solo si el certificado es autofirmado (laboratorio)
```

El contenedor del analizador debe poder alcanzar esa URL (si MISP está en otra VM, usa su IP, no `localhost`). Reinicia el contenedor.

Qué se consulta: IP de origen y destino y hashes (MD5/SHA-1/SHA-256) que aparecen en los eventos, hasta 50 valores por análisis. Se omiten IP privadas y de loopback salvo `MISP_INCLUDE_PRIVATE=1`; los rangos de documentación (por ejemplo `203.0.113.x`) sí se consultan, para poder probar con un indicador de demostración. Se pide a MISP que descarte valores de sus listas de advertencia (`enforceWarninglist`) y, por defecto, solo atributos marcados `to_ids` (`MISP_ONLY_IDS=0` los incluye todos).

Una coincidencia genera un hallazgo **Alto** que cita los eventos de MISP. Indica que el dato fue reportado como malicioso; no prueba por sí sola que un equipo esté comprometido.

### Probarlo

1. En MISP crea un evento y agrega el atributo `ip-dst` = `203.0.113.50` con «For Intrusion Detection System» marcado.
2. Genera actividad que mencione esa IP: por ejemplo, sube al analizador un CSV de eventos con `203.0.113.50` como destino o IP de origen, o usa la prueba de [WAZUH.md](WAZUH.md).
3. En el panel aparece «Indicador conocido en MISP: 203.0.113.50».

## Variables

| Variable | Por defecto | Descripción |
|---|---|---|
| `CONTEXT_ENABLED` | apagado | Activa KEV + EPSS. |
| `CONTEXT_DIR` | `/tmp/context` (compose) | Dónde se guardan los archivos descargados. |
| `CONTEXT_REFRESH_HOURS` | 24 | Cada cuánto se vuelven a descargar. |
| `CONTEXT_KEV_URL` / `CONTEXT_EPSS_URL` | oficiales | Para apuntar a una copia propia. |
| `MISP_URL` / `MISP_KEY` | vacío | Activan la consulta a MISP. |
| `MISP_VERIFY` / `MISP_CA` | verificar | Certificado autofirmado o CA propia. |
| `MISP_ONLY_IDS` | 1 | Solo atributos `to_ids`. |
| `MISP_INCLUDE_PRIVATE` | 0 | Consultar también IP privadas. |

## Límites conocidos

- KEV y EPSS se cruzan por el texto del evento: si el log no menciona el CVE, no hay cruce.
- La coincidencia con MISP es exacta (el valor tal cual); los atributos compuestos (`ip|puerto`) no cuentan.
- Los avisos de vulnerabilidades dependen de lo que Wazuh alerte. En Wazuh 4.14 con la imagen Docker oficial el módulo de vulnerabilidades viene desactivado y no emitió alertas en las pruebas; para probar el cruce se envió una alerta con su formato (`data.vulnerability.cve`, `severity`, `status`, `package`) a `POST /api/wazuh/alerts`.
- Si usas un certificado autofirmado en MISP necesitas `MISP_VERIFY=0` (sin eso el analizador rechaza la conexión y, por diseño, el análisis sigue sin la consulta; el motivo queda en el registro como `misp_failed type=ConnectError`).
- La clave de MISP distingue mayúsculas y minúsculas: un solo carácter distinto da «Authentication failed».
