# Feed JSON propio de indicadores

Un archivo (o una URL) con **tus** indicadores —IP, dominios y hashes— que el analizador cruza **en local** con los eventos. Sirve para
listas que no están en MISP: lo que te pasó un colega, lo que anotaste en un incidente, una exportación de otra herramienta.
Apagado por defecto. Nada sale de tu red: el archivo se lee y se compara en el propio contenedor.

## Activarlo

1. Copia tu archivo a la carpeta `feed/` del repositorio (el compose la monta en solo lectura como `/feed`).
2. En el `.env`:
   ```
   FEED_PATH=/feed/indicadores.json
   FEED_TTL_DAYS=30
   ```
3. Recrea el contenedor (con los dos compose si usas Wazuh en vivo: `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --force-recreate`).
4. Comprueba con `GET /api/context/status`: el bloque `feed` indica cuántos indicadores hay y cuántos siguen vigentes.

Para un feed publicado en tu red, usa `FEED_URL=https://…` (se descarga en segundo plano cada `FEED_REFRESH_HOURS`; si falla se conserva la última copia buena).

## Formato

Una lista, o un objeto con `indicadores` (también se acepta `indicators`). Ejemplo completo: `sample_data/feed_ejemplo.json`.

| Campo | Alternativas aceptadas | Obligatorio | Qué es |
|---|---|---|---|
| `valor` | `value`, `indicator` | sí | IP, dominio o hash (MD5, SHA-1 o SHA-256) |
| `tipo` | `type` | no | `ip`, `dominio` o `hash`. Si se indica y no coincide con el valor, se ignora la entrada |
| `descripcion` | `description` | no | Se muestra en el hallazgo |
| `fuente` | `source` | no | De dónde salió |
| `fecha` | `added`, `first_seen`, `last_seen` | no | Desde cuándo es válido (`AAAA-MM-DD`) |
| `expira` | `expires`, `valid_until` | no | Fecha de vencimiento explícita |

## TTL: cuándo vence un indicador

Un indicador viejo da falsos positivos (las IP cambian de dueño). Por eso:

- Con `expira`, vence ese día.
- Sin `expira` pero con `fecha`, vence a los `FEED_TTL_DAYS` días de esa fecha (30 por defecto; `0` desactiva el vencimiento por tiempo).
- Sin ninguna fecha **nunca vence**: ponle fecha si quieres que caduque.
- Los vencidos no disparan; el hallazgo y «Límites del análisis» indican cuántos hay vigentes.

## Qué detecta

Regla `ctx_feed` (**Alto**): una IP de origen o destino, un hash o un dominio (incluidos sus subdominios) del evento que coincide con un indicador vigente.
El hallazgo muestra valor, tipo, fuente, fecha, vencimiento y descripción; el aviso de Telegram lo etiqueta «Feed».

## Variables

| Variable | Por defecto | Descripción |
|---|---|---|
| `FEED_PATH` | — | Archivo local (se recarga solo cuando cambia) |
| `FEED_URL` | — | URL `http(s)` alternativa |
| `FEED_TTL_DAYS` | 30 | Vencimiento por tiempo (0 a 3650) |
| `FEED_REFRESH_HOURS` | 6 | Cada cuánto se vuelve a descargar `FEED_URL` |
| `MISP_CACHE_SECONDS` | 600 | Cuánto se recuerda una respuesta de MISP (0 a 86400) |

## Límites

- Coincidencia exacta (con subdominios para dominios). No hay rangos CIDR ni comodines.
- Máximo 20 MB por archivo. Un archivo roto no reemplaza a la última copia buena.
- Es una pista para priorizar, no una confirmación: revisa el contexto antes de escalar.
