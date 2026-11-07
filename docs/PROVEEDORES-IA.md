# Proveedores de IA

La IA solo **redacta y recomienda**. El motor de reglas fija la criticidad, un verificador descarta los `Log_ID` y las IP que no existen en el archivo, y si el proveedor falla se mantiene el resultado por reglas. Eso vale igual para todos los proveedores.

| Proveedor | Clave | Modelo por defecto | Dónde van los datos |
|---|---|---|---|
| Claude (Anthropic) | `ANTHROPIC_API_KEY` o campo de la interfaz | `claude-sonnet-5-5` (`ANTHROPIC_MODEL`) | Anthropic |
| OpenAI | `OPENAI_API_KEY` o campo de la interfaz | `gpt-5.4-mini` (`OPENAI_MODEL`) | OpenAI |
| Gemini (Google) | `GEMINI_API_KEY` o campo de la interfaz | `gemini-3.8-flash` (`GEMINI_MODEL`) | Google |
| Ollama | sin clave | el que elijas entre los instalados | tu equipo (ver [IA-LOCAL.md](IA-LOCAL.md)) |

Los nombres de modelo cambian con frecuencia: los de la tabla son valores por defecto y sugerencias. Puedes escribir otro en el campo de modelo (letras, números, punto, guion y guion bajo) o fijarlo en `.env`. Si el proveedor responde «modelo no encontrado», revisa el nombre en su documentación.

## Qué se envía
Lo mismo que con Claude: filas de evidencia por incidente (usuarios, equipos e IP reales) y el resumen del conjunto; no se envía el nombre del cliente ni del analista ni el archivo completo. Consulta las condiciones de uso y retención de datos de cada proveedor antes de activarlo y confirma que tienes permiso para compartir esos datos. Ver [PRIVACIDAD.md](PRIVACIDAD.md).

## Seguridad de la integración
- Las direcciones (`api.openai.com`, `generativelanguage.googleapis.com`) están fijas en el código: el navegador no puede indicar otra URL.
- La clave viaja en una cabecera, se usa en esa consulta y no se guarda ni se registra; no vuelve al navegador. Con Gemini va en la cabecera `x-goog-api-key`, no en la URL.
- Los errores se traducen a mensajes propios por código HTTP (clave rechazada, modelo inexistente, cuota agotada…); no se repite el cuerpo de la respuesta, que a veces incluye parte de la clave.
- Se reintenta hasta 2 veces ante 429 y 5xx; el tiempo máximo por consulta es de 3 minutos.
- No hay dependencias nuevas (se usa `httpx`).

## Limitaciones
- Los adaptadores se probaron con servidores simulados que reproducen el formato documentado de cada API. Pruébalos con tu clave antes de depender de ellos.
- Un modelo pequeño o económico puede redactar peor o recomendar peor en el triaje; la comprobación de evidencia y la protección de incidentes graves siguen activas.
