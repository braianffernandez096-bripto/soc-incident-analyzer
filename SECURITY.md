# Política de seguridad

## Cómo reportar una vulnerabilidad

Si encuentras un fallo de seguridad, **no abras un issue público**. Usa el reporte privado de GitHub:
pestaña **Security** del repositorio → **Report a vulnerability**.

Incluye, si puedes: qué hiciste, qué esperabas que pasara, qué pasó, la versión o el commit y, si hace falta, un archivo de prueba (sin datos reales de ningún cliente). Es un proyecto personal: intento responder en pocos días, sin plazos garantizados.

## Versiones con soporte

Solo la rama `main`.

## Qué protege la aplicación

| Riesgo | Cómo se mitiga |
|---|---|
| Archivos subidos hostiles | El tipo se decide por el contenido, no por la extensión. Se rechazan ejecutables y archivos renombrados, rutas internas sospechosas y declaraciones XML peligrosas. Se avisa de macros, objetos incrustados, vínculos externos e inyección de fórmulas. Nada se ejecuta ni se evalúa. |
| Archivos enormes o "bombas" de compresión | 25 MB de subida, 300 MB descomprimidos, 100.000 filas, 500 columnas y límite de peticiones por IP. |
| XSS | Todo dato del archivo se escapa antes de mostrarse y antes de entrar al PDF. La CSP restringe los scripts a `'self'`. |
| IA local (Ollama) | La dirección de Ollama la define solo el servidor (`OLLAMA_HOST`); el navegador solo elige un modelo que Ollama lista, así que la app no sirve para consultar otras direcciones de la red. Sin redirecciones ni proxies del entorno. Si Ollama no está en este equipo, la pantalla lo avisa. |
| Inyección de prompts (IA) | Los logs viajan al modelo como datos no confiables, con `<` y `>` escapados para que no cierren el bloque de datos ni imiten una instrucción. La criticidad la decide siempre el motor de reglas, un verificador descarta las IP y los `Log_ID` inventados, y el texto del modelo se escapa en pantalla y en el PDF. Es opcional: sin clave de Anthropic no se envía nada. |
| Filtración de claves | Las claves viven en `.env` (fuera de Git) o se pegan en la interfaz; no se guardan, no se registran y no se devuelven al navegador. |
| Acceso no deseado | La app escucha solo en `127.0.0.1`. Con `APP_ACCESS_TOKEN` toda la API exige una clave, con límite de intentos fallidos por IP y un tope global (100 por minuto) que no depende de la IP. Sin la clave, `/api/health` solo responde que el servicio está vivo. |
| DNS rebinding | Solo se atienden peticiones cuyo `Host` sea `127.0.0.1`, `localhost`, el de `APP_BASE_URL` o uno de `ALLOWED_HOSTS`; el resto recibe 400. Así una página web no puede usar el navegador del analista para leer la API local. |
| Archivos que agotan el servidor | El análisis corre fuera del bucle de eventos (la app sigue respondiendo), con 2 análisis simultáneos como máximo (el resto recibe 503). Las filas y celdas de un `.xlsx` se cuentan al descomprimir y se rechaza antes de abrirlo si pasa de 100.000 filas o 4 millones de celdas. |
| Límites por IP detrás de un proxy | `X-Forwarded-For` solo se acepta del proxy indicado en `FORWARDED_ALLOW_IPS` (vacío por defecto en Docker y en `make start`: de ninguno). |
| Salida a Internet (DNS) | Las herramientas de dominio consultan DNS sobre HTTPS solo si el analista lo pide, a Cloudflare y Google (servidores fijos, sin redirecciones, respuesta limitada a 64 KB, 5 s de espera, 6 consultas por minuto por IP). Solo sale el nombre de dominio. `DNS_LOOKUPS=off` las desactiva. |
| Uso automatizado | Opcional: con `CAPTCHA=on` las subidas exigen resolver un captcha local (imágenes o rompecabezas deslizante; sin terceros ni internet), con un solo intento por desafío, pase de un solo uso y límite de fallos por IP. Frena bots genéricos; no detiene a un atacante dirigido ni sustituye a `APP_ACCESS_TOKEN`. |
| Cadena de suministro | Dependencias con versión exacta y hash (`requirements.lock`), Dependabot, y en cada cambio `bandit`, `pip-audit` y Trivy. |
| Superficie expuesta | Documentación de la API desactivada por defecto, contenedor sin privilegios, de solo lectura y sin capacidades. |
| Alertas de Wazuh en vivo | La instantánea del panel solo se abre con `APP_ACCESS_TOKEN` definido: sin él las alertas se reciben y se avisan por Telegram, pero no se sirven a nadie (403). |
| Ingesta de Wazuh | Clave propia en `X-Wazuh-Token` (16 caracteres o más, comparación en tiempo constante; sin clave el endpoint queda cerrado), 10 intentos fallidos por minuto y 429, máximo 1 MB y 200 alertas por llamada, campos recortados y limpios. |
| Contexto del Indexer de Wazuh | Usuario de solo lectura; la consulta la arma el servidor (el navegador no envía consultas); solo disponible en las alertas de Wazuh en vivo, **no en archivos subidos**; 30 consultas por minuto; la contraseña no se muestra ni se registra. |
| Avisos de Telegram | Sin usuarios, IPs, comandos ni logs por defecto; el token no se registra. |
| MISP, KEV/EPSS y feed propio | Las direcciones las define solo el servidor; MISP e Indexer sin redirecciones; descargas con tope de tamaño; un archivo roto no reemplaza al bueno; la clave de MISP no se registra. |

## Lo que la aplicación NO hace

- **No es un antivirus.** "Sin avisos" no significa "archivo seguro".
- **Sin `APP_ACCESS_TOKEN` no tiene login.** Cualquiera que llegue al puerto puede usarla. Por defecto solo es accesible desde tu equipo.
- **La clave de acceso es una sola, compartida.** No hay usuarios, roles ni aislamiento entre personas: quien tenga el identificador de una sesión puede verla.
- **No incluye HTTPS.** Si la expones en una red, ponla detrás de un proxy inverso con HTTPS; sin él la clave viaja sin cifrar.
- **No cifra la comunicación con Wazuh, MISP o el Indexer por sí sola.** `MISP_VERIFY=0` y `WAZUH_INDEXER_VERIFY=0` apagan la verificación del certificado (el servicio lo registra como aviso); son para laboratorio. Usa `MISP_CA` o `WAZUH_INDEXER_CA` con la CA de tu servicio. Más en [docs/ENDURECER_LAB.md](docs/ENDURECER_LAB.md).
- **Las sesiones viven en memoria** (máximo 10) y se pierden al reiniciar.
- **La CSP permite estilos en línea** (`style-src 'unsafe-inline'`) porque la interfaz los usa. Es un riesgo aceptado: los scripts siguen limitados a `'self'`, así que un dato malicioso no puede ejecutar código.

## Datos que salen de tu equipo

Nada sale sin una acción tuya: la IA y la reputación están apagadas hasta que las activas. Detalle en la sección *Privacidad* del [README](README.md) y en [docs/PRIVACIDAD.md](docs/PRIVACIDAD.md).

## Si vas a desplegarla

1. Define `APP_ACCESS_TOKEN` (16 caracteres o más; `openssl rand -hex 24` genera uno).
   Agrega en `ALLOWED_HOSTS` el nombre con el que se va a abrir, y en `FORWARDED_ALLOW_IPS` la IP del proxy inverso (que debe sobrescribir `X-Forwarded-For`).
2. Si la publicas en internet, activa también `CAPTCHA=on` para frenar el uso automatizado de las subidas.
3. Sírvela detrás de HTTPS y no publiques el puerto 8000 directamente.
4. Mantén las dependencias al día (acepta los pull requests de Dependabot) y ejecuta `make audit` de vez en cuando.
5. Usa datos de logs de los que tengas permiso para procesar: pueden contener información personal.
6. Si lo conectas a Wazuh, MISP o Telegram, revisa [docs/ENDURECER_LAB.md](docs/ENDURECER_LAB.md): contraseñas por defecto, puertos publicados, certificados y rotación de claves.
