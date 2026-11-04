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
| Filtración de claves | Las claves viven en `.env` (fuera de Git) o se pegan en la interfaz; no se guardan, no se registran y no se devuelven al navegador. |
| Acceso no deseado | La app escucha solo en `127.0.0.1`. Con `APP_ACCESS_TOKEN` toda la API exige una clave, con límite de intentos fallidos. |
| Cadena de suministro | Dependencias con versión exacta y hash (`requirements.lock`), Dependabot, y en cada cambio `bandit`, `pip-audit` y Trivy. |
| Superficie expuesta | Documentación de la API desactivada por defecto, contenedor sin privilegios, de solo lectura y sin capacidades. |

## Lo que la aplicación NO hace

- **No es un antivirus.** "Sin avisos" no significa "archivo seguro".
- **Sin `APP_ACCESS_TOKEN` no tiene login.** Cualquiera que llegue al puerto puede usarla. Por defecto solo es accesible desde tu equipo.
- **La clave de acceso es una sola, compartida.** No hay usuarios, roles ni aislamiento entre personas: quien tenga el identificador de una sesión puede verla.
- **No incluye HTTPS.** Si la expones en una red, ponla detrás de un proxy inverso con HTTPS; sin él la clave viaja sin cifrar.
- **Las sesiones viven en memoria** (máximo 10) y se pierden al reiniciar.
- **La CSP permite estilos en línea** (`style-src 'unsafe-inline'`) porque la interfaz los usa. Es un riesgo aceptado: los scripts siguen limitados a `'self'`, así que un dato malicioso no puede ejecutar código.

## Datos que salen de tu equipo

Nada sale sin una acción tuya: la IA y la reputación están apagadas hasta que las activas. Detalle en la sección *Privacidad* del [README](README.md).

## Si vas a desplegarla

1. Define `APP_ACCESS_TOKEN` (16 caracteres o más; `openssl rand -hex 24` genera uno).
2. Sírvela detrás de HTTPS y no publiques el puerto 8000 directamente.
3. Mantén las dependencias al día (acepta los pull requests de Dependabot) y ejecuta `make audit` de vez en cuando.
4. Usa datos de logs de los que tengas permiso para procesar: pueden contener información personal.
