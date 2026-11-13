# Endurecer el laboratorio: lo que protege al analizador y lo que no

Volver al [README](../README.md).

[SECURITY.md](../SECURITY.md) describe cómo se protege **la aplicación**. Esta guía cubre lo que la rodea en un laboratorio con Wazuh, MISP y Telegram: ahí es donde suelen quedar los puntos débiles, porque son otros programas con sus propias contraseñas y puertos.

## 1. Credenciales por defecto (lo primero)

Los despliegues de ejemplo traen usuarios y contraseñas conocidos. Comprueba y cambia, en este orden:

| Qué | Qué hacer |
|---|---|
| **Wazuh (Docker)**: usuarios `admin` del Indexer/Dashboard y `wazuh-wui` de la API | Si no las cambiaste tras instalar, siguen siendo las del ejemplo del repositorio oficial. Cámbialas siguiendo «Change the password of Wazuh users» en la [documentación de Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html) |
| **MISP**: el usuario `admin` inicial | Cambia su contraseña y la clave de API; usa para el analizador una clave de un usuario de solo lectura (ver [MISP.md](MISP.md)) |
| **Otros contenedores del servidor** (por ejemplo n8n) | Comprueba que piden inicio de sesión y que su puerto no está abierto a toda la red |
| **Usuario del Indexer para el analizador** | De solo lectura, nunca `admin` ([WAZUH.md](WAZUH.md#contexto-desde-el-indexer-opcional)) |

Las contraseñas van solo en el `.env` del servidor y no se repiten entre servicios.

## 2. Puertos publicados

Mira qué escucha en todas las interfaces (`0.0.0.0`):

```bash
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"
```

En un Wazuh de un solo nodo aparecen, entre otros, `9200` (Indexer), `55000` (API), `443` (Dashboard), `1514/1515` (agentes) y `514/udp` (syslog). Para un laboratorio:

- **Indexer (9200) y API (55000):** el analizador llega al Indexer por la red de Docker, no por el puerto del equipo. Publícalos solo en local en el compose de Wazuh (`"127.0.0.1:9200:9200"`, `"127.0.0.1:55000:55000"`) salvo que los necesites desde otra máquina.
- **Dashboard (443) y agentes (1514/1515):** ábrelos solo a la red del laboratorio.
- **Aviso:** `ufw` **no filtra los puertos que publica Docker** (Docker escribe sus propias reglas de `iptables`). Para limitar de verdad, publica en `127.0.0.1` o usa la cadena `DOCKER-USER`.
- **El analizador** ya publica solo en `127.0.0.1:8000`. Si necesitas acceder desde otro equipo, define `APP_ACCESS_TOKEN` y ponlo detrás de HTTPS (proxy inverso); no abras el puerto 8000.

## 3. Cifrado y certificados

`MISP_VERIFY=0` y `WAZUH_INDEXER_VERIFY=0` apagan la verificación del certificado. Sirven para un laboratorio con certificados autofirmados, y el analizador lo registra como aviso (`tls_verify_disabled`). Para algo más serio, usa la CA de tu servicio: `MISP_CA=/ruta/ca.pem` o `WAZUH_INDEXER_CA=/ruta/ca.pem`, y deja la verificación activa.

La integración de Wazuh envía las alertas a `http://soc-analyzer:8000` por la red interna de Docker, sin cifrar. Es aceptable mientras esa red sea solo de contenedores; si el manager y el analizador estuvieran en equipos distintos, usa HTTPS delante del analizador.

## 4. Secretos y su rotación

- Si un token se filtra (captura, mensaje, repositorio), **revócalo y crea otro**: Telegram (`/revoke` en `@BotFather`), clave de MISP, contraseña del usuario del Indexer, `WAZUH_INGEST_TOKEN`, `APP_ACCESS_TOKEN`.
- Antes de compartir capturas o grabaciones, revisa que no muestren claves, nombres de bot, `chat_id` ni cuentas reales. Las imágenes publicadas en `img/` se revisaron y no los contienen.
- El `.env` está en `.gitignore` y `.dockerignore`; se comprobó que no hay secretos en el árbol ni en el historial del repositorio.

## 5. El repositorio en GitHub

Estos ajustes se hacen en **Settings** del repositorio y no cambian el código:

- Activar **verificación en dos pasos** en la cuenta.
- **Code security**: activar *Dependabot alerts*, *Secret scanning* y *Push protection* (frena un commit con una clave antes de publicarlo) y *Private vulnerability reporting* (ya lo pide [SECURITY.md](../SECURITY.md)).
- Cuando el flujo lo permita, proteger `main` exigiendo que el CI pase antes de integrar.

## 6. Lista de comprobación

- [ ] Contraseñas por defecto cambiadas (Wazuh, MISP y otros contenedores).
- [ ] `docker ps` revisado: Indexer y API de Wazuh no abiertos a toda la red.
- [ ] Certificados verificados con CA propia, o `VERIFY=0` solo en el laboratorio.
- [ ] Tokens revocables y registrados dónde se usan.
- [ ] 2FA, escaneo de secretos y alertas de Dependabot activos en GitHub.
- [ ] `APP_ACCESS_TOKEN` y HTTPS si el analizador se usa desde otro equipo.
