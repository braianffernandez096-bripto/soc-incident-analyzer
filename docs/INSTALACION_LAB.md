# Instalación completa en un laboratorio (Wazuh, Telegram, contexto e Indexer)

Volver al [README](../README.md).

El README explica cómo instalar **solo la aplicación** (Python o Docker), que ya sirve para analizar exports de un SIEM. Esta guía es el camino completo para repetir el laboratorio con
Wazuh en vivo, avisos a Telegram, contexto de amenazas y contexto desde el Indexer. Cada paso es opcional y tiene su propia guía; aquí está el **orden** y cómo comprobar que cada uno funciona.

> Es un laboratorio: nada de esto está pensado para exponerse a Internet. Las claves y contraseñas van solo en el `.env` del servidor, nunca en el repositorio ni en un chat.

## Qué se probó

| Pieza | Versión / entorno |
|---|---|
| Servidor | Ubuntu 24.04 con Docker y Docker Compose |
| Wazuh | 4.14.7, un solo nodo en Docker (manager, indexer y dashboard) |
| Equipo vigilado | Windows 10 con agente de Wazuh (y, opcionalmente, Sysmon) |
| MISP | 2.4 en otra VM (opcional) |
| Analizador | Python 3.12 (en Docker) |

Se usaron tres máquinas virtuales (servidor, Windows y MISP), pero se puede empezar solo con el servidor.

## Orden recomendado

| # | Paso | Guía | Cómo saber que funciona |
|---|---|---|---|
| 1 | Analizador en Docker | [README](../README.md#con-docker) | `http://127.0.0.1:8000` abre y **Probar con datos de ejemplo** muestra incidentes |
| 2 | Wazuh en Docker | [Documentación oficial de Wazuh](https://documentation.wazuh.com/current/deployment-options/docker/index.html) | El Dashboard abre en `https://IP-DEL-SERVIDOR` y `sudo docker ps` muestra `manager`, `indexer` y `dashboard` |
| 3 | Agente en el equipo a vigilar | [Instalación del agente](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) | En el Dashboard, **Agents** lo muestra «Active» |
| 4 | Unir analizador y Wazuh | [WAZUH.md](WAZUH.md#puesta-en-marcha) | `GET /api/wazuh/status` cuenta alertas recibidas |
| 5 | Probar con una ráfaga | [WAZUH.md](WAZUH.md#probar-la-integración) | El panel muestra «Fuerza bruta (Windows)» en **Abrir alertas de Wazuh** |
| 6 | Avisos a Telegram | [WAZUH.md](WAZUH.md#telegram-opcional) | Llega el aviso «Escalar · Alto» |
| 7 | CISA KEV y EPSS | [CONTEXTO.md](CONTEXTO.md) | `GET /api/context/status` muestra entradas de KEV y EPSS |
| 8 | MISP propio | [MISP.md](MISP.md) | Un indicador de prueba genera el hallazgo «Indicador conocido en MISP» |
| 9 | Feed JSON propio | [FEED.md](FEED.md) | `sample_data/feed_ejemplo.json` genera «Indicador conocido en tu feed» |
| 10 | Contexto desde el Indexer | [WAZUH.md](WAZUH.md#contexto-desde-el-indexer-opcional) | El botón **Ver contexto en Wazuh (Indexer)** lista registros del hallazgo |

Si algo no responde como en la columna de la derecha, mira [SOLUCION_PROBLEMAS.md](SOLUCION_PROBLEMAS.md): reúne los síntomas que aparecieron al montar este laboratorio.

## Cinco reglas que ahorran horas

1. **Recrea siempre con los dos archivos de compose** si usas Wazuh: `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --build --force-recreate`. Con el comando simple, el analizador sale de la red de Wazuh y las alertas dejan de llegar **sin ningún error**.
2. **Cambiar el `.env` exige recrear** el contenedor (`--force-recreate`); un simple reinicio no relee las variables.
3. **Un carácter mal copiado** en una clave (mayúscula por minúscula) da «Authentication failed» o `401`. Escríbela a mano y compara el largo, sin mostrarla.
4. **Usuario de solo lectura para el Indexer**, nunca `admin`, y certificados autofirmados solo en laboratorio (`..._VERIFY=0`).
5. **Los eventos crudos necesitan dos ajustes** en Wazuh (`logall_json` y `archives: enabled: true` en Filebeat); sin ellos el Indexer solo tiene alertas y el botón lo indica.

## Qué ve quien repite esto

Cada paso termina con algo visible: un panel con incidentes, un aviso en el móvil, un hallazgo que dice por qué es importante (KEV, MISP, feed) y una tabla con lo que pasó en el equipo alrededor del hallazgo.
Para ver el recorrido completo contado de punta a punta, lee el [caso de estudio](CASO_DE_ESTUDIO.md).
