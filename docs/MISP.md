# MISP paso a paso

Volver al [README](../README.md) · Guía general del contexto: [CONTEXTO.md](CONTEXTO.md) · Problemas: [SOLUCION_PROBLEMAS.md](SOLUCION_PROBLEMAS.md).

Cómo conectar el analizador con **tu propia instancia de MISP** (opcional, apagado por defecto). El analizador solo le **pregunta** si una IP o un hash de los eventos figura como indicador; no escribe nada en MISP.

## Requisitos previos

- Una instancia de MISP funcionando y alcanzable por red **desde el contenedor del analizador** (se usa su IP, no `localhost`). Probado con MISP 2.4.
- Al menos un evento con indicadores de tu organización (o el de prueba del paso 7).
- El analizador ya levantado (ver el [README](../README.md)).

## 1. Un usuario de solo lectura

La clave de API del analizador solo necesita consultar. Conviene dedicarle un usuario de solo lectura en vez de usar `admin`.

1. En MISP: *Administration* → *Add User*.
2. Email: por ejemplo `soc-analyzer@lab.local`. **Organisation**: la **misma** que tiene tus eventos (un usuario solo ve lo de su organización). **Role**: `Read Only`.
3. Desmarca *Receive email alerts…* y *Send credentials automatically* si tu MISP no envía correo. Guarda.
4. Comprueba que el rol puede usar la API: *Administration* → *List Roles*; en la fila `Read Only` debe haber una tilde en **Auth key access**. Si no la tiene, crea un rol propio con *Read Only* y *Auth key access*.

## 2. Su clave de API

1. Inicia sesión **como ese usuario** → su nombre arriba a la derecha → *My profile* → *Auth keys* → *Add authentication key*. Comentario: `soc-analyzer`.
2. **Copia la clave en ese momento**: MISP la muestra una sola vez (después solo ve los primeros y últimos 4 caracteres). Distingue mayúsculas y minúsculas, y cuidado con `l`/`I`/`1` y `O`/`0`.

> Desde `admin`, en *List Auth Keys* → *Add*, el selector de usuario puede mostrar solo a `admin`. Crear la clave desde la cuenta del propio usuario evita ese problema.

## 3. Variables en el `.env`

Edita el `.env` del servidor (nunca en el chat ni en el repositorio):

```
CONTEXT_ENABLED=on          # opcional: solo para KEV/EPSS
MISP_URL=https://IP-DE-TU-MISP
MISP_KEY=la-clave-copiada
MISP_VERIFY=0               # solo si el certificado es autofirmado (lo habitual en un laboratorio)
```

Comprueba lo que quedó guardado comparando con la clave original, carácter por carácter: `grep ^MISP_KEY .env` (se ve en tu terminal).

## 4. Recrear el contenedor

Desde la carpeta del proyecto:

```
docker compose up -d --force-recreate
```

Si usas también el [modo Wazuh](WAZUH.md), usa siempre los dos archivos: `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --force-recreate`. Si no, el contenedor sale de la red de Wazuh y las alertas dejan de llegar.

(El nombre del contenedor en los comandos siguientes, `soc-incident-analyzer-analyzer-1`, depende del nombre de tu carpeta; mira `docker ps`.)

## 5. Comprobar que MISP acepta la clave

```
docker exec soc-incident-analyzer-analyzer-1 python -c "import os,httpx;k=os.environ['MISP_KEY'];r=httpx.get(os.environ['MISP_URL']+'/users/view/me',headers={'Authorization':k,'Accept':'application/json'},verify=False);print(len(k),r.status_code)"
```

Debe imprimir `40 200`. `403` = clave mal copiada o rol sin acceso por API; un `KeyError` = una variable no llegó al contenedor.

## 6. Comprobar la consulta del analizador

```
docker exec soc-incident-analyzer-analyzer-1 python -c "from backend import misp;c=misp.get_client();print(c.search(['203.0.113.50']))"
```

Con el indicador del paso 7 cargado debe imprimir un diccionario con la IP y tu evento. Si imprime `{}` y en los registros (`docker logs … | grep misp`) aparece `misp_failed type=ConnectError`, es el certificado (`MISP_VERIFY=0`) o la red.

## 7. Un indicador de prueba

1. Con un usuario que pueda crear eventos (por ejemplo `admin`): *Event Actions* → *Add Event*, *Distribution* = *Your organisation only*, *Info* = `Prueba SOC analyzer`.
2. En el evento, *Add Attribute*: *Category* `Network activity`, *Type* `ip-dst`, *Value* `203.0.113.50`, **For Intrusion Detection System** marcado, *Distribution* = *Inherit event*.
3. Publica el evento si MISP lo pide.

## 8. Verlo en el analizador

Sube [`sample_data/ejemplo_misp.csv`](../sample_data/ejemplo_misp.csv). Debe aparecer un hallazgo **Alto**, «Indicador conocido en MISP: 203.0.113.50», que cita tu evento, y la IP en *Indicadores (IoC)*. «Límites del análisis» indica que se consultó tu MISP.

## Qué se consulta y qué no

- IP de origen y destino y hashes (MD5, SHA-1, SHA-256), hasta 50 valores por análisis.
- Las IP privadas y de loopback no se consultan (`MISP_INCLUDE_PRIVATE=1` las incluye). Los rangos de documentación (`203.0.113.x`) sí, para poder probar.
- Se pide a MISP que descarte valores de sus listas de advertencia y, por defecto, solo atributos marcados «to_ids» (`MISP_ONLY_IDS=0` los incluye todos).
- Un fallo de red o de clave nunca tumba el análisis: la consulta se omite y el motivo queda en el registro, sin la clave.
