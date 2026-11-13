# Caso de estudio: de un ataque simulado al aviso en Telegram y al informe

Un recorrido completo, con los pasos que se pueden repetir en un laboratorio propio: se genera actividad sospechosa, Wazuh la detecta, el analizador la
correlaciona y la prioriza con contexto de amenazas, y el analista recibe un aviso y llega a un informe. **Todo corre en local**; no se envía ningún log a terceros.

## Escenario

Un equipo Windows y un servidor Ubuntu, ambos con agente de Wazuh. El analizador recibe las alertas por `integratord` ([WAZUH.md](WAZUH.md)).
Contexto activado: CISA KEV + EPSS, un MISP propio y un feed JSON de indicadores ([CONTEXTO.md](CONTEXTO.md), [FEED.md](FEED.md)).

## 1. Actividad simulada

| Paso | Qué se hizo | Qué se espera ver |
|---|---|---|
| A | Varios intentos de inicio de sesión fallidos contra el equipo Windows (RDP/red) | Eventos 4625 en Wazuh |
| B | Varios intentos SSH con usuario inexistente contra Ubuntu | Alertas de `sshd` (autenticación fallida) |
| C | Una alerta de vulnerabilidad con un CVE conocido (formato `data.vulnerability.*`) | Cruce con KEV/EPSS |
| D | Una conexión saliente hacia una IP marcada como indicador en MISP y en el feed | Coincidencias de contexto |

## 2. Qué hace cada pieza

1. **Wazuh** genera alertas (nivel 5 o más) y las reenvía al analizador.
2. **El traductor** (`backend/wazuh.py`) las lleva al esquema común: usuario, IP de origen, equipo, tipo de evento.
3. **El motor de reglas** (determinista, sin IA) las acumula en una ventana y **correlaciona**: eventos sueltos de bajo nivel pasan a ser «Fuerza bruta (Windows)» o «Fuerza bruta (SSH)» según el volumen y la ventana de tiempo, con su táctica y técnica MITRE.
4. **El contexto** sube o baja la prioridad:
   - `ctx_cve`: el CVE figura en KEV → **Alto** (**Crítico** si CISA indica uso en ransomware); sin KEV, EPSS ≥ 70 % → Alto.
   - `ctx_misp`: la IP o el hash figura en tu MISP (con lista de advertencia aplicada) → **Alto**.
   - `ctx_feed`: coincide con un indicador vigente de tu feed → **Alto**.
5. **El aviso de Telegram** lleva solo severidad, recomendación, táctica y técnica y el tipo de origen (Windows, SSH, Vulnerabilidad, MISP, Feed). Sin usuarios, IPs ni comandos.
6. **El panel** abre el análisis como una sesión normal: línea de tiempo, hallazgos, entidades, consultas para el SIEM e informe.
7. **Contexto en Wazuh** (opcional): desde un hallazgo, un botón consulta el Indexer y muestra lo que ocurrió en ese equipo o con esa IP en la ventana alrededor del hallazgo.

## 3. Resultado

| Hallazgo | Severidad | Por qué |
|---|---|---|
| Fuerza bruta (Windows) | Alto | Ráfaga de fallos 4625 desde la misma IP |
| Fuerza bruta (SSH) | Alto | Ráfaga de fallos de `sshd` sobre usuarios inexistentes |
| Vulnerabilidad explotada activamente | Alto / Crítico | CVE en KEV (Crítico si hay uso en ransomware) |
| Indicador conocido (MISP / feed) | Alto | Coincidencia exacta con un indicador `to_ids` o con uno vigente del feed |

Cada aviso llegó a Telegram una sola vez; un hallazgo que **sube de severidad** vuelve a avisar, y lo medio y bajo va en un resumen horario.

## 4. Cómo lo trabaja el analista (L1)

1. **Leer el aviso**: severidad y recomendación («Escalar», «Investigar»).
2. **Abrir el hallazgo**: qué regla disparó, métricas (cantidad, ventana, IP) y la táctica MITRE.
3. **Mirar el contexto**: ¿hay coincidencia con KEV/MISP/feed? ¿qué más pasó en ese equipo? (botón del Indexer).
4. **Decidir**: falso positivo (por ejemplo, un escáner interno autorizado), investigar más o **escalar** a L2 con el informe.
5. **Documentar**: el informe (HTML/PDF) incluye cronología, evidencias y «Límites del análisis», que dice qué contexto se usó y qué no.

## 5. Qué se aprendió

- Un nivel mínimo de 5 en Wazuh es lo que permite al motor ver los eventos sueltos y correlacionarlos; con un umbral más alto solo llegan alertas ya agregadas.
- Recrear el contenedor del analizador sin el compose de Wazuh lo saca de la red de Wazuh y las alertas dejan de llegar **sin error visible** ([SOLUCION_PROBLEMAS.md](SOLUCION_PROBLEMAS.md)).
- El contexto prioriza pero no confirma: un CVE fuera de KEV no es «seguro», y una IP en un feed puede estar vencida; por eso los indicadores llevan TTL.
- Un detalle de clave de API (una mayúscula) dio «Authentication failed» en MISP: los errores de contexto nunca tumban el análisis y se registran sin la clave.

## 6. Cómo repetirlo

1. [WAZUH.md](WAZUH.md): puesta en marcha e integración.
2. [CONTEXTO.md](CONTEXTO.md) y [MISP.md](MISP.md): KEV/EPSS y MISP.
3. [FEED.md](FEED.md): tu feed. El modelo está en `sample_data/feed_ejemplo.json`.
4. Sin Wazuh: sube `sample_data/ejemplo_cve.csv` y `ejemplo_misp.csv` al panel para ver el mismo cruce.
