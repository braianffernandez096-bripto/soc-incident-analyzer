# IA local con Ollama (opcional)

Volver al [README](../README.md).

Alternativa a Claude para quien no quiere pagar ni enviar datos a un tercero. En la pestaña **Informe**, elige **IA local (Ollama)** y uno de los modelos que tengas instalados.

## Cuándo usar cada uno

| | IA local (Ollama) | Claude (Anthropic) |
|---|---|---|
| Costo | Sin costo | De pago por uso, con tu propia clave |
| Privacidad | Los datos no salen del equipo | Los datos del análisis se envían a un tercero |
| Calidad de redacción y triaje | Depende del modelo; un 8B comete errores de redacción y tiende a restar gravedad con razonamientos débiles | Mejor y más consistente |
| Tiempo | Minutos por incidente sin GPU | Segundos |

Qué se midió con llama3.1:8b (CPU, 2 vCPU / 12 GB): las garantías del proyecto se cumplen (no cambia la criticidad, no se aceptan citas inventadas, el motor se conserva ante un conflicto), pero sin ajustes el modelo propuso bajar la gravedad de los 9 incidentes de una muestra, y con un prompt más estricto pasó a coincidir con el motor en los 9. Los datos de ejemplo son todos ataques, así que **no se ha medido** si distingue bien un falso positivo real. Ver [TRIAGE.md](TRIAGE.md).

**Recomendación:** usa Ollama para practicar, para trabajar sin conexión o cuando los datos no puedan salir del equipo, y mira siempre la recomendación del motor. Para el informe formal y el triaje que vaya a leer un tercero, usa un modelo de mayor calidad como Claude. Si usas Ollama, prefiere un modelo más grande que tu equipo soporte.

```bash
# Instala Ollama (https://ollama.com) y un modelo; el nombre es de ejemplo, usa el que prefieras y tu equipo aguante
ollama pull llama3.1:8b
```

- **La dirección la define el servidor,** no el navegador: `OLLAMA_HOST` (por defecto `http://127.0.0.1:11434`). Con Docker, define en `.env` `OLLAMA_HOST=http://host.docker.internal:11434` (el contenedor alcanza el Ollama de tu equipo) y haz que Ollama escuche en todas las interfaces locales (`OLLAMA_HOST=0.0.0.0` en el servicio de Ollama), porque por defecto solo escucha en `127.0.0.1`.

- **Contexto:** Ollama recorta en silencio lo que supera su ventana (2.048-4.096 tokens por defecto), así que la app pide 16.384 (`OLLAMA_NUM_CTX` lo cambia). Si el equipo se queda sin memoria, usa un modelo más chico.

- **Mismas garantías que con Claude:** la criticidad la decide el motor, el verificador descarta los `Log_ID` y las IP inventados y, si el modelo falla, el informe se genera por reglas.

- **Calidad y tiempo:** un modelo local pequeño redacta peor que uno grande y, sin GPU, tarda minutos por consulta (medido con un modelo de 8B en una VM de 2 procesadores: unos 5 minutos por consulta con 100 eventos y bastante más con incidentes grandes). La app consulta de a una vez y espera hasta 60 minutos por consulta; `OLLAMA_TIMEOUT` (en segundos) lo cambia. Si una consulta se agota, ese incidente se redacta por reglas. Con cualquier modelo, la criticidad y la prioridad del plan de acción las fija el motor; un modelo chico solo puede empeorar el texto, no el orden de urgencia.

- **Sin probar con modelos reales en CI:** las pruebas usan un servidor Ollama simulado; el funcionamiento con cada modelo depende de tu equipo.
