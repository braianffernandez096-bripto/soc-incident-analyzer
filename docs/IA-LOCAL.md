# IA local con Ollama (opcional)

Volver al [README](../README.md).

Alternativa a Claude para quien no quiere pagar ni enviar datos a un tercero. En la pestaña **Informe**, elige **IA local (Ollama)** y uno de los modelos que tengas instalados.

```bash
# Instala Ollama (https://ollama.com) y un modelo; el nombre es de ejemplo, usa el que prefieras y tu equipo aguante
ollama pull llama3.1:8b
```

- **La dirección la define el servidor,** no el navegador: `OLLAMA_HOST` (por defecto `http://127.0.0.1:11434`). Con Docker, define en `.env` `OLLAMA_HOST=http://host.docker.internal:11434` (el contenedor alcanza el Ollama de tu equipo) y haz que Ollama escuche en todas las interfaces locales (`OLLAMA_HOST=0.0.0.0` en el servicio de Ollama), porque por defecto solo escucha en `127.0.0.1`.

- **Contexto:** Ollama recorta en silencio lo que supera su ventana (2.048-4.096 tokens por defecto), así que la app pide 16.384 (`OLLAMA_NUM_CTX` lo cambia). Si el equipo se queda sin memoria, usa un modelo más chico.

- **Mismas garantías que con Claude:** la criticidad la decide el motor, el verificador descarta los `Log_ID` y las IP inventados y, si el modelo falla, el informe se genera por reglas.

- **Calidad y tiempo:** un modelo local pequeño redacta peor que uno grande y, sin GPU, tarda minutos por consulta (medido con un modelo de 8B en una VM de 2 procesadores: unos 5 minutos por consulta con 100 eventos y bastante más con incidentes grandes). La app consulta de a una vez y espera hasta 60 minutos por consulta; `OLLAMA_TIMEOUT` (en segundos) lo cambia. Si una consulta se agota, ese incidente se redacta por reglas. Con cualquier modelo, la criticidad y la prioridad del plan de acción las fija el motor; un modelo chico solo puede empeorar el texto, no el orden de urgencia.

- **Sin probar con modelos reales en CI:** las pruebas usan un servidor Ollama simulado; el funcionamiento con cada modelo depende de tu equipo.
