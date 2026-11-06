# Triaje asistido por IA

Muchos SOC ya usan IA para el primer filtro (L1) y un analista humano confirma antes de escalar. Esta función reproduce ese flujo con las garantías del resto del proyecto: **la IA recomienda, el motor fija la severidad y el analista decide.**

## Qué ve el analista (pestaña Incidentes)

Por cada incidente:

- **Recomendación**: `Escalar`, `Probable falso positivo` o `Falta información`, con su **confianza** (Alta / Media / Baja).
- **Motivos** concretos que citan `Log_ID` (clic para abrir la evidencia).
- **Cambiaría de opinión si…**: el dato o la prueba que cambiaría la recomendación.
- **Decisión del analista**: `Escalado`, `Descartado` o `En investigación`, con una nota de hasta 500 caracteres. Queda registrada con la hora (UTC) y el analista de la portada, y aparece en el PDF.

Sin IA, la recomendación sale del motor (Crítico → Escalar; Alto → Escalar; Medio → Falta información; Bajo → Probable falso positivo). Con IA, se genera desde el panel «Triaje asistido por IA», con Claude o con Ollama (el mismo selector que el informe).

## Garantías

| Riesgo | Cómo se controla |
|---|---|
| La IA baja la severidad | No puede: la severidad es del motor y el triaje es una opinión aparte. |
| La IA quiere descartar un incidente Crítico o Alto | Se **conserva la recomendación del motor**, se marca «Conflicto» y se muestra lo que sugirió la IA. Bajar la guardia es decisión humana. |
| La IA inventa `Log_ID` o IP | El verificador los elimina (y solo se aceptan `Log_ID` del propio incidente). Se cuentan en el panel. |
| Motivos vacíos o genéricos («revisar logs») | Se descartan; sin motivos concretos se usa la recomendación del motor. |
| Respuesta inválida o fallo del modelo | Ese incidente queda con la recomendación del motor; el resto sigue. Si ninguno es válido, se informa el error y no se guarda nada. |
| Log hostil con instrucciones | Los datos viajan escapados dentro de un bloque delimitado; la nota del analista y todo el texto se escapan al mostrarlo. |

Las decisiones viven en la sesión (en memoria, como el análisis): no se guardan en disco.

## Medir la IA

`scripts/evaluar_triage.py` compara la recomendación final con las etiquetas de `sample_data/triage_esperado.json`:

```bash
python scripts/evaluar_triage.py                                  # solo el motor
python scripts/evaluar_triage.py --provider ollama --model llama3.1:8b --json resultados.json
ANTHROPIC_API_KEY=... python scripts/evaluar_triage.py --provider anthropic
```

Métricas: aciertos (coincide con la esperada o una aceptable) y exactos (solo la esperada), **subescalado** (se esperaba Escalar y no se entregó: el error caro), sobreescalado, conflictos con el motor, citas e IPs descartadas y casos en que se usó el respaldo del motor.

### Límites que conviene tener claros

- Las etiquetas son **criterio del autor sobre datos sintéticos**. No son verdad de campo ni salen de incidentes reales.
- Todos los ejemplos son ataques: la mayoría esperada es `Escalar`, y los casos ambiguos (persistencia de una cuenta de soporte, túnel DNS, password spraying sin acceso) aceptan también `Escalar`. Por eso el motor solo ya puntúa alto. El script **no mide** si la IA distingue bien un falso positivo real; para eso hace falta sumar casos benignos etiquetados.
- Sirve para comparar versiones del motor o modelos entre sí (por ejemplo, cuántos «subescalado» produce un modelo de 8B frente a Claude), no para prometer una tasa de acierto en producción.
- Con un modelo local de 8B en CPU, esperá varios minutos para evaluar todos los incidentes.

## API

- `GET /api/sessions/{id}/triage`: recomendaciones vigentes y decisiones.
- `POST /api/sessions/{id}/triage/ai?provider=&model=`: genera con IA (misma clave, límite de peticiones y validación de proveedor que el informe).
- `POST /api/sessions/{id}/triage/{incidente}/decision`: campos `decision` y `note`.
