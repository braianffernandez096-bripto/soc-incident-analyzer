# Cómo contribuir

¡Gracias por querer aportar! Es un proyecto personal de portafolio, así que respondo cuando puedo y sin plazos garantizados. Si el cambio es grande, abre antes un issue para acordar el enfoque.

## Reglas del proyecto (no negociables)

1. **El motor decide, la IA solo redacta o recomienda.** La criticidad la fijan las reglas; ningún cambio debe permitir que un modelo la modifique.
2. **Todo lo que viene de un archivo es hostil.** Se escapa al mostrarlo y al generar el PDF; nada se ejecuta ni se evalúa.
3. **Sin datos reales.** Ni en pruebas, ni en capturas, ni en issues. Usa datos sintéticos (IP de documentación como `203.0.113.x`, `198.51.100.x`, `192.0.2.x`).
4. **Sin claves en el repositorio.** Viven en `.env` (ignorado por Git) o se pegan en la interfaz.
5. **Lo documentado debe coincidir con lo hecho.** Si cambias comportamiento, actualiza README/`docs/`, `CHANGELOG.md` y el número de pruebas.

## Preparar el entorno

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Para las pruebas de navegador: `pip install playwright==1.63.0 && python -m playwright install --with-deps chromium`.

## Antes de abrir un pull request

```bash
python -m pytest --cov=backend --cov-fail-under=85     # todas las pruebas y cobertura mínima
bandit -q -r backend                                    # análisis estático
```

(O `make test-cov`, `make lint` y `make audit`.) El CI ejecuta lo mismo, más pip-audit, la imagen Docker con Trivy y las pruebas de navegador.

- Cada regla de detección nueva lleva **un caso que debe detectar y uno de actividad normal que no debe detectar**.
- Un arreglo de error lleva la prueba que lo habría atrapado.
- Cambios en el frontend: sin manejadores en línea (`onclick=`…); la CSP los bloquea.
- Dependencias: se fijan con hash en `requirements*.lock`; no agregues una sin necesidad.
- Mensajes de commit y textos de la interfaz, en español.

## Qué es especialmente útil

- Casos de actividad **legítima** que hoy generan falso positivo (con datos sintéticos).
- Formatos de log que no se interpretan bien.
- Reglas de detección con su técnica ATT&CK y su caso negativo.

## Seguridad

Si encontraste una vulnerabilidad, **no abras un issue público**: sigue [SECURITY.md](SECURITY.md).
