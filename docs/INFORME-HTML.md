# Informe HTML

Volver al [README](../README.md).

Junto al PDF, en la pestaña **Informe** está **Descargar informe HTML**: un único archivo que se abre con doble clic en cualquier navegador, sin conexión y sin instalar nada. Trae el mismo contenido que el PDF (resumen, incidentes con evidencia y plan de acción, IoC, reputación, triaje y decisiones del analista, correos sospechosos) más:

- gráficos SVG (criticidad, eventos por ventana de 10 minutos con cada criticidad) y animaciones con [anime.js](https://animejs.com/) 3.2.2 incluido dentro del archivo (sin CDN);
- diseño «glass» con modo claro y oscuro (sigue al sistema y se puede cambiar), adaptado al celular;
- incidentes y hallazgos desplegables, filtro de indicadores y versión imprimible (botón «Imprimir / PDF»: se abre todo y se quitan los efectos);
- las animaciones son opcionales: sin JavaScript o con «reducir movimiento» activado el informe se ve completo y quieto.

El análisis de **Phishing** tiene su propio **Descargar informe HTML** (junto al PDF, en Phishing → Correos): el mismo contenido que su PDF, con el mismo diseño y las mismas garantías de seguridad.

Seguridad: todo dato del archivo analizado, de la IA o de un correo se escapa al generar el HTML, y el propio informe lleva una política CSP que solo permite su script y su estilo (por hash) y ninguna conexión: aunque algo se escapara mal, el navegador no ejecutaría código. Como cualquier informe con datos del cliente, compártelo solo con quien corresponda.
