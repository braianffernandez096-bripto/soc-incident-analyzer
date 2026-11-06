# Capturas

Galería completa de la interfaz y de los informes. Volver al [README](../README.md).

**Inicio: carga del archivo o prueba con datos de ejemplo** (arriba, las pestañas «Análisis de logs» y «Phishing»)

![Pantalla de inicio con las pestañas Análisis de logs y Phishing, la zona de carga y el botón de datos de ejemplo](../img/Inicio.png)

**Panel: resumen e incidentes detectados**

![Panel con las tarjetas de incidentes y la línea de tiempo](../img/Dashboard.png)

**Panel: actividad, hallazgos por criticidad e IP con más movimiento**

![Actividad de la ventana analizada, hallazgos por criticidad e IP](../img/Metricas.png)

**Incidentes: secuencia de eventos con el `Log_ID` que respalda cada paso** (INC-002)

![Incidente INC-002 con su secuencia de eventos](../img/INC-002.png)

**Hallazgos: explicación técnica, criticidad, impacto y plan de acción**

![Hallazgo con explicación, impacto y plan de acción en tres columnas](../img/Seccion-Hallazgos.png)

**ATT&CK: técnicas sugeridas por los hallazgos, agrupadas por táctica, con descarga de la capa para Navigator**

![Matriz MITRE ATT&CK por táctica](../img/Matriz-ATTACK.png)

**Eventos: los 715 registros originales, con marca de los ligados a incidentes**

![Tabla de eventos con filtros](../img/Eventos.png)

**Indicadores de compromiso (IoC)**

![Tabla de indicadores de compromiso](../img/IOCs.png)

**Informe: datos de portada, redacción con IA y descarga del PDF**

![Pantalla del informe técnico](../img/Informe.png)

**Verificación del archivo: un PNG renombrado a `.csv` se rechaza por su contenido, no por su extensión**

![Mensaje de rechazo al subir una imagen renombrada como CSV](../img/Archivo-rechazado.png)

**Informe técnico generado**

[Ver el informe de ejemplo en PDF](../examples/informe-ejemplo.pdf) (29 páginas: resumen ejecutivo, 6 incidentes, hallazgos con evidencia, plan de acción y recomendaciones). El nombre del cliente es ficticio.

## Capturas del análisis de correos (phishing)

**Phishing: carga de uno o varios `.eml` o de cabeceras pegadas, con el campo opcional «Remitente esperado»**

![Pantalla de carga de correos con las pestañas de herramientas, las cabeceras pegadas y el campo Remitente esperado](../img/Phishing-inicio.png)

**Resultados: los correos de ejemplo ordenados por criticidad, con veredicto y puntaje**

![Tabla de correos analizados con criticidad, remitente, veredicto y puntaje](../img/Phishing-resultados.png)

**Recorrido del correo: saltos `Received` del origen al destino, con hora UTC, retraso y avisos**

![Tabla de saltos del correo con hora UTC, retraso entre servidores y un salto marcado con retraso largo](../img/Phishing-recorrido.png)

**Puntaje con factores visibles: qué sumó cada señal, los topes por categoría y los umbrales**

![Desglose del puntaje de un correo crítico por categoría y señal](../img/Phishing-puntaje.png)

**Dominios parecidos: variantes de typosquatting con descarga de la lista**

![Lista de variantes de un dominio con el tipo de cambio y botones para descargar](../img/Phishing-parecidos.png)

**Homógrafos: desglose carácter por carácter de un remitente con una «о» cirílica (U+043E) que parece latina**

![Desglose de caracteres del remitente con la letra cirílica resaltada](../img/Phishing-homografo.png)

**Remitente esperado: se escribe la dirección legítima y la app señala qué letra cambió**

![Campo Remitente esperado completado con la dirección legítima](../img/Phishing-remitente-esperado.png)

![Resultado que indica que la «I» mayúscula de la posición 15 reemplaza a una «l» minúscula](../img/Phishing-esperado-resultado.png)

**Informe en PDF del análisis de correos** (los caracteres fuera del alfabeto latino se muestran como `[U+XXXX]`)

![Página del informe PDF con señales, verificación de caracteres y qué verificar](../img/Informe-phishing.png)

**Ayuda: «¿Cómo funciona?» tiene una sección para el análisis de logs y otra para phishing**

![Ventana de ayuda con la sección de phishing abierta](../img/Como-funciona-phishing.png)

## Captcha local opcional (`CAPTCHA=on`)

**Imágenes: marcar las 3 que muestran la misma figura, aunque estén giradas o de otro color**

![Captcha de imágenes con seis figuras de dispositivos](../img/Captcha-imagenes.png)

**Rompecabezas deslizante: arrastrar la pieza hasta el hueco correcto**

![Captcha de rompecabezas deslizante](../img/Captcha-rompecabezas.png)
