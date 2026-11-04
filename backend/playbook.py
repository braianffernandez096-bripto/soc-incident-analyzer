"""Impacto y plan de acción de referencia por tipo de hallazgo.

Se usa en el modo sin IA (determinista). Son prácticas estándar de respuesta a
incidentes parametrizadas con las entidades del hallazgo; no afirman hechos nuevos
sobre los logs.
"""
from __future__ import annotations

PLAYBOOK: dict[str, dict] = {
    "brute_force": {
        "impact": "Riesgo de obtener credenciales válidas sin explotar ninguna vulnerabilidad. Si hay éxito posterior, el atacante opera con la identidad de un empleado; si hay bloqueo de cuentas, también puede causar denegación de servicio a usuarios legítimos.",
        "investigate": [
            "Revisar en el controlador de dominio todos los 4625/4624 de {ip} y confirmar qué cuentas llegaron a autenticarse.",
            "Identificar por qué {ip} alcanzó el servicio (puerto expuesto, VPN, regla de firewall) y desde cuándo.",
            "Consultar inteligencia de amenazas sobre {ip} (el export no incluye reputación).",
        ],
        "contain": [
            "Bloquear {ip} en el perímetro.",
            "Restablecer contraseñas y revocar sesiones/tokens de las cuentas objetivo con éxito posterior.",
        ],
        "remediate": [
            "Habilitar MFA y bloqueo inteligente de cuentas.",
            "Quitar la exposición directa a Internet del servicio atacado (VPN/ZTNA).",
            "Crear una alerta por ráfagas de 4625 por origen y por cuenta.",
        ],
    },
    "external_logon": {
        "impact": "Un tercero opera con una cuenta corporativa válida: acceso a datos, ejecución de comandos y base para moverse por la red.",
        "investigate": [
            "Reconstruir toda la actividad de {user} desde el inicio de sesión (4624/4688/5140/4672) y comparar con su comportamiento habitual.",
            "Confirmar con el titular de la cuenta que no reconoce el acceso desde {ip}.",
            "Determinar cómo se obtuvo la credencial (spraying previo, reutilización, phishing).",
        ],
        "contain": [
            "Deshabilitar la cuenta {user} y cerrar sus sesiones activas.",
            "Bloquear {ip} y cortar el acceso remoto (RDP/VPN) que se usó.",
        ],
        "remediate": [
            "Rotar la contraseña y todas las credenciales/secretos accesibles por la cuenta.",
            "Exigir MFA para el acceso remoto y revisar la política de contraseñas.",
        ],
    },
    "privilege": {
        "impact": "Con privilegios elevados el atacante puede volcar credenciales, desactivar controles y acceder a cualquier recurso del host.",
        "investigate": [
            "Listar los privilegios asignados en el evento 4672 y las acciones posteriores de {user} en {host}.",
            "Verificar si {user} pertenece a grupos privilegiados y si esa pertenencia es legítima.",
        ],
        "contain": ["Revocar la sesión y limitar temporalmente los privilegios de {user}.", "Aislar {host} si se confirma uso indebido."],
        "remediate": ["Aplicar mínimo privilegio y gestión de accesos privilegiados (PAM).", "Alertar 4672 asociado a orígenes externos."],
    },
    "cmd_encoded_ps": {
        "impact": "Ejecución de código ofuscado en {host}: puede descargar herramientas, robar credenciales o establecer persistencia sin dejar el script a la vista.",
        "investigate": [
            "Recuperar y decodificar el comando (Script Block Logging 4104, memoria, EDR) — en el export está redactado.",
            "Revisar el proceso padre y las conexiones de red de ese proceso en {host}.",
        ],
        "contain": ["Aislar {host} de la red.", "Deshabilitar la cuenta {user} mientras se investiga."],
        "remediate": ["Habilitar Script Block Logging y AMSI; aplicar Constrained Language Mode/WDAC.", "Alertar -EncodedCommand lanzado desde cmd.exe."],
    },
    "cmd_discovery": {
        "impact": "El atacante mapea usuarios, grupos y recursos compartidos para decidir sus siguientes pasos (movimiento lateral, objetivos de datos).",
        "investigate": ["Revisar qué recursos enumeró {user} (net view, grupos de administradores) y qué hizo después.", "Correlacionar con accesos a otros hosts en los minutos siguientes."],
        "contain": ["Restringir la cuenta {user} y monitorear los recursos enumerados."],
        "remediate": ["Limitar la enumeración de recursos compartidos y grupos a quienes la necesitan.", "Alertar combinaciones de whoami/net view/Get-SmbShare en cuentas administrativas."],
    },
    "cmd_archive_staging": {
        "impact": "Datos reunidos y comprimidos, listos para salir de la red: indica intención de exfiltración.",
        "investigate": ["Identificar el contenido del archivo comprimido y su ruta, y si llegó a salir (proxy/firewall).", "Revisar qué archivos leyó {user} antes de comprimir."],
        "contain": ["Aislar {host} y preservar el archivo comprimido como evidencia.", "Bloquear el destino de salida asociado si existe."],
        "remediate": ["Controlar la creación de archivos comprimidos en rutas públicas/temporales (DLP/EDR).", "Clasificar y restringir el acceso a los datos afectados."],
    },
    "cmd_anti_recovery": {
        "impact": "Eliminar las copias de sombra impide restaurar archivos y es un paso habitual justo antes de cifrar. Riesgo inminente de ransomware.",
        "investigate": ["Verificar si hay cifrado o cambios masivos de archivos en {host} y en los recursos compartidos accedidos por {user}.", "Comprobar el estado de los backups y de las copias de sombra en otros servidores."],
        "contain": ["Aislar {host} de inmediato y deshabilitar la cuenta {user}.", "Proteger los repositorios de backup (desconexión/inmutabilidad)."],
        "remediate": ["Mantener backups offline/inmutables y probados.", "Alertar de inmediato vssadmin/wbadmin delete y bcdedit recoveryenabled."],
    },
    "cmd_cred_dump": {
        "impact": "Compromiso de credenciales que permite moverse libremente y persistir.",
        "investigate": ["Determinar qué credenciales estaban en memoria en {host}.", "Buscar usos posteriores de esas cuentas."],
        "contain": ["Aislar {host}.", "Restablecer todas las credenciales expuestas."],
        "remediate": ["Habilitar Credential Guard y LSA Protection.", "Limitar sesiones privilegiadas en hosts no administrativos."],
    },
    "cmd_download_cradle": {
        "impact": "Descarga de código externo para ejecutarlo en {host}.",
        "investigate": ["Identificar la URL/archivo descargado y su ejecución posterior."],
        "contain": ["Aislar {host} y bloquear el destino."],
        "remediate": ["Restringir PowerShell/BITS/certutil con WDAC y filtrar la salida web."],
    },
    "cmd_web_service_shell": {
        "impact": "El atacante ejecuta comandos en {host} a través de la aplicación web (RCE/webshell): control del servidor y punto de entrada a la red interna.",
        "investigate": [
            "Buscar archivos nuevos o modificados en las rutas de subida (por ejemplo /uploads/) de {host} y revisar test.aspx y similares.",
            "Revisar todos los procesos hijo del pool de aplicaciones y sus conexiones salientes.",
            "Revisar los logs IIS completos de {ip} (más allá de esta ventana).",
        ],
        "contain": ["Poner {host} en aislamiento y retirar el sitio de producción.", "Bloquear {ip} y deshabilitar el pool/aplicación afectados."],
        "remediate": [
            "Eliminar la webshell y reconstruir {host} desde una imagen conocida.",
            "Impedir ejecución de scripts en directorios de subida; ejecutar el pool con mínimo privilegio; WAF.",
            "Corregir la vulnerabilidad que permitió la carga/ejecución.",
        ],
    },
    "lateral": {
        "impact": "El atacante amplía su alcance a {dest}, donde reside información sensible; el compromiso deja de estar acotado a un único servidor.",
        "investigate": ["Revisar toda la actividad de {user} en {dest} después del inicio de sesión.", "Verificar si se creó alguna otra sesión o servicio desde {src} hacia otros hosts."],
        "contain": ["Deshabilitar {user} y aislar {src} y {dest}."],
        "remediate": ["Segmentar la red y restringir SMB/administración remota entre servidores.", "Usar credenciales administrativas únicas por host (LAPS) y MFA."],
    },
    "mass_access": {
        "impact": "Lectura masiva de archivos del recurso {share}: posible recolección previa a cifrado o exfiltración, con exposición de información sensible.",
        "investigate": ["Determinar si los archivos fueron copiados, modificados o cifrados (4663 con tipo de acceso, tráfico saliente).", "Verificar si {user} tiene motivo operativo legítimo para ese recorrido."],
        "contain": ["Suspender {user} y limitar el acceso al recurso compartido."],
        "remediate": ["Alertar accesos masivos/secuenciales por cuenta y por ventana.", "Revisar permisos del recurso (mínimo privilegio) y habilitar auditoría de archivos críticos."],
    },
    "sensitive_share": {
        "impact": "Exposición potencial de información del recurso {share}; relevante sobre todo si forma parte de una cadena de ataque.",
        "investigate": ["Revisar qué archivos se abrieron y qué hizo {user} a continuación."],
        "contain": ["Restringir temporalmente el acceso de {user} al recurso si el incidente se confirma."],
        "remediate": ["Aplicar mínimo privilegio y auditoría detallada (5145) en recursos sensibles."],
    },
    "exfil_proxy": {
        "impact": "Salida de un volumen importante de datos hacia un destino no corporativo: posible fuga de información confidencial con impacto legal, contractual y reputacional.",
        "investigate": [
            "Identificar el contenido del archivo comprimido (ruta indicada en el hallazgo de staging) y qué datos incluía.",
            "Revisar el proxy para otras conexiones a {dest} y otros usuarios/hosts hacia ese destino.",
            "Evaluar la obligación de notificación si los datos incluyen información personal o contractual.",
        ],
        "contain": ["Bloquear {dest} en proxy y firewall.", "Aislar {host} y suspender la cuenta {user}."],
        "remediate": ["Controles DLP y alertas de volumen de salida (POST grandes a destinos nuevos).", "Filtrado de egreso por categoría/reputación y lista de destinos permitidos."],
    },
    "outbound_shell": {
        "impact": "Canal de salida desde un servidor hacia Internet iniciado por un intérprete de comandos: posible comando y control o envío de datos.",
        "investigate": ["Identificar qué datos se enviaron y el volumen (firewall/NetFlow) hacia {dest}.", "Revisar si otros hosts se comunican con {dest}."],
        "contain": ["Bloquear {dest} y aislar {host}."],
        "remediate": ["Restringir la salida de servidores a destinos explícitamente permitidos.", "Alertar conexiones salientes iniciadas por powershell/cmd."],
    },
    "persistence": {
        "impact": "El atacante mantiene acceso a {host} aunque se cambien contraseñas o se reinicie el equipo; la ejecución periódica sugiere comunicación recurrente con un controlador.",
        "investigate": [
            "Obtener y analizar wuhelper.exe y updatecheck.ps1 (hash, firma, contenido) y revisar qué hace cada ejecución.",
            "Revisar las conexiones de red de esos procesos en {host} y quién autorizó a {user} a crear tareas/servicios.",
            "Buscar la misma tarea/servicio en otros servidores.",
        ],
        "contain": ["Aislar {host}.", "Deshabilitar la cuenta {user}."],
        "remediate": [
            "Eliminar la tarea programada y el servicio, y borrar los binarios de ProgramData tras preservar evidencia.",
            "Restringir la creación de servicios/tareas a cuentas administrativas y vigilar 4698/7045.",
            "Bloquear ejecución desde ProgramData mediante AppLocker/WDAC.",
        ],
    },
    "web_attack": {
        "impact": "Reconocimiento y explotación de la aplicación web: riesgo de ejecución de comandos, exposición de datos (/api/v1/export) y acceso al panel de administración.",
        "investigate": ["Revisar los logs IIS completos de {ip} y las respuestas 200 a /uploads/ y /api/v1/export (qué datos devolvieron).", "Confirmar si /uploads/test.aspx existe en el servidor."],
        "contain": ["Bloquear {ip} y poner la aplicación en modo protegido (WAF/mantenimiento)."],
        "remediate": ["Desplegar WAF, limitar el acceso a /admin/ por origen y revisar la carga de archivos.", "Parchear y revisar el código de /login y /api/v1/export."],
    },
    "dq_host_alias": {
        "impact": "Las variantes de nombre fragmentan las correlaciones por host y pueden ocultar actividad.",
        "investigate": ["Confirmar con el equipo de infraestructura si DC-01 y DC01 son el mismo servidor."],
        "contain": [],
        "remediate": ["Normalizar el nombre de host en el parser/SIEM."],
    },
    "dq_logsource": {
        "impact": "Un origen de log incoherente puede indicar un error de parseo o inserción de eventos.",
        "investigate": ["Verificar el evento en el host de origen."],
        "contain": [],
        "remediate": ["Validar el mapeo de fuentes de log del conector."],
    },
    "dq_account_lookalike": {
        "impact": "Posible confusión entre cuentas; si una fuera fraudulenta, dificultaría la detección.",
        "investigate": ["Consultar en Active Directory quién creó cada cuenta, cuándo y con qué permisos."],
        "contain": [],
        "remediate": ["Definir una convención de nombres y revisar las cuentas de servicio."],
    },
    "siem_underclass": {
        "impact": "El SIEM no habría priorizado estos comportamientos: el equipo podría no enterarse de actividad maliciosa.",
        "investigate": ["Revisar qué reglas del SIEM generan estos eventos y con qué severidad."],
        "contain": [],
        "remediate": ["Crear/ajustar reglas de correlación para los patrones detectados (persistencia, compresión, accesos externos exitosos)."],
    },
}

GENERIC = {
    "impact": "Actividad que requiere validación por parte del equipo de seguridad.",
    "investigate": ["Revisar las evidencias citadas y el contexto de {host} y {user}."],
    "contain": ["Evaluar el aislamiento de {host} si se confirma actividad maliciosa."],
    "remediate": ["Definir controles preventivos según la causa raíz."],
}

GENERAL_RECOMMENDATIONS = {
    "brute_force": "Habilitar MFA para todo acceso remoto y bloqueo inteligente de cuentas; alertar ráfagas de 4625 por IP de origen.",
    "external_logon": "Eliminar la exposición directa de RDP/servicios administrativos a Internet (VPN o ZTNA con MFA) y revisar las reglas de firewall de entrada.",
    "privilege": "Aplicar mínimo privilegio, separar cuentas administrativas de las de uso diario y gestionar accesos privilegiados (PAM).",
    "lateral": "Segmentar la red entre servidores, restringir SMB/administración remota y usar contraseñas de administrador únicas por host (LAPS).",
    "cmd_encoded_ps": "Activar PowerShell Script Block Logging, AMSI y Constrained Language Mode; aplicar AppLocker/WDAC para limitar la ejecución.",
    "exfil_proxy": "Implementar DLP y filtrado de salida (egress) con alertas por volumen de subida y destinos nuevos.",
    "persistence": "Monitorear 4698/7045, restringir la creación de servicios/tareas y bloquear la ejecución desde ProgramData/Temp.",
    "web_attack": "Proteger las aplicaciones expuestas con WAF, impedir ejecución en directorios de subida y ejecutar los pools con mínimo privilegio.",
    "cmd_anti_recovery": "Mantener backups offline e inmutables, probar la restauración y alertar de inmediato cualquier uso de vssadmin/wbadmin delete.",
    "siem_underclass": "Revisar la severidad y las reglas de correlación del SIEM: varios eventos que sustentan incidentes quedaron como Informational.",
    "dq_host_alias": "Normalizar nombres de host y fuentes de log en el pipeline del SIEM para no fragmentar correlaciones.",
}


# Hallazgos de fuentes que no son de Windows (backend/detection_generic.py).
def _pb(impact, investigate, contain, remediate):
    return {"impact": impact, "investigate": investigate, "contain": contain, "remediate": remediate}


PLAYBOOK.update({
    "g_auth": _pb(
        "Riesgo de obtener credenciales válidas sin explotar ninguna vulnerabilidad. Si hubo un acceso exitoso, el atacante opera con una identidad legítima y puede escalar o moverse a otros equipos.",
        ["Revisar en el servidor destino todos los intentos y accesos de {ip}, y confirmar qué cuentas llegaron a autenticarse.",
         "Reconstruir lo ejecutado por {user} tras el acceso exitoso (shell, comandos, cambios de configuración).",
         "Consultar inteligencia de amenazas sobre {ip}."],
        ["Bloquear {ip} en el firewall o en la regla de acceso del servicio.", "Deshabilitar la cuenta {user} y cerrar sus sesiones activas."],
        ["Exigir MFA o claves en lugar de contraseñas para acceso remoto; deshabilitar el acceso directo de root/administrador.",
         "Restringir el servicio a una VPN o a una lista de orígenes permitidos y activar bloqueo por intentos (fail2ban o equivalente)."]),
    "g_web": _pb(
        "Una aplicación expuesta está siendo atacada; si la explotación tuvo éxito, el atacante puede leer o modificar la base de datos y ejecutar código en {host}.",
        ["Revisar los logs de la aplicación y de la base de datos de {host} a partir del primer intento de {ip}.",
         "Confirmar qué respondió el servidor a cada petición y si hubo consultas anómalas después."],
        ["Bloquear {ip} en el WAF o el perímetro.", "Si hubo consultas a datos sensibles, aislar {host} y rotar las credenciales de la base de datos."],
        ["Usar consultas parametrizadas y validación de entrada; desplegar un WAF con reglas de inyección.",
         "Dar a la cuenta de la aplicación solo los permisos mínimos sobre la base de datos."]),
    "g_exfil": _pb(
        "Datos salieron de la organización hacia un destino externo: posible fuga de información sensible con impacto legal y reputacional.",
        ["Identificar qué datos se consultaron justo antes de la transferencia y su clasificación.", "Revisar el tráfico de {src} hacia {ip} y si hubo otras transferencias previas."],
        ["Bloquear el destino {ip} en el egress.", "Aislar {src} y preservar la evidencia."],
        ["Implementar DLP y alertas por volumen de salida y destinos nuevos.", "Restringir el egress a destinos autorizados."]),
    "g_phishing": _pb(
        "Un correo con adjunto malicioso llegó a un usuario; si se ejecutó, el equipo del usuario queda comprometido y es el punto de partida del atacante.",
        ["Buscar el mismo remitente y adjunto en otros buzones.", "Revisar qué ejecutó el equipo de {user} después de abrir el adjunto y a qué destinos se conectó."],
        ["Eliminar el correo de todos los buzones y bloquear el remitente.", "Aislar el equipo de {user} si el adjunto se ejecutó."],
        ["Bloquear en el gateway de correo adjuntos ejecutables y de doble extensión.", "Capacitación breve de phishing y botón de reporte para los usuarios."]),
    "g_cmd": _pb(
        "Ejecución de comandos de ataque en {host}: descarga de herramientas, evasión de controles o robo de credenciales.",
        ["Recuperar el comando completo, el proceso padre y las conexiones de red de {host}.", "Revisar qué archivos se descargaron y ejecutaron después."],
        ["Aislar {host} de la red.", "Deshabilitar la cuenta {user} mientras se investiga."],
        ["Restringir la ejecución de scripts (políticas de ejecución firmadas, WDAC/AppLocker).", "Alertar PowerShell con bypass de política y descargas desde Internet."]),
    "g_c2": _pb(
        "{host} mantiene comunicación periódica con infraestructura externa asociada a comando y control: el atacante puede controlar el equipo y recibir instrucciones.",
        ["Identificar el proceso que origina la conexión en {host} y desde cuándo ocurre.", "Consultar inteligencia de amenazas sobre {ip}."],
        ["Bloquear {ip} en el egress.", "Aislar {host}."],
        ["Inspeccionar y filtrar el tráfico saliente; alertar beaconing periódico a destinos poco frecuentes."]),
    "g_persistence": _pb(
        "El atacante asegura que su código vuelva a ejecutarse tras reiniciar o cerrar sesión en {host}.",
        ["Obtener el binario o comando que apunta la entrada de persistencia y analizarlo.", "Buscar la misma entrada en otros equipos."],
        ["Aislar {host} y eliminar la entrada de persistencia tras preservar evidencia."],
        ["Monitorear cambios en claves Run, tareas programadas y authorized_keys."]),
    "g_share_probe": _pb(
        "Reconocimiento de recursos administrativos: suele preceder al movimiento lateral con credenciales robadas.",
        ["Revisar si {src} obtuvo acceso a alguno de esos equipos después.", "Confirmar qué cuenta se usó para los intentos."],
        ["Aislar {src} si el equipo no debería escanear la red."],
        ["Restringir SMB entre estaciones de trabajo y deshabilitar los recursos administrativos donde no se necesiten."]),
    "g_ransomware": _pb(
        "Cifrado de datos con fines de extorsión en {host}: pérdida de disponibilidad de la información y riesgo de que se extienda por la red.",
        ["Determinar el origen del cifrado (cuenta {user}, proceso) y cuántos equipos y recursos compartidos alcanzó.", "Verificar el estado de las copias de seguridad y si el borrado de instantáneas afectó otros hosts."],
        ["Aislar {host} de inmediato y deshabilitar la cuenta {user}.", "No apagar el equipo hasta preservar memoria si es posible."],
        ["Mantener copias offline e inmutables y probar la restauración.", "Segmentar la red y limitar los permisos de escritura en recursos compartidos."]),
    "g_mining": _pb(
        "Uso no autorizado de recursos de {host} para minar criptomonedas: degradación del servicio y señal de que alguien ejecutó código en el servidor.",
        ["Determinar cómo llegó el minero a {host} (vulnerabilidad web, credencial, descarga).", "Revisar si hay otros equipos que se conectan al mismo pool."],
        ["Aislar {host}, finalizar el proceso y bloquear el pool en el egress."],
        ["Corregir la vía de entrada y monitorear CPU sostenida y conexiones stratum."]),
    "g_privesc": _pb(
        "Un usuario obtuvo privilegios de root en {host} y accedió a archivos de credenciales: el atacante puede suplantar cuentas y moverse a otros sistemas.",
        ["Identificar el binario SUID o el método usado por {user} y cómo llegó a ese acceso.", "Revisar qué credenciales se leyeron y si se reutilizan en otros sistemas."],
        ["Aislar {host} y deshabilitar la cuenta {user}.", "Rotar las contraseñas almacenadas en los archivos leídos."],
        ["Auditar y quitar bits SUID innecesarios; restringir sudo.", "Alertar lecturas de /etc/shadow por cuentas no administrativas."]),
    "g_dns_tunnel": _pb(
        "Canal encubierto por DNS en {host}: permite comando y control o exfiltración saltándose los controles de salida habituales.",
        ["Identificar el proceso de {host} que genera las consultas.", "Cuantificar el volumen consultado hacia el dominio sospechoso."],
        ["Bloquear el dominio en el DNS corporativo y aislar {host}."],
        ["Forzar el uso del DNS corporativo y bloquear DNS saliente directo; alertar consultas largas y de alta entropía."]),
    "g_cloud": _pb(
        "Una identidad cloud fue usada para sondear permisos y luego modificar políticas o crear credenciales: riesgo de control persistente del entorno cloud.",
        ["Revisar en CloudTrail (o equivalente) todas las acciones de {user} y desde qué IPs.", "Verificar si las claves o políticas creadas siguen activas."],
        ["Deshabilitar las claves de acceso de {user}, revertir los cambios de políticas y revocar sesiones."],
        ["Aplicar mínimo privilegio a cuentas de servicio y exigir MFA.", "Alertar cambios de políticas IAM y creación de claves."]),
})

GENERAL_RECOMMENDATIONS.update({
    "g_auth": "Exigir MFA o claves SSH, deshabilitar el acceso directo de root/administrador, exponer los servicios solo por VPN y bloquear orígenes tras ráfagas de fallos.",
    "g_web": "Proteger las aplicaciones con WAF, consultas parametrizadas y permisos mínimos en la base de datos.",
    "g_exfil": "Implementar DLP y filtrado de salida con alertas por volumen y destinos nuevos.",
    "g_phishing": "Bloquear adjuntos ejecutables y de doble extensión en el correo y reforzar el reporte de phishing.",
    "g_ransomware": "Mantener backups offline e inmutables, probar la restauración y segmentar la red.",
    "g_privesc": "Auditar bits SUID y sudo, y alertar lecturas de archivos de credenciales por cuentas no administrativas.",
    "g_dns_tunnel": "Forzar el DNS corporativo y alertar consultas largas y de alta entropía.",
    "g_cloud": "Aplicar mínimo privilegio a identidades cloud y alertar cambios de políticas IAM y creación de claves.",
    "g_mining": "Monitorear CPU sostenida y conexiones a pools de minería; corregir la vía de entrada.",
})
