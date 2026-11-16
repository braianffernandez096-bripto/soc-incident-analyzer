# Medir los falsos positivos en tu laboratorio

La validación con OTRF ([VALIDACION.md](VALIDACION.md)) mide si las reglas detectan ataques reales, pero esos datos son **todo ataque**: no
dicen cuánto ruido genera la app sobre actividad normal ni si la confianza baja cuando la actividad es legítima. Esta guía mide eso con
tu propio laboratorio de Wazuh, en dos partes:

1. **Jornada normal:** 24 a 48 horas de uso habitual. Lo ideal es que no aparezca ningún hallazgo.
2. **Tareas de administración legítimas:** tareas reales de un administrador que tocan justo las reglas más propensas a ruido.
   Muchas **van a alertar**, y está bien: un servicio nuevo o una sesión de PowerShell remoto se ven igual cuando los hace un atacante.
   Lo que se mide es **con qué criticidad y confianza** aparecen. Una tarea legítima debería quedar en confianza Media o Baja, con su motivo en contra.

La herramienta (`backend/medicion_fp.py`) corre dentro del contenedor del analizador, usa la conexión al Indexer que ya tienes en el `.env`
y **no guarda los eventos**: lee, analiza en memoria e imprime la medición. Tampoco consulta servicios externos: MISP queda apagado
mientras mide (los datos del laboratorio no salen del servidor), así que la regla de indicadores de MISP no entra en la medición.

> Todos los comandos son de una línea. Los de Windows van en **PowerShell como administrador**; los del servidor, por SSH en el Ubuntu Server.
> La guía usa un laboratorio con **un Windows 10** (el equipo medido, `WIN10` en los ejemplos) y un **Linux de escritorio** que hace de
> equipo de administración para las tareas remotas (con las herramientas de Samba). Cambia `WIN10` por el nombre del agente de Wazuh y
> `IP-WIN10` por la IP del Windows. Si tienes un segundo Windows, la sección 3.3 agrega PowerShell remoto y WMI remoto.

## 1. Requisitos previos (una sola vez)

Sin estos eventos, varias reglas no pueden verse y la medición daría un «cero» que no prueba nada. La herramienta avisa de los que falten.

**En el Windows** (PowerShell como administrador):

Auditar el acceso a recursos compartidos (evento 5145):
```
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```
Auditar la creación de procesos (evento 4688):
```
auditpol /set /subcategory:"Process Creation" /success:enable
```
Incluir la línea de comandos en el 4688:
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**En el agente de Wazuh del Windows:** por defecto, el agente **descarta el 5145**. Abre `C:\Program Files (x86)\ossec-agent\ossec.conf`
con el Bloc de notas como administrador, busca el bloque `<location>Security</location>` y, en su línea `<query>`, borra el texto
`EventID != 5145 and ` (con el espacio y el `and`). Guarda y reinicia el agente:
```
Restart-Service -Name WazuhSvc
```

**En el servidor:** el índice de *archives* tiene que estar activo (`<logall_json>yes</logall_json>` en el manager y los archivos habilitados en
Filebeat; ver [WAZUH.md](WAZUH.md)), y el `.env` del analizador tiene que tener la conexión al Indexer (`WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`,
`WAZUH_INDEXER_PASSWORD`). Si ya usas «Ver contexto en Wazuh», está listo.

Comprueba que funciona con una medición corta de la última hora (cambia las fechas por la hora actual):
```
sudo docker exec soc-incident-analyzer-analyzer-1 python -m backend.medicion_fp --agente WIN10 --desde 2026-11-16T09:00-03:00 --hasta 2026-11-16T10:00-03:00 --sin-detalle
```
En «Tipos de evento recibidos» tienen que aparecer con ✔ al menos el 4624, el 4688 con línea de comandos y, después de usar un recurso
compartido, el 5145. Si usas Sysmon, también su evento 1. Cómo leer esa lista:

- **✔**: llegaron eventos de ese tipo.
- **✘ requisito sin cumplir**: es un tipo que solo llega si Windows y el agente lo auditan (5145, 4688 con línea de comandos, Sysmon). Las
  reglas que dependen de él **no se midieron**: revisa la configuración de esta sección.
- **· no ocurrió en este rango**: es un tipo que aparece cuando pasa la acción (inicios fallidos, servicios o tareas nuevas). En una hora
  tranquila es normal que esté en 0.

Las horas del detalle se muestran en la zona horaria que pongas en `--desde`. Si sale «No se leyó ningún evento», el nombre del agente
no coincide (tiene que ser exacto: `sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l` los lista) o el rango
no tiene datos.

Ojo con los `:` de las horas: si por error escribes `-03>00`, la terminal guarda la salida en un archivo llamado `00` en vez de mostrarla
(se lee con `cat 00` y se borra con `rm 00`).

## 2. Jornada normal

Usa los equipos como siempre durante 24 a 48 horas (navegar, abrir programas, dejar que Windows se actualice) **sin hacer tareas de
administración**. Anota la hora de inicio y de fin, y mide:
```
sudo docker exec soc-incident-analyzer-analyzer-1 python -m backend.medicion_fp --agente WIN10 --desde 2026-11-16T09:00-03:00 --hasta 2026-11-17T09:00-03:00 --etiqueta "jornada normal"
```
Si el Linux de escritorio también tiene agente de Wazuh, agrega otro `--agente` con su nombre: suma su actividad normal (inicios de sesión,
`sudo`, SSH) a la medición.

Si el rango supera los 100.000 eventos, la herramienta avisa: divídelo en dos mediciones (por ejemplo, de 12 horas).

## 3. Tareas de administración legítimas

Hazlas en una misma sesión, **anotando la hora de inicio y de fin**. Cada una es algo que un administrador hace de verdad.

### 3.1 En el Windows

1. Tarea programada de mantenimiento:
   ```
   schtasks /create /tn "Limpieza semanal" /tr "C:\Windows\System32\cleanmgr.exe /sagerun:1" /sc weekly /d SUN /st 03:00 /f
   ```
2. Regla de firewall para una aplicación:
   ```
   netsh advfirewall firewall add rule name="App de prueba" dir=in action=allow protocol=TCP localport=8080
   ```
3. Servicio nuevo:
   ```
   sc.exe create PruebaLegitima binPath= "C:\Windows\System32\notepad.exe" start= demand
   ```
4. Comandos de soporte técnico, uno por vez: `whoami /all`, `ipconfig /all`, `systeminfo` y `net user`.
5. Contraseña mal escrita: bloquea la sesión (Windows + L), escribe mal la contraseña **tres veces** y después entra bien.
6. Preparar la administración remota desde el Linux (la carpeta de la copia, el puerto de archivos compartidos solo para la IP del
   Linux y el permiso para que una cuenta local administre por red, que Windows bloquea por defecto fuera de un dominio):
   ```
   mkdir C:\Temp
   ```
   ```
   New-NetFirewallRule -DisplayName "SMB desde el Linux del lab" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress IP-LINUX -Action Allow
   ```
   ```
   reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
   ```
   Este último cambio debilita la seguridad del equipo: se revierte en la limpieza.

### 3.2 Desde el Linux de escritorio

7. Instalar las herramientas de Samba:
   ```
   sudo apt install -y smbclient samba-common-bin
   ```
8. Consultar un servicio del Windows por la red (usa el administrador de servicios remoto, como `sc \\equipo`). Te pide la contraseña de la cuenta de Windows:
   ```
   net rpc service status wuauserv -I IP-WIN10 -U usuario
   ```
9. Copiar un instalador al Windows por su recurso administrativo:
   ```
   smbclient //IP-WIN10/C$ -U usuario -c "put /usr/bin/true Temp/instalador-prueba.exe"
   ```

Mide la sesión, con un margen de unos minutos antes y después:
```
sudo docker exec soc-incident-analyzer-analyzer-1 python -m backend.medicion_fp --agente WIN10 --desde 2026-11-16T15:00-03:00 --hasta 2026-11-16T16:00-03:00 --etiqueta "tareas de administración"
```

**Limpieza en el Windows** al terminar, en este orden:
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
```
```
Remove-NetFirewallRule -DisplayName "SMB desde el Linux del lab"
```
```
schtasks /delete /tn "Limpieza semanal" /f
```
```
netsh advfirewall firewall delete rule name="App de prueba"
```
```
sc.exe delete PruebaLegitima
```
```
del C:\Temp\instalador-prueba.exe
```

### 3.3 Opcional: con un segundo Windows

Con un segundo Windows (`WIN-A`) que administra al primero, se miden también PowerShell remoto y WMI remoto. En el Windows medido:
`Enable-PSRemoting -Force`. En `WIN-A`, fuera de un dominio: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value WIN10 -Force`, y luego:
```
Invoke-Command -ComputerName WIN10 -ScriptBlock { Get-Service wuauserv } -Credential (Get-Credential)
```
```
Invoke-CimMethod -ComputerName WIN10 -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="ipconfig.exe /all"}
```
Sin un segundo Windows, esas dos reglas (`lat_winrm` y `lat_wmi` remoto) quedan **sin medir** con actividad legítima, y así se publica.

**Por qué no usar Kali para esto:** sus herramientas de ataque (`wmiexec`, `evil-winrm`, `psexec.py`) dejan huellas propias de un atacante,
y la medición es de actividad **legítima**. Kali sirve para otra medición: ataques reales contra el laboratorio, para medir la detección.

## 4. Qué compartir y cómo se usa

La salida tiene los totales, la cobertura y el detalle de cada hallazgo: regla, criticidad, confianza, título, hasta tres ejemplos de lo
que lo disparó (por ejemplo, los comandos) y los motivos en contra.
Los títulos nombran equipos y cuentas de tu laboratorio; los eventos crudos nunca salen del servidor.

Con cada hallazgo se decide una de dos cosas:

- **Calibrar la regla:** se cambia la regla o la confianza con una prueba negativa escrita a partir del patrón (sin copiar tus datos) y
  se comprueba con la vara del CI que no se pierde detección en OTRF.
- **Aceptarlo y documentarlo:** cuando lo legítimo y el ataque son indistinguibles con esos eventos (por ejemplo, PsExec de un
  administrador), se deja y se explica en [VALIDACION.md](VALIDACION.md), sección 3.

En [VALIDACION.md](VALIDACION.md) se publica solo la tabla agregada (eventos, hallazgos por cada 1.000 eventos, por regla, criticidad y
confianza), sin nombres de tus equipos ni cuentas.

## Opciones

| Opción | Para qué |
|---|---|
| `--agente` | Agente de Wazuh a medir (repetible) |
| `--desde`, `--hasta` | Rango, con zona horaria (`-03:00`); sin zona se toma como UTC |
| `--indice alertas` | Medir solo lo que generó alerta en Wazuh, en vez de todos los eventos |
| `--etiqueta` | Nombre de la medición en la salida |
| `--sin-detalle` | Solo totales y cobertura, sin la lista de hallazgos |
| `--json` | Salida en JSON |
| `--max-eventos` | Tope de eventos (100.000 como máximo, el mismo que un archivo cargado a mano) |
