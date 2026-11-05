# Validación de las reglas de detección

Este documento mide qué tan bien detectan las reglas y cuánto ruido generan, con datos que **no escribí yo**. Los números salen de las pruebas
reproducibles de este repositorio: `tests/unit/test_negativos.py` y `scripts/validar_datasets.py`.

Resumen honesto: las reglas **funcionan bien contra los ataques para los que fueron diseñadas** (fuerza bruta, descarga de código, volcado de
credenciales, acceso a LSASS, DCSync, tareas programadas y claves Run), **no cubren muchas técnicas** (sobre todo evasión de defensas y
movimiento lateral) y mantienen unas pocas decisiones de diseño que generan alertas con actividad legítima (sección 3). La versión 1.5.0
calibró los 5 falsos positivos que midió la primera versión de este documento y cubrió los huecos de credenciales; el antes y el después
están en la sección 2.1.

## 1. SSH real (Loghub, `OpenSSH_2k.log`)

Un servidor OpenSSH expuesto a Internet, con ataques reales. Se convirtió cada «Failed/Accepted password» en un evento y se calculó **por
separado** qué IPs hicieron 3 o más fallos con huecos de hasta 10 minutos, para compararlo con lo que reporta la regla de autenticación.

| Medida | Resultado |
|---|---|
| Eventos de autenticación | 518 (517 fallos, 1 acceso) |
| IPs distintas con fallos | 23 |
| IPs con ráfaga real (≥3 fallos) | 11 |
| Detectadas por la app | **11 de 11** |
| Falsos positivos / omitidas | **0 / 0** |

Límite: la verdad se calculó con el mismo umbral de la regla, así que esto valida el procesamiento, el agrupamiento y la severidad con datos
reales, **no** el umbral en sí. Es un servidor de prueba: casi no hay tráfico legítimo.

## 2. Ataques de Windows etiquetados (OTRF Security-Datasets)

107 datasets de laboratorio (Windows, host) donde un adversario ejecuta una técnica ATT&CK conocida (Empire, Covenant, Mimikatz, etc.). Cada
uno declara su técnica en un metadato. Se comparó con las técnicas que cita la app:

- **técnica**: algún hallazgo cita la misma técnica (o su técnica padre);
- **táctica**: no la misma técnica, pero sí un hallazgo de la misma táctica;
- **otros**: hay hallazgos, pero de otra técnica;
- **ninguno**: la app no reportó nada.

| Resultado | Datasets | % |
|---|---|---|
| Misma técnica | 19 | 18 % |
| Misma táctica | 3 | 3 % |
| Otra técnica | 27 | 25 % |
| Sin hallazgos | 58 | 54 % |

(Resultados con la versión 1.5.0. Antes de la calibración: 13 / 2 / 39 / 53; ver sección 2.1.)

Por táctica del dataset:

| Táctica | Datasets | Técnica | Táctica | Otros | Ninguno |
|---|---|---|---|---|---|
| Evasión de defensas | 37 | 0 | 0 | 11 | 26 |
| Movimiento lateral | 26 | 1 | 2 | 10 | 13 |
| Acceso a credenciales | 21 | 9 | 0 | 4 | 8 |
| Descubrimiento | 9 | 4 | 0 | 0 | 5 |
| Persistencia | 7 | 4 | 1 | 1 | 1 |
| Ejecución | 4 | 1 | 0 | 0 | 3 |
| Escalamiento de privilegios | 2 | 0 | 0 | 1 | 1 |
| Recolección | 1 | 0 | 0 | 0 | 1 |

**Cómo leerlo.** Es una medida **estricta y de cobertura**, no de corrección: muchos datasets ejercitan técnicas que la app no pretende cubrir
(inyección de procesos, binarios de confianza como `mshta`, cambios en el registro de eventos). «Otra técnica» suele ser una detección
genuina pero distinta (por ejemplo, un servicio nuevo detectado como persistencia cuando el dataset es de movimiento lateral). Aun así, hay
**huecos concretos dentro del alcance** de la herramienta:

| Hueco que sigue abierto | Evidencia |
|---|---|
| Mimikatz sin acceso a LSASS visible | `extract_keys`, `sam_access`, `dcsync` de Empire y `over_pth_patch_lsass` ya no generan hallazgos incidentales y tampoco el correcto: requieren eventos que el export de ejemplo no trae |
| Pass-the-hash / Kerberoasting / ticket (4768/4769) | Sin reglas |
| Modificación de tareas programadas | Solo se detecta la creación (4698), no el cambio |
| Suscripciones WMI persistentes | Se reporta como persistencia (misma táctica), pero no la técnica T1546.003 |
| Evasión de defensas | 26 de 37 sin hallazgos |

### 2.1 Antes y después de la calibración (1.5.0)

Mismos 107 datasets, mismo script, mismo criterio:

| Resultado | Antes | Después |
|---|---|---|
| Misma técnica | 13 | **19** |
| Misma táctica | 2 | **3** |
| Otra técnica | 39 | 27 |
| Sin hallazgos | 53 | 58 |

Qué cambió y por qué:

- **Ganancias reales (+6 técnica):** `reg.exe" save HKLM\sam` entre comillas, `esentutl` sobre SAM/NTDS, Dumpert, acceso a LSASS (Sysmon 10),
  DCSync (4662) y claves Run (Sysmon 13). Las reglas nuevas se probaron contra los 107 datasets: `cred_lsass` solo dispara en volcados de
  LSASS (más un caso de `wsmprovhost.exe` con acceso total a LSASS en un dataset de PowerShell remoting, que se considera legítimo de
  investigar), `cred_dcsync` en el DCSync de Covenant y `persist_run` en los datasets de claves Run y de suscripción WMI.
- **«Otra técnica» baja de 39 a 27 por menos ruido, no por menos detección:** 9 datasets tenían como único hallazgo un «comando de
  reconocimiento» suelto (`whoami`, `ipconfig`) ajeno a la técnica del ataque. Ese ruido ya no se reporta, así que pasan a «sin hallazgos».
  La enumeración de dominio (`net user`, `nltest`, `Get-AD*`) sigue alertando con un solo comando.
- **Un empeoramiento:** `purplesharp_ad_playbook_I` (técnica → ninguno). Coincidía solo porque un `whoami` suelto citaba T1135; era una
  coincidencia, no una detección del ataque real (Kerberoasting y password spraying).
- **Los 5 falsos positivos conocidos desaparecen** (sección 3) y se agregaron pruebas de que la calibración no apaga la detección real.

## 3. Tráfico normal (falsos positivos)

`tests/unit/test_negativos.py` ejecuta actividad corriente cerca de los umbrales de cada regla: un día normal, 2 fallos externos, 9 fallos
internos, fallos espaciados, IP privadas, comandos legítimos, descargas entrantes, DNS de CDN, llamadas normales a la nube, etc.

- **30 casos de actividad normal no generan ningún hallazgo** (prueba verde).
- **5 falsos positivos medidos en 1.4.0, calibrados en 1.5.0** (ahora son pruebas normales que deben seguir en verde):

| Actividad normal | Qué se hizo |
|---|---|
| Un solo `ipconfig /all`, `whoami`, `tasklist`… de un usuario de soporte | Los comandos de información local necesitan ≥3 en el mismo grupo u origen externo; los de enumeración de dominio siguen alertando solos |
| `7z a backup.7z` de un usuario | El «staging» se descarta salvo origen externo, ruta temporal/ProgramData, contraseña (`-p`), ≥3 comandos o conexión saliente posterior |
| Tarea programada de Windows Update creada por SYSTEM | Se ignoran las tareas `\Microsoft\Windows\…` creadas por SYSTEM |
| `curl` a un repositorio interno (`.tar.gz`) | La regla de compresión exige que el archivador sea el comando, no que el nombre de archivo termine en `.tar.gz` |

Pruebas inversas (`test_discovery_burst_still_alerts`, `test_staging_in_temp_still_alerts`, etc.) fijan que el ruido bajó sin apagar la alerta real.

Otros casos que se observaron y **no** se marcaron como errores porque son decisiones de diseño discutibles:

- 3 fallos desde una IP pública seguidos de un acceso exitoso del mismo usuario generan Alto: es el patrón de un ataque exitoso y se prefiere
  alertar (la prueba `test_failures_then_success_from_public_ip_is_flagged_on_purpose` lo fija).
- 9 fallos de RDP desde un equipo interno generan Medio en la regla genérica.
- 30 MB salientes a un servicio legítimo (OneDrive) generan Alto por superar el umbral, sin lista de destinos conocidos.
- Una administradora que crea su propia clave de acceso en la nube genera Crítico.
- Un instalador legítimo que agrega una clave Run genera Medio (`persist_run` solo sube a Alto si el binario está en una ruta escribible o lo escribió un intérprete); sigue apareciendo para que el analista lo descarte.

## 4. Cobertura ATT&CK

La app cita **50 técnicas** de ATT&CK en **29 reglas** (16 para exports de Windows y 13 para exports multi-fuente). No cubre la matriz
completa y no pretende hacerlo:

| Táctica | Técnicas citadas | Cuáles |
|---|---|---|
| Reconocimiento | 1 | T1598.003 Spearphishing Link |
| Acceso inicial | 6 | T1078 Valid Accounts; T1078.004 Cloud Accounts; T1190 Exploit Public-Facing Application; T1566 Phishing; T1566.001 Spearphishing Attachment; T1566.002 Spearphishing Link |
| Ejecución | 5 | T1053.005 Scheduled Task; T1059 Command and Scripting Interpreter; T1059.001 PowerShell; T1204.001 Malicious Link; T1204.002 Malicious File |
| Persistencia | 8 | T1053.005 Scheduled Task; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1098 Account Manipulation; T1098.004 SSH Authorized Keys; T1505.003 Web Shell; T1543.003 Windows Service; T1547.001 Registry Run Keys / Startup Folder |
| Escalamiento de privilegios | 9 | T1053.005 Scheduled Task; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1098 Account Manipulation; T1098.004 SSH Authorized Keys; T1134 Access Token Manipulation; T1543.003 Windows Service; T1547.001 Registry Run Keys / Startup Folder; T1548.001 Setuid and Setgid |
| Sigilo (evasión de defensas) | 10 | T1027 Obfuscated Files or Information; T1027.013 Encrypted/Encoded File; T1036 Masquerading; T1036.004 Masquerade Task or Service; T1036.007 Double File Extension; T1036.008 Masquerade File Type; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1134 Access Token Manipulation; T1684.001 Impersonation |
| Acceso a credenciales | 7 | T1003 OS Credential Dumping; T1003.001 LSASS Memory; T1003.006 DCSync; T1003.008 /etc/passwd and /etc/shadow; T1110 Brute Force; T1110.001 Password Guessing; T1110.003 Password Spraying |
| Descubrimiento | 3 | T1069 Permission Groups Discovery; T1087 Account Discovery; T1135 Network Share Discovery |
| Movimiento lateral | 2 | T1021.001 Remote Desktop Protocol; T1021.002 SMB/Windows Admin Shares |
| Recolección | 4 | T1005 Data from Local System; T1039 Data from Network Shared Drive; T1074.001 Local Data Staging; T1560.001 Archive via Utility |
| Comando y control | 3 | T1071.001 Web Protocols; T1071.004 DNS; T1105 Ingress Tool Transfer |
| Exfiltración | 1 | T1041 Exfiltration Over C2 Channel |
| Impacto | 4 | T1486 Data Encrypted for Impact; T1490 Inhibit System Recovery; T1496 Resource Hijacking; T1496.001 Compute Hijacking |

Sin cobertura (lista parcial): desarrollo de recursos, deterioro de defensas (T1562), gran parte de evasión de defensas (T1218 binarios de
confianza, T1055 inyección de procesos) y de movimiento lateral (T1021 sobre WMI/DCOM/WinRM, T1550 pass-the-hash).

## 5. Limitaciones de este método

- Son **datasets de laboratorio**, con un adversario por escenario y mucho ruido de fondo del propio laboratorio. No equivalen a un entorno real.
- Los datos de OTRF son eventos crudos de Windows y Sysmon, no un export de SIEM; la app los lee, pero no fue diseñada para todos sus campos.
- La comparación por técnica es estricta: un hallazgo útil de otra técnica cuenta como «otros». Por eso se reporta también cuántos datasets
  tienen hallazgos y cuáles.
- No hay un conjunto de **tráfico normal real** equivalente (solo el sintético de las pruebas negativas), así que la tasa de falsos positivos
  en producción es desconocida. Los casos de la sección 3 son pruebas puntuales, no una tasa.
- Los resultados dependen de la versión de la app (1.5.0) y de la versión de los datasets; se pueden regenerar.

## 6. Cómo reproducirlo

```bash
# Ataques de Windows etiquetados (OTRF)
git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets
cd Security-Datasets && git sparse-checkout set --no-cone 'datasets/atomic/_metadata/*' 'datasets/atomic/windows/*/host/*' && cd ..
python scripts/validar_datasets.py Security-Datasets --json resultados.json

# SSH real (Loghub)
git clone --depth 1 https://github.com/logpai/loghub
python scripts/validar_datasets.py --loghub loghub/OpenSSH/OpenSSH_2k.log

# Pruebas con tráfico normal
python -m pytest tests/unit/test_negativos.py
```

Los datasets son de terceros y **no se incluyen** en el repositorio: cada uno tiene su propia licencia; consúltala en sus repositorios antes de redistribuirlos.
