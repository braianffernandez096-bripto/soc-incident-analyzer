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
| Misma técnica | 20 | 19 % |
| Misma táctica | 3 | 3 % |
| Otra técnica | 27 | 25 % |
| Sin hallazgos | 57 | 53 % |

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
| Pass-the-hash | Sin regla a propósito: el inicio de sesión tipo 9 (`seclogo`) que deja es idéntico al de `runas /netonly`, de uso legítimo, y sin telemetría adicional no se distingue |
| Pass-the-ticket / AS-REP roasting (4768) | Sin reglas |
| Modificación de tareas programadas | Solo se detecta la creación (4698), no el cambio |
| Suscripciones WMI persistentes | Se reporta como persistencia (misma táctica), pero no la técnica T1546.003 |
| Evasión de defensas | 26 de 37 sin hallazgos |

### 2.1 Antes y después de la calibración (1.5.0)

Mismos 107 datasets, mismo script, mismo criterio:

| Resultado | Antes | Después |
|---|---|---|
| Misma técnica | 13 | **20** |
| Misma táctica | 2 | **3** |
| Otra técnica | 39 | 27 |
| Sin hallazgos | 53 | 57 |

Qué cambió y por qué:

- **Ganancias reales (+6 técnica):** `reg.exe" save HKLM\sam` entre comillas, `esentutl` sobre SAM/NTDS, Dumpert, acceso a LSASS (Sysmon 10),
  DCSync (4662) y claves Run (Sysmon 13). Las reglas nuevas se probaron contra los 107 datasets: `cred_lsass` solo dispara en volcados de
  LSASS (más un caso de `wsmprovhost.exe` con acceso total a LSASS en un dataset de PowerShell remoting, que se considera legítimo de
  investigar), `cred_dcsync` en el DCSync de Covenant y `persist_run` en los datasets de claves Run y de suscripción WMI.
- **«Otra técnica» baja de 39 a 27 por menos ruido, no por menos detección:** 9 datasets tenían como único hallazgo un «comando de
  reconocimiento» suelto (`whoami`, `ipconfig`) ajeno a la técnica del ataque. Ese ruido ya no se reporta, así que pasan a «sin hallazgos».
  La enumeración de dominio (`net user`, `nltest`, `Get-AD*`) sigue alertando con un solo comando.
- **`purplesharp_ad_playbook_I`:** antes coincidía por casualidad (un `whoami` suelto citaba T1135). Al calibrar quedó sin hallazgos y, con la regla
  nueva de Kerberoasting (4769, T1558.003), vuelve a coincidir, esta vez por la técnica real del ataque. Es el único dataset donde dispara
  `kerberoast`: sin falsos positivos en los otros 106.
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

## 3b. Correos reales (phishing y legítimos) y comandos ofuscados

**Phishing.** Se analizaron los **12.864 correos** del corpus público [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (phishing y spam recibidos de verdad)
con `scripts/validar_correos.py`, de forma estática y con la versión final de las reglas:

| Resultado | Correos | % |
|---|---|---|
| Crítico | 1.213 | 9,4 |
| Alto | 7.140 | 55,5 |
| Medio | 2.934 | 22,8 |
| Bajo (sin señales relevantes) | 1.575 | 12,2 |
| Rechazados por el propio análisis (no es un .eml / supera 5 MB) | 2 | 0,0 |

Detectados como **Medio o más: 87,7 %**; **Alto o más: 64,9 %**. Tiempo medio 0,11 s por correo y máximo 1,6 s.

**Correo legítimo (falsos positivos).** Se probaron **20 correos reales y legítimos** (boletines, LinkedIn, GitHub, cursos, alertas de empleo; todos con SPF, DKIM y DMARC en «pass»),
aportados por el autor. Con las reglas de la primera versión, **14 de 20 (70 %) salían como Medio o más**. Las causas y su corrección:
- Los envíos masivos pasan por plataformas de envío, así que «SPF/DKIM no se alinea», «Message-ID de otro dominio» o «Return-Path de otro dominio» son normales. Con **DMARC en «pass»** una de las dos ya
  está alineada y esas señales dejan de sumar; sin DMARC en «pass» siguen contando. El Reply-To hacia otro dominio baja de Alto a Medio solo con DMARC en «pass» y sin correo gratuito.
- El rastreo de clics (el texto del enlace muestra un sitio y el enlace pasa por un subdominio del propio remitente o de un servicio de envío conocido) ya no se trata como engaño.
  **Excepción importante:** si el texto del enlace habla de pagos, cuentas, facturas o inicio de sesión, sigue siendo señal de alto riesgo. Un primer arreglo sin esa excepción dejaba pasar
  un phishing real de «billing.spotify.com» enviado desde una plataforma legítima con DMARC en «pass».
- Mis propias señales nuevas hacían ruido: el relleno invisible de los boletines (`preheader`), el texto oculto, los dobles codificados `%25xx` en enlaces de rastreo y las cifras en las
  direcciones de rebote (VERP). Ahora el invisible solo cuenta si **parte palabras**, el texto oculto no suma puntos, la doble codificación solo importa si afecta al servidor y los rebotes no se evalúan como suplantación.

Resultado tras corregir: **0 de 20** (los 20 en Bajo). El precio: sobre el corpus de phishing la detección Medio o más bajó de 92,2 % a 87,7 %. Los correos que se dejaron de marcar son sobre todo
spam comercial (casinos, clínicas, ofertas) que antes salía «detectado» solo por señales débiles de desalineación, no por señales de phishing.

**Cómo se evitó engañarse.** Se ajustó mirando una muestra aleatoria de 1.500 correos y se comprobó con los **11.364 restantes**, que no se habían usado para ajustar: 87,6 % Medio o más y 64,8 % Alto o más,
prácticamente igual a la tasa global. Los 20 legítimos se usaron para ajustar y después para medir, así que **su 0 % no es una medición independiente**: es una prueba de que los falsos positivos
que se vieron están corregidos.

Lo que el corpus real enseñó (con pruebas en `tests/unit/test_casos_reales.py`):
- **Un fallo real:** una plantilla sin rellenar (`http://[placeholder_1]/`) hacía fallar el análisis de todo el correo. Ahora se marca como enlace inválido.
- **Falsos positivos propios:** los emoji (`❤️`, `⚠️`) usan un selector de variación legítimo y se marcaban como caracteres invisibles; y los espacios dentro de una plantilla (`{{{ pm:unsubscribe }}}`) se tomaban por ofuscación.
- **Huecos:** marcas muy suplantadas que no estaban (Ledger, MetaMask, Trust Wallet, Kraken, Bradesco, Correios…); nombres con selectores de variación o marcas combinantes; estafas de adelanto de pago sin ningún enlace;
  cebos de «reclamar tokens» o validar la billetera.
- **Ofuscación de URL en el mundo real:** aparecieron IP en octal y decimal (`http://0137.0323.0053.0062/` = 95.211.43.50), HTML smuggling y JavaScript ofuscado en adjuntos.

Límites: 20 correos son una muestra muy pequeña (el margen de error es grande: con 0 falsos positivos en 20, el límite superior razonable ronda el 15 %) y todos vienen de una sola bandeja de entrada
(boletines en español e inglés de ciberseguridad y empleo). Falta probar correo corporativo, bancario y de otros rubros. El corpus de phishing mezcla phishing con spam comercial: los 1.575 correos
sin señales son sobre todo spam sin enlaces peligrosos ni suplantación, que la herramienta no pretende filtrar como tal.

**Comandos ofuscados.** `scripts/validar_ofuscacion.py` pasa por el desofuscador los **1.360 comandos de cmd y PowerShell** de las pruebas públicas de
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (299 técnicas): 11 contienen alguna ofuscación que se resuelve, en 2 la ofuscación escondía un programa relevante
(ambos solo se detectan tras desofuscar) y ninguno de los otros 1.349 comandos genera la regla de «comando ofuscado» (sin falsos positivos en ese corpus). La corrida encontró dos
fallos propios que ya están corregidos: el desofuscador **dañaba** escapes legítimos de PowerShell (`` `r`n ``) y no entendía la ofuscación con el operador `-f` (`"{1}{0}" -f 'a','b'`), muy
usada por Invoke-Obfuscation. Es una muestra pequeña de ofuscación real (la mayoría de los comandos de Atomic no están ofuscados), por lo que mide falsos positivos mejor que cobertura.
Sigue sin resolverse todo lo que exige ejecutar código (ver sección 5).

## 4. Cobertura ATT&CK

La app cita **56 técnicas** de ATT&CK en **31 reglas** (18 para exports de Windows y 13 para exports multi-fuente). No cubre la matriz
completa y no pretende hacerlo:

| Táctica | Técnicas citadas | Cuáles |
|---|---|---|
| Reconocimiento | 1 | T1598.003 Spearphishing Link |
| Acceso inicial | 6 | T1078 Valid Accounts; T1078.004 Cloud Accounts; T1190 Exploit Public-Facing Application; T1566 Phishing; T1566.001 Spearphishing Attachment; T1566.002 Spearphishing Link |
| Ejecución | 6 | T1053.005 Scheduled Task; T1059 Command and Scripting Interpreter; T1059.001 PowerShell; T1059.007 JavaScript; T1204.001 Malicious Link; T1204.002 Malicious File |
| Persistencia | 8 | T1053.005 Scheduled Task; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1098 Account Manipulation; T1098.004 SSH Authorized Keys; T1505.003 Web Shell; T1543.003 Windows Service; T1547.001 Registry Run Keys / Startup Folder |
| Escalamiento de privilegios | 9 | T1053.005 Scheduled Task; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1098 Account Manipulation; T1098.004 SSH Authorized Keys; T1134 Access Token Manipulation; T1543.003 Windows Service; T1547.001 Registry Run Keys / Startup Folder; T1548.001 Setuid and Setgid |
| Sigilo (evasión de defensas) | 13 | T1027 Obfuscated Files or Information; T1027.006 HTML Smuggling; T1027.010 Command Obfuscation; T1027.013 Encrypted/Encoded File; T1036 Masquerading; T1036.004 Masquerade Task or Service; T1036.007 Double File Extension; T1036.008 Masquerade File Type; T1078 Valid Accounts; T1078.004 Cloud Accounts; T1134 Access Token Manipulation; T1140 Deobfuscate/Decode Files or Information; T1684.001 Impersonation |
| Acceso a credenciales | 8 | T1003 OS Credential Dumping; T1003.001 LSASS Memory; T1003.006 DCSync; T1003.008 /etc/passwd and /etc/shadow; T1110 Brute Force; T1110.001 Password Guessing; T1110.003 Password Spraying; T1558.003 Kerberoasting |
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
- **Ofuscación: lo que se resuelve y lo que no.** Se normalizan estáticamente: IP numéricas en URL (decimal, hexadecimal, octal, abreviada, IPv6 mapeada), `%XX` en el host o repetido, caracteres invisibles y entidades en el esquema, `^` de cmd, acentos graves, comillas intercaladas, concatenación `'a'+'b'`, `.Replace()`, `[char]`, `-join` y `FromBase64String` con literales; en HTML, `atob`/`unescape`/`fromCharCode`/`\x` con literales, `meta refresh`, texto oculto y «HTML smuggling». Un comando ofuscado solo se reporta si la ofuscación **escondía** un programa o técnica relevante (no por usar `+` o comillas). Queda fuera todo lo que exige **ejecutar** el código: claves construidas en tiempo de ejecución, cadenas invertidas (`[-1..-n]`), variables de entorno con subcadenas (`%COMSPEC:~0,1%`), empaquetadores de JavaScript, varias capas de cifrado y la desofuscación de macros VBA o scripts largos. No se hizo una medición sobre un corpus etiquetado de ofuscación; la verificación son pruebas unitarias con técnicas conocidas y con comandos normales que no deben alertar.
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

# Correos de phishing reales (phishing_pot) y comandos ofuscados (Atomic Red Team)
git clone --depth 1 https://github.com/rf-peixoto/phishing_pot
python scripts/validar_correos.py phishing_pot/email --json correos.json
git clone --depth 1 --filter=blob:none --sparse https://github.com/redcanaryco/atomic-red-team
cd atomic-red-team && git sparse-checkout set --no-cone 'atomics/T*/T*.yaml' && cd ..
python scripts/validar_ofuscacion.py atomic-red-team --json ofuscacion.json

# Pruebas con tráfico normal
python -m pytest tests/unit/test_negativos.py
```

Los datasets son de terceros y **no se incluyen** en el repositorio: cada uno tiene su propia licencia; consúltala en sus repositorios antes de redistribuirlos.
