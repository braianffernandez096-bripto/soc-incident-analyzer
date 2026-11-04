"""Reglas para eventos que no son de Windows: SSH, web, DNS, correo, nube (IAM), Linux, endpoint genérico.

Los exports de otros SIEM no traen Event IDs numéricos sino una acción (``ssh_login``, ``dns_query``,
``UpdateAssumeRolePolicy``…) y un mensaje. Estas reglas leen esa acción, la categoría y el mensaje; nunca deciden
por una cuenta o IP concreta. Solo miran filas cuyo Event_ID no es numérico (los numéricos son de Windows y los cubren
las reglas de ``detection.py``) y no las de IIS/Proxy, que ya tienen reglas propias.

Igual que el resto del motor: la criticidad la fijan estas reglas, la IA solo redacta, y el mapeo ATT&CK es orientativo.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import unquote

import pandas as pd

from . import detection as D
from .detection import CONFIG, State, _groups, _ioc, _mk, clusters, fmt_dec, fmt_dur, hhmmss, is_external, pl, short_user

CONFIG.update({
    "generic_brute_internal_min_failures": 5,
    "web_attack_min_hits": 3,
    "ransomware_min_files": 5,
    "dns_tunnel_min_queries": 5,
    "cloud_denied_min": 3,
    "c2_min_connections": 3,
    "followup_window_s": 900,
})

_NUMERIC = r"\d+"
_FAIL = r"fail|denied|reject|invalid|unauthori[sz]ed|error"
_OK = r"^(?:success|succeeded|ok|accepted|allowed|delivered)"


# ---------------------------------------------------------------- utilidades

def _scope(d: pd.DataFrame) -> pd.DataFrame:
    """Filas de fuentes genéricas: Event_ID no numérico y fuera de IIS/Proxy."""
    return d[~d["Event_ID"].str.fullmatch(_NUMERIC) & ~d["Log_Source"].isin(["IIS", "Proxy"])]


def _text(d: pd.DataFrame) -> pd.Series:
    return (d["Event_Description"] + " " + d["Process_CommandLine"]).str.lower()


def _ev(d: pd.DataFrame, rx: str) -> pd.Series:
    return d["Event_ID"].str.contains(rx, case=False, regex=True)


def _failed(d: pd.DataFrame) -> pd.Series:
    return d["Result"].str.lower().str.contains(_FAIL, regex=True)


def _ok(d: pd.DataFrame) -> pd.Series:
    return d["Result"].str.lower().str.contains(_OK, regex=True)


def _local(user: str) -> str:
    """j.doe@empresa.com y EMPRESA\\j.doe son la misma persona que j.doe."""
    return short_user(user).split("@")[0]


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


def _after(d: pd.DataFrame, ts, seconds: int) -> pd.DataFrame:
    return d[(d["Timestamp"] >= ts) & (d["Timestamp"] <= ts + timedelta(seconds=seconds))]


def _hosts(*parts) -> list[str]:
    return [h for h in dict.fromkeys(x for p in parts for x in p) if h]


_PROTO = [("ssh", "SSH"), ("rdp", "RDP"), ("kerberos|domain|ldap", "Kerberos/dominio"), ("smb", "SMB"),
          ("ftp", "FTP"), ("vpn", "VPN"), ("winrm", "WinRM"), ("telnet", "Telnet")]


def _proto(event_ids) -> str:
    joined = " ".join(event_ids).lower()
    return next((label for rx, label in _PROTO if re.search(rx, joined)), "autenticación")


# ---------------------------------------------------------------- autenticación

def rule_g_auth(st: State) -> None:
    d = _scope(st.df)
    auth = d[_ev(d, r"ssh|rdp|ftp|vpn|smb|kerberos|ldap|domain|login|logon|auth|telnet|winrm")]
    fails = auth[_failed(auth)]
    for ip, g in _groups(fails, "Source_IP"):
        if not ip:
            continue
        ext = is_external(ip)
        for c in clusters(g, CONFIG["brute_cluster_gap_s"]):
            n = len(c)
            if n < (CONFIG["brute_external_min_failures"] if ext else CONFIG["generic_brute_internal_min_failures"]):
                continue
            users = list(dict.fromkeys(c["User"]))
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            proto = _proto(c["Event_ID"])
            targets = _hosts(c["Destination"])
            succ = auth[(auth["Source_IP"] == ip) & _ok(auth) & (auth["Timestamp"] >= t0)
                        & (auth["Timestamp"] <= t1 + timedelta(seconds=CONFIG["post_bruteforce_success_window_s"]))]
            post = pd.DataFrame()
            if len(succ):
                post = _after(d[(d["Source_IP"] == ip) & _ev(d, r"shell|spawn|exec|process|command") & ~d["Log_ID"].isin(succ["Log_ID"])],
                              succ["Timestamp"].min(), CONFIG["followup_window_s"])
            spray = len(users) >= 3
            admin_ok = bool(len(succ)) and succ["User"].map(D.is_admin_like).any()
            sev = ("Crítico" if (ext and admin_ok) else "Alto") if (len(succ) or spray or n >= CONFIG["brute_internal_min_failures"]) else "Medio"
            lateral = bool(len(succ)) and not ext
            reasons = [f"{n} fallos de {proto} desde la IP {'externa' if ext else 'interna'} {ip} en {fmt_dur((t1 - t0).total_seconds())}."]
            if spray:
                reasons.append(f"Afecta a {len(users)} cuentas distintas con pocos intentos cada una (patrón de password spraying).")
            if ext:
                reasons.append("El origen es una IP externa a las redes privadas (RFC1918).")
            if len(succ):
                reasons.append(f"Tras la ráfaga hubo {pl(len(succ), 'acceso exitoso', 'accesos exitosos')} desde la misma IP "
                               f"({', '.join(succ['Log_ID'])}) con {', '.join(sorted(set(succ['User'])))}.")
            else:
                reasons.append("No se observaron accesos exitosos desde esa IP.")
            if len(post):
                reasons.append(f"Después de acceder se ejecutó actividad desde esa IP ({', '.join(post['Log_ID'])}).")
            if lateral:
                reasons.append("El origen es un equipo interno: encaja con movimiento lateral tras comprometer ese equipo.")
            kind = "Password spraying" if spray else f"Fuerza bruta por {proto}"
            title = f"{kind} desde {ip}" + (f" con acceso exitoso a {targets[0]}" if len(succ) and targets else "")
            expl = (f"Se registraron {n} intentos fallidos ({proto}) originados en {ip} entre {hhmmss(t0)} y {hhmmss(t1)}, dirigidos a "
                    f"{pl(len(users), 'cuenta', 'cuentas')} ({', '.join(short_user(u) for u in users[:8])}) sobre {', '.join(targets[:4]) or 'destino n/d'}. "
                    + (f"Después hubo {pl(len(succ), 'acceso exitoso', 'accesos exitosos')} desde la misma IP "
                       f"({', '.join(f'{r.Log_ID} {hhmmss(r.Timestamp)} {r.User}' for r in succ.itertuples())}). " if len(succ) else
                       "No se observaron accesos exitosos desde esa IP. ")
                    + ("Muchas cuentas con pocos intentos cada una es característico de password spraying (T1110.003). " if spray else
                       "Intentos repetidos sobre pocas cuentas son consistentes con fuerza bruta (T1110.001). "))
            mitre = ["T1110.003" if spray else "T1110.001"] + (["T1078"] if len(succ) else []) + (
                ["T1021.001"] if lateral and proto == "RDP" else ["T1021.002"] if lateral and proto == "SMB" else [])
            ev = pd.concat([c, succ, post]) if len(succ) else c
            _mk(st, "g_auth", title, "Movimiento lateral" if lateral else "Fuerza bruta",
                "Movimiento lateral" if lateral else "Acceso a credenciales", mitre, sev, reasons, expl, ev,
                actor_ips=[ip], actor_users=list(succ["User"]) if len(succ) else (),
                link_ips=targets if len(succ) else None, hosts=targets,
                metrics={"intentos_fallidos": n, "cuentas_objetivo": len(users), "protocolo": proto, "ip_origen": ip,
                         "origen_externo": ext, "exitos_posteriores": list(succ["Log_ID"]), "host": targets[0] if targets else ""},
                iocs=[_ioc("IP", ip, f"Origen de la ráfaga de fallos de {proto}")]
                + [_ioc("Cuenta", short_user(u), "Cuenta con acceso exitoso tras la ráfaga") for u in dict.fromkeys(succ["User"])])


# ---------------------------------------------------------------- web, base de datos y exfiltración

_WEB_ATTACK = [
    ("inyección SQL", r"union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\(|information_schema|--\s*$|;\s*drop\s"),
    ("recorrido de rutas", r"\.\./|\.\.\\|/etc/passwd|win\.ini"),
    ("XSS", r"<script|javascript:|onerror\s*="),
    ("webshell / ejecución de comandos", r"cmd=|\.aspx\?|\.php\?cmd|/bin/(?:ba)?sh|exec\("),
    ("Log4Shell", r"\$\{jndi:"),
]


def rule_g_web(st: State) -> None:
    d = _scope(st.df)
    web = d[d["Log_Source"].str.contains(r"web|waf|http|nginx|apache", case=False, regex=True) | _ev(d, r"http|request")]
    if web.empty:
        return
    blob = web["Event_Description"].map(lambda s: unquote(s).lower()) + " " + web["Process_CommandLine"].map(lambda s: unquote(s).lower())
    kinds = {k: blob.str.contains(rx, regex=True) for k, rx in _WEB_ATTACK}
    hit = pd.concat(kinds, axis=1).any(axis=1)
    for ip, g in _groups(web[hit], "Source_IP"):
        for c in clusters(g, CONFIG["web_cluster_gap_s"]):
            if len(c) < CONFIG["web_attack_min_hits"]:
                continue
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            labels = [k for k in kinds if kinds[k].reindex(c.index).any()]
            servers = _hosts(c["Destination"])
            follow = pd.DataFrame()
            if servers:
                follow = _after(d[(d["Source_IP"].isin(servers)) & _ev(d, r"sql|query|db")
                                  & _text(d).str.contains(r"select|dump|credit|passw|users|information_schema", regex=True)],
                                t1, CONFIG["followup_window_s"])
            sev = "Crítico" if len(follow) else "Alto"
            reasons = [f"{len(c)} peticiones con patrones de {', '.join(labels)} desde {ip} en {fmt_dur((t1 - t0).total_seconds())}.",
                       "El origen es una IP externa." if is_external(ip) else "El origen es un equipo interno."]
            if len(follow):
                reasons.append(f"Minutos después el servidor consultó datos sensibles ({', '.join(follow['Log_ID'])}): posible explotación exitosa.")
            example = c.iloc[0]["Event_Description"]
            expl = (f"Desde {ip} se enviaron {len(c)} peticiones con patrones de {', '.join(labels)} contra {', '.join(servers[:3]) or 'el servidor web'} "
                    f"entre {hhmmss(t0)} y {hhmmss(t1)}; por ejemplo {c.iloc[0]['Log_ID']}: «{D.trunc(example, 120)}». "
                    + ("El servidor respondió con éxito a esas peticiones. " if c["Result"].str.fullmatch(r"2\d\d|success|ok", case=False).any() else "")
                    + (f"Después se ejecutaron consultas a datos sensibles ({', '.join(follow['Log_ID'])}). " if len(follow) else "")
                    + "La explotación de una aplicación expuesta es el vector de acceso inicial T1190.")
            _mk(st, "g_web", f"Ataque web ({', '.join(labels)}) contra {servers[0] if servers else 'aplicación web'} desde {ip}",
                "Otras anomalías", "Acceso inicial", ["T1190"], sev, reasons, expl, pd.concat([c, follow]),
                actor_ips=[ip], link_ips=servers, hosts=servers,
                metrics={"peticiones": len(c), "tipos": labels, "ip_origen": ip, "host": servers[0] if servers else "",
                         "consulta_sensible_posterior": bool(len(follow))},
                iocs=[_ioc("IP", ip, "Origen del ataque web")] + [_ioc("URL/URI", D.trunc(x, 160), "Petición con patrón de ataque")
                                                                 for x in dict.fromkeys(c["Event_Description"])][:6])


_SIZE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(kb|mb|gb|tb)\b", re.I)
_UNIT = {"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12}


def _bytes(text: str) -> float:
    m = _SIZE.search(text or "")
    return float(m.group(1).replace(",", ".")) * _UNIT[m.group(2).lower()] if m else 0.0


def rule_g_exfil(st: State) -> None:
    d = _scope(st.df)
    out = d[(_ev(d, r"transfer|upload|exfil") | _text(d).str.contains(r"outbound data transfer|exfiltrat", regex=True))
            & d["Destination"].map(is_external).astype(bool)]
    for (src, dst), g in _groups(out, ["Source_IP", "Destination"]):
        total = sum(_bytes(x) for x in g["Event_Description"])
        t0, t1 = g["Timestamp"].min(), g["Timestamp"].max()
        prior = d[(d["Source_IP"] == src) & (d["Timestamp"] < t0) & (d["Timestamp"] >= t0 - timedelta(seconds=CONFIG["followup_window_s"]))
                  & _ev(d, r"sql|query|db|file_read|archive|compress")
                  & _text(d).str.contains(r"select\s+\*|credit|passw|dump|information_schema|ssn|salary|archive|\.zip|\.7z", regex=True)]
        sev = "Crítico" if total >= CONFIG["exfil_critico_bytes"] else "Alto" if (total >= CONFIG["exfil_alto_bytes"] or len(prior)) else "Medio"
        if len(prior) and sev != "Crítico":
            sev = D.bump(sev, 1)
        size_txt = f"{fmt_dec(total / 1e6, 0)} MB" if total else "volumen no informado"
        reasons = [f"Salida de datos desde {src} hacia la IP externa {dst} ({size_txt})."]
        if len(prior):
            reasons.append(f"Justo antes se consultaron datos sensibles desde el mismo equipo ({', '.join(prior['Log_ID'])}).")
        if total >= CONFIG["exfil_critico_bytes"]:
            reasons.append("El volumen supera el umbral de exfiltración crítica.")
        expl = (f"{src} envió {size_txt} a la IP externa {dst} entre {hhmmss(t0)} y {hhmmss(t1)} ({', '.join(g['Log_ID'])}). "
                + (f"Antes de la transferencia hubo consultas a datos sensibles ({'; '.join(f'{r.Log_ID}: {D.trunc(r.Event_Description, 70)}' for r in prior.itertuples())}). "
                   if len(prior) else "") + "La salida de datos hacia un destino externo es consistente con exfiltración (T1041).")
        _mk(st, "g_exfil", f"Exfiltración de datos desde {src} hacia {dst}", "Otras anomalías", "Exfiltración", ["T1041"] + (["T1005"] if len(prior) else []),
            sev, reasons, expl, pd.concat([prior, g]), actor_ips=[dst], link_ips=[src], hosts=[src],
            metrics={"bytes": int(total), "destino": dst, "origen": src, "host": src, "consulta_previa": bool(len(prior))},
            iocs=[_ioc("IP", dst, "Destino externo de la transferencia")])


# ---------------------------------------------------------------- correo y ejecución

_BAD_ATT = re.compile(r"([\w\-.]+\.(?:pdf|docx?|xlsx?|jpe?g|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|ps1|lnk|iso|jar|hta)\b|[\w\-.]+\.(?:exe|scr|js|vbs|hta|iso|lnk)\b)", re.I)


def rule_g_phishing(st: State) -> None:
    d = _scope(st.df)
    mail = d[_ev(d, r"mail|email|smtp")]
    for r in mail.itertuples():
        m = _BAD_ATT.search(f"{r.Event_Description} {r.Process_CommandLine}")
        if not m:
            continue
        name = m.group(1).strip().lower()
        ran = _after(d[_ev(d, r"execute|process|run|open|launch") & _text(d).str.contains(re.escape(name), regex=True)],
                     r.Timestamp, 3600)
        sev = "Crítico" if len(ran) else "Alto"
        recipient = _local(r.User)
        reasons = [f"Correo entregado a {r.User} con un adjunto peligroso ({m.group(1)}): doble extensión o ejecutable."]
        if len(ran):
            reasons.append(f"El adjunto se ejecutó {ran.iloc[0]['Timestamp'] - r.Timestamp} después ({', '.join(ran['Log_ID'])}).")
        else:
            reasons.append("No hay evidencia en los logs de que el adjunto se haya ejecutado.")
        expl = (f"{r.Log_ID} ({hhmmss(r.Timestamp)}): se entregó a {r.User} un correo desde {r.Source_IP or 'origen n/d'} con el adjunto «{m.group(1)}». "
                + (f"Luego {', '.join(f'{x.Log_ID} ({hhmmss(x.Timestamp)}, {x.User}): {D.trunc(x.Event_Description, 70)}' for x in ran.itertuples())}. "
                   if len(ran) else "") + "Un adjunto con doble extensión es un truco clásico de phishing (T1566.001); su ejecución por el usuario es T1204.002.")
        host_ips = list(ran["Source_IP"]) if len(ran) else []
        _mk(st, "g_phishing", f"Phishing con adjunto malicioso ({m.group(1)}) para {recipient}", "Inicios sospechosos", "Acceso inicial",
            ["T1566.001"] + (["T1204.002"] if len(ran) else []), sev, reasons, expl, pd.concat([mail[mail["Log_ID"] == r.Log_ID], ran]),
            actor_ips=[r.Source_IP] if is_external(r.Source_IP) else (), actor_users=[recipient], link_ips=host_ips, hosts=_hosts(host_ips),
            metrics={"adjunto": m.group(1), "ejecutado": bool(len(ran)), "destinatario": r.User, "host": host_ips[0] if host_ips else ""},
            iocs=[_ioc("Ruta/archivo", m.group(1), "Adjunto del correo"), _ioc("IP", r.Source_IP, "Origen del correo")] if r.Source_IP else
            [_ioc("Ruta/archivo", m.group(1), "Adjunto del correo")])


_CMD_ACT = r"process|exec|command|shell|spawn|run"


def rule_g_cmd(st: State) -> None:
    d = _scope(st.df)
    cand = d[_ev(d, _CMD_ACT)].copy()
    if cand.empty:
        return
    cand["Process_CommandLine"] = cand["Process_CommandLine"].where(cand["Process_CommandLine"] != "", cand["Event_Description"])
    keep = {"encoded_ps", "download_cradle", "cred_dump", "archive_staging"}
    ps_bypass = re.compile(r"powershell.*-executionpolicy\s+bypass|-ep\s+bypass|\bnc(?:\.exe)?\s+-e\b|/bin/(?:ba)?sh\s+-i", re.I)
    pat = {p["key"]: p for p in D.CMD_PATTERNS}
    rows = []
    for r in cand.itertuples():
        txt = f"{r.Event_Description} {r.Process_CommandLine}"
        p = D._match_cmd(r)
        if p and p["key"] in keep:
            rows.append((r.Log_ID, p["key"]))
        elif ps_bypass.search(txt):
            rows.append((r.Log_ID, "download_cradle"))
    if not rows:
        return
    key_by_id = dict(rows)
    sub = cand[cand["Log_ID"].isin(key_by_id)].copy()
    sub["_key"] = sub["Log_ID"].map(key_by_id)
    for (key, ip), g in _groups(sub, ["_key", "Source_IP"]):
        p = pat[key]
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            dl = _after(d[(d["Source_IP"] == ip) & _ev(d, r"download|fetch|transfer|wget|curl") & ~d["Log_ID"].isin(c["Log_ID"])
                          & ~d["Destination"].eq(ip)], t0, CONFIG["followup_window_s"])
            sev = "Alto"
            reasons = [f"Coincide con el patrón «{p['label']}»: {p['why']}"]
            if len(dl):
                reasons.append(f"Enseguida se descargó contenido desde fuera ({', '.join(dl['Log_ID'])}).")
            who = ", ".join(sorted({short_user(u) for u in c["User"]}))
            expl = (f"En {ip}, la cuenta {who} ejecutó {pl(len(c), 'comando', 'comandos')} con el patrón «{p['label']}» entre {hhmmss(t0)} y {hhmmss(t1)}: "
                    + "; ".join(f"{r.Log_ID}: {D.trunc(r.Process_CommandLine, 110)}" for r in c.itertuples()) + ". "
                    + (f"Luego se descargó contenido ({'; '.join(f'{r.Log_ID}: {D.trunc(r.Event_Description, 80)}' for r in dl.itertuples())}). " if len(dl) else "")
                    + p["why"])
            ext_dst = [x for x in dl["Destination"] if is_external(x)]
            _mk(st, "g_cmd", f"{p['label']} en {ip} ({who})", "Comandos y procesos", p["tactic"], p["mitre"] + (["T1105"] if len(dl) and "T1105" not in p["mitre"] else []),
                sev, reasons, expl, pd.concat([c, dl]), actor_users=list(c["User"]), link_ips=[ip] + ext_dst[:1], hosts=[ip],
                metrics={"comandos": len(c), "host": ip, "usuario": who, "ejemplos": [D.trunc(x, 140) for x in c["Process_CommandLine"]][:5]},
                iocs=[_ioc("Comando", D.trunc(x, 200), p["label"]) for x in dict.fromkeys(c["Process_CommandLine"])]
                + [_ioc("IP", x, "Destino de la descarga") for x in dict.fromkeys(ext_dst)])


# ---------------------------------------------------------------- comando y control, persistencia, reconocimiento

def rule_g_c2(st: State) -> None:
    d = _scope(st.df)
    net = d[d["Destination"].map(is_external).astype(bool) & ~_text(d).str.contains(r"mining pool|stratum|xmrig|minexmr", regex=True)
            & ~_ev(d, r"dns|transfer|upload|download|email|mail")]
    kw = net[_text(net).str.contains(r"\bc2\b|command and control|beacon|botnet|known malicious", regex=True) | _ev(net, r"beacon")]
    for (src, dst), g in _groups(kw, ["Source_IP", "Destination"]):
        if len(g) < CONFIG["c2_min_connections"]:
            continue
        t0, t1 = g["Timestamp"].min(), g["Timestamp"].max()
        gap = D.median_gap(g)
        reasons = [f"{len(g)} conexiones de {src} hacia {dst} descritas como beaconing / infraestructura C2 en {fmt_dur((t1 - t0).total_seconds())}.",
                   "El destino es una IP externa."]
        expl = (f"{src} se conectó {len(g)} veces a {dst} entre {hhmmss(t0)} y {hhmmss(t1)}"
                + (f" (mediana de {fmt_dec(gap, 0)} s entre conexiones)" if gap else "") + f"; el log las describe como «{D.trunc(g.iloc[0]['Event_Description'], 90)}». "
                "Conexiones repetidas hacia un mismo destino externo son consistentes con beaconing de comando y control (T1071.001).")
        _mk(st, "g_c2", f"Comunicación con infraestructura C2 desde {src} hacia {dst}", "Otras anomalías", "Comando y control", ["T1071.001"],
            "Alto", reasons, expl, g, actor_ips=[dst], link_ips=[src], hosts=[src], actor_users=list(g["User"]),
            metrics={"conexiones": len(g), "destino": dst, "origen": src, "host": src, "mediana_s": gap},
            iocs=[_ioc("IP", dst, "Posible servidor de comando y control")])


_PERSIST = [
    (r"currentversion\\run|runonce|\\startup\\", "clave Run / carpeta de inicio", "T1547.001"),
    (r"schtasks|scheduled task|crontab|cron\.d", "tarea programada", "T1053.005"),
    (r"authorized_keys", "clave SSH autorizada", "T1098.004"),
]


def rule_g_persistence(st: State) -> None:
    d = _scope(st.df)
    for rx, label, tid in _PERSIST:
        hits = d[_text(d).str.contains(rx, regex=True)]
        for ip, g in _groups(hits, "Source_IP"):
            for c in clusters(g, CONFIG["command_cluster_gap_s"]):
                t0 = c["Timestamp"].min()
                reasons = [f"Se modificó un mecanismo de arranque automático ({label}) en {ip}."]
                expl = (f"En {ip}, {', '.join(f'{r.Log_ID} ({hhmmss(r.Timestamp)}): {D.trunc(r.Event_Description, 90)}' for r in c.itertuples())}. "
                        f"Modificar {label} hace que el código se ejecute en cada arranque o inicio de sesión (persistencia).")
                _mk(st, "g_persistence", f"Persistencia en {ip} ({label})", "Otras anomalías", "Persistencia", [tid], "Alto", reasons, expl, c,
                    link_ips=[ip], hosts=[ip], actor_users=[u for u in c["User"] if u not in ("system", "")],
                    metrics={"mecanismo": label, "host": ip, "hora": hhmmss(t0)}, iocs=[_ioc("Ruta/archivo", D.trunc(c.iloc[0]["Event_Description"], 160), "Entrada de persistencia")])


def rule_g_share_probe(st: State) -> None:
    d = _scope(st.df)
    probes = d[_ev(d, r"share|smb") & _text(d).str.contains(r"ipc\$|\bc\$|admin\$", regex=True) & _failed(d)]
    for ip, g in _groups(probes, "Source_IP"):
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            if c["Destination"].nunique() < 2:
                continue
            dests = _hosts(c["Destination"])
            reasons = [f"{len(c)} intentos fallidos de acceder a recursos administrativos (IPC$/C$) de {len(dests)} equipos distintos desde {ip}."]
            expl = (f"{ip} intentó acceder sin autorización a recursos administrativos de {', '.join(dests)} "
                    f"({', '.join(f'{r.Log_ID} {hhmmss(r.Timestamp)}' for r in c.itertuples())}). Es el reconocimiento de recursos compartidos que suele "
                    "preceder al movimiento lateral (T1135, T1021.002).")
            _mk(st, "g_share_probe", f"Sondeo de recursos compartidos administrativos desde {ip}", "Movimiento lateral", "Descubrimiento", ["T1135", "T1021.002"],
                "Medio", reasons, expl, c, link_ips=[ip] + dests, hosts=[ip], actor_users=list(c["User"]),
                metrics={"intentos": len(c), "destinos": dests, "host": ip, "origen": ip})


# ---------------------------------------------------------------- impacto: ransomware, minería

_RANSOM = r"\.locked|\.encrypted|\.crypt\b|\.lockbit|how_to_decrypt|readme_recover|decrypt_instructions|ransom"


def rule_g_ransomware(st: State) -> None:
    d = _scope(st.df)
    enc = d[_ev(d, r"encrypt|ransom") | _text(d).str.contains(_RANSOM, regex=True)]
    anti = d[_text(d).str.contains(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wbadmin(?:\.exe)?\s+delete|bcdedit.*recoveryenabled\s+no", regex=True)]
    for ip, g in _groups(enc, "Source_IP"):
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            files = c[_ev(c, r"encrypt") | c["Event_Description"].str.lower().str.contains(r"\.locked|\.encrypted|\.crypt\b|\.lockbit", regex=True)]
            note = c[c["Event_Description"].str.lower().str.contains(r"how_to_decrypt|readme_recover|decrypt_instructions|ransom", regex=True)]
            near = anti[(anti["Source_IP"] == ip) & (anti["Timestamp"] >= c["Timestamp"].min() - timedelta(minutes=10))
                        & (anti["Timestamp"] <= c["Timestamp"].max() + timedelta(minutes=10))]
            if len(files) < CONFIG["ransomware_min_files"] and not (len(note) and len(near)):
                continue
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            who = sorted({short_user(u) for u in c["User"]})
            reasons = [f"{len(files)} archivos cifrados/renombrados con extensión de ransomware en {fmt_dur((t1 - t0).total_seconds())}."]
            if len(near):
                reasons.append(f"Se borraron copias de seguridad ({', '.join(near['Log_ID'])}), un paso típico previo al cifrado.")
            if len(note):
                reasons.append(f"Se creó una nota de rescate ({', '.join(note['Log_ID'])}).")
            expl = (f"En {ip}, la cuenta {', '.join(who)} cifró {len(files)} archivos entre {hhmmss(t0)} y {hhmmss(t1)} "
                    f"(p. ej. {D.trunc(files.iloc[0]['Event_Description'], 80) if len(files) else 'n/d'}). "
                    + (f"Además se ejecutó «{D.trunc(near.iloc[0]['Event_Description'], 60)}» para impedir la recuperación (T1490). " if len(near) else "")
                    + (f"Se dejó una nota de rescate ({D.trunc(note.iloc[0]['Event_Description'], 60)}). " if len(note) else "")
                    + "Es el comportamiento del cifrado de datos con fines de extorsión (T1486).")
            _mk(st, "g_ransomware", f"Ransomware: cifrado de archivos en {ip}", "Comandos y procesos", "Impacto",
                ["T1486"] + (["T1490"] if len(near) else []), "Crítico", reasons, expl, pd.concat([c, near]),
                link_ips=[ip], hosts=[ip], actor_users=list(c["User"]),
                metrics={"archivos_cifrados": len(files), "ventana_s": round((t1 - t0).total_seconds()), "host": ip,
                         "copias_borradas": bool(len(near)), "nota_de_rescate": bool(len(note))},
                iocs=[_ioc("Archivo", D.trunc(x, 120), "Archivo cifrado") for x in list(files["Event_Description"])[:3]]
                + [_ioc("Archivo", D.trunc(x, 120), "Nota de rescate") for x in list(note["Event_Description"])[:1]])


def rule_g_mining(st: State) -> None:
    d = _scope(st.df)
    t = _text(d)
    miner = d[t.str.contains(r"xmrig|minerd|cpuminer|stratum|mining pool|minexmr|coinhive", regex=True)]
    cpu = d[_ev(d, r"cpu") & t.str.contains(r"utili[sz]ation at (?:9\d|100)", regex=True)]
    for ip, g in _groups(miner, "Source_IP"):
        cpus = cpu[(cpu["Source_IP"] == ip) & (cpu["Timestamp"] <= g["Timestamp"].max())]
        pools = [x for x in g["Destination"] if is_external(x)]
        reasons = [f"Se ejecutó/conectó software de minería ({', '.join(g['Log_ID'])}) en {ip}."]
        if len(cpus):
            reasons.append(f"{len(cpus)} alertas de CPU al ~100 % en el mismo equipo antes de la ejecución.")
        expl = (f"En {ip}: " + "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}): {D.trunc(r.Event_Description, 80)}" for r in g.itertuples()) + ". "
                + (f"Previamente hubo {len(cpus)} alertas de CPU sostenida. " if len(cpus) else "")
                + "Es consistente con secuestro de recursos para minar criptomonedas (T1496).")
        _mk(st, "g_mining", f"Minería de criptomonedas en {ip}", "Comandos y procesos", "Impacto", ["T1496.001"], "Alto", reasons, expl,
            pd.concat([cpus, g]), link_ips=[ip], hosts=[ip], actor_users=[u for u in g["User"] if u not in ("system", "")],
            metrics={"host": ip, "alertas_cpu": len(cpus), "pool": pools[0] if pools else ""},
            iocs=[_ioc("IP", x, "Servidor/pool de minería") for x in dict.fromkeys(pools)])


# ---------------------------------------------------------------- escalamiento y credenciales (Linux)

def rule_g_privesc(st: State) -> None:
    d = _scope(st.df)
    t = _text(d)
    priv = d[t.str.contains(r"\bsuid\b|setuid|effective uid changed to 0|chmod\s+[0-7]*[+]?s|pkexec|dirty ?pipe|sudo\s+su\b", regex=True)]
    creds = d[_ev(d, r"read|file|access") & t.str.contains(r"/etc/shadow|/etc/passwd|id_rsa|\.aws/credentials|lsass|sam hive|ntds\.dit", regex=True)]
    for ip, g in _groups(priv, "Source_IP"):
        for c in clusters(g, CONFIG["command_cluster_gap_s"]):
            t0, t1 = c["Timestamp"].min(), c["Timestamp"].max()
            cr = creds[(creds["Source_IP"] == ip) & (creds["Timestamp"] >= t0) & (creds["Timestamp"] <= t1 + timedelta(seconds=1800))]
            sev = "Crítico" if len(cr) >= 3 else "Alto"
            users = list(dict.fromkeys(list(c["User"]) + list(cr["User"])))
            reasons = [f"Cambio de privilegios a root/SUID en {ip} ({', '.join(c['Log_ID'])})."]
            if len(cr):
                reasons.append(f"Después se leyeron {pl(len(cr), 'archivo de credenciales', 'archivos de credenciales')} ({', '.join(cr['Log_ID'][:6])}).")
            expl = (f"En {ip}: " + "; ".join(f"{r.Log_ID} ({hhmmss(r.Timestamp)}, {r.User}): {D.trunc(r.Event_Description, 80)}" for r in c.itertuples())
                    + ". " + (f"A continuación, como root, se leyeron {len(cr)} archivos sensibles ({D.trunc('; '.join(cr['Event_Description'][:3]), 140)}). " if len(cr) else "")
                    + "Abusar de un binario SUID para obtener root es escalamiento de privilegios (T1548.001)"
                    + ("; leer archivos de contraseñas es volcado de credenciales (T1003.008)." if len(cr) else "."))
            _mk(st, "g_privesc", f"Escalamiento de privilegios local en {ip}" + (" con lectura de credenciales" if len(cr) else ""),
                "Escalamiento", "Escalamiento de privilegios", ["T1548.001"] + (["T1003.008"] if len(cr) else []), sev, reasons, expl,
                pd.concat([c, cr]), link_ips=[ip], hosts=[ip], actor_users=[u for u in users if u],
                metrics={"host": ip, "archivos_credenciales": len(cr), "usuario": short_user(users[0]) if users else ""},
                iocs=[_ioc("Ruta/archivo", D.trunc(x, 140), "Archivo sensible leído") for x in dict.fromkeys(cr["Event_Description"])][:5])


# ---------------------------------------------------------------- DNS y nube

_DOMAIN = re.compile(r"([a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)+\.[a-z]{2,})", re.I)


def rule_g_dns_tunnel(st: State) -> None:
    d = _scope(st.df)
    dns = d[_ev(d, r"dns") | d["Log_Source"].str.contains("dns", case=False)]
    rows = []
    for r in dns.itertuples():
        m = _DOMAIN.findall(r.Event_Description)
        if not m:
            continue
        name = max(m, key=len).lower()
        labels = name.split(".")
        sub, parent = ".".join(labels[:-2]), ".".join(labels[-2:])
        if len(sub) >= 12 and _entropy(sub.replace(".", "")) >= 3.0:
            rows.append((r.Log_ID, parent, name))
    if not rows:
        return
    info = pd.DataFrame(rows, columns=["Log_ID", "parent", "name"]).set_index("Log_ID")
    sub = dns[dns["Log_ID"].isin(info.index)].copy()
    sub["_parent"] = sub["Log_ID"].map(info["parent"])
    for (ip, parent), g in _groups(sub, ["Source_IP", "_parent"]):
        if len(g) < CONFIG["dns_tunnel_min_queries"]:
            continue
        t0, t1 = g["Timestamp"].min(), g["Timestamp"].max()
        txt = int(g["Event_Description"].str.contains("TXT", case=False).sum())
        reasons = [f"{len(g)} consultas DNS de {ip} a subdominios largos y aleatorios de {parent} en {fmt_dur((t1 - t0).total_seconds())}."]
        if txt:
            reasons.append(f"{txt} son consultas TXT, el tipo que más se usa para transportar datos.")
        expl = (f"{ip} consultó {len(g)} subdominios distintos de {parent} entre {hhmmss(t0)} y {hhmmss(t1)} "
                f"(p. ej. {info.loc[g.iloc[0]['Log_ID'], 'name']}). Nombres largos, de alta entropía y repetidos contra un mismo dominio son típicos de un "
                "túnel DNS para comando y control o exfiltración (T1071.004).")
        _mk(st, "g_dns_tunnel", f"Túnel DNS desde {ip} hacia {parent}", "Otras anomalías", "Comando y control", ["T1071.004"], "Alto", reasons, expl, g,
            link_ips=[ip], hosts=[ip], metrics={"consultas": len(g), "dominio": parent, "host": ip, "txt": txt},
            iocs=[_ioc("Dominio", parent, "Dominio usado para el túnel DNS")])


_IAM_PRIV = ("UpdateAssumeRolePolicy", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateUser",
             "CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup", "StopLogging", "DeleteTrail", "DisableKey", "PutBucketPolicy")


def rule_g_cloud(st: State) -> None:
    d = _scope(st.df)
    cloud = d[d["Log_Source"].str.contains(r"cloud|aws|azure|gcp|iam|trail", case=False, regex=True) | d["Event_ID"].isin(_IAM_PRIV)]
    for user, g in _groups(cloud, "User"):
        denied = g[_failed(g) | g["Result"].str.contains("denied", case=False)]
        priv = g[g["Event_ID"].isin(_IAM_PRIV) & _ok(g)]
        if len(denied) < CONFIG["cloud_denied_min"] and not len(priv):
            continue
        ips = _hosts(g["Source_IP"])
        sev = "Crítico" if len(priv) else "Medio"
        reasons = []
        if len(denied):
            reasons.append(f"{len(denied)} llamadas denegadas (AccessDenied) de la identidad {user}: enumeración de permisos.")
        if len(priv):
            reasons.append(f"Cambios de identidad/permisos con éxito: {', '.join(priv['Event_ID'])}.")
        names = ", ".join(dict.fromkeys(priv["Event_ID"])) or "ninguno"
        expl = (f"La identidad {user} (origen {', '.join(ips) or 'n/d'}) hizo {len(denied)} llamadas denegadas entre {hhmmss(g['Timestamp'].min())} y "
                f"{hhmmss(denied['Timestamp'].max() if len(denied) else g['Timestamp'].max())}"
                + (f" y después ejecutó con éxito {names} ({', '.join(f'{r.Log_ID} {hhmmss(r.Timestamp)}' for r in priv.itertuples())}). "
                   "Probar permisos y luego modificar políticas o crear credenciales indica abuso de una cuenta cloud para escalar privilegios y persistir "
                   "(T1078.004, T1098)." if len(priv) else ". Probar permisos sin éxito es reconocimiento (T1078.004)."))
        rel = pd.concat([denied, priv]).drop_duplicates("Log_ID")
        _mk(st, "g_cloud", f"Abuso de la identidad cloud {short_user(user)}" + (": cambios de permisos" if len(priv) else ": enumeración denegada"),
            "Escalamiento", "Escalamiento de privilegios", ["T1078.004"] + (["T1098"] if len(priv) else []), sev, reasons, expl, rel,
            actor_ips=[i for i in ips if is_external(i)], link_ips=ips, hosts=ips, actor_users=[user],
            metrics={"identidad": user, "llamadas_denegadas": len(denied), "cambios_privilegiados": list(priv["Event_ID"]), "host": ips[0] if ips else ""},
            iocs=[_ioc("IP", i, "Origen de las llamadas a la API") for i in ips] + [_ioc("Cuenta", short_user(user), "Identidad cloud abusada")])


# ---------------------------------------------------------------- registro y títulos de incidentes

RULES = [
    ("g_auth", "Autenticación (SSH/RDP/Kerberos/VPN…): ráfagas de fallos, spraying y acceso exitoso posterior", rule_g_auth),
    ("g_web", "Ataque web por patrones en la petición (inyección SQL, rutas, XSS, webshell, Log4Shell)", rule_g_web),
    ("g_exfil", "Exfiltración: transferencia a destino externo, con consulta previa de datos sensibles", rule_g_exfil),
    ("g_phishing", "Phishing: adjunto con doble extensión o ejecutable, y su ejecución posterior", rule_g_phishing),
    ("g_cmd", "Comandos sospechosos en eventos de proceso (PowerShell con bypass, descargas, credenciales)", rule_g_cmd),
    ("g_c2", "Comando y control: conexiones repetidas a infraestructura marcada como C2", rule_g_c2),
    ("g_persistence", "Persistencia: clave Run, tareas programadas, claves SSH autorizadas", rule_g_persistence),
    ("g_share_probe", "Sondeo de recursos compartidos administrativos (IPC$/C$) en varios equipos", rule_g_share_probe),
    ("g_ransomware", "Ransomware: cifrado masivo, nota de rescate y borrado de copias de seguridad", rule_g_ransomware),
    ("g_mining", "Minería de criptomonedas: procesos, pools y CPU sostenida", rule_g_mining),
    ("g_privesc", "Escalamiento de privilegios en Linux (SUID/root) y lectura de archivos de credenciales", rule_g_privesc),
    ("g_dns_tunnel", "Túnel DNS: subdominios largos y aleatorios hacia un mismo dominio", rule_g_dns_tunnel),
    ("g_cloud", "Cuentas cloud: enumeración denegada y cambios de permisos/credenciales", rule_g_cloud),
]


def incident_title(fs: list[D.Finding]) -> str | None:
    """Título de un incidente formado por hallazgos genéricos (None si no hay ninguno: se usa el de Windows)."""
    rules = {f.rule for f in fs}
    if not any(r.startswith("g_") for r in rules):
        return None
    host = next((f.metrics.get("host") for f in fs if f.metrics.get("host")), "")
    users = [u for f in fs for u in f.actor_users]
    user = short_user(Counter(users).most_common(1)[0][0]) if users else ""
    if "g_ransomware" in rules:
        return f"Ransomware: cifrado de archivos y borrado de copias de seguridad en {host}" if any(
            f.metrics.get("copias_borradas") for f in fs if f.rule == "g_ransomware") else f"Ransomware: cifrado de archivos en {host}"
    if "g_phishing" in rules:
        more = " con movimiento lateral" if rules & {"g_auth", "g_share_probe"} else ""
        return f"Cadena de ataque iniciada por phishing ({user}){more}" if len(rules) > 1 else f"Phishing con adjunto malicioso para {user}"
    if "g_web" in rules:
        return "Ataque web con acceso a datos y exfiltración" if "g_exfil" in rules else f"Ataque web contra {next((f.metrics.get('host') for f in fs if f.rule == 'g_web'), 'la aplicación')}"
    if "g_exfil" in rules:
        return f"Exfiltración de datos desde {host}"
    auth = next((f for f in fs if f.rule == "g_auth" and f.metrics.get("exitos_posteriores")), None)
    if auth and rules & {"g_mining", "g_persistence", "g_cmd", "g_privesc"}:
        extra = " y minería de criptomonedas" if "g_mining" in rules else " y persistencia" if "g_persistence" in rules else ""
        return f"Fuerza bruta {auth.metrics.get('protocolo', '')} desde {auth.metrics.get('ip_origen', '')} con compromiso de {user or 'una cuenta'}{extra}".replace("  ", " ")
    if "g_cloud" in rules:
        return f"Abuso de la identidad cloud {user}"
    if "g_dns_tunnel" in rules:
        return f"Túnel DNS desde {host}"
    if "g_privesc" in rules:
        return f"Escalamiento de privilegios en {host} por {user}"
    if "g_mining" in rules:
        return f"Minería de criptomonedas en {host}"
    if "g_auth" in rules:
        f0 = next(f for f in fs if f.rule == "g_auth")
        base = "Password spraying" if "spraying" in f0.title.lower() else f"Fuerza bruta {f0.metrics.get('protocolo', '')}".strip()
        return f"{base} desde {f0.metrics.get('ip_origen', '')}" + (f" con compromiso de la cuenta {user}" if f0.metrics.get("exitos_posteriores") else "")
    return "Actividad sospechosa correlacionada"
