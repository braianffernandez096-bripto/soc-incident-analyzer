"""Carga y normalización del export de SIEM (Excel, CSV/TSV y JSON/NDJSON).

El parser es tolerante: detecta el formato, la fila de cabecera, acepta variantes
de nombres de columna (espacios, mayúsculas, alias en español/inglés y los campos
típicos de Elastic ECS / Winlogbeat y Splunk) y normaliza tipos. No inventa datos:
lo que falta queda vacío.

Cada lector devuelve una tabla "cruda" sin cabecera (como ``header=None``) y el
resto del proceso (detección de cabecera, tipos, orden) es común a todos los formatos.
"""
from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
import zipfile
from pathlib import Path
from typing import BinaryIO

import pandas as pd

from . import syslog as syslog_mod

CANONICAL = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
    "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
    "Result", "Severity",
]

# alias (normalizados: minúsculas, sin espacios/guiones/puntos/@) -> nombre canónico
ALIASES = {
    "logid": "Log_ID", "id": "Log_ID", "eventrecordid": "Log_ID", "winlogrecordid": "Log_ID",
    "timestamp": "Timestamp", "time": "Timestamp", "fecha": "Timestamp",
    "fechahora": "Timestamp", "timecreated": "Timestamp", "datetime": "Timestamp",
    "hostname": "Hostname", "host": "Hostname", "computer": "Hostname",
    "equipo": "Hostname", "computername": "Hostname", "winlogcomputername": "Hostname",
    "eventid": "Event_ID", "evento": "Event_ID", "eventcode": "Event_ID",
    "winlogeventid": "Event_ID",
    "user": "User", "usuario": "User", "account": "User", "username": "User",
    "cuenta": "User",
    "sourceip": "Source_IP", "srcip": "Source_IP", "ipaddress": "Source_IP",
    "ip": "Source_IP", "ipv4origen": "Source_IP", "ipdeorigen": "Source_IP",
    "srcaddr": "Source_IP",
    "destination": "Destination", "destino": "Destination", "destip": "Destination",
    "destinationip": "Destination", "dest": "Destination", "dstip": "Destination",
    "dstaddr": "Destination",
    "logsource": "Log_Source", "source": "Log_Source", "fuente": "Log_Source",
    "channel": "Log_Source", "winlogchannel": "Log_Source",
    "eventdescription": "Event_Description", "description": "Event_Description",
    "descripcion": "Event_Description", "message": "Event_Description",
    "mensaje": "Event_Description", "raw": "Event_Description",
    "processcommandline": "Process_CommandLine", "commandline": "Process_CommandLine",
    "comando": "Process_CommandLine", "process": "Process_CommandLine",
    "result": "Result", "resultado": "Result", "status": "Result",
    "eventoutcome": "Result",
    "severity": "Severity", "severidad": "Severity", "level": "Severity",
    "criticidad": "Severity", "loglevel": "Severity",
}

# Alias de segunda prioridad: solo se aplican si ninguna otra columna aporta ese campo (así «action» pasa a ser
# el código de evento únicamente cuando el archivo no trae un Event_ID de verdad).
SECONDARY_ALIASES = {
    "action": "Event_ID", "accion": "Event_ID", "eventtype": "Event_ID", "eventaction": "Event_ID",
    "category": "Log_Source", "categoria": "Log_Source",
}

REQUIRED_MIN = ["Timestamp", "Event_ID"]

EXCEL_EXT = (".xlsx", ".xlsm")
CSV_EXT = (".csv", ".tsv", ".txt", ".log")
JSON_EXT = (".json", ".jsonl", ".ndjson")
SUPPORTED_EXT = EXCEL_EXT + CSV_EXT + JSON_EXT

MAX_UNCOMPRESSED_BYTES = 300 * 1024 * 1024   # un .xlsx es un zip: limita su tamaño descomprimido (zip bomb)
MAX_ROWS = 100_000
MAX_COLUMNS = 500
MAX_JSON_DEPTH = 8


class ParseError(ValueError):
    """Error legible para el usuario (se muestra en la interfaz)."""


def _norm_header(h: object) -> str:
    """Minúsculas, sin acentos ni separadores: 'Descripción', 'descripcion' y 'DESCRIPCION' son lo mismo."""
    text = unicodedata.normalize("NFKD", str(h or "")).encode("ascii", "ignore").decode()
    return re.sub(r"[\s_\-\.@]+", "", text.strip().lower())


def _map_columns(cells) -> list[str]:
    """Nombre canónico de cada columna. Los alias secundarios solo rellenan campos que nadie más aportó."""
    names = [ALIASES.get(_norm_header(c)) for c in cells]
    taken = {n for n in names if n}
    out = []
    for c, n in zip(cells, names):
        if n is None:
            sec = SECONDARY_ALIASES.get(_norm_header(c))
            if sec and sec not in taken:
                n = sec
                taken.add(sec)
        out.append(n or str(c).strip())
    return out


def _find_header_row(raw: pd.DataFrame) -> int:
    for i in range(min(len(raw), 15)):
        hits = sum(1 for c in set(_map_columns(raw.iloc[i].tolist())) if c in CANONICAL)
        if hits >= 4:
            return i
    raise ParseError(
        "No encontré una fila de cabecera reconocible. Se esperan columnas como "
        "Timestamp, Hostname, Event_ID, User, Source_IP, Event_Description…"
    )


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _json_in_sheet(raw: pd.DataFrame):
    """Un JSON guardado línea por línea en una hoja (una celda por línea). Devuelve (objeto, reparado) o None.

    Si faltan líneas sueltas del original, solo sobran comas finales; se retiran para poder leer lo que sí está."""
    if raw.shape[1] > 1 and raw.iloc[:, 1:].notna().any().any():
        return None
    lines = ["" if pd.isna(v) else str(v) for v in raw.iloc[:, 0]]
    first = next((x.strip() for x in lines if x.strip()), "")
    if first[:1] not in ("{", "["):
        return None
    text = "\n".join(lines)
    try:
        return json.loads(text), False
    except (json.JSONDecodeError, RecursionError):
        pass
    try:
        return json.loads(_TRAILING_COMMA.sub(r"\1", text)), True
    except (json.JSONDecodeError, RecursionError):
        return None


def _looks_like_json_text(raw: pd.DataFrame) -> bool:
    if raw.shape[1] > 1 and raw.iloc[:, 1:].notna().any().any():
        return False
    first = next((str(v).strip() for v in raw.iloc[:, 0] if str(v).strip() not in ("", "nan")), "")
    return first[:1] in ("{", "[")


def _too_many_rows(n: int) -> ParseError:
    return ParseError(f"El archivo tiene {n:,} filas; el máximo soportado es {MAX_ROWS:,}. Divide el export por rango de fechas.".replace(",", "."))


# ---------------------------------------------------------------- lectores por formato

def _check_zip_size(source) -> None:
    """Rechaza archivos cuyo contenido descomprimido es desproporcionado, antes de que pandas los expanda."""
    try:
        with zipfile.ZipFile(source) as z:
            total = sum(i.file_size for i in z.infolist())
    except zipfile.BadZipFile as exc:
        raise ParseError("El archivo no es un Excel (.xlsx) válido.") from exc
    finally:
        if hasattr(source, "seek"):
            source.seek(0)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise ParseError(f"El archivo ocupa {total // (1024 * 1024)} MB descomprimido; el máximo permitido es {MAX_UNCOMPRESSED_BYTES // (1024 * 1024)} MB.")


def _read_excel(data: bytes) -> tuple[pd.DataFrame, str]:
    source = io.BytesIO(data)
    _check_zip_size(source)
    try:
        sheets = pd.read_excel(source, sheet_name=None, header=None, dtype=object)
    except Exception as exc:  # archivo corrupto, formato incorrecto…
        raise ParseError(f"No pude leer el archivo como Excel (.xlsx): {exc}") from exc
    if not sheets:
        raise ParseError("El archivo no contiene hojas.")
    # Usa la hoja con más filas de datos
    sheet_name, raw = max(sheets.items(), key=lambda kv: len(kv[1]))
    return raw, str(sheet_name)


def _decode_text(data: bytes) -> str:
    """Decodifica texto de un export: UTF-8 (con o sin BOM), UTF-16 con BOM o Windows-1252."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:4096]:
        raise ParseError("El archivo parece binario, no un export de texto (CSV/JSON).")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _pad(rows: list[list]) -> pd.DataFrame:
    width = max((len(r) for r in rows), default=0)
    return pd.DataFrame([r + [None] * (width - len(r)) for r in rows], dtype=object)


def _sniff_delimiter(text: str, filename: str | None) -> str:
    if filename and filename.lower().endswith(".tsv"):
        return "\t"
    lines = [ln for ln in text.splitlines()[:30] if ln.strip()]
    best, best_score = ",", 0
    for d in [",", ";", "\t", "|"]:
        counts = sorted(len(r) for r in csv.reader(lines, delimiter=d))
        if not counts:
            continue
        score = counts[len(counts) // 2]          # mediana de campos por línea
        if score > best_score:
            best, best_score = d, score
    return best


def _read_csv(data: bytes, filename: str | None) -> tuple[pd.DataFrame, str]:
    text = _decode_text(data)
    delim = _sniff_delimiter(text, filename)
    rows: list[list] = []
    try:
        for row in csv.reader(io.StringIO(text), delimiter=delim):
            if not any(c.strip() for c in row):
                continue
            rows.append(row)
            if len(rows) > MAX_ROWS + 100:          # corta pronto: no hace falta leer todo para rechazar
                raise _too_many_rows(len(rows))
    except csv.Error as exc:
        raise ParseError(f"No pude leer el archivo como CSV: {exc}") from exc
    if not rows:
        raise ParseError("El archivo está vacío.")
    label = {",": "CSV (coma)", ";": "CSV (punto y coma)", "\t": "TSV", "|": "CSV (barra vertical)"}[delim]
    return _pad(rows), label


def _flatten(obj: dict, prefix: str = "", depth: int = 0) -> dict:
    """Aplana objetos anidados con claves separadas por punto (host.name, winlog.event_id…)."""
    out: dict = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            if depth >= MAX_JSON_DEPTH:
                out[key] = json.dumps(v, ensure_ascii=False)
            else:
                out.update(_flatten(v, key, depth + 1))
        elif isinstance(v, list):
            out[key] = ", ".join(str(x) if not isinstance(x, (dict, list)) else json.dumps(x, ensure_ascii=False) for x in v)
        else:
            out[key] = v
    return out


_CONTAINERS = ("events", "records", "logs", "data", "items", "results", "result", "rows", "entries")


def _extract_records(obj, depth: int = 0) -> list[dict] | None:
    """Encuentra la lista de eventos dentro de un JSON: lista directa, contenedor típico o respuesta de Elastic."""
    if depth > 4:
        return None
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            return [_unwrap(x) for x in obj]
        return None
    if isinstance(obj, dict):
        hits = obj.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):          # Elasticsearch / OpenSearch
            return [_unwrap(h) for h in hits["hits"] if isinstance(h, dict)]
        for k in _CONTAINERS:
            if k in obj:
                found = _extract_records(obj[k], depth + 1)
                if found is not None:
                    return found
        if sum(1 for v in obj.values() if not isinstance(v, (dict, list))) >= 3:   # un único evento
            return [obj]
        best = _best_list(obj, depth)
        if best is not None:
            return best
        if any(not isinstance(v, (dict, list)) for v in obj.values()):
            return [obj]
    return None


def _has_time_field(records: list[dict]) -> bool:
    return any(ALIASES.get(_norm_header(k)) == "Timestamp" for r in records[:5] for k in r)


def _best_list(obj: dict, depth: int) -> list[dict] | None:
    """Contenedor con otro nombre («logs_database», «alerts»…): elige la lista de objetos que parece de eventos,
    es decir, la que tiene un campo de fecha y, entre ellas, la más larga."""
    cands = []
    for v in obj.values():
        found = _extract_records(v, depth + 1) if isinstance(v, (list, dict)) else None
        if found and _has_time_field(found):
            cands.append(found)
    return max(cands, key=len) if cands else None


def _unwrap(rec: dict) -> dict:
    """Elastic guarda el evento en _source (y su id en _id); Splunk en result."""
    if isinstance(rec.get("_source"), dict):
        inner = dict(rec["_source"])
        if "_id" in rec:
            inner.setdefault("_id", rec["_id"])
        return inner
    if isinstance(rec.get("result"), dict) and len(rec) <= 3:
        return rec["result"]
    return rec


def _read_json(data: bytes) -> tuple[pd.DataFrame, str]:
    text = _decode_text(data).strip()
    if not text:
        raise ParseError("El archivo está vacío.")
    label = "JSON"
    try:
        obj = json.loads(text)
    except RecursionError as exc:
        raise ParseError("El JSON tiene un anidamiento excesivo.") from exc
    except json.JSONDecodeError:
        # NDJSON / JSON Lines: un objeto por línea
        objs = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                objs.append(json.loads(line))
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ParseError(f"El archivo no es un JSON válido (error en la línea {n}).") from exc
            if len(objs) > MAX_ROWS + 100:
                raise _too_many_rows(len(objs))
        obj, label = objs, "NDJSON"
    records = _extract_records(obj)
    if not records:
        raise ParseError("No encontré una lista de eventos en el JSON. Se espera un arreglo de objetos, "
                         "un objeto por línea (NDJSON) o un contenedor como {\"events\": [...]}.")
    if len(records) > MAX_ROWS + 100:
        raise _too_many_rows(len(records))
    return _records_to_frame(records), label


def _records_to_frame(records: list[dict]) -> pd.DataFrame:
    flat = [_flatten(r) for r in records]
    cols: list[str] = []
    seen: set[str] = set()
    for r in flat:
        for k in r:
            if k not in seen:
                seen.add(k)
                cols.append(k)
        if len(cols) > MAX_COLUMNS:
            raise ParseError(f"Los eventos tienen más de {MAX_COLUMNS} campos distintos; no parece un export de logs.")
    rows = [cols] + [[r.get(c) for c in cols] for r in flat]
    return pd.DataFrame(rows, dtype=object)


# ---------------------------------------------------------------- marcas de tiempo

_TZ_RE = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$", re.I)


def _parse_timestamps(s: pd.Series) -> tuple[pd.Series, bool]:
    """Devuelve (serie datetime sin zona, True si hubo que convertir desde una zona horaria a UTC)."""
    nn = s.dropna()
    nn = nn[nn.astype(str).str.strip() != ""]
    if nn.empty:
        return pd.to_datetime(s, errors="coerce"), False
    looks_numeric = nn.astype(str).str.strip().str.fullmatch(r"\d+(?:\.\d+)?").all()
    num = pd.to_numeric(nn, errors="coerce") if looks_numeric else None
    if num is not None and num.notna().all() and (num >= 1e9).all():   # epoch (Splunk _time, Unix…): siempre UTC
        mx = num.max()
        unit = "s" if mx < 1e11 else "ms" if mx < 1e14 else "us" if mx < 1e17 else "ns"
        return pd.to_datetime(pd.to_numeric(s, errors="coerce"), unit=unit, errors="coerce"), True
    strs = s.astype(str).str.strip()
    if nn.astype(str).str.strip().str.contains(_TZ_RE).any():
        ts = pd.to_datetime(strs, errors="coerce", utc=True, format="mixed")
        return ts.dt.tz_localize(None), True
    return pd.to_datetime(s, errors="coerce"), False


# ---------------------------------------------------------------- punto de entrada

def _detect_format(data: bytes, filename: str | None) -> str:
    ext = Path(filename).suffix.lower() if filename else ""
    if ext in EXCEL_EXT or not ext:
        return "xlsx"                                   # sin nombre: comportamiento histórico (Excel)
    if ext in JSON_EXT:
        return "json"
    if ext in CSV_EXT:
        head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
        if head[:1] in (b"{", b"["):
            return "json"                                       # un .txt/.log puede traer JSON
        return "syslog" if syslog_mod.looks_like_syslog(_decode_text(data[:65536])) else "csv"   # o un auth.log de Linux
    raise ParseError("Formato no soportado. Usa Excel (.xlsx), CSV/TSV o JSON/NDJSON.")


def load_events(source: str | BinaryIO | bytes, filename: str | None = None) -> tuple[pd.DataFrame, dict]:
    """Devuelve (DataFrame normalizado, metadatos de carga).

    ``source`` puede ser una ruta, bytes o un archivo abierto. El formato se decide por la
    extensión de ``filename`` (o de la ruta); sin nombre se asume Excel.
    """
    if isinstance(source, str):
        filename = filename or source
        data = Path(source).read_bytes()
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        data = source.read()

    fmt = _detect_format(data, filename)
    if fmt == "xlsx":
        raw, label = _read_excel(data)
    elif fmt == "json":
        raw, label = _read_json(data)
    elif fmt == "syslog":
        events, sl = syslog_mod.parse_auth_log(_decode_text(data))
        if not events:
            raise ParseError("Parece un log de syslog, pero no encontré líneas de sshd ni de sudo (inicios de sesión SSH o comandos sudo). "
                             "Por ahora solo se interpretan esos eventos de auth.log / secure.")
        raw, label = _read_json(json.dumps(events).encode())
        label = "auth.log (syslog)"
    else:
        raw, label = _read_csv(data, filename)
    df, meta = _normalize(raw, label)
    meta["format"] = fmt
    if fmt == "syslog":
        meta["syslog"] = sl
    return df, meta


def _normalize(raw: pd.DataFrame, label: str) -> tuple[pd.DataFrame, dict]:
    raw = raw.dropna(how="all")
    if len(raw) > MAX_ROWS:
        raise _too_many_rows(len(raw))
    if raw.empty:
        raise ParseError("La hoja está vacía.")
    raw = raw.reset_index(drop=True)

    try:
        hdr = _find_header_row(raw)
    except ParseError:
        found = _json_in_sheet(raw)
        records = _extract_records(found[0]) if found else None
        if records:
            df, meta = _normalize(_records_to_frame(records), label)
            meta["json_in_sheet"], meta["json_repaired"] = True, found[1]
            return df, meta
        if _looks_like_json_text(raw):
            raise ParseError("Este archivo parece un JSON guardado en una hoja de cálculo (una línea por celda) y no se pudo "
                             "reconstruir. Vuelve a exportar el original como .json y súbelo con esa extensión.") from None
        raise
    columns = _map_columns(raw.iloc[hdr].tolist())
    df = raw.iloc[hdr + 1:].copy()
    df.columns = columns
    df = df.loc[:, ~pd.Index(df.columns).duplicated()]  # descarta columnas duplicadas (conserva la primera)

    missing_min = [c for c in REQUIRED_MIN if c not in df.columns]
    if missing_min:
        raise ParseError(
            "Faltan columnas indispensables: " + ", ".join(missing_min)
            + ". Columnas encontradas: " + ", ".join(map(str, df.columns))
        )

    missing_optional = [c for c in CANONICAL if c not in df.columns]
    for c in missing_optional:
        df[c] = ""

    for c in CANONICAL:
        if c != "Timestamp":
            df[c] = df[c].where(df[c].notna(), "").astype(str).str.strip()
    df["Timestamp"], tz_converted = _parse_timestamps(df["Timestamp"])
    bad_ts = int(df["Timestamp"].isna().sum())
    df = df.dropna(subset=["Timestamp"])
    if df.empty:
        raise ParseError("Ninguna fila tiene un Timestamp válido.")

    # Log_ID: si falta, se genera de forma estable (se avisa en los metadatos)
    generated_ids = False
    if (df["Log_ID"] == "").any():
        generated_ids = True
        blank = df["Log_ID"] == ""
        df.loc[blank, "Log_ID"] = [f"ROW-{i + 1:05d}" for i in range(int(blank.sum()))]

    df = df.sort_values(["Timestamp", "Log_ID"], kind="stable").reset_index(drop=True)
    df = df[CANONICAL]
    meta = {
        "sheet": label,
        "rows": int(len(df)),
        "rows_dropped_invalid_timestamp": bad_ts,
        "missing_columns": missing_optional,
        "generated_log_ids": generated_ids,
        "duplicate_log_ids": int(df["Log_ID"].duplicated().sum()),
        "timezone_converted": bool(tz_converted),
    }
    return df, meta
