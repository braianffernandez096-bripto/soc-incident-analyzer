"""Carga y normalización del export de SIEM (.xlsx).

El parser es tolerante: detecta la fila de cabecera, acepta variantes de
nombres de columna (espacios, mayúsculas, alias en español/inglés) y
normaliza tipos. No inventa datos: lo que falta queda vacío.
"""
from __future__ import annotations

import io
import zipfile
import re
from typing import BinaryIO

import pandas as pd

CANONICAL = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
    "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
    "Result", "Severity",
]

# alias (normalizados: minúsculas, sin espacios/guiones) -> nombre canónico
ALIASES = {
    "logid": "Log_ID", "id": "Log_ID", "eventrecordid": "Log_ID",
    "timestamp": "Timestamp", "time": "Timestamp", "fecha": "Timestamp",
    "fechahora": "Timestamp", "timecreated": "Timestamp", "datetime": "Timestamp",
    "hostname": "Hostname", "host": "Hostname", "computer": "Hostname",
    "equipo": "Hostname", "computername": "Hostname",
    "eventid": "Event_ID", "evento": "Event_ID", "eventcode": "Event_ID",
    "user": "User", "usuario": "User", "account": "User", "username": "User",
    "cuenta": "User",
    "sourceip": "Source_IP", "srcip": "Source_IP", "ipaddress": "Source_IP",
    "ip": "Source_IP", "ipv4origen": "Source_IP", "ipdeorigen": "Source_IP",
    "destination": "Destination", "destino": "Destination", "destip": "Destination",
    "destinationip": "Destination", "dest": "Destination",
    "logsource": "Log_Source", "source": "Log_Source", "fuente": "Log_Source",
    "channel": "Log_Source",
    "eventdescription": "Event_Description", "description": "Event_Description",
    "descripcion": "Event_Description", "message": "Event_Description",
    "mensaje": "Event_Description",
    "processcommandline": "Process_CommandLine", "commandline": "Process_CommandLine",
    "comando": "Process_CommandLine", "process": "Process_CommandLine",
    "result": "Result", "resultado": "Result", "status": "Result",
    "severity": "Severity", "severidad": "Severity", "level": "Severity",
    "criticidad": "Severity",
}

REQUIRED_MIN = ["Timestamp", "Event_ID"]


class ParseError(ValueError):
    """Error legible para el usuario (se muestra en la interfaz)."""


def _norm_header(h: object) -> str:
    return re.sub(r"[\s_\-\.]+", "", str(h or "").strip().lower())


def _find_header_row(raw: pd.DataFrame) -> int:
    for i in range(min(len(raw), 15)):
        cells = {_norm_header(c) for c in raw.iloc[i].tolist()}
        hits = sum(1 for c in cells if c in ALIASES)
        if hits >= 4:
            return i
    raise ParseError(
        "No encontré una fila de cabecera reconocible. Se esperan columnas como "
        "Timestamp, Hostname, Event_ID, User, Source_IP, Event_Description…"
    )


MAX_UNCOMPRESSED_BYTES = 300 * 1024 * 1024   # un .xlsx es un zip: limita su tamaño descomprimido (zip bomb)
MAX_ROWS = 100_000


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


def load_events(source: str | BinaryIO | bytes) -> tuple[pd.DataFrame, dict]:
    """Devuelve (DataFrame normalizado, metadatos de carga)."""
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    _check_zip_size(source)
    try:
        sheets = pd.read_excel(source, sheet_name=None, header=None, dtype=object)
    except Exception as exc:  # archivo corrupto, formato incorrecto…
        raise ParseError(f"No pude leer el archivo como Excel (.xlsx): {exc}") from exc
    if not sheets:
        raise ParseError("El archivo no contiene hojas.")

    # Usa la hoja con más filas de datos
    sheet_name, raw = max(sheets.items(), key=lambda kv: len(kv[1]))
    raw = raw.dropna(how="all")
    if len(raw) > MAX_ROWS:
        raise ParseError(f"El archivo tiene {len(raw):,} filas; el máximo soportado es {MAX_ROWS:,}. Divide el export por rango de fechas.".replace(",", "."))
    if raw.empty:
        raise ParseError("La hoja está vacía.")
    raw = raw.reset_index(drop=True)

    hdr = _find_header_row(raw)
    columns = [ALIASES.get(_norm_header(c), str(c).strip()) for c in raw.iloc[hdr].tolist()]
    df = raw.iloc[hdr + 1:].copy()
    df.columns = columns
    df = df.loc[:, ~pd.Index(df.columns).duplicated()]  # descarta columnas duplicadas

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
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
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
        "sheet": str(sheet_name),
        "rows": int(len(df)),
        "rows_dropped_invalid_timestamp": bad_ts,
        "missing_columns": missing_optional,
        "generated_log_ids": generated_ids,
        "duplicate_log_ids": int(df["Log_ID"].duplicated().sum()),
    }
    return df, meta
