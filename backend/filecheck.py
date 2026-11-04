"""Upload content checks.

Security model
- Nothing here opens, runs or evaluates the uploaded file: we only look at bytes and zip metadata.
- The real type is decided by CONTENT (magic bytes), never by the file extension.
- Risky-but-legitimate features (macros, embedded objects, external links, formula injection) do not block the
  upload; they are reported to the analyst. Clearly wrong or hostile files are rejected with a human message.
- A clean result is NOT a guarantee that the file is safe: this is a first filter, not an antivirus.

User-facing messages are in Spanish on purpose (product language); code and comments are in English.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import pandas as pd

from .parser import EXCEL_EXT

MAX_ZIP_ENTRIES = 5_000          # a spreadsheet has tens of parts, not thousands
XML_SNIFF_BYTES = 4_096          # DOCTYPE / ENTITY declarations live in the XML prolog

# (magic bytes, description shown to the user)
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "un ejecutable de Windows"),
    (b"\x7fELF", "un ejecutable de Linux"),
    (b"\xcf\xfa\xed\xfe", "un ejecutable de macOS"),
    (b"\xfe\xed\xfa\xcf", "un ejecutable de macOS"),
    (b"\xca\xfe\xba\xbe", "un ejecutable de macOS o Java"),
    (b"%PDF", "un documento PDF"),
    (b"\x1f\x8b", "un archivo comprimido (gzip)"),
    (b"Rar!", "un archivo comprimido (RAR)"),
    (b"7z\xbc\xaf\x27\x1c", "un archivo comprimido (7-Zip)"),
    (b"\x89PNG", "una imagen"),
    (b"\xff\xd8\xff", "una imagen"),
    (b"GIF8", "una imagen"),
]
_OLE = bytes.fromhex("D0CF11E0A1B11AE1")     # legacy .xls / .doc container
_ZIP = (b"PK\x03\x04", b"PK\x05\x06")

# xlsx parts that deserve a warning -> message shown to the analyst
_FEATURES: list[tuple[str, str]] = [
    ("xl/vbaproject.bin", "contiene macros VBA"),
    ("xl/embeddings/", "contiene objetos incrustados (OLE)"),
    ("xl/externallinks/", "contiene vínculos a libros externos"),
    ("xl/connections.xml", "contiene conexiones de datos externas"),
    ("xl/querytables/", "contiene consultas de datos externas"),
    ("xl/activex/", "contiene controles ActiveX"),
]

# A cell is suspicious when it starts like a formula AND uses something Excel can run or fetch.
_FORMULA_START = r"^[\t\r]*(?:=|@|\+|-(?=[\d(@+=]))"
_FORMULA_RISK = r"(?i)(?:hyperlink|webservice|importxml|importdata|importhtml|cmd\s*\||/c\s|powershell|\bdde\b|msexcel|shell\()"


@dataclass
class FileCheck:
    kind: str                                   # xlsx | text
    reject: str | None = None                   # human message when the upload must be refused
    warnings: list[str] = field(default_factory=list)


def _binary_label(head: bytes) -> str | None:
    """Description of a known non-text container, or None when the bytes look like text."""
    if head.startswith(_OLE):
        return "un archivo de Office antiguo (.xls/.doc)"
    if head.startswith(_ZIP):
        return "un archivo ZIP"
    for magic, label in _SIGNATURES:
        if head.startswith(magic):
            return label
    return None


def _inspect_xlsx(data: bytes) -> FileCheck:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return FileCheck("xlsx", reject="El archivo no es un Excel (.xlsx) válido: el contenido está dañado.")
    with z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            return FileCheck("xlsx", reject="El archivo tiene una estructura interna anormal (demasiadas partes) y no se analizó.")
        names = [i.filename for i in infos]
        for n in names:                          # zip-slip style names: never legitimate in a spreadsheet
            parts = PurePosixPath(n.replace("\\", "/")).parts
            if n.startswith(("/", "\\")) or ".." in parts:
                return FileCheck("xlsx", reject="El archivo contiene rutas internas sospechosas y no se analizó.")
        lower = {n.lower() for n in names}
        if "[content_types].xml" not in lower or "xl/workbook.xml" not in lower:
            return FileCheck("xlsx", reject="El archivo es un ZIP, pero no un libro de Excel válido (por ejemplo, un .docx o un ZIP cualquiera).")
        for info in infos:                       # XML bombs / XXE need a DOCTYPE or ENTITY; real Excel never has one
            if info.filename.lower().endswith((".xml", ".rels")) and info.file_size:
                with z.open(info) as fh:
                    prolog = fh.read(XML_SNIFF_BYTES).upper()
                if b"<!DOCTYPE" in prolog or b"<!ENTITY" in prolog:
                    return FileCheck("xlsx", reject="El archivo contiene declaraciones XML peligrosas (DOCTYPE/ENTITY) y no se analizó.")
        warnings = []
        for prefix, msg in _FEATURES:
            if any(n == prefix or (prefix.endswith("/") and n.startswith(prefix)) for n in lower):
                warnings.append(f"Seguridad del archivo: el Excel {msg}. La aplicación no lo ejecuta, pero no abras el original con esas funciones habilitadas.")
        return FileCheck("xlsx", warnings=warnings)


def inspect_upload(data: bytes, name: str) -> FileCheck:
    """Decide whether the content matches the declared extension and report risky features."""
    ext = PurePosixPath(name.lower()).suffix
    label = _binary_label(data[:16])
    if ext in EXCEL_EXT:
        if label == "un archivo ZIP":
            return _inspect_xlsx(data)
        if label and label.startswith("un archivo de Office antiguo"):
            return FileCheck("xlsx", reject="Es un Excel antiguo (.xls). Guárdalo como .xlsx, CSV o JSON y vuelve a cargarlo.")
        if label:
            return FileCheck("xlsx", reject=f"El archivo se llama «{name}» pero su contenido es {label}, no un Excel. No se analizó.")
        return FileCheck("xlsx", reject="El contenido no corresponde a un Excel (.xlsx) válido. No se analizó.")
    if label:
        return FileCheck("text", reject=f"El archivo tiene extensión «{ext}» pero su contenido es {label}, no un export de texto (CSV/JSON). No se analizó.")
    return FileCheck("text")


def formula_warnings(df: pd.DataFrame) -> list[str]:
    """Spreadsheet formula injection: text cells that Excel could execute if the ORIGINAL file is reopened."""
    total = 0
    for col in df.columns:
        s = df[col]
        if pd.api.types.is_numeric_dtype(s) or pd.api.types.is_datetime64_any_dtype(s):
            continue                    # text columns are `object` or `str` depending on the pandas version
        s = s.astype(str)
        total += int((s.str.contains(_FORMULA_START, regex=True) & s.str.contains(_FORMULA_RISK, regex=True)).sum())
    if not total:
        return []
    return [f"Seguridad del archivo: {total} celda(s) empiezan como una fórmula (=, +, -, @) e incluyen funciones o comandos que Excel podría "
            "ejecutar (inyección de fórmulas). La aplicación no evalúa fórmulas; no abras el original en Excel."]
