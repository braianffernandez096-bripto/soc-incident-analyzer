"""Columnas que aportan el mismo campo y cuentas con dos grafías: el dato no se pierde y la misma actividad no se cuenta dos veces.

Antes, si un JSON traía «Description» (de Sysmon) y «Message», o «host» (del colector) y «Hostname», se conservaba solo la primera
columna y los eventos que no la tenían quedaban con el campo vacío. Medido con OTRF: ver docs/VALIDACION.md.
"""
import json

import pandas as pd

from backend import detection as D
from backend.analysis import analyze
from backend.parser import load_events


def _load(records):
    return load_events(json.dumps(records).encode(), "x.json")[0]


def test_se_combinan_por_fila_con_prioridad():
    df = _load([
        {"@timestamp": "2026-11-15T10:00:00Z", "EventID": 1, "host": "wec.colector", "Hostname": "WS-01", "Description": "WMI Provider Host",
         "Message": "Process Create:\nImage: C:\\x.exe", "SourceIp": "", "IpAddress": "10.0.0.9"},
        {"@timestamp": "2026-11-15T10:00:01Z", "EventID": 4624, "host": "wec.colector", "Hostname": "", "Description": "",
         "Message": "An account was successfully logged on.", "SourceIp": "10.0.0.7", "IpAddress": "-"},
    ])
    assert list(df["Event_Description"]) == ["Process Create:\nImage: C:\\x.exe", "An account was successfully logged on."]   # el mensaje gana a «Description»
    assert list(df["Hostname"]) == ["WS-01", "wec.colector"]       # el equipo real; el colector solo si no hay otro dato
    assert list(df["Source_IP"]) == ["10.0.0.9", "10.0.0.7"]        # «-» y vacío cuentan como sin dato


def test_cuenta_desde_target_o_subject_username():
    df = _load([
        {"@timestamp": "2026-11-15T10:00:00Z", "EventID": 4624, "TargetUserName": "ana", "Message": "x"},
        {"@timestamp": "2026-11-15T10:00:01Z", "EventID": 4672, "SubjectUserName": "luis", "Message": "x"},
        {"@timestamp": "2026-11-15T10:00:02Z", "EventID": 1, "User": "CORP\\eva", "SubjectUserName": "otro", "Message": "x"},
    ])
    assert list(df["User"]) == ["ana", "luis", "CORP\\eva"]


def test_archivo_sin_columnas_repetidas_no_cambia():
    csv = "Timestamp,Event_ID,Hostname,User,Event_Description\n2026-11-15 10:00:00,4624,WS-01,ana,ok\n".encode()
    df, _ = load_events(csv, "x.csv")
    assert df.iloc[0]["Hostname"] == "WS-01" and df.iloc[0]["Event_Description"] == "ok"


def test_unifica_grafias_de_una_misma_cuenta():
    df = pd.DataFrame({"User": ["THESHIRE\\pgustavo", "pgustavo", "SYSTEM", "NT AUTHORITY\\SYSTEM", "theshire\\PGUSTAVO", "PC$", "", "-"]})
    assert list(D.unify_accounts(df)["User"]) == ["THESHIRE\\pgustavo", "THESHIRE\\pgustavo", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\SYSTEM",
                                                  "THESHIRE\\pgustavo", "PC$", "", "-"]


def test_no_unifica_si_el_nombre_es_ambiguo():
    df = pd.DataFrame({"User": ["CORP\\admin", "LAB\\admin", "admin"]})
    assert list(D.unify_accounts(df)["User"]) == ["CORP\\admin", "LAB\\admin", "admin"]


def test_la_misma_actividad_con_dos_grafias_es_un_solo_hallazgo():
    cmd = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    recs = [{"@timestamp": "2026-11-15T10:00:00Z", "EventID": 1, "Hostname": "WS-01", "User": "CORP\\ana", "CommandLine": cmd, "Message": "Process Create"},
            {"@timestamp": "2026-11-15T10:00:01Z", "EventID": 4688, "Hostname": "WS-01", "SubjectUserName": "ana", "CommandLine": cmd, "Message": "A new process"}]
    df, meta = load_events(json.dumps(recs).encode(), "x.json")
    enc = [f for f in analyze(df, meta)["findings"] if f["rule"] == "cmd_encoded_ps"]
    assert len(enc) == 1


def test_mayusculas_no_son_cuentas_parecidas():
    recs = [{"@timestamp": f"2026-11-15T10:00:0{i}Z", "EventID": 4624, "Hostname": "WS-01", "User": u, "Message": "x"} for i, u in enumerate(["SYSTEM", "System"])]
    df, meta = load_events(json.dumps(recs).encode(), "x.json")
    assert not [f for f in analyze(df, meta)["findings"] if f["rule"] == "dq_account_lookalike"]


def test_inicio_externo_sin_cuenta_no_marca_comprometidos_a_todos():
    recs = [{"@timestamp": "2026-11-15T10:00:00Z", "EventID": 4624, "Hostname": "WS-01", "IpAddress": "203.0.113.5", "Message": "Logon Type: 3"},
            {"@timestamp": "2026-11-15T10:01:00Z", "EventID": 4672, "Hostname": "WS-01", "Message": "Special privileges assigned to new logon."}]
    df, meta = load_events(json.dumps(recs).encode(), "x.json")
    assert not [f for f in analyze(df, meta)["findings"] if f["rule"] == "privilege"]
