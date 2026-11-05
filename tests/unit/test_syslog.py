"""Lectura de auth.log de Linux y análisis de punta a punta."""
from datetime import datetime

import pytest

from backend import syslog
from backend.analysis import analyze
from backend.parser import ParseError, load_events

NOW = datetime(2026, 11, 5, 12, 0, 0)


def log(lines):
    return "\n".join(lines).encode()


def fails(n, ip="203.0.113.7", user="root", start=0):
    return [f"Nov  2 09:{(start + i) // 60:02d}:{(start + i) % 60:02d} srv sshd[100{i}]: Failed password for {user} from {ip} port 4{i:04d} ssh2" for i in range(n)]


def test_classic_syslog_brute_force_is_detected_end_to_end():
    df, meta = load_events(log(fails(8) + ["Nov  2 09:01:00 srv CRON[1]: pam_unix(cron:session): session opened for user root"]), "auth.log")
    assert meta["format"] == "syslog" and meta["syslog"]["events"] == 8 and meta["syslog"]["ignored"] == 1
    f = [x for x in analyze(df, meta)["findings"] if x["rule"] == "g_auth"]
    assert f and "203.0.113.7" in f[0]["ips"]


def test_success_after_failures_is_reported_with_the_user():
    lines = fails(5, user="admin") + ["Nov  2 09:02:00 srv sshd[2]: Accepted password for admin from 203.0.113.7 port 5000 ssh2"]
    df, meta = load_events(log(lines), "secure.log")
    assert (df["Event_Description"].str.contains("Accepted")).any()
    assert any(x["rule"] == "g_auth" for x in analyze(df, meta)["findings"])


def test_iso_timestamps_are_converted_to_utc():
    ev, st = syslog.parse_auth_log("2026-11-02T09:00:01.123456-03:00 srv sshd[1]: Failed password for bob from 198.51.100.4 port 22 ssh2\n"
                                   "2026-11-02T09:00:02+00:00 srv sshd[1]: Failed password for bob from 198.51.100.4 port 22 ssh2\n"
                                   "2026-11-02T09:00:03Z srv sshd[1]: Failed password for bob from 198.51.100.4 port 22 ssh2", now=NOW)
    assert [e["timestamp"] for e in ev] == ["2026-11-02T12:00:01Z", "2026-11-02T09:00:02Z", "2026-11-02T09:00:03Z"]


def test_year_is_inferred_and_never_in_the_future():
    ev, _ = syslog.parse_auth_log("Dec 30 23:59:59 srv sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", now=NOW)
    assert ev[0]["timestamp"].startswith("2025-12-30")          # diciembre no puede ser posterior a «hoy» (nov 2026)


def test_invalid_user_line_is_not_counted_twice():
    ev, _ = syslog.parse_auth_log("Nov  2 09:00:00 srv sshd[1]: Invalid user x from 203.0.113.1 port 1\n"
                                  "Nov  2 09:00:00 srv sshd[1]: Failed password for invalid user x from 203.0.113.1 port 1 ssh2", now=NOW)
    assert len(ev) == 1


def test_sudo_failures_and_commands():
    ev, _ = syslog.parse_auth_log("Nov  2 09:00:00 srv sudo: ana : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/bin/bash\n"
                                  "Nov  2 09:00:05 srv sudo:      ana : TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", now=NOW)
    assert [e["action"] for e in ev] == ["sudo", "sudo_command"] and "cat /etc/shadow" in ev[1]["message"]


def test_a_csv_is_not_mistaken_for_syslog():
    csv = b"Timestamp,Hostname,Event_ID,User\n2026-11-02 09:00:00,A,4624,x\n2026-11-02 09:00:01,A,4625,y\n2026-11-02 09:00:02,A,4625,y\n"
    assert not syslog.looks_like_syslog(csv.decode())
    assert load_events(csv, "x.log")[1]["format"] == "csv"


def test_syslog_without_ssh_or_sudo_gets_a_clear_error():
    with pytest.raises(ParseError, match="sshd ni de sudo"):
        load_events(log([f"Nov  2 09:00:0{i} srv CRON[1]: pam_unix(cron:session): session opened" for i in range(5)]), "syslog.log")


def test_hostile_lines_do_not_crash_the_reader():
    ev, st = syslog.parse_auth_log("Nov  2 09:00:00 srv sshd[1]: Failed password for " + "A" * 5000 + " from 1.2.3.4 port 1\n\x00\x01garbage\n" + "x" * 100000, now=NOW)
    assert st["lines"] == 3 and isinstance(ev, list)


def test_bundled_sample_auth_log_is_a_critical_spraying_with_success():
    from pathlib import Path
    df, meta = load_events(str(Path(__file__).resolve().parents[2] / "sample_data" / "auth_log_ejemplo.txt"))
    f = [x for x in analyze(df, meta)["findings"] if x["rule"] == "g_auth"]
    assert len(f) == 1 and f[0]["severity"] == "Crítico" and "185.220.101.47" in f[0]["ips"]
