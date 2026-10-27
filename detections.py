import re
import sqlite3
from datetime import datetime, timedelta
from itertools import groupby
from urllib.parse import unquote_plus

BRUTE_FORCE_FAILURES = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=120)
SCAN_404S = 20
SCAN_WINDOW = timedelta(seconds=60)

# Run against the lowercased, URL-decoded path. "--" is broad (it can catch harmless
# paths) but it's how most injected queries comment out the rest of the statement.
SQLI_RE = re.compile(r"'\s*or\s+1\s*=\s*1|union\s+select|sleep\s*\(|--|information_schema")


def find_bursts(times: list[datetime], threshold: int, window: timedelta) -> list[tuple[int, int]]:
    # Slide a window over the sorted times. Whenever it holds `threshold` or more events,
    # that's part of a burst. Windows that share events get merged, so one long attack
    # becomes one burst. Returns (first index, last index) pairs.
    bursts = []
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        if end - start + 1 >= threshold:
            if bursts and start <= bursts[-1][1]:
                bursts[-1] = (bursts[-1][0], end)
            else:
                bursts.append((start, end))
    return bursts


def seconds_between(a: datetime, b: datetime) -> int:
    return int((b - a).total_seconds())


def brute_force(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT ip, ts FROM events WHERE source = 'ssh' AND outcome = 'failed' AND ip IN "
        "(SELECT ip FROM events WHERE source = 'ssh' AND outcome = 'failed' GROUP BY ip HAVING COUNT(*) >= ?) "
        "ORDER BY ip, ts",
        (BRUTE_FORCE_FAILURES,),
    ).fetchall()

    alerts = []
    for ip, group in groupby(rows, key=lambda row: row["ip"]):
        times = [datetime.fromisoformat(row["ts"]) for row in group]
        for first, last in find_bursts(times, BRUTE_FORCE_FAILURES, BRUTE_FORCE_WINDOW):
            start, end = times[first], times[last]
            severity = "high"
            details = f"{last - first + 1} failed logins in {seconds_between(start, end)} seconds"
            accepted = conn.execute(
                "SELECT ts, user FROM events WHERE source = 'ssh' AND outcome = 'accepted' AND ip = ? AND ts > ? "
                "ORDER BY ts LIMIT 1",
                (ip, start.isoformat()),
            ).fetchone()
            if accepted:
                severity = "critical"
                end = datetime.fromisoformat(accepted["ts"])
                details += f", then accepted login as {accepted['user']}"
            alerts.append({
                "ts_start": start.isoformat(), "ts_end": end.isoformat(),
                "rule": "SSH brute force", "technique": "T1110.001 Password Guessing",
                "severity": severity, "ip": ip, "details": details,
            })
    return alerts


def sql_injection(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT ip, ts, path, status FROM events WHERE source = 'web' ORDER BY ip, ts").fetchall()
    hits = [row for row in rows if SQLI_RE.search(unquote_plus(row["path"]).lower())]

    alerts = []
    for ip, group in groupby(hits, key=lambda row: row["ip"]):
        group = list(group)
        succeeded = sum(1 for row in group if row["status"] == 200)
        details = f"{len(group)} requests matching SQL injection patterns"
        if succeeded:
            details += f", {succeeded} returned 200"
        alerts.append({
            "ts_start": group[0]["ts"], "ts_end": group[-1]["ts"],
            "rule": "SQL injection attempt", "technique": "T1190 Exploit Public-Facing Application",
            "severity": "high" if succeeded else "medium", "ip": ip, "details": details,
        })
    return alerts


def directory_scanning(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT ip, ts FROM events WHERE source = 'web' AND status = 404 AND ip IN "
        "(SELECT ip FROM events WHERE source = 'web' AND status = 404 GROUP BY ip HAVING COUNT(*) >= ?) "
        "ORDER BY ip, ts",
        (SCAN_404S,),
    ).fetchall()

    alerts = []
    for ip, group in groupby(rows, key=lambda row: row["ip"]):
        times = [datetime.fromisoformat(row["ts"]) for row in group]
        for first, last in find_bursts(times, SCAN_404S, SCAN_WINDOW):
            start, end = times[first], times[last]
            alerts.append({
                "ts_start": start.isoformat(), "ts_end": end.isoformat(),
                "rule": "Web directory scanning", "technique": "T1595.003 Wordlist Scanning",
                "severity": "low", "ip": ip,
                "details": f"{last - first + 1} requests returned 404 in {seconds_between(start, end)} seconds",
            })
    return alerts


def run_all(conn: sqlite3.Connection) -> list[dict]:
    return brute_force(conn) + sql_injection(conn) + directory_scanning(conn)
