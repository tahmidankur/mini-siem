import sqlite3

SCHEMA = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    ip TEXT NOT NULL,
    user TEXT,
    outcome TEXT,
    method TEXT,
    path TEXT,
    status INTEGER,
    user_agent TEXT,
    raw TEXT NOT NULL
);
CREATE INDEX idx_events_source_ip_ts ON events (source, ip, ts);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    ts_start TEXT NOT NULL,
    ts_end TEXT NOT NULL,
    rule TEXT NOT NULL,
    technique TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT NOT NULL,
    details TEXT NOT NULL
);
"""

EVENT_FIELDS = ["ts", "source", "ip", "user", "outcome", "method", "path", "status", "user_agent", "raw"]


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def insert_events(conn: sqlite3.Connection, events: list[dict]) -> None:
    # SSH events have no web fields and vice versa, so fill the missing ones with None.
    rows = [{**dict.fromkeys(EVENT_FIELDS), **event} for event in events]
    conn.executemany(
        "INSERT INTO events (ts, source, ip, user, outcome, method, path, status, user_agent, raw) "
        "VALUES (:ts, :source, :ip, :user, :outcome, :method, :path, :status, :user_agent, :raw)",
        rows,
    )
    conn.commit()


def insert_alerts(conn: sqlite3.Connection, alerts: list[dict]) -> None:
    conn.executemany(
        "INSERT INTO alerts (ts_start, ts_end, rule, technique, severity, ip, details) "
        "VALUES (:ts_start, :ts_end, :rule, :technique, :severity, :ip, :details)",
        alerts,
    )
    conn.commit()


def count_events(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT source, COUNT(*) AS n FROM events GROUP BY source").fetchall()
    return {row["source"]: row["n"] for row in rows}
