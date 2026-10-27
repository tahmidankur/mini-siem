from datetime import datetime, timedelta

import db
from detections import brute_force, directory_scanning, sql_injection

T0 = datetime(2026, 10, 12, 14, 0, 0)


def at(seconds: int) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()


def ssh(seconds, ip, outcome, user="root"):
    return {"ts": at(seconds), "source": "ssh", "ip": ip, "user": user, "outcome": outcome, "raw": ""}


def web(seconds, ip, path, status):
    return {"ts": at(seconds), "source": "web", "ip": ip, "method": "GET", "path": path,
            "status": status, "user_agent": "test", "raw": ""}


def load(events):
    conn = db.connect(":memory:")
    db.create_tables(conn)
    db.insert_events(conn, events)
    return conn


def test_brute_force_fires_high():
    conn = load([ssh(i * 10, "203.0.113.5", "failed") for i in range(6)])
    alerts = brute_force(conn)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["details"] == "6 failed logins in 50 seconds"


def test_brute_force_then_accepted_is_critical():
    events = [ssh(i * 4, "192.0.2.44", "failed", "deploy") for i in range(5)]
    events.append(ssh(30, "192.0.2.44", "accepted", "deploy"))
    alerts = brute_force(load(events))
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["details"].endswith("then accepted login as deploy")
    assert alerts[0]["ts_end"] == at(30)


def test_brute_force_near_miss():
    # Three typos then a login, and five failures spread too thin to count.
    events = [ssh(i * 9, "10.0.4.35", "failed", "priya") for i in range(3)]
    events.append(ssh(31, "10.0.4.35", "accepted", "priya"))
    events += [ssh(i * 60, "10.0.6.14", "failed", "tom") for i in range(5)]
    assert brute_force(load(events)) == []


def test_brute_force_one_alert_per_burst():
    events = [ssh(i * 5, "203.0.113.5", "failed") for i in range(10)]
    events += [ssh(3600 + i * 5, "203.0.113.5", "failed") for i in range(10)]
    assert len(brute_force(load(events))) == 2


def test_sql_injection_fires():
    ip = "198.51.100.23"
    conn = load([
        web(0, ip, "/products?id=1%27%20OR%201%3D1--", 200),
        web(5, ip, "/products?id=1%20UNION%20SELECT%20NULL%2CNULL--", 500),
        web(9, ip, "/products?id=1%20AND%20SLEEP%285%29", 500),
    ])
    alerts = sql_injection(conn)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["details"] == "3 requests matching SQL injection patterns, 1 returned 200"


def test_sql_injection_medium_when_nothing_succeeds():
    conn = load([web(0, "198.51.100.23", "/products?id=1%20UNION%20SELECT%201", 500)])
    assert sql_injection(conn)[0]["severity"] == "medium"


def test_sql_injection_near_miss():
    conn = load([
        web(0, "10.0.4.21", "/search?q=union+station+boots", 200),
        web(1, "10.0.4.21", "/products?id=12", 200),
        web(2, "10.0.4.21", "/search?q=rain%20jacket", 200),
    ])
    assert sql_injection(conn) == []


def test_directory_scanning_fires():
    conn = load([web(i, "203.0.113.77", f"/word{i}", 404) for i in range(25)])
    alerts = directory_scanning(conn)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "low"
    assert alerts[0]["details"] == "25 requests returned 404 in 24 seconds"


def test_directory_scanning_near_miss():
    # 25 404s, but spread out so no 60 second window has more than 13.
    conn = load([web(i * 5, "10.0.4.21", f"/old{i}", 404) for i in range(25)])
    assert directory_scanning(conn) == []
