import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

SEED = 1012
DAY = datetime(2026, 10, 12)
HOST = "web01"
OUT_DIR = Path("sample_logs")

USERS = {
    "maria": "10.0.4.21",
    "james": "10.0.4.22",
    "priya": "10.0.4.35",
    "tom": "10.0.6.14",
    "chen": "10.0.6.30",
    "deploy": "10.0.9.10",
}

# Rough shape of a store's day: quiet overnight, busy during work hours.
HOUR_WEIGHTS = [1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 10, 9, 8, 9, 10, 10, 9, 7, 5, 4, 3, 2, 2, 1]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
]

PAGES = ["/", "/products", "/about", "/contact", "/cart", "/login", "/static/css/main.css",
         "/static/js/app.js", "/images/logo.png"]
SEARCHES = ["rain jacket", "boots", "wool socks", "tent", "backpack"]
BROKEN_LINKS = ["/favicon.ico", "/products/old-catalog", "/blog", "/careers"]

SQLI_PAYLOADS = [
    "1' OR 1=1-- ",
    "1 AND 1=1",
    "1 AND SLEEP(5)",
    "1' AND SLEEP(5)-- ",
    "1 UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT username,password,NULL FROM users--",
    "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
]

WORDLIST = ["admin", "backup", "backups", "bin", "cgi-bin", "config", "console", "dashboard", "db",
            "debug", "dev", "files", "include", "install", "logs", "manager", "old", "panel",
            "phpmyadmin", "private", "server-status", "setup", "sql", "temp", "test", "tmp",
            "uploads", "user", "wp-admin", "wp-content", "wp-login.php", ".env", ".git/HEAD",
            "login", "static", "robots.txt"]
SCAN_HITS = {"/login": 200, "/static": 403, "/uploads": 403, "/robots.txt": 200}


def at(hour: int) -> datetime:
    return DAY + timedelta(hours=hour, seconds=random.randint(0, 3599))


def syslog(ts: datetime, pid: int, message: str) -> tuple[datetime, str]:
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} sshd[{pid}]: {message}"


def failed(ts: datetime, user: str, ip: str) -> tuple[datetime, str]:
    who = user if user in USERS or user == "root" else f"invalid user {user}"
    port = random.randint(40000, 65000)
    return syslog(ts, random.randint(1000, 32000), f"Failed password for {who} from {ip} port {port} ssh2")


def login(ts: datetime, user: str, ip: str, method: str = "password") -> list[tuple[datetime, str]]:
    pid = random.randint(1000, 32000)
    port = random.randint(40000, 65000)
    closed = min(ts + timedelta(minutes=random.randint(5, 240)), DAY.replace(hour=23, minute=59))
    return [
        syslog(ts, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2"),
        syslog(ts, pid, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"),
        syslog(closed, pid, f"pam_unix(sshd:session): session closed for user {user}"),
    ]


def normal_ssh() -> list:
    lines = []
    for _ in range(80):
        user = random.choice(list(USERS))
        ts = at(random.randint(8, 18))
        if random.random() < 0.1:
            lines.append(failed(ts - timedelta(seconds=random.randint(4, 15)), user, USERS[user]))
        lines += login(ts, user, USERS[user], "publickey" if user == "deploy" else "password")
    return lines


def near_miss() -> list:
    # priya fumbles her password three times, then gets in. Should stay under the threshold.
    start = DAY.replace(hour=11, minute=42, second=5)
    lines = [failed(start + timedelta(seconds=i * 9), "priya", USERS["priya"]) for i in range(3)]
    return lines + login(start + timedelta(seconds=31), "priya", USERS["priya"])


def brute_force(ip: str, start: datetime, names: list[str], attempts: int, gap: tuple[int, int]) -> list:
    lines, ts = [], start
    for i in range(attempts):
        lines.append(failed(ts, names[i % len(names)], ip))
        ts += timedelta(seconds=random.randint(*gap))
    return lines


def web_line(ts, ip, method, path, status, ua, referer="-") -> tuple[datetime, str]:
    size = random.randint(200, 9000) if status == 200 else random.randint(150, 600)
    return ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} -0700] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def normal_web(count: int) -> list:
    clients = [f"10.{random.randint(0, 20)}.{random.randint(0, 255)}.{random.randint(2, 254)}" for _ in range(40)]
    lines = []
    for _ in range(count):
        ts = at(random.choices(range(24), weights=HOUR_WEIGHTS)[0])
        ip, ua = random.choice(clients), random.choice(BROWSERS)
        roll = random.random()
        if roll < 0.03:
            lines.append(web_line(ts, ip, "GET", random.choice(BROKEN_LINKS), 404, ua))
        elif roll < 0.15:
            path = f"/products?id={random.randint(1, 60)}"
            lines.append(web_line(ts, ip, "GET", path, 200, ua, "https://shop.example.com/products"))
        elif roll < 0.22:
            path = "/search?q=" + quote(random.choice(SEARCHES))
            lines.append(web_line(ts, ip, "GET", path, 200, ua, "https://shop.example.com/"))
        elif roll < 0.25:
            lines.append(web_line(ts, ip, "POST", "/login", random.choice([200, 302]), ua))
        else:
            path = random.choice(PAGES)
            status = random.choice([200, 304]) if path.startswith(("/static", "/images")) else 200
            lines.append(web_line(ts, ip, "GET", path, status, ua))
    return lines


def sqli(ip: str, start: datetime) -> list:
    ua = "sqlmap/1.8#stable (https://sqlmap.org)"
    lines, ts = [], start
    for i in range(40):
        payload, status = random.choice(SQLI_PAYLOADS), random.choice([500, 500, 400])
        if i in (12, 27):
            payload, status = "1' OR 1=1-- ", 200
        lines.append(web_line(ts, ip, "GET", "/products?id=" + quote(payload), status, ua))
        ts += timedelta(seconds=random.randint(1, 6))
    return lines


def scan(ip: str, start: datetime) -> list:
    ua = "gobuster/3.6"
    lines, ts = [], start
    for word in WORDLIST:
        for path in (f"/{word}", f"/{word}.php", f"/{word}.bak"):
            lines.append(web_line(ts, ip, "GET", path, SCAN_HITS.get(path, 404), ua))
            ts += timedelta(milliseconds=random.randint(200, 700))
    return lines


def write(path: Path, lines: list) -> None:
    lines.sort(key=lambda pair: pair[0])
    path.write_text("\n".join(line for _, line in lines) + "\n")
    print(f"wrote {len(lines)} lines to {path}")


def main() -> None:
    random.seed(SEED)
    OUT_DIR.mkdir(exist_ok=True)

    ssh = normal_ssh() + near_miss()
    ssh += brute_force("203.0.113.5", DAY.replace(hour=14, minute=3, second=22),
                       ["admin", "root", "test", "oracle", "ubuntu", "deploy", "git", "postgres", "guest"],
                       attempts=36, gap=(2, 5))
    # This one guesses deploy's password on the 15th try.
    ssh += brute_force("192.0.2.44", DAY.replace(hour=2, minute=17, second=10), ["deploy"], attempts=14, gap=(3, 5))
    ssh += login(DAY.replace(hour=2, minute=18, second=25), "deploy", "192.0.2.44")
    write(OUT_DIR / "auth.log", ssh)

    web = normal_web(2850)
    web += sqli("198.51.100.23", DAY.replace(hour=14, minute=5, second=1))
    web += scan("203.0.113.77", DAY.replace(hour=16, minute=20, second=0))
    write(OUT_DIR / "access.log", web)


if __name__ == "__main__":
    main()
