import re
from datetime import datetime

# Only failed and accepted logins matter here. Other sshd lines (pam_unix sessions,
# disconnects) don't match and get skipped.
# Oct 12 14:03:22 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2
SSH_RE = re.compile(
    r"^(?P<ts>\w{3} +\d{1,2} \d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
    r"(?P<outcome>Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port \d+"
)

# Combined log format:
# 198.51.100.23 - - [12/Oct/2026:14:05:01 -0700] "GET /products?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.8"
WEB_RE = re.compile(
    r'^(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)


def parse_ssh(line: str, year: int) -> dict | None:
    match = SSH_RE.match(line)
    if not match:
        return None
    ts = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S")
    return {
        "ts": ts.isoformat(),
        "source": "ssh",
        "ip": match["ip"],
        "user": match["user"],
        "outcome": match["outcome"].lower(),
        "raw": line,
    }


def parse_web(line: str) -> dict | None:
    match = WEB_RE.match(line)
    if not match:
        return None
    # auth.log has no timezone, so drop the offset here too and keep both sources in
    # the server's local time. Otherwise the two would be hard to compare.
    ts = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return {
        "ts": ts.isoformat(),
        "source": "web",
        "ip": match["ip"],
        "method": match["method"],
        "path": match["path"],
        "status": int(match["status"]),
        "user_agent": match["ua"],
        "raw": line,
    }
