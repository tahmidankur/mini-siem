from parsers import parse_ssh, parse_web


def test_ssh_accepted():
    line = "Oct 12 09:15:40 web01 sshd[1874]: Accepted password for maria from 10.0.4.21 port 51022 ssh2"
    event = parse_ssh(line, 2026)
    assert event["ts"] == "2026-10-12T09:15:40"
    assert event["source"] == "ssh"
    assert event["ip"] == "10.0.4.21"
    assert event["user"] == "maria"
    assert event["outcome"] == "accepted"
    assert event["raw"] == line


def test_ssh_failed_invalid_user():
    line = "Oct 12 14:03:22 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2"
    event = parse_ssh(line, 2026)
    assert event["user"] == "admin"
    assert event["outcome"] == "failed"
    assert event["ip"] == "203.0.113.5"


def test_ssh_publickey_and_single_digit_day():
    line = "Oct  2 08:01:09 web01 sshd[901]: Accepted publickey for deploy from 10.0.9.10 port 40122 ssh2"
    event = parse_ssh(line, 2026)
    assert event["ts"] == "2026-10-02T08:01:09"
    assert event["user"] == "deploy"


def test_ssh_skips_other_lines():
    line = "Oct 12 09:15:40 web01 sshd[1874]: pam_unix(sshd:session): session opened for user maria by (uid=0)"
    assert parse_ssh(line, 2026) is None
    assert parse_ssh("not a log line", 2026) is None


def test_web_sqlmap_request():
    line = ('198.51.100.23 - - [12/Oct/2026:14:05:01 -0700] '
            '"GET /products?id=1%27%20OR%201%3D1-- HTTP/1.1" 200 512 "-" "sqlmap/1.8"')
    event = parse_web(line)
    assert event["ts"] == "2026-10-12T14:05:01"
    assert event["source"] == "web"
    assert event["ip"] == "198.51.100.23"
    assert event["method"] == "GET"
    assert event["path"] == "/products?id=1%27%20OR%201%3D1--"
    assert event["status"] == 200
    assert event["user_agent"] == "sqlmap/1.8"


def test_web_browser_request_with_referer():
    line = ('10.0.4.21 - - [12/Oct/2026:10:22:47 -0700] "POST /login HTTP/1.1" 302 231 '
            '"https://shop.example.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"')
    event = parse_web(line)
    assert event["method"] == "POST"
    assert event["status"] == 302
    assert event["user_agent"].startswith("Mozilla/5.0")


def test_web_malformed_line():
    assert parse_web('10.0.4.21 - - [12/Oct/2026:10:22:47 -0700] "GET /" 200') is None
