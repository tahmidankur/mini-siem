import argparse
from datetime import date
from pathlib import Path

import db
from parsers import parse_ssh, parse_web


def parse_file(path: Path, parse) -> tuple[list[dict], int]:
    events, skipped = [], 0
    for line in path.read_text().splitlines():
        event = parse(line)
        if event:
            events.append(event)
        else:
            skipped += 1
    return events, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="Load SSH and web logs into SQLite and run detections.")
    parser.add_argument("--auth", default="sample_logs/auth.log", help="SSH auth log")
    parser.add_argument("--access", default="sample_logs/access.log", help="web access log")
    parser.add_argument("--db", default="siem.db", help="SQLite file to (re)create")
    parser.add_argument("--year", type=int, default=date.today().year,
                        help="year for auth.log timestamps, which don't include one")
    args = parser.parse_args()

    ssh_events, ssh_skipped = parse_file(Path(args.auth), lambda line: parse_ssh(line, args.year))
    web_events, web_skipped = parse_file(Path(args.access), parse_web)
    print(f"{args.auth}: {len(ssh_events)} events, {ssh_skipped} lines skipped")
    print(f"{args.access}: {len(web_events)} events, {web_skipped} lines skipped")

    Path(args.db).unlink(missing_ok=True)
    conn = db.connect(args.db)
    db.create_tables(conn)
    db.insert_events(conn, ssh_events + web_events)
    counts = db.count_events(conn)
    print(f"stored {sum(counts.values())} events in {args.db} (ssh {counts.get('ssh', 0)}, web {counts.get('web', 0)})")
    conn.close()


if __name__ == "__main__":
    main()
