"""Tail UTF-8 JSONL/log files through a durable SQLite outbox.

Run: python -m collectors.file_forwarder --file /logs/auth.log --state /state/collector.db
Set LAB_SOC_URL and LAB_COLLECTOR_KEY. Files are read only; never execute log content.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from integrations.client import NoRedirect


def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, identity TEXT, position INTEGER);
    CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, body TEXT NOT NULL,
        attempts INTEGER DEFAULT 0, next_attempt REAL DEFAULT 0, error TEXT);
    """)
    return db


def enqueue_file(db, filename):
    file = Path(filename).resolve()
    if db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] >= 1000:
        return 0  # Backpressure: leave source offset untouched.
    stat = file.stat()
    identity = str(stat.st_dev) + ":" + str(stat.st_ino)
    row = db.execute("SELECT identity,position FROM offsets WHERE path=?", (str(file),)).fetchone()
    position = row[1] if row and row[0]==identity and row[1]<=stat.st_size else 0
    with file.open("rb") as stream:
        stream.seek(position)
        lines = []
        size = 0
        while len(lines) < 500:
            before = stream.tell()
            line = stream.readline(65538)
            if not line:
                break
            if len(line)>65536:
                raise ValueError("Source line too long; offset retained for manual review")
            if not line.endswith(b"\n"):
                stream.seek(before)  # Incomplete writer line is retried later.
                break
            text = line.decode("utf-8", "strict")
            if len(text.strip()) > 16384:
                raise ValueError("SOC line limit exceeded; offset retained")
            if size+len(line)>1024*1024:
                stream.seek(before)
                break
            size += len(line)
            lines.append(text)
        end = stream.tell()
    if end == position:
        return 0
    raw = "".join(lines)
    with db:
        if raw.strip():
            db.execute("INSERT INTO outbox(body) VALUES (?)", (json.dumps({"raw_logs": raw}),))
        db.execute("INSERT OR REPLACE INTO offsets VALUES (?,?,?)", (str(file), identity, end))
    return len(lines)


def deliver(db, base, key):
    row = db.execute("SELECT id,body,attempts FROM outbox WHERE next_attempt<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
    if not row:
        return False
    item, body, attempts = row
    try:
        req = Request(base.rstrip("/")+"/api/soc/ingest", data=body.encode(),
            headers={"Content-Type":"application/json", "X-API-Key":key,
                     "User-Agent":"LogIntelligenceLab-Collector/1.0"}, method="POST")
        with build_opener(NoRedirect).open(req, timeout=15) as response:
            result = json.loads(response.read(65536))
            # A response must explicitly acknowledge this exact payload, including duplicates.
            expected = hashlib.sha256(json.loads(body)["raw_logs"].encode()).hexdigest()
            if response.status not in {200,201} or not isinstance(result, dict) or result.get("sha256") != expected:
                raise ValueError("No matching acknowledgment")
        with db:
            db.execute("DELETE FROM outbox WHERE id=?", (item,))
        return True
    except (HTTPError, URLError, OSError, ValueError):
        with db:
            db.execute("UPDATE outbox SET attempts=?,next_attempt=?,error=? WHERE id=?",
                (attempts+1, time.time()+min(300, 2**min(attempts+1,8)), "delivery_failed", item))
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    base, key = os.getenv("LAB_SOC_URL", "http://127.0.0.1:5000"), os.getenv("LAB_COLLECTOR_KEY", "")
    from urllib.parse import urlsplit
    url = urlsplit(base)
    if (url.scheme!="https" and not (url.scheme=="http" and (url.hostname in {"127.0.0.1", "localhost"} or os.getenv('LAB_ALLOW_PRIVATE_HTTP')=='true'))) or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        parser.error("LAB_SOC_URL must be an HTTPS origin or localhost HTTP")
    if len(key)<24:
        parser.error("LAB_COLLECTOR_KEY of at least 24 characters required")
    db = connect(args.state)
    while True:
        for file in args.file:
            try:
                enqueue_file(db, file)
            except (OSError, ValueError):
                print("Source unavailable or invalid; checkpoint retained", flush=True)
        deliver(db, base, key)
        if args.once:
            break
        time.sleep(2)


if __name__ == "__main__":
    main()
