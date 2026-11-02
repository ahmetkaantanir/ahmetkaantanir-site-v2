"""Consistent SQLite snapshots and non-destructive recovery, without HTTP exposure.

Run: python -m backend.backup backup --source analysis.db --output backups/soc.db
     python -m backend.backup verify --source backups/soc.db
     python -m backend.backup restore --source backups/soc.db --output recovered.db
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3


def connect_readonly(path):
    path = Path(path).resolve(strict=True)
    return sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=30)


def verify(path):
    with closing(connect_readonly(path)) as db:
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValueError('SQLite integrity verification failed')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {'soc_events', 'soc_cases', 'soc_batches', 'soc_audit'}
        if not required <= tables:
            raise ValueError('Not a SOC database')
        if db.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Broken database references')
        tracked = required | {'soc_raw_batches', 'lab_custody', 'lab_investigations'}
        counts = {table: db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                  for table in sorted(tracked & tables)}
    with Path(path).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'verified': True, 'sha256': digest, 'counts': counts,
            'schema': 'v7' if 'lab_investigations' in tables else 'legacy'}


def snapshot(source, output):
    source = Path(source).resolve(strict=True)
    output = Path(output).resolve()
    # Exclusive creation prevents overwriting either a running DB or an earlier backup.
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        with closing(connect_readonly(source)) as origin, closing(sqlite3.connect(output)) as destination:
            origin.backup(destination, pages=256, sleep=0.05)
        return verify(output)
    except Exception:
        output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backup', 'verify', 'restore'])
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action != 'verify' and args.output is None:
        parser.error('--output is required for backup and restore')
    try:
        if args.action == 'verify':
            result = verify(args.source)
        else:
            if args.action == 'restore':
                verify(args.source)
            result = snapshot(args.source, args.output)
        print(json.dumps(result, indent=2))
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.exit(1, 'Backup operation failed: '+str(exc)+'\n')


if __name__ == '__main__':
    main()
