"""Recovery keeps evidence, cases, research and custody, including live WAL data."""
import sqlite3
import pytest
from backend.backup import snapshot, verify
from tests.test_v7_workspace import client, post, get, event


def test_backup_restore_preserves_workspace_and_wal(client, tmp_path):
    post(client, 'ingest', {'raw_logs':event(1)})
    post(client, 'workspace/investigations', {'title':'Recover me','context':{}})
    source = tmp_path / 'v7.db'
    with sqlite3.connect(source) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("INSERT INTO soc_watchlist(kind,value,label,created_at) VALUES ('ip','192.0.2.3','WAL recovery','now')")
        writer.commit()
        backup = tmp_path/'backup.db'
        result = snapshot(source, backup)
        assert result['verified'] and result['counts']['soc_events'] == 1
        assert result['counts']['lab_investigations'] == 1
        assert result['counts']['lab_custody'] >= 1
        restored = tmp_path/'recovered.db'
        snapshot(backup, restored)
        with sqlite3.connect(restored) as db:
            assert db.execute('SELECT value FROM soc_watchlist').fetchone()[0] == '192.0.2.3'
        assert verify(restored)['counts'] == result['counts']


def test_backup_never_overwrites_or_creates_missing_source(client, tmp_path):
    output = tmp_path/'important.db'
    output.write_bytes(b'keep this')
    with pytest.raises(FileExistsError):
        snapshot(tmp_path/'v7.db',output)
    assert output.read_bytes() == b'keep this'
    missing = tmp_path/'missing.db'
    with pytest.raises(FileNotFoundError):
        snapshot(missing,tmp_path/'unused.db')
    assert not missing.exists()


def test_invalid_database_does_not_leave_a_backup(tmp_path):
    source = tmp_path/'wrong.db'
    with sqlite3.connect(source) as db:
        db.execute('CREATE TABLE unrelated(id)')
    output = tmp_path/'bad-backup.db'
    with pytest.raises(ValueError):
        snapshot(source,output)
    assert not output.exists()


def test_legacy_soc_can_be_backed_up_before_upgrade(tmp_path):
    source = tmp_path/'legacy.db'
    with sqlite3.connect(source) as db:
        for name in ['soc_events', 'soc_cases', 'soc_batches', 'soc_audit']:
            db.execute('CREATE TABLE '+name+'(id INTEGER PRIMARY KEY)')
        db.execute('INSERT INTO soc_events VALUES (1)')
    result = snapshot(source,tmp_path/'legacy-backup.db')
    assert result['schema'] == 'legacy' and result['counts']['soc_events'] == 1
