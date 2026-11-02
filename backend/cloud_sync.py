"""Explicit private uploads to Loki with durable, retryable acknowledgments."""
import base64
import json
import os
import time
from datetime import datetime, timezone

from integrations.client import IntegrationError, _request_json
from backend.identity import export_signature


def now():
    return datetime.now(timezone.utc).isoformat()


def configured():
    return bool(os.getenv('LAB_LOKI_URL') and os.getenv('LAB_LOKI_WRITE_USER') and os.getenv('LAB_LOKI_WRITE_TOKEN'))


def enqueue(db, batch_id, events):
    if not configured():
        raise ValueError('Cloud upload is unavailable until write-only Loki credentials are configured')
    rows, queued, size = [], 0, 0
    stamp = time.time_ns()
    for event in events:
        if not db.execute('INSERT OR IGNORE INTO lab_loki_exported(event_id,batch_id) VALUES (?,?)',
                          (event['event_id'],batch_id)).rowcount:
            continue
        try:
            raw = json.loads(event['raw'])
        except (ValueError,TypeError):
            raw = {}
        record = dict(raw) if isinstance(raw,dict) else {}
        record.update(lab_event_id=event['event_id'],lab_batch_id=batch_id,lab_raw=event['raw'],
            lab_source=event['source'],lab_source_timestamp=event.get('timestamp'),
            lab_received_at=event.get('received_at'),lab_severity=event.get('severity'),
            lab_action=event.get('action'),lab_outcome=event.get('outcome'))
        record.setdefault('hostname',event.get('host'))
        record['lab_signature']=export_signature(event['raw'],event['event_id'],batch_id)
        line=json.dumps(record,ensure_ascii=False)
        if rows and size+len(line.encode())>512*1024:
            _save(db,batch_id,rows);queued+=1;stamp+=len(rows);rows=[];size=0
        rows.append([str(stamp+len(rows)),line]);size+=len(line.encode())
        if len(rows)>=100:
            _save(db,batch_id,rows);queued+=1;stamp+=len(rows);rows=[];size=0
    if rows:
        _save(db,batch_id,rows);queued+=1
    return queued


def _save(db,batch_id,rows):
    db.execute('INSERT INTO lab_loki_outbox(batch_id,payload_json,created_at) VALUES (?,?,?)',
        (batch_id,json.dumps({'streams':[{'stream':{'job':'security'},'values':rows}]}),now()))


def status(db):
    counts={r['state']:r['n'] for r in db.execute('SELECT state,COUNT(*) n FROM lab_loki_outbox GROUP BY state')}
    return {'configured':configured(),'pending':counts.get('pending',0)+counts.get('failed',0)+counts.get('sending',0),
        'sent':counts.get('sent',0),'failed':counts.get('failed',0),'sending':counts.get('sending',0)}


def flush(connection, max_jobs=4):
    if not configured():
        with connection() as db:
            return status(db)
    authorization='Basic '+base64.b64encode((os.environ['LAB_LOKI_WRITE_USER']+':'+os.environ['LAB_LOKI_WRITE_TOKEN']).encode()).decode()
    for _ in range(max_jobs):
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE lab_loki_outbox SET state='pending' WHERE state='sending' AND julianday(attempted_at)<julianday('now','-1 minute')")
            row=db.execute("SELECT id,payload_json FROM lab_loki_outbox WHERE state IN ('pending','failed') ORDER BY id LIMIT 1").fetchone()
            if not row:
                break
            db.execute("UPDATE lab_loki_outbox SET state='sending',attempts=attempts+1,attempted_at=? WHERE id=?",(now(),row['id']))
        try:
            _request_json('loki','/loki/api/v1/push',method='POST',payload=json.loads(row['payload_json']),authorization=authorization)
        except IntegrationError:
            with connection() as db:
                db.execute("UPDATE lab_loki_outbox SET state='failed',last_error='Delivery failed; retry available' WHERE id=?",(row['id'],))
            break
        else:
            with connection() as db:
                db.execute("UPDATE lab_loki_outbox SET state='sent',sent_at=?,last_error=NULL WHERE id=?",(now(),row['id']))
    with connection() as db:
        return status(db)
