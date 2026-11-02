"""Canonical event identities, cross-batch correlation and evidence custody."""
import hashlib
import json
from datetime import datetime,timedelta,timezone

from soc_engine import inspect,detect_events,RULES
from backend import cloud_sync

LEVELS={'low':0,'medium':1,'high':2,'critical':3}


def now():
    return datetime.now(timezone.utc).isoformat()


def custody(db,actor,action,subject):
    previous=db.execute('SELECT hash FROM lab_custody ORDER BY id DESC LIMIT 1').fetchone()
    data={'at':now(),'actor':actor,'action':action,'subject':str(subject),'previous_hash':previous[0] if previous else ''}
    digest=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    db.execute('INSERT INTO lab_custody(at,actor,action,subject,previous_hash,hash) VALUES (?,?,?,?,?,?)',
        (data['at'],actor,action,str(subject),data['previous_hash'],digest))
    return digest


def verify_custody(db):
    previous='';count=0
    for row in db.execute('SELECT * FROM lab_custody ORDER BY id LIMIT 10001'):
        count+=1
        if count>10000:
            return {'verified':None,'checked':10000,'limited':True}
        data={k:row[k] for k in ('at','actor','action','subject','previous_hash')}
        digest=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if row['previous_hash']!=previous or digest!=row['hash']:
            return {'verified':False,'checked':count,'broken_at':row['id']}
        previous=digest
    return {'verified':True,'checked':count,'head':previous,
        'scope':'Application hash chain; external anchoring is required to detect privileged full-chain rewrites.'}


def ingest_text(connection,audit,text,source,actor,source_id=None,sync=False):
    result=inspect(text)
    source_id=source_id or source
    if not isinstance(source_id,str) or not 1<=len(source_id)<=80:
        raise ValueError('source_id must contain 1-80 characters')
    if type(sync) is not bool:
        raise ValueError('sync_loki must be a boolean')
    if sync and not cloud_sync.configured():
        raise ValueError('Loki write-only credentials are not configured; import to SOC without cloud sync')
    moment=now()
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT * FROM soc_batches WHERE sha256=?',(result['sha256'],)).fetchone()
        if old:
            if sync:
                events=[json.loads(r[0]) for r in db.execute('SELECT raw_json FROM soc_events WHERE batch_id=?',(old['id'],))]
                cloud_sync.enqueue(db,old['id'],events)
            return {'batch_id':old['id'],'duplicate':True,'sha256':result['sha256'],
                    'events':old['event_count'],'alert_count':old['alert_count'],'risk':old['risk'],
                    'cloud_sync':cloud_sync.status(db)},200
        all_events,new_events,occurrences={},[],[]
        for event in result['events']:
            fingerprint=hashlib.sha256(event['raw'].encode()).hexdigest()
            existing=db.execute('SELECT event_id FROM lab_fingerprints WHERE hash=?',(fingerprint,)).fetchone()
            event['event_id']=existing[0] if existing else 'evt-'+fingerprint[:24]
            event.update(canonical_id=fingerprint,source_id=source_id,received_at=moment,schema_version='7.0',
                data_quality={'timestamp_known':bool(event['timestamp']),'ip_known':bool(event['ip']),'parsed':event['source']!='unknown'})
            try:
                payload=json.loads(event['raw'])
                event['synthetic']=isinstance(payload,dict) and payload.get('synthetic') is True
            except ValueError:
                event['synthetic']=False
            if not existing and event['event_id'] not in all_events:
                new_events.append(event)
                db.execute('INSERT INTO lab_fingerprints(hash,event_id) VALUES (?,?)',(fingerprint,event['event_id']))
            all_events[event['event_id']]=event
            occurrences.append((event['event_id'],event['line']))
        batch=db.execute('INSERT INTO soc_batches(created_at,source,sha256,event_count,alert_count,risk) VALUES (?,?,?,?,?,?)',
            (moment,source,result['sha256'],len(new_events),0,'low')).lastrowid
        db.execute('INSERT INTO soc_raw_batches(batch_id,raw_text) VALUES (?,?)',(batch,text))
        dates=[datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')) for e in new_events if e['timestamp']]
        ips=list({e['ip'] for e in new_events if e['ip']})
        history=[]
        if dates and ips:
            rows=db.execute("SELECT raw_json FROM soc_events WHERE ip IN (SELECT value FROM json_each(?)) AND julianday(timestamp) BETWEEN julianday(?) AND julianday(?) ORDER BY id DESC LIMIT 10000",
                (json.dumps(ips),(min(dates)-timedelta(minutes=5)).isoformat(),(max(dates)+timedelta(minutes=5)).isoformat()))
            size=0
            for row in rows:
                size+=len(row[0].encode())
                if size>8*1024*1024:break
                history.append(json.loads(row[0]))
        events={e['event_id']:e for e in history}
        events.update({e['event_id']:e for e in new_events})
        previous={key:value.get('severity') for key,value in events.items()}
        alerts=detect_events(list(events.values()))
        from backend.rules import evaluate_rules
        alerts+=evaluate_rules(db,list(events.values()))
        new_ids={e['event_id'] for e in new_events}
        alerts=[a for a in alerts if new_ids.intersection(a['event_ids'])]
        for e in events.values():
            if previous[e['event_id']] and LEVELS[previous[e['event_id']]]>LEVELS.get(e.get('severity'),-1):
                e['severity']=previous[e['event_id']]
        added=[]
        for alert in alerts:
            for event_id in alert['event_ids']:
                if event_id not in events:
                    continue
                e=events[event_id]
                e['detection_rules']=sorted(set(e.get('detection_rules',[])+[alert['rule_id']]))
                mitre=alert.get('mitre')
                e['mitre']=sorted(set(e.get('mitre',[])+([mitre] if mitre else [])))
                if LEVELS[alert['severity']]>LEVELS.get(e.get('severity'),-1):
                    e['severity']=alert['severity']
            if db.execute('SELECT 1 FROM soc_cases WHERE alert_id=?',(alert['alert_id'],)).fetchone():
                continue
            db.execute('INSERT INTO soc_cases(batch_id,alert_id,rule_id,severity,ip,reason,evidence_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (batch,alert['alert_id'],alert['rule_id'],alert['severity'],alert['ip'],alert['reason'],json.dumps(alert['event_ids']),moment,moment))
            added.append(alert)
        for e in new_events:
            e['batch_id']=batch
            db.execute('INSERT INTO soc_events(batch_id,event_id,timestamp,source,ip,user_name,raw_json) VALUES (?,?,?,?,?,?,?)',
                (batch,e['event_id'],e['timestamp'],e['source'],e['ip'],e['user'],json.dumps(e,ensure_ascii=False)))
        for e in history:
            if e['event_id'] in events:
                db.execute('UPDATE soc_events SET raw_json=? WHERE event_id=?',
                    (json.dumps(events[e['event_id']],ensure_ascii=False),e['event_id']))
        db.executemany('INSERT OR IGNORE INTO lab_occurrences(event_id,batch_id,line,source_id) VALUES (?,?,?,?)',
            [(event_id,batch,line,source_id) for event_id,line in occurrences])
        risk=max((a['severity'] for a in added),key=lambda s:LEVELS[s],default='low')
        db.execute('UPDATE soc_batches SET alert_count=?,risk=? WHERE id=?',(len(added),risk,batch))
        db.execute('INSERT INTO lab_sources(id,name,kind,last_ingested) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_ingested=excluded.last_ingested',
            (source_id,source_id,source,moment))
        if sync:
            cloud_sync.enqueue(db,batch,list(all_events.values()))
        custody(db,actor,'ingest',batch)
        audit(db,'ingest',batch)
        sync_status=cloud_sync.status(db)
    return {'batch_id':batch,'duplicate':False,'sha256':result['sha256'],'events':len(new_events),
            'received_events':result['total'],'duplicate_events':result['total']-len(new_events),
            'alert_count':len(added),'risk':risk,'sources':result['sources'],
            'unknown_timestamps':result['unknown_timestamps'],'cloud_sync':sync_status,
            'correlation':{'cross_batch':True,'history_events':len(history),'history_limit':10000},
            'limitations':result['limitations']+['Exact normalized raw content is deduplicated; semantically different encodings are not.']},201
