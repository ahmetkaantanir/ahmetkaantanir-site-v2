"""The site's remote log query and evidence identity adapter."""
import hashlib
import json
from datetime import datetime,timedelta,timezone
from backend.query import where,utc
from integrations.client import fetch_json,IntegrationError
from soc_engine import normalize
from backend.identity import verified_export


def query_logs(filters=None,query=None,db=None):
    filters=filters or {};where(filters)
    end=datetime.fromisoformat(utc(filters['end']).replace('Z','+00:00')) if filters.get('end') else datetime.now(timezone.utc)
    start=datetime.fromisoformat(utc(filters['start']).replace('Z','+00:00')) if filters.get('start') else end-timedelta(hours=1)
    if not timedelta(0)<end-start<=timedelta(days=1):raise ValueError('Loki range must be between zero and 24 hours')
    query=query or '{job=~"security|linux-auth"}'
    if not isinstance(query,str) or not 1<=len(query)<=2000:raise ValueError('LogQL limit is 2000 characters')
    for field in ('ip','host','user','q'):
        if filters.get(field):query+=' |= '+json.dumps(str(filters[field]))
    data=fetch_json('loki','/loki/api/v1/query_range',{'query':query,'start':str(int(start.timestamp()*1e9)),
        'end':str(int(end.timestamp()*1e9)),'limit':'200','direction':'backward'})
    if not isinstance(data,dict) or data.get('status')!='success':raise IntegrationError('Loki query failed')
    items=[];series=[];result=data.get('data',{})
    for stream in result.get('result',[])[:200]:
        if result.get('resultType')=='streams':
            for stamp,line in stream.get('values',[]):
                try:original=json.loads(line)
                except ValueError:original={}
                if not isinstance(original,dict):original={}
                verified=verified_export(original)
                raw=original['lab_raw'] if verified else line
                fingerprint=hashlib.sha256(raw.strip().encode()).hexdigest()
                existing=db.execute('SELECT event_id FROM lab_fingerprints WHERE hash=?',(fingerprint,)).fetchone() if db else None
                e=normalize(raw,len(items)+1)
                stored=db.execute('SELECT batch_id FROM soc_events WHERE event_id=? LIMIT 1',(existing[0],)).fetchone() if db and existing else None
                e.update(event_id=existing[0] if existing else 'evt-'+fingerprint[:24],
                    canonical_id=fingerprint,raw=raw,loki_timestamp=stamp,labels=stream.get('stream',{}),
                    provenance='loki',link_state='soc_linked' if existing else 'loki_only',gateway_metadata_verified=verified,
                    received_at=datetime.fromtimestamp(int(stamp)/1e9,timezone.utc).isoformat(),
                    timestamp=original.get('lab_source_timestamp') if verified else e.get('timestamp'),
                    source=original.get('lab_source',e['source']) if verified else e['source'],host=e.get('host'),
                    severity=original.get('lab_severity') if verified else None,batch_id=stored[0] if stored else None)
                if any(filters.get(key) not in (None,'') and str(e.get(key) or '')!=str(filters[key]) for key in ('source','outcome','action','severity','event_id')):
                    continue
                if filters.get('event_ids') and e['event_id'] not in filters['event_ids']:
                    continue
                items.append(e)
                if len(items)>=200:break
        else:
            points=stream.get('values') or ([stream['value']] if stream.get('value') else [])
            series.append({'labels':stream.get('metric',{}),'points':points[:200]})
        if len(items)>=200:break
    return {'items':items,'series':series,'query':query,'limit':200,
        'scope':'At most 200 remote records; source timestamp preserved, query axis is ingestion time',
        'state':'ready' if items or series else 'no_matching_data','filters':filters}
