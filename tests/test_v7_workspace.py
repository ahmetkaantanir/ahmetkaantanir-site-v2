"""V7 acceptance: common evidence, cross-batch rules, query safety and custody."""
import importlib
import json
from datetime import datetime,timedelta,timezone
from unittest.mock import patch

import pytest

KEY='v7-owner-token-longer-than-24-characters'
READER='v7-reader-token-longer-than-24-characters'
COLLECTOR='v7-collector-token-longer-than-24-characters'


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('LOG_LAB_DB_PATH',str(tmp_path/'v7.db'))
    monkeypatch.setenv('LOG_LAB_API_KEY',KEY)
    monkeypatch.setenv('LOG_LAB_PRINCIPALS',json.dumps([
        {'name':'reader','role':'reader','key':READER},{'name':'collector','role':'collector','key':COLLECTOR}]))
    for name in ('LAB_LOKI_WRITE_USER','LAB_LOKI_WRITE_TOKEN','LAB_OLLAMA_MODEL'):
        monkeypatch.delenv(name,raising=False)
    import app
    return importlib.reload(app).app.test_client()


def headers(key=KEY):return {'X-API-Key':key}
def post(client,path,payload,key=KEY):return client.post('/api/soc/'+path,headers=headers(key),json=payload)
def get(client,path,key=KEY):return client.get('/api/soc/'+path,headers=headers(key))
def event(second,code=4625,ip='192.0.2.25'):
    return json.dumps({'timestamp':(datetime(2026,11,2,10,tzinfo=timezone.utc)+timedelta(seconds=second)).isoformat(),
        'EventID':code,'ip':ip,'host':'lab-host','user':'test-user'})


def test_cross_batch_correlation_keeps_all_evidence(client):
    a=post(client,'ingest',{'raw_logs':'\n'.join(event(i) for i in range(5))})
    b=post(client,'ingest',{'raw_logs':'\n'.join(event(i) for i in range(5,10))})
    assert a.status_code==201 and a.json['alert_count']==0
    assert b.status_code==201 and b.json['alert_count']==1
    case=get(client,'cases').json['items'][0]
    timeline=get(client,f"cases/{case['id']}/timeline").json['items']
    assert len(timeline)==10 and all(e['event_id'].startswith('evt-') for e in timeline)
    assert get(client,'summary').json['events']==10


def test_event_dedup_across_different_batches_preserves_occurrences(client):
    first=post(client,'ingest',{'raw_logs':event(1),'source_id':'source-a'})
    second=post(client,'ingest',{'raw_logs':'\n'+event(1)+'\n','source_id':'source-b'})
    assert first.json['events']==1 and second.json['events']==0 and second.json['duplicate_events']==1
    assert get(client,'summary').json['events']==1
    e=post(client,'workspace/query',{'filters':{}}).json['items'][0]
    evidence=get(client,'workspace/evidence/'+e['event_id']).json
    assert len(evidence['occurrences'])==2
    assert evidence['event']['raw']==event(1)


def test_reader_can_query_copilot_but_cannot_mutate(client):
    post(client,'ingest',{'raw_logs':event(1)})
    assert post(client,'workspace/query',{'filters':{}},READER).status_code==200
    assert post(client,'workspace/copilot',{'question':'Başarısız girişleri incele','filters':{}},READER).json['counts']['matched']==1
    assert post(client,'workspace/investigations',{'title':'No','context':{}},READER).status_code==403
    assert get(client,'workspace/capabilities',COLLECTOR).status_code==403
    heartbeat=post(client,'workspace/heartbeat',{'version':'7.0','metadata':{'pending':0}},COLLECTOR)
    assert heartbeat.status_code==200 and heartbeat.json['collector_id']=='collector'


def test_query_rejects_sql_fields_unknown_timezones_and_wrong_bounds(client):
    for filters in ({'sql':'DROP TABLE soc_events'},{'start':'2026-11-02T10:00:00'},
                    {'start':'2026-11-03T00:00:00Z','end':'2026-11-02T00:00:00Z'}):
        assert post(client,'workspace/query',{'filters':filters}).status_code==400
    assert post(client,'workspace/query',{'filters':{'q':"' OR 1=1 --"}}).json['total']==0


def test_copilot_answers_from_counts_and_verified_ids(client):
    post(client,'ingest',{'raw_logs':'\n'.join([event(1),event(2),event(3,ip='192.0.2.26')])})
    result=post(client,'workspace/copilot',{'question':'En çok başarısız giriş hangi IP adresinden geldi?','filters':{}}).json
    assert result['counts']['top_ips'][0]=={'ip':'192.0.2.25','count':2}
    assert result['counts']['matched']==3 and result['read_only'] and not result['ai_generated']
    known={e['event_id'] for e in post(client,'workspace/query',{'filters':{}}).json['items']}
    assert {e['event_id'] for e in result['evidence']}<=known
    empty=post(client,'workspace/copilot',{'question':'203.0.113.50 adresini araştır','filters':{}}).json
    assert empty['insufficient_data'] and empty['evidence']==[]


def test_investigations_queries_rules_and_manual_cases_share_events(client):
    post(client,'ingest',{'raw_logs':event(1,4740)})
    e=post(client,'workspace/query',{'filters':{}}).json['items'][0]
    saved=post(client,'workspace/investigations',{'title':'Lockout investigation','context':{'filters':{'host':'lab-host'},'event_id':e['event_id']},'notes':'Verify change window'})
    assert saved.status_code==201
    assert get(client,'workspace/investigations').json['items'][0]['context']['event_id']==e['event_id']
    assert post(client,'workspace/saved-queries',{'name':'Host','filters':{'host':'lab-host'}}).status_code==201
    manual=post(client,'workspace/cases',{'title':'Manual evidence review','event_ids':[e['event_id']]})
    assert manual.status_code==201
    assert get(client,f"cases/{manual.json['id']}/timeline").json['items'][0]['event_id']==e['event_id']
    rule={'id':'USR-LOCKOUT','title':'Test lockout','detection':{'selection':{'EventID':4740},'condition':'selection'},'severity':'medium','mitre':'T1110'}
    assert post(client,'workspace/rules',{'rule':rule}).json['version']==1
    assert post(client,'workspace/rules/test',{'rule':rule,'filters':{}}).json['alerts']
    assert post(client,'workspace/rules',{'rule':rule,'active':True}).json['version']==2
    post(client,'ingest',{'raw_logs':event(2,4740)})
    assert any(c['rule_id']=='USR-LOCKOUT' for c in get(client,'cases').json['items'])
    assert len(get(client,'workspace/rules/USR-LOCKOUT/versions').json['items'])==2


def test_custody_verifies_appended_actions(client):
    post(client,'ingest',{'raw_logs':event(1)})
    e=post(client,'workspace/query',{'filters':{}}).json['items'][0]
    get(client,'workspace/evidence/'+e['event_id'])
    data=get(client,'workspace/custody').json
    assert data['verification']['verified'] and data['verification']['checked']==2
    assert data['items'][0]['action']=='evidence_read'


def test_cloud_sync_requires_explicit_write_config_and_retries_without_reimport(client,monkeypatch):
    rejected=post(client,'ingest',{'raw_logs':event(1),'sync_loki':True})
    assert rejected.status_code==400 and get(client,'summary').json['events']==0
    monkeypatch.setenv('LAB_LOKI_URL','https://logs.example')
    monkeypatch.setenv('LAB_LOKI_WRITE_USER','test-user')
    monkeypatch.setenv('LAB_LOKI_WRITE_TOKEN','test-write-token')
    from integrations.client import IntegrationError
    with patch('backend.cloud_sync._request_json',side_effect=IntegrationError('unavailable')):
        result=post(client,'ingest',{'raw_logs':event(1),'sync_loki':True})
        assert result.status_code==201 and result.json['cloud_sync']['pending']==1
    with patch('backend.cloud_sync._request_json',return_value={}) as push:
        assert post(client,'workspace/sync',{}).json['pending']==0
        payload=push.call_args.kwargs['payload']
        record=json.loads(payload['streams'][0]['values'][0][1])
        assert record['lab_raw']==event(1) and record['lab_event_id'].startswith('evt-')
    assert get(client,'summary').json['events']==1


def test_live_stream_uses_auth_header_and_resumable_cursor(client):
    post(client,'ingest',{'raw_logs':event(1)})
    assert client.get('/api/soc/workspace/live').status_code==401
    response=client.get('/api/soc/workspace/live',headers=headers(),buffered=False)
    chunk=next(response.response).decode()
    response.close()
    assert 'event: events' in chunk and 'evt-' in chunk and 'id: ' in chunk
