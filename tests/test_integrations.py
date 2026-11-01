"""Integration boundaries, evidence integrity, roles and crash-safe collection."""
import importlib
import json
import sqlite3
from unittest.mock import patch

import pytest

from collectors.file_forwarder import connect, deliver, enqueue_file
from collectors.convert import convert
from integrations.client import IntegrationError, origin
from soc_engine import inspect, normalize

OWNER = "owner-example-secret-longer-than-24"
READER = "reader-example-secret-longer-than-24"
COLLECTOR = "collector-example-secret-longer-than-24"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_LAB_DB_PATH", str(tmp_path / "soc.db"))
    monkeypatch.setenv("LOG_LAB_API_KEY", OWNER)
    monkeypatch.setenv("LOG_LAB_PRINCIPALS", json.dumps([
        {"name":"reader", "key":READER, "role":"reader"},
        {"name":"collector", "key":COLLECTOR, "role":"collector"}]))
    for service in ("LOKI", "GRAFANA", "GNS3", "WAZUH"):
        monkeypatch.delenv("LAB_"+service+"_URL", raising=False)
    import app
    return importlib.reload(app).app.test_client()


def auth(key=OWNER):
    return {"X-API-Key":key}


def ingest(client, **fields):
    return client.post('/api/soc/ingest', headers=auth(), json={"raw_logs":json.dumps({
        "timestamp":"2026-11-01T12:00:00Z", "EventID":1102, "ip":"192.0.2.1", **fields})})


def test_parent_auth_applies_to_every_module(client):
    for path in ('integrations','loki/query','gns3/projects','modules/network','report','ueba','forensics/batches/1'):
        assert client.get('/api/soc/platform/'+path).status_code==401
    assert client.get('/platform-ui.js').status_code==200
    for path in ('/integrations/platform.py','/collectors/file_forwarder.py','/deploy/compose.yaml','/.env.example'):
        assert client.get(path).status_code==404


def test_roles_block_mutation_and_collector_reads(client):
    assert client.get('/api/soc/summary',headers=auth(READER)).status_code==200
    assert client.post('/api/soc/ingest',headers=auth(READER),json={"raw_logs":"x"}).status_code==403
    assert client.get('/api/soc/audit',headers=auth(READER)).status_code==403
    assert client.get('/api/soc/platform/integrations',headers=auth(COLLECTOR)).status_code==403
    assert client.post('/api/soc/ingest',headers=auth(COLLECTOR),json={"raw_logs":"x"}).status_code==201


def test_original_package_integrity_and_export(client):
    r=ingest(client)
    assert r.status_code==201
    manifest=client.get('/api/soc/platform/forensics/batches/'+str(r.json['batch_id']),headers=auth()).json
    assert manifest['original_sha256_verified'] is True
    assert manifest['cases'][0]['rule_id']=='WIN-001'
    check=client.post('/api/soc/platform/forensics/verify',headers=auth(),json={
        'raw_text':manifest['raw_text']+'tamper','sha256':manifest['manifest']['sha256']})
    assert check.json['matches'] is False
    assert 'actor=owner' in client.get('/api/soc/audit',headers=auth()).json['items'][0]['subject']


def test_adapters_are_explicit_and_unconfigured_by_default(client):
    result=client.get('/api/soc/platform/integrations',headers=auth()).json
    assert all(i['state']=='not_configured' and i['connected'] is None for i in result['items'])
    assert client.get('/api/soc/platform/loki/query',headers=auth()).status_code==503
    assert client.get('/api/soc/platform/loki/query?query=x&start=2026-01-01',headers=auth()).status_code==400


def test_fixed_gns3_routes_strip_console_credentials(client):
    with patch('integrations.platform.fetch_json',return_value=[{'project_id':'id','name':'Lab','password':'secret'}]) as upstream:
        response=client.get('/api/soc/platform/gns3/projects',headers=auth())
        assert response.json['items']==[{'project_id':'id','name':'Lab','status':None}]
        upstream.assert_called_once_with('gns3','/v2/projects')
    assert client.get('/api/soc/platform/gns3/projects/bad/topology',headers=auth()).status_code==400


def test_upstream_uris_are_admin_only(monkeypatch):
    for value in ('file:///secret','https://u:p@example.com','https://example.com/path','https://example.com?x=1','http://192.168.1.2'):
        monkeypatch.setenv('LAB_LOKI_URL',value)
        with pytest.raises(IntegrationError):
            origin('loki')
    monkeypatch.setenv('LAB_LOKI_URL','http://127.0.0.1:3100')
    assert origin('loki')=='http://127.0.0.1:3100'


def test_sigma_subset_matches_shared_evidence_and_rejects_unsupported(client):
    ingest(client)
    rule={'title':'Audit clear','detection':{'selection':{'EventID':1102},'condition':'selection'}}
    r=client.post('/api/soc/platform/sigma/test',headers=auth(),json={'rule':rule})
    assert r.status_code==200 and r.json['count']==1
    for selection,condition in [({'EventID|regex':'.*'},'selection'),({'EventID':'*'},'selection'),({'EventID':1102},'not selection')]:
        rule['detection']={'selection':selection,'condition':condition}
        assert client.post('/api/soc/platform/sigma/test',headers=auth(),json={'rule':rule}).status_code==400


def test_protocol_sources_and_evidence_severity():
    zeek=normalize(json.dumps({'ts':1793534400,'uid':'flow','id.orig_h':'192.0.2.1','id.resp_h':'198.51.100.1','id.resp_p':53,'query':'a'*55+'.example'}),1)
    assert zeek['source']=='dns' and zeek['port']==53 and 'long_dns_label' in zeek['tags']
    wazuh=inspect(json.dumps({'timestamp':'2026-11-01T00:00:00Z','agent':{'name':'win','ip':'192.0.2.2'},'rule':{'id':'123'}}))
    assert wazuh['events'][0]['source']=='wazuh' and wazuh['events'][0]['severity']=='medium'
    assert normalize(json.dumps({'eventid':'cowrie.login.failed','src_ip':'192.0.2.1'}),1)['source']=='cowrie'
    assert inspect(json.dumps({'EventID':4740}))['alerts'][0]['rule_id']=='WIN-004'


def test_module_scope_and_ueba_no_invented_baseline(client):
    ingest(client,host='host1',user='user1')
    assert client.get('/api/soc/platform/modules/ad',headers=auth()).json['count']==1
    ueba=client.get('/api/soc/platform/ueba',headers=auth()).json
    assert ueba['items'][0]['state']=='insufficient_baseline'
    assert client.get('/api/soc/platform/intelligence/192.0.2.1',headers=auth()).json['reputation']=='unknown'
    assert client.get('/api/soc/platform/report',headers=auth()).json['totals']['events']==1


def test_outbox_transaction_restart_partial_line_and_rotation(tmp_path):
    file=tmp_path/'input.log'
    file.write_bytes(b'first\npartial')
    state=tmp_path/'collector.db'
    db=connect(state)
    assert enqueue_file(db,file)==1
    db.close()
    db=connect(state)
    assert enqueue_file(db,file)==0
    with file.open('ab') as stream:
        stream.write(b' complete\n')
    assert enqueue_file(db,file)==1
    payloads=[json.loads(r[0])['raw_logs'] for r in db.execute('SELECT body FROM outbox ORDER BY id')]
    assert payloads==['first\n','partial complete\n']
    file.write_text('new\n',encoding='utf-8')
    assert enqueue_file(db,file)==1


def test_outbox_requires_matching_acknowledgment(tmp_path):
    file=tmp_path/'input.log';file.write_text('record\n',encoding='utf-8')
    db=connect(tmp_path/'state.db');enqueue_file(db,file)
    class FakeResponse:
        status=201
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,size):return b'{"sha256":"wrong"}'
    with patch('collectors.file_forwarder.build_opener') as opener:
        opener.return_value.open.return_value=FakeResponse()
        assert deliver(db,'http://127.0.0.1','a'*24) is False
    assert db.execute('SELECT attempts FROM outbox').fetchone()[0]==1


def test_geoip_is_separate_validated_local_feed(client,tmp_path,monkeypatch):
    feed=tmp_path/'geo.json'
    feed.write_text(json.dumps({'192.0.2.1':{'location':[29,41],'source':'synthetic'},
        '192.0.2.2':{'location':[False,41],'source':'invalid'}}),encoding='utf-8')
    monkeypatch.setenv('LAB_GEOIP_FEED',str(feed))
    r=client.get('/api/soc/platform/geoip?ips=192.0.2.1,192.0.2.2',headers=auth())
    assert r.status_code==200 and len(r.json['items'])==1
    assert r.json['items'][0]['approximate'] is True and r.json['external_disclosure'] is False
    assert client.get('/api/soc/platform/geoip?ips=bad',headers=auth()).status_code==400


def test_external_intel_requires_consent_and_public_ip(client,monkeypatch):
    assert client.post('/api/soc/platform/intelligence/enrich',headers=auth(),json={'ip':'1.1.1.1'}).status_code==400
    assert client.post('/api/soc/platform/intelligence/enrich',headers=auth(),json={'provider':'abuseipdb','ip':'192.0.2.1','consent':True}).status_code==400
    monkeypatch.delenv('LAB_ABUSEIPDB_KEY',raising=False)
    assert client.post('/api/soc/platform/intelligence/enrich',headers=auth(),json={'provider':'abuseipdb','ip':'1.1.1.1','consent':True}).status_code==503


def test_ai_does_not_accept_fabricated_evidence_ids(client,monkeypatch):
    batch=ingest(client).json['batch_id']
    case=client.get('/api/soc/cases',headers=auth()).json['items'][0]['id']
    monkeypatch.setenv('LAB_OLLAMA_MODEL','test-model')
    with patch('integrations.platform.fetch_json',return_value={'response':json.dumps({'summary':'test','evidence_ids':['invented']})}):
        assert client.post(f'/api/soc/platform/assistant/{case}',headers=auth(),json={'allow_model':True}).status_code==503
    ids=[e['event_id'] for e in client.get(f'/api/soc/platform/forensics/batches/{batch}',headers=auth()).json['events']]
    with patch('integrations.platform.fetch_json',return_value={'response':json.dumps({'summary':'Inspect source','evidence_ids':ids,'next_steps':['Verify original log']})}) as model:
        result=client.post(f'/api/soc/platform/assistant/{case}',headers=auth(),json={'allow_model':True})
        assert result.json['ai_generated'] is True
        prompt=model.call_args.kwargs['payload']['prompt']
        assert 'raw' not in json.loads(prompt)['events'][0]
    assert client.post(f'/api/soc/platform/assistant/{case}',headers=auth(),json={}).status_code==400


def test_zeek_and_tshark_conversion_preserves_source_hash(tmp_path):
    zeek=tmp_path/'conn.log'
    zeek.write_text('#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\n1793534400\tflow1\t192.0.2.1\t198.51.100.1\t443\n',encoding='utf-8')
    row=list(convert(zeek,'zeek-tsv'))[0]
    assert row['id.resp_p']==443 and len(row['derived_from_sha256'])==64
    assert normalize(json.dumps(row),1)['source']=='zeek'
    packets=tmp_path/'packets.json'
    packets.write_text(json.dumps([{'_source':{'layers':{'frame':{'frame.time_epoch':'1793534400.5'},'ip':{'ip.src':'192.0.2.1','ip.dst':'198.51.100.1'},'data':{'payload':'secret'}}}}]),encoding='utf-8')
    packet=list(convert(packets,'tshark-json'))[0]
    assert 'payload' not in json.dumps(packet)
    assert normalize(json.dumps(packet),1)['source']=='pcap'


def test_concurrent_retries_persist_exactly_one_package(client):
    from concurrent.futures import ThreadPoolExecutor
    def send(_):
        with client.application.test_client() as session:
            return session.post('/api/soc/ingest',headers=auth(),json={'raw_logs':'identical concurrent package'}).status_code
    with ThreadPoolExecutor(max_workers=4) as pool:
        codes=list(pool.map(send,range(8)))
    assert codes.count(201)==1 and codes.count(200)==7
    assert client.get('/api/soc/summary',headers=auth()).json['events']==1
