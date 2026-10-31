"""SOC engine and API regression tests: deterministic, offline and isolated."""
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_engine import inspect, normalize, RULES


def event(second, code=4625, ip="192.0.2.10", user="admin"):
    t = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc) + timedelta(seconds=second)
    return json.dumps({"timestamp": t.isoformat(), "EventID": code, "ip": ip, "user": user})


def test_windows_events_normalize():
    e = normalize(event(0), 1)
    assert e["source"] == "windows" and e["outcome"] == "failure"
    assert e["timestamp"] == "2026-10-31T10:00:00Z"


def test_no_fake_timezone_or_geolocation():
    e = normalize(json.dumps({"timestamp": "2026-10-31T10:00:00", "ip": "not an ip"}), 1)
    assert e["timestamp"] is None and e["ip"] is None


def test_bad_json_status_does_not_crash():
    for status in ("not-int", [], {}, None, "600"):
        e = normalize(json.dumps({"status": status}), 1)
        assert e["status"] is None


def test_windows_audit_clear_raises_critical():
    r = inspect(event(0, 1102))
    assert r["risk"] == "critical"
    assert r["alerts"][0]["rule_id"] == "WIN-001"


def test_brute_force_in_five_minutes():
    r = inspect("\n".join(event(i * 10) for i in range(10)))
    a = [x for x in r["alerts"] if x["rule_id"] == "AUTH-001"]
    assert len(a) == 1 and len(a[0]["event_ids"]) >= 10


def test_old_failures_do_not_trigger():
    r = inspect("\n".join(event(i * 180) for i in range(10)))
    assert not any(x["rule_id"] == "AUTH-001" for x in r["alerts"])


def test_password_spraying():
    r = inspect("\n".join(event(i * 10, user=f"user{i}") for i in range(6)))
    assert any(x["rule_id"] == "AUTH-002" for x in r["alerts"])


def test_success_after_failures():
    lines = [event(i * 10) for i in range(3)] + [event(45, 4624)]
    r = inspect("\n".join(lines))
    assert any(x["rule_id"] == "AUTH-003" for x in r["alerts"])


def test_success_before_failures_does_not_trigger():
    lines = [event(0, 4624)] + [event(i * 10 + 10) for i in range(4)]
    r = inspect("\n".join(lines))
    assert not any(x["rule_id"] == "AUTH-003" for x in r["alerts"])


def test_ip_isolation():
    lines = [event(i * 10, ip="192.0.2.1" if i % 2 else "192.0.2.2") for i in range(16)]
    r = inspect("\n".join(lines))
    assert not any(x["rule_id"] == "AUTH-001" for x in r["alerts"])


def test_unsupported_time_excluded_from_correlation():
    lines = [json.dumps({"EventID": 4625, "ip": "192.0.2.1"}) for _ in range(12)]
    r = inspect("\n".join(lines))
    assert r["unknown_timestamps"] == 12
    assert not any(x["rule_id"] == "AUTH-001" for x in r["alerts"])


def test_web_indicator_not_confirmed_breach():
    raw = '192.0.2.5 - - [31/Oct/2026:10:00:00 +0000] "GET /?q=UNION SELECT HTTP/1.1" 403 32'
    r = inspect(raw)
    assert any(x["rule_id"] == "WEB-001" for x in r["alerts"])
    assert "not established" in r["alerts"][0]["reason"]


def test_suricata_alert():
    r = inspect(json.dumps({"timestamp":"2026-10-31T10:00:00Z", "event_type":"alert",
                            "src_ip":"192.0.2.3","alert":{"signature":"test rule"}}))
    assert any(x["rule_id"] == "IDS-001" for x in r["alerts"])


def test_sha256_stable():
    assert inspect(event(1))["sha256"] == inspect(event(1))["sha256"]


def test_invalid_input_rejected():
    with pytest.raises(ValueError):
        inspect("")
    with pytest.raises(ValueError):
        inspect("x" * 16385)
    with pytest.raises(ValueError):
        inspect("x\n" * 10001)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_LAB_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("LOG_LAB_API_KEY", "a-secure-example-token-of-32-bytes!")
    # import uses configuration at module load; isolate by resetting the module.
    import importlib
    import app as module
    module = importlib.reload(module)
    module.app.config.update(TESTING=True)
    yield module.app.test_client()


def headers():
    return {"X-API-Key": "a-secure-example-token-of-32-bytes!"}


def test_api_private_by_default(client):
    assert client.get("/api/soc/summary").status_code == 401
    assert client.get("/api/soc/summary", headers=headers()).status_code == 200


def test_source_files_not_public(client):
    for p in ("/app.py", "/soc_api.py", "/log_engine.py", "/analysis.db", "/.env", "/requirements.txt", "/datasets/mixed.log"):
        assert client.get(p).status_code == 404


def test_health_and_public_demo(client):
    assert client.get("/api/health").status_code == 200
    r = client.post("/api/analyze", json={"raw_logs": event(0)})
    assert r.status_code == 200 and r.json["analysis_id"] is None


def test_legacy_history_disabled(client):
    assert client.get("/api/analysis/history").status_code == 410


def test_soc_ingest_dedup_and_cases(client):
    raw = "\n".join([event(i * 10) for i in range(10)])
    first = client.post("/api/soc/ingest", json={"raw_logs": raw}, headers=headers())
    assert first.status_code == 201, first.json
    assert first.json["alert_count"] >= 1
    dup = client.post("/api/soc/ingest", json={"raw_logs": raw}, headers=headers())
    assert dup.status_code == 200 and dup.json["duplicate"] is True
    summary = client.get("/api/soc/summary", headers=headers()).json
    assert summary["events"] == 10 and summary["batches"] == 1
    cases = client.get("/api/soc/cases", headers=headers()).json["items"]
    assert cases
    case_id = cases[0]["id"]
    updated = client.patch(f"/api/soc/cases/{case_id}", headers=headers(),
                           json={"status":"investigating","notes":"Confirmed synthetic example"})
    assert updated.status_code == 200
    timeline = client.get(f"/api/soc/cases/{case_id}/timeline", headers=headers())
    assert timeline.status_code == 200 and timeline.json["items"]
    explanation = client.get(f"/api/soc/cases/{case_id}/explain", headers=headers()).json
    assert explanation["ai_generated"] is False


def test_soc_filters(client):
    client.post("/api/soc/ingest", headers=headers(), json={"raw_logs": event(0)})
    r = client.get("/api/soc/events?ip=192.0.2.10",headers=headers())
    assert r.status_code == 200 and len(r.json["items"]) == 1
    assert client.get("/api/soc/events?ip=192.0.2.90",headers=headers()).json["items"] == []


def test_file_upload_restrictions(client):
    r = client.post("/api/soc/ingest", headers=headers(),
                    data={"file":(io.BytesIO(b"data"),"example.exe")}, content_type="multipart/form-data")
    assert r.status_code == 400


def test_audit_actions(client):
    client.post("/api/soc/ingest", headers=headers(),json={"raw_logs":event(0)})
    items=client.get("/api/soc/audit",headers=headers()).json["items"]
    assert any(i["action"]=="ingest" for i in items)


def test_rules_api(client):
    r = client.get("/api/soc/rules",headers=headers())
    assert r.status_code == 200 and len(r.json["rules"]) == len(RULES)

def test_intelligence_access_and_quality(client):
    assert client.get('/api/soc/intelligence').status_code == 401
    raw = '\n'.join([event(0), 'unrecognized entry', json.dumps({'ip': '2606:4700:4700::1111'})])
    assert client.post('/api/soc/ingest', json={'raw_logs': raw}, headers=headers()).status_code == 201
    data = client.get('/api/soc/intelligence', headers=headers()).json
    assert data['total'] == 3
    assert data['missing_time'] == 2 and data['missing_ip'] == 1 and data['unparsed'] == 1
    ips = {i['ip']: i for i in data['ips']}
    assert ips['192.0.2.10']['scope'] == 'documentation'
    assert ips['2606:4700:4700::1111']['version'] == 6
    assert all(i['country'] is None and i['reputation'] == 'unknown' for i in data['ips'])

def test_intelligence_hourly_counts_and_severity(client):
    raw = '\n'.join([event(0, 1102), event(1), event(3600), json.dumps({'ip': '127.0.0.1'})])
    client.post('/api/soc/ingest', json={'raw_logs': raw}, headers=headers())
    data = client.get('/api/soc/intelligence', headers=headers()).json
    assert data['timeline'] == [{'hour': '2026-10-31T10', 'events': 2}, {'hour': '2026-10-31T11', 'events': 1}]
    assert data['severities'] == {'critical': 1}
    assert data['missing_time'] == 1
    assert next(i for i in data['ips'] if i['ip'] == '127.0.0.1')['scope'] == 'loopback'

@pytest.mark.parametrize('code,rule', [(4720,'WIN-002'),(4698,'WIN-003')])
def test_account_and_task_indicators(code, rule):
    result=inspect(event(0,code))
    assert any(a['rule_id']==rule and a['event_ids'] for a in result['alerts'])


def test_encoded_powershell_is_process_scoped():
    command='powershell.exe -NoProfile -EncodedCommand QQBBAEEA'
    suspicious=json.dumps({'EventID':1,'provider':'Microsoft-Windows-Sysmon','CommandLine':command})
    assert any(a['rule_id']=='PROC-001' for a in inspect(suspicious)['alerts'])
    assert not any(a['rule_id']=='PROC-001' for a in inspect(json.dumps({'message':command}))['alerts'])
    assert not any(a['rule_id']=='PROC-001' for a in inspect(json.dumps({'EventID':4688,'CommandLine':'powershell.exe Get-Date'}))['alerts'])


def test_encoded_web_payload():
    raw='192.0.2.5 - - [31/Oct/2026:10:00:00 +0000] "GET /?q=UNION%2520SELECT HTTP/1.1" 403 32'
    assert any(a['rule_id']=='WEB-001' for a in inspect(raw)['alerts'])


def test_cloudtrail_console_login_normalization():
    raw=json.dumps({'eventSource':'signin.amazonaws.com','eventName':'ConsoleLogin',
                    'eventTime':'2026-10-31T09:00:00Z','sourceIPAddress':'2001:4860:4860::8888',
                    'userIdentity':{'type':'IAMUser','userName':'analyst'},'responseElements':{'ConsoleLogin':'Failure'}})
    e=normalize(raw,1)
    assert e['source']=='cloudtrail' and e['action']=='login' and e['outcome']=='failure'
    assert e['user']=='analyst' and e['timestamp']=='2026-10-31T09:00:00Z'


def test_watchlist_crud_matching_and_auth(client):
    assert client.get('/api/soc/watchlist').status_code==401
    assert client.post('/api/soc/watchlist',json={'kind':'ip','value':'127.0.0.1'}).status_code==401
    client.post('/api/soc/ingest',headers=headers(),json={'raw_logs':event(0)})
    r=client.post('/api/soc/watchlist',headers=headers(),json={'kind':'ip','value':'192.0.2.10','label':'review'})
    assert r.status_code==201
    item_id=r.json['id']
    assert client.post('/api/soc/watchlist',headers=headers(),json={'kind':'ip','value':'192.0.2.10'}).status_code==409
    assert client.post('/api/soc/watchlist',headers=headers(),json={'kind':'ip','value':'invalid'}).status_code==400
    assert client.post('/api/soc/watchlist',headers=headers(),json={'kind':'sql','value':'x'}).status_code==400
    items=client.get('/api/soc/watchlist',headers=headers()).json['items']
    assert len(items)==1 and items[0]['matches']==1
    assert client.delete(f'/api/soc/watchlist/{item_id}').status_code==401
    assert client.delete(f'/api/soc/watchlist/{item_id}',headers=headers()).status_code==200
    assert client.get('/api/soc/watchlist',headers=headers()).json['items']==[]
    actions=[x['action'] for x in client.get('/api/soc/audit',headers=headers()).json['items']]
    assert 'watchlist_add' in actions and 'watchlist_delete' in actions


def test_hunting_filters_pagination_and_dates(client):
    rows=[event(i, user='alice' if i%2 else 'bob') for i in range(7)]
    client.post('/api/soc/ingest',headers=headers(),json={'raw_logs':'\n'.join(rows)})
    r=client.get('/api/soc/events?user=alice&action=login&outcome=failure&limit=2',headers=headers()).json
    assert r['total']==3 and len(r['items'])==2 and r['has_more']
    r2=client.get('/api/soc/events?user=alice&limit=2&offset=2',headers=headers()).json
    assert len(r2['items'])==1 and not r2['has_more']
    assert not set(e['event_id'] for e in r['items']) & set(e['event_id'] for e in r2['items'])
    r=client.get('/api/soc/events',query_string={'start':'2026-10-31T13:00:02+03:00','end':'2026-10-31T10:00:04Z'},headers=headers()).json
    assert r['total']==3
    for query in ('start=invalid','start=2026-10-31T10:00:00','offset=-1','offset=bad','start=2026-11-01T00:00:00Z&end=2026-10-01T00:00:00Z'):
        assert client.get('/api/soc/events?'+query,headers=headers()).status_code==400
    assert client.get('/api/soc/events',query_string={'user':"alice' OR 1=1--"},headers=headers()).json['total']==0


def test_source_visibility_is_not_heartbeat(client):
    assert client.get('/api/soc/source-health').status_code==401
    client.post('/api/soc/ingest',headers=headers(),json={'raw_logs':event(0)+'\nunknown line'})
    r=client.get('/api/soc/source-health',headers=headers())
    assert r.status_code==200 and r.json['heartbeat_available'] is False
    sources={x['source']:x for x in r.json['items']}
    assert sources['windows']['events']==1 and sources['windows']['missing_time']==0
    assert sources['unknown']['missing_time']==1 and sources['unknown']['missing_ip']==1
    assert sources['windows']['last_ingested']


def test_map_assets_and_csp_are_scoped(client):
    for path in ('/atlas.js','/vendor/maplibre/maplibre-gl-csp.js','/vendor/maplibre/maplibre-gl-csp-worker.js','/vendor/maplibre/maplibre-gl.css'):
        assert client.get(path).status_code==200
    assert client.get('/vendor/maplibre/package.json').status_code==404
    csp=client.get('/soc').headers['Content-Security-Policy']
    assert "worker-src 'self'" in csp
    assert 'https://tile.openstreetmap.org' in csp and 'https://tiles.maps.eox.at' in csp
    assert 'unsafe-eval' not in csp

@pytest.mark.parametrize('bad_kind',[[],{},None,True,3])
def test_watchlist_bad_kind_is_client_error(client,bad_kind):
    response=client.post('/api/soc/watchlist',headers=headers(),json={'kind':bad_kind,'value':'x'})
    assert response.status_code==400

@pytest.mark.parametrize('bad_status',[[],{},None,True,3])
def test_case_bad_status_is_client_error(client,bad_status):
    response=client.patch('/api/soc/cases/999',headers=headers(),json={'status':bad_status})
    assert response.status_code==400


def test_non_ascii_invalid_api_key_is_unauthorized(client):
    assert client.get('/api/soc/summary',headers={'X-API-Key':'invalid-\u011f-key'}).status_code==401


def test_fractional_seconds_do_not_reorder_login_evidence():
    records=[{'timestamp':'2026-10-31T10:00:00Z','EventID':4624,'ip':'192.0.2.10','user':'admin'}]
    records += [{'timestamp':f'2026-10-31T10:00:00.{i}Z','EventID':4625,'ip':'192.0.2.10','user':'admin'} for i in (1,2,3)]
    assert not any(a['rule_id']=='AUTH-003' for a in inspect('\n'.join(json.dumps(x) for x in records))['alerts'])


def test_fractional_timeline_stays_chronological(client):
    records=[{'timestamp':'2026-10-31T10:00:00Z','EventID':4625,'ip':'192.0.2.10','user':'admin'}]
    records += [{'timestamp':f'2026-10-31T10:00:00.{i}Z','EventID':4625,'ip':'192.0.2.10','user':'admin'} for i in (1,2)]
    records.append({'timestamp':'2026-10-31T10:00:00.3Z','EventID':4624,'ip':'192.0.2.10','user':'admin'})
    client.post('/api/soc/ingest',headers=headers(),json={'raw_logs':'\n'.join(json.dumps(x) for x in reversed(records))})
    cases=client.get('/api/soc/cases',headers=headers()).json['items']
    case=next(c for c in cases if c['rule_id']=='AUTH-003')
    events=client.get(f"/api/soc/cases/{case['id']}/timeline",headers=headers()).json['items']
    assert [e['timestamp'] for e in events]==['2026-10-31T10:00:00Z','2026-10-31T10:00:00.100000Z','2026-10-31T10:00:00.200000Z','2026-10-31T10:00:00.300000Z']
