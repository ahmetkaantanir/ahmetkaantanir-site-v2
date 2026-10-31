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
