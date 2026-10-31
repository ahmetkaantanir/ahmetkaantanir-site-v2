"""Log Intelligence Lab SOC engine.

Deterministic, offline-first event normalisation, detections and forensic context.
Only evidence-backed alerts are produced; no claims of confirmed compromise.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

UTC = timezone.utc
MAX_EVENTS = 20_000
RULES = {
    "WEB-001": ("Web SQL injection indicator", "high", "T1190"),
    "WEB-002": ("Cross-site scripting indicator", "medium", "T1190"),
    "WEB-003": ("Path traversal indicator", "high", "T1190"),
    "AUTH-001": ("Repeated failed authentication", "high", "T1110"),
    "AUTH-002": ("Possible password spraying", "high", "T1110.003"),
    "AUTH-003": ("Successful authentication after failures", "high", "T1078"),
    "NET-001": ("Multiple destination ports contacted", "medium", "T1046"),
    "NET-002": ("High request rate", "medium", "T1498"),
    "CORR-001": ("Reconnaissance followed by authentication attempts", "high", "T1110"),
    "SYS-001": ("Security log clearing or audit disruption indicator", "high", "T1070.001"),
    "SYS-002": ("Suspicious system utility execution", "medium", "T1059"),
    "CLOUD-001": ("Sensitive cloud identity policy change", "high", "T1098"),
    "IDS-001": ("Network detection engine signature", "high", "T1204"),
}
WEB_PATTERNS = {
    "WEB-001": re.compile(r"union\s+(?:all\s+)?select\b|(?:%27|')\s*or\s+(?:%271%27|'1'|1)\s*=\s*(?:%271%27|'1'|1)|information_schema|sleep\s*\(", re.I),
    "WEB-002": re.compile(r"<script\b|%3cscript\b|onerror\s*=|javascript:", re.I),
    "WEB-003": re.compile(r"(?:\.\./|%2e%2e(?:%2f|/)|/etc/passwd|win\.ini)", re.I),
}
APACHE_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)')
SSH_RE = re.compile(r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SECRET_RE = re.compile(r"(?i)\b(password|passwd|api[_-]?key|authorization|access[_-]?token|secret)\b\s*[:=]\s*(?:[^\s,;]+)")
TIME_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d")
STATUS_LABEL = {"high": 75, "medium": 45, "low": 20}


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def redact(value: str) -> str:
    return SECRET_RE.sub(lambda m: m.group(1) + "=[REDACTED]", value)[:8192]


def clean_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except (ValueError, TypeError):
        return "unknown"


def parse_time(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            return None
    raw = str(value).strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo:
            return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return None  # No timezone: do not silently claim UTC.
    except ValueError:
        pass
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def _get(data: dict, *paths: str, default: Any = None) -> Any:
    for path in paths:
        node: Any = data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node is not None:
            return node
    return default


def _event(line: str, number: int, received: str) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": hashlib.sha256((str(number) + "\0" + line).encode("utf-8")).hexdigest()[:20],
        "sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
        "line": number,
        "source": "unknown", "event_type": "unknown", "action": "unknown",
        "timestamp": None, "ingested_at": received, "ip": "unknown",
        "user": None, "host": None, "destination_ip": None, "port": None,
        "status": None, "outcome": "unknown", "request": None,
        "raw": redact(line), "parse_error": False,
    }
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        obj = None
    if isinstance(obj, dict):
        event["source"] = "json"
        event["timestamp"] = parse_time(_get(obj, "timestamp", "@timestamp", "time", "event.created", "eventTime"))
        event["ip"] = clean_ip(_get(obj, "src_ip", "source.ip", "sourceIPAddress", "client_ip", "ip", "winlog.event_data.IpAddress"))
        event["destination_ip"] = clean_ip(_get(obj, "dest_ip", "destination.ip")) if _get(obj, "dest_ip", "destination.ip") else None
        event["port"] = _get(obj, "dest_port", "destination.port", "destination_port")
        event["user"] = _get(obj, "user.name", "username", "winlog.event_data.TargetUserName", "userIdentity.userName")
        event["host"] = _get(obj, "host.name", "computer_name", "winlog.computer_name", "Computer")
        event["status"] = _get(obj, "status", "http.response.status_code")
        event["request"] = str(_get(obj, "url.path", "endpoint", "http.url", "query", "message", default=""))[:2048]
        event["action"] = str(_get(obj, "event.action", "eventName", "event_type", "action", default="event"))[:128]
        event["event_type"] = "application"
        if _get(obj, "event_type") in ("alert", "dns", "http", "flow", "tls", "fileinfo"):
            event["source"] = "suricata"
            event["event_type"] = str(obj["event_type"])
            event["request"] = str(_get(obj, "alert.signature", "dns.rrname", "http.url", default=event["request"]))[:2048]
        elif _get(obj, "winlog.event_id", "EventID", "event.code", "event_id") is not None:
            code = str(_get(obj, "winlog.event_id", "EventID", "event.code", "event_id"))
            event["source"] = "windows"
            event["event_type"] = "windows_event"
            event["action"] = code
            if code in ("4625", "4771", "4776"):
                event["outcome"] = "failure"
            elif code in ("4624", "4768"):
                event["outcome"] = "success"
            if code in ("1102", "104"):
                event["action"] = "clear_security_log"
        elif _get(obj, "eventName", "eventSource") is not None:
            event["source"] = "cloudtrail"
            event["event_type"] = "cloud_audit"
        elif _get(obj, "dns.question.name", "dns.query") is not None:
            event["source"] = "dns"
            event["event_type"] = "dns"
            event["request"] = str(_get(obj, "dns.question.name", "dns.query"))
        elif _get(obj, "http.request.method") is not None:
            event["source"] = "web"
            event["event_type"] = "http"
        message = str(_get(obj, "message", default="")).lower()
        if event["outcome"] == "unknown":
            if _get(obj, "event.outcome", "outcome") in ("failure", "success"):
                event["outcome"] = str(_get(obj, "event.outcome", "outcome"))
            elif re.search(r"failed (?:password|login)|authentication failed", message):
                event["outcome"] = "failure"
        return event
    match = APACHE_RE.search(line)
    if match:
        event.update(source="web", event_type="http", action=match["method"], ip=clean_ip(match["ip"]),
                     timestamp=parse_time(match["time"]), request=match["path"], status=int(match["status"]),
                     outcome="failure" if match["status"] == "401" else "unknown")
        return event
    ssh = SSH_RE.search(line)
    if ssh:
        event.update(source="linux_auth", event_type="authentication", ip=clean_ip(ssh["ip"]),
                     user=ssh["user"], action="ssh_login",
                     outcome="failure" if ssh["result"].lower() == "failed" else "success")
        return event
    if "SRC=" in line and ("DROP" in line or "ACCEPT" in line):
        src = re.search(r"\bSRC=(\S+)", line)
        dst = re.search(r"\bDST=(\S+)", line)
        port = re.search(r"\bDPT=(\d+)", line)
        event.update(source="firewall", event_type="network", action="DROP" if "DROP" in line else "ACCEPT",
                     ip=clean_ip(src.group(1)) if src else "unknown",
                     destination_ip=clean_ip(dst.group(1)) if dst else None,
                     port=int(port.group(1)) if port else None)
        return event
    event["parse_error"] = True
    match = IP_RE.search(line)
    if match:
        event["ip"] = clean_ip(match.group(0))
    return event


def normalize_logs(raw: str) -> dict[str, Any]:
    """Keep malformed records visible; bound memory by rejecting excessive inputs."""
    lines = [(i, line.strip()) for i, line in enumerate(raw.splitlines(), start=1) if line.strip()]
    if len(lines) > MAX_EVENTS:
        raise ValueError("Too many lines; maximum 20000 per analysis")
    stamp = utc_now()
    seen: set[str] = set()
    events = []
    duplicates = 0
    errors = 0
    for number, line in lines:
        sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
        if sha in seen:
            duplicates += 1
            continue
        seen.add(sha)
        event = _event(line, number, stamp)
        errors += int(event["parse_error"])
        events.append(event)
    return {"events": events, "stats": {
        "input_lines": len(lines), "parsed": len(events) - errors,
        "unsupported": errors, "duplicates": duplicates, "unique_events": len(events)
    }}


def _make_alert(rule_id: str, events: list[dict], reason: str | None = None) -> dict:
    name, severity, technique = RULES[rule_id]
    ips = [e["ip"] for e in events if e["ip"] != "unknown"]
    return {
        "id": hashlib.sha256((rule_id + ":".join(e["event_id"] for e in events)).encode()).hexdigest()[:16],
        "rule_id": rule_id, "name": name, "severity": severity,
        "confidence": "medium", "mitre_technique": technique,
        "description": reason or name,
        "source_ip": ips[0] if ips else "unknown",
        "event_ids": [e["event_id"] for e in events[:30]],
        "evidence_count": len(events), "status": "new",
    }


def _dt(event: dict) -> datetime | None:
    if not event.get("timestamp"):
        return None
    try:
        return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        return None


def detections(events: list[dict]) -> list[dict]:
    result: list[dict] = []
    by_ip: dict[str, list[dict]] = defaultdict(list)
    auth_ip: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        ip = event["ip"]
        if ip != "unknown":
            by_ip[ip].append(event)
        text = (str(event.get("request") or "") + " " + event["raw"])[:8192]
        if event["source"] in ("web", "json", "suricata"):
            for rule, pattern in WEB_PATTERNS.items():
                if pattern.search(text):
                    result.append(_make_alert(rule, [event], "Suspicious request indicator; exploitation is unconfirmed"))
        if event["source"] == "suricata" and event["event_type"] == "alert":
            result.append(_make_alert("IDS-001", [event], "Suricata alert: review signature, context and false positives"))
        if event["action"] in ("clear_security_log", "1102", "104") or re.search(r"auditd (?:stopped|disabled)|wevtutil\s+cl", text, re.I):
            result.append(_make_alert("SYS-001", [event]))
        if re.search(r"(?:powershell\s+-(?:enc|encodedcommand)\b|certutil\s+-urlcache)", text, re.I):
            result.append(_make_alert("SYS-002", [event]))
        if event["source"] == "cloudtrail" and event["action"] in ("AttachUserPolicy", "PutUserPolicy", "CreateAccessKey", "UpdateAssumeRolePolicy"):
            result.append(_make_alert("CLOUD-001", [event]))
        if event["outcome"] == "failure" and (event["source"] in ("linux_auth", "windows") or "login" in str(event.get("request") or "").lower()):
            if ip != "unknown":
                auth_ip[ip].append(event)
    # Sliding windows are based on event time, never record count alone.
    for ip, failures in auth_ip.items():
        ordered = sorted(((_dt(e), e) for e in failures if _dt(e) is not None), key=lambda row: row[0])
        window: deque[tuple[datetime, dict]] = deque()
        emitted = False
        for instant, item in ordered:
            window.append((instant, item))
            while window and instant - window[0][0] > timedelta(minutes=5):
                window.popleft()
            if not emitted and len(window) >= 10:
                result.append(_make_alert("AUTH-001", [e for _, e in window], "10+ failed logins within five minutes"))
                emitted = True
            users = {e.get("user") for _, e in window if e.get("user")}
            if len(users) >= 5:
                if not any(a["rule_id"] == "AUTH-002" and a["source_ip"] == ip for a in result):
                    result.append(_make_alert("AUTH-002", [e for _, e in window], "Failed logins for five or more accounts within five minutes"))
        successes = sorted(((_dt(e), e) for e in by_ip.get(ip, []) if e["outcome"] == "success" and _dt(e)), key=lambda row: row[0])
        for t_success, success in successes:
            prior = [e for t, e in ordered if timedelta(0) <= t_success - t <= timedelta(minutes=15)]
            if len(prior) >= 3:
                result.append(_make_alert("AUTH-003", prior[-10:] + [success],
                                          "Success after repeated failed logins; investigate account and target host"))
                break
    for ip, group in by_ip.items():
        timed = sorted(((_dt(e), e) for e in group if _dt(e) is not None), key=lambda row: row[0])
        for i, (begin, _) in enumerate(timed):
            within = [e for t, e in timed[i:] if timedelta(0) <= t - begin <= timedelta(minutes=1)]
            if len(within) >= 100:
                result.append(_make_alert("NET-002", within[:100], "100+ events in a 60 second window"))
                break
        ports = {str(e.get("port")) for e in group if e.get("port") is not None}
        if len(ports) >= 15:
            result.append(_make_alert("NET-001", group[:40], "Traffic to at least 15 distinct destination ports"))
        scans = [(t, e) for t, e in timed if re.search(r"wp-admin|phpmyadmin|/\.env|\.\./", str(e.get("request") or ""), re.I)]
        fails = [(t, e) for t, e in timed if e["outcome"] == "failure"]
        for scan_time, scan in scans:
            followers = [e for t, e in fails if timedelta(0) <= t - scan_time <= timedelta(minutes=15)]
            if len(followers) >= 3:
                result.append(_make_alert("CORR-001", [scan] + followers[:10],
                                          "Web reconnaissance followed by unsuccessful authentication"))
                break
    return result[:500]


def anomaly_summary(events: list[dict]) -> dict:
    buckets = Counter(e["timestamp"][:13] for e in events if e.get("timestamp"))
    if len(buckets) < 5:
        return {"method": "median-mad", "status": "insufficient_data", "anomalies": []}
    values = list(buckets.values())
    median = statistics.median(values)
    mad = statistics.median(abs(x - median) for x in values)
    if mad == 0:
        return {"method": "median-mad", "status": "low_variation", "anomalies": []}
    found = [
        {"hour_utc": hour, "events": count, "robust_z": round(.6745 * (count - median) / mad, 2)}
        for hour, count in sorted(buckets.items())
        if .6745 * (count - median) / mad > 3.5
    ]
    return {"method": "median-mad", "status": "ok", "anomalies": found[:24]}


def cases_for(alerts: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        grouped[alert["source_ip"]].append(alert)
    cases = []
    for ip, rows in grouped.items():
        severity = "high" if any(a["severity"] == "high" for a in rows) else "medium"
        score = min(95, max(STATUS_LABEL[a["severity"]] for a in rows) + min(20, 5 * (len(rows) - 1)))
        cases.append({
            "case_id": hashlib.sha256(("case:" + ip + ":" + rows[0]["id"]).encode()).hexdigest()[:16],
            "title": "Security indicators associated with " + ip, "source_ip": ip,
            "severity": severity, "risk_score": score, "confidence": "medium",
            "alert_ids": [r["id"] for r in rows], "status": "new",
            "explanation": "Review linked evidence before deciding whether a compromise occurred.",
        })
    return sorted(cases, key=lambda c: c["risk_score"], reverse=True)[:100]


def run_soc_analysis(raw: str, include_events: bool = False) -> dict:
    normalized = normalize_logs(raw)
    events = normalized["events"]
    alerts = detections(events)
    sources = Counter(e["source"] for e in events)
    cases = cases_for(alerts)
    return {
        "schema_version": "1.0",
        "stats": normalized["stats"], "sources": dict(sources),
        "detections": alerts, "cases": cases,
        "anomalies": anomaly_summary(events),
        "mitre_coverage": dict(Counter(a["mitre_technique"] for a in alerts)),
        "events": events[:MAX_EVENTS] if include_events else [],
        "notes": [
            "Alerts are indicators, not proof of successful compromise.",
            "Unknown event timestamps are not inferred from ingestion time.",
            "Reputation and geolocation require configured, authoritative providers.",
            "AI assistant is disabled until a private, explicitly configured model is available.",
        ],
    }


def explain_case(case: dict, linked_alerts: list[dict]) -> dict:
    """Deterministic analyst guidance. This is not an LLM."""
    return {
        "case_id": case.get("case_id"),
        "summary": case.get("title", "Security case"),
        "assessment": "Evidence-based indicators require analyst verification; outcome is not confirmed.",
        "rule_ids": sorted({a["rule_id"] for a in linked_alerts}),
        "evidence_ids": sorted({eid for a in linked_alerts for eid in a["event_ids"]}),
        "recommended_steps": [
            "Check original event timestamps and identity/host correlation.",
            "Compare with authorized activity, maintenance windows and allowlists.",
            "Collect supporting endpoint, network and authentication evidence.",
            "Document your decision and retain the original log file securely.",
        ],
        "generated_by": "deterministic-playbook-v1", "uses_external_ai": False,
    }
