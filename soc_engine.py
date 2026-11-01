"""Deterministic SOC normalization, event correlation and evidence-linked alerts.

All input is untrusted. No external requests; detections are indicators, not proof.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote

MAX_LINES = 10000
MAX_LINE = 16384
RULES = {
    "WEB-001": {"name": "Web attack indicator", "severity": "high", "mitre": "T1190"},
    "WEB-002": {"name": "High volume web requests", "severity": "medium", "mitre": "T1595"},
    "AUTH-001": {"name": "Possible brute force", "severity": "high", "mitre": "T1110"},
    "AUTH-002": {"name": "Possible password spraying", "severity": "high", "mitre": "T1110.003"},
    "AUTH-003": {"name": "Login after repeated failures", "severity": "high", "mitre": "T1078"},
    "NET-001": {"name": "Possible port scanning", "severity": "medium", "mitre": "T1046"},
    "WIN-001": {"name": "Windows audit log cleared", "severity": "critical", "mitre": "T1070.001"},
    "IDS-001": {"name": "IDS rule alert", "severity": "medium", "mitre": None},
    "PROC-001": {"name": "Encoded PowerShell command indicator", "severity": "high", "mitre": "T1059.001"},
    "WIN-002": {"name": "Windows user account created", "severity": "medium", "mitre": "T1136.001"},
    "WIN-003": {"name": "Windows scheduled task created", "severity": "medium", "mitre": "T1053.005"},
    "WIN-004": {"name": "Windows account lockout", "severity": "medium", "mitre": "T1110"},
    "DNS-001": {"name": "Long DNS label indicator", "severity": "medium", "mitre": "T1071.004"},
    "END-001": {"name": "Wazuh rule alert", "severity": "medium", "mitre": None},
    "HNY-001": {"name": "Honeypot authentication activity", "severity": "medium", "mitre": "T1110"},
}
WEB_PATTERNS = {
    "SQLi": re.compile(r"\bunion\s+select\b|\binformation_schema\b|\bsleep\s*\(", re.I),
    "XSS": re.compile(r"<script\b|javascript:|\bonerror\s*=", re.I),
    "Traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini", re.I),
}
APACHE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^]]+)\]\s+"(?P<method>\S+)\s+(?P<path>.*?)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})')
SSH = re.compile(r'(?P<action>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)', re.I)
FIREWALL = re.compile(r"\b(?:SRC|src)=(?P<ip>[0-9a-fA-F:.]+).*?\b(?:DPT|dpt)=(?P<port>\d+)")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _timestamp(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            d = datetime.fromtimestamp(value, timezone.utc)
        else:
            raw = str(value).strip().replace("Z", "+00:00")
            d = datetime.fromisoformat(raw)
        if d.tzinfo is None:
            return None
        return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _field(value: Any, limit: int = 256) -> str | None:
    return str(value)[:limit] if value is not None else None


def normalize(line: str, number: int) -> dict[str, Any]:
    e: dict[str, Any] = {
        "event_id": hashlib.sha256((str(number) + ":" + line).encode()).hexdigest()[:24],
        "line": number, "raw": line[:MAX_LINE], "timestamp": None, "source": "unknown",
        "ip": None, "user": None, "host": None, "action": None, "status": None,
        "outcome": "unknown", "port": None, "tags": []
    }
    try:
        item = json.loads(line)
    except (ValueError, TypeError):
        item = None
    if isinstance(item, dict):
        source_obj = item.get("source")
        src = source_obj.get("ip") if isinstance(source_obj, dict) else None
        src = src or item.get("src_ip") or item.get("source_ip") or item.get("ip")
        event_obj = item.get("event") if isinstance(item.get("event"), dict) else {}
        e.update(source="json", ip=_ip(src), timestamp=_timestamp(
            item.get("@timestamp") or item.get("timestamp") or item.get("time")),
            user=_field(item.get("username") or item.get("user")),
            host=_field(item.get("hostname") or item.get("host")),
            action=_field(item.get("action") or event_obj.get("action")),
            outcome=_field(item.get("outcome") or event_obj.get("outcome")) or "unknown")
        if isinstance(item.get("host"), dict):
            e["host"] = _field(item["host"].get("name"))
        if isinstance(item.get("user"), dict):
            e["user"] = _field(item["user"].get("name"))
        process = item.get('process') if isinstance(item.get('process'), dict) else {}
        command = item.get('CommandLine') or item.get('command_line') or process.get('command_line')
        if isinstance(command, str):
            e['command_line'] = command[:4096]
        try:
            v = int(item.get("status"))
            if 100 <= v <= 599:
                e["status"] = v
        except (TypeError, ValueError, OverflowError):
            pass
        code = item.get("EventID", item.get("EventCode", item.get("event_id")))
        if code is not None:
            code = str(code)
            e.update(source="windows", action="event_" + code[:12])
            if code in ("4625", "4771"):
                e.update(outcome="failure", action="login")
            if code == "4624":
                e.update(outcome="success", action="login")
            if code == "1102":
                e["tags"].append("audit_clear")
            if code == '4720':
                e['tags'].append('account_created')
            if code == '4698':
                e['tags'].append('task_created')
        kind = item.get("event_type")
        if kind:
            e["source"] = "suricata"
            e["action"] = _field(kind)
            if kind == "alert" and isinstance(item.get("alert"), dict):
                e["tags"].append("ids_alert")
            if kind == "dns":
                e["source"] = "dns"
        provider = str(item.get("provider", item.get("ProviderName", ""))).lower()
        if "sysmon" in provider:
            e["source"] = "sysmon"
        if e['source'] in ('windows', 'sysmon') and isinstance(command, str):
            if re.search(r'\b(?:powershell|pwsh)(?:\.exe)?\b', command, re.I) and re.search(r'(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+\S+', command, re.I):
                e['tags'].append('encoded_powershell')
        if item.get('eventSource') and item.get('eventName') and isinstance(item.get('userIdentity'), dict):
            identity = item['userIdentity']
            e.update(source='cloudtrail', ip=_ip(item.get('sourceIPAddress')),
                     timestamp=_timestamp(item.get('eventTime')), action=_field(item.get('eventName')),
                     user=_field(identity.get('userName') or identity.get('arn')),
                     outcome='failure' if item.get('errorCode') else 'unknown')
            response = item.get('responseElements')
            if e['action'] == 'ConsoleLogin' and isinstance(response, dict):
                e.update(action='login', outcome='success' if response.get('ConsoleLogin') == 'Success' else 'failure' if response.get('ConsoleLogin') == 'Failure' else 'unknown')
        # Zeek JSON, Wazuh alerts, Cloudflare Logpush, Cowrie and tshark JSONL.
        if 'id.orig_h' in item and ('uid' in item or 'ts' in item):
            e.update(source='zeek', ip=_ip(item.get('id.orig_h')), timestamp=_timestamp(item.get('ts')),
                     action=_field(item.get('_path') or item.get('service') or 'connection'),
                     port=item.get('id.resp_p'), destination_ip=_ip(item.get('id.resp_h')),
                     flow_id=_field(item.get('uid')))
            if isinstance(item.get('query'), str):
                e.update(source='dns', action='dns_query', domain=item['query'][:512])
        if isinstance(item.get('rule'), dict) and isinstance(item.get('agent'), dict):
            agent = item['agent']
            e.update(source='wazuh', host=_field(agent.get('name')), ip=_ip(agent.get('ip')),
                     action='wazuh_rule', provider_rule=_field(item['rule'].get('id')))
            e['tags'].append('wazuh_alert')
        if item.get('ClientIP') and ('RayID' in item or 'ClientRequestURI' in item):
            e.update(source='cloudflare', ip=_ip(item['ClientIP']), action=_field(item.get('ClientRequestURI')),
                     timestamp=_timestamp(item.get('EdgeStartTimestamp')/1e9 if isinstance(item.get('EdgeStartTimestamp'), (int,float)) else item.get('EdgeStartTimestamp')))
        if str(item.get('eventid', '')).startswith('cowrie.'):
            e.update(source='cowrie', action=_field(item['eventid']), ip=_ip(item.get('src_ip')))
            if item['eventid'] in {'cowrie.login.failed', 'cowrie.login.success'}:
                e['tags'].append('honeypot_login')
        layers = item.get('_source', {}).get('layers') if isinstance(item.get('_source'), dict) else None
        if isinstance(layers, dict):
            ip_layer = layers.get('ip', {})
            frame_layer = layers.get('frame', {})
            if isinstance(ip_layer, dict) and isinstance(frame_layer, dict):
                e.update(source='pcap', ip=_ip(ip_layer.get('ip.src')), destination_ip=_ip(ip_layer.get('ip.dst')),
                         timestamp=_timestamp(float(frame_layer['frame.time_epoch'])) if str(frame_layer.get('frame.time_epoch','')).replace('.','',1).isdigit() else None,
                         action='packet_metadata')
        if code == '4740':
            e['tags'].append('account_lockout')
        if isinstance(item.get('dns'), dict):
            dns = item['dns']
            if isinstance(dns.get('rrname'), str):
                e['domain'] = dns['rrname'][:512]
        if e.get('domain') and any(len(label)>=50 for label in e['domain'].split('.')):
            e['tags'].append('long_dns_label')
        if e["status"] in (401, 403) and e["outcome"] == "unknown":
            e["outcome"] = "failure"
        port = e.get('port') or item.get("dest_port", item.get("port"))
        try:
            port = int(port)
            e["port"] = port if 1 <= port <= 65535 else None
        except (ValueError, TypeError, OverflowError):
            pass
    else:
        m = APACHE.search(line)
        if m:
            e.update(source="web", ip=_ip(m["ip"]), action=m["method"] + " " + m["path"][:240],
                     status=int(m["status"]))
            try:
                e["timestamp"] = _timestamp(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").isoformat())
            except ValueError:
                pass
        else:
            m = SSH.search(line)
            if m:
                e.update(source="auth", ip=_ip(m["ip"]), user=_field(m["user"]), action="login",
                         outcome="failure" if m["action"].lower() == "failed" else "success")
            else:
                m = FIREWALL.search(line)
                if m:
                    e.update(source="firewall", ip=_ip(m["ip"]), action="network_connection",
                             port=int(m["port"]))
                elif 'filterlog:' in line:
                    # pfSense/OPNsense IPv4 filterlog CSV; unknown layouts stay unknown.
                    fields = line.split('filterlog:',1)[1].strip().split(',')
                    if len(fields)>=22 and fields[8]=='4' and fields[6] in {'pass','block'}:
                        try:
                            port = int(fields[21])
                            e.update(source='firewall',ip=_ip(fields[18]),destination_ip=_ip(fields[19]),
                                     action=fields[6],outcome='failure' if fields[6]=='block' else 'unknown',
                                     port=port if 1<=port<=65535 else None)
                        except ValueError:
                            pass
        # Syslog without year or zone does not carry a forensically trustworthy timestamp.
        if ISO.match(line):
            m = re.match(r"^(\S+)\s+", line)
            if m:
                e["timestamp"] = e["timestamp"] or _timestamp(m[1])
    if e["source"] in ("web", "json", "suricata"):
        for key, pattern in WEB_PATTERNS.items():
            if pattern.search(unquote(unquote(line))):
                e["tags"].append(key)
    return e


def _alert(rule: str, records: list[dict], explanation: str) -> dict[str, Any]:
    meta = RULES[rule]
    ids = [e["event_id"] for e in records]
    return {
        "alert_id": hashlib.sha256((rule + "|" + "|".join(ids)).encode()).hexdigest()[:20],
        "rule_id": rule, "rule": meta["name"], "severity": meta["severity"],
        "mitre": meta["mitre"], "reason": explanation,
        "ip": records[-1]["ip"], "timestamp": records[-1]["timestamp"],
        "event_ids": ids[:100], "confidence": "medium",
    }


def inspect(raw_text: str) -> dict[str, Any]:
    if not isinstance(raw_text, str):
        raise ValueError("Log input must be text")
    lines = [(i, row.strip()) for i, row in enumerate(raw_text.splitlines(), 1) if row.strip()]
    if not lines:
        raise ValueError("No events to analyze")
    if len(lines) > MAX_LINES:
        raise ValueError(f"Maximum {MAX_LINES} log lines")
    if any(len(row) > MAX_LINE for _, row in lines):
        raise ValueError(f"Maximum {MAX_LINE} characters per line")
    events = [normalize(row, i) for i, row in lines]
    alerts: list[dict] = []
    for e in events:
        if any(t in WEB_PATTERNS for t in e["tags"]):
            alerts.append(_alert("WEB-001", [e], "Suspicious web payload: exploitation is not established."))
        if "audit_clear" in e["tags"]:
            alerts.append(_alert("WIN-001", [e], "Windows audit trail cleared (event 1102)."))
        if "ids_alert" in e["tags"]:
            alerts.append(_alert("IDS-001", [e], "Suricata IDS alert; inspect original signature and flow."))
        if 'encoded_powershell' in e['tags']:
            alerts.append(_alert('PROC-001', [e], 'Encoded PowerShell command line observed; legitimate automation is possible. Review parent process and script content.'))
        if 'account_created' in e['tags']:
            alerts.append(_alert('WIN-002', [e], 'Account creation (4720); verify change approval and the creating account.'))
        if 'task_created' in e['tags']:
            alerts.append(_alert('WIN-003', [e], 'Scheduled task creation (4698); review task XML, executable and author.'))
        for tag, rule, reason in [
            ('account_lockout', 'WIN-004', 'Account lockout (4740); investigate authentication history.'),
            ('long_dns_label', 'DNS-001', 'DNS label of 50 or more characters; tunneling is not established.'),
            ('wazuh_alert', 'END-001', 'Upstream Wazuh rule matched; inspect source rule and agent context.'),
            ('honeypot_login', 'HNY-001', 'Authentication recorded by an explicitly identified Cowrie honeypot.')]:
            if tag in e['tags']:
                alerts.append(_alert(rule, [e], reason))
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["ip"] and e["timestamp"]:
            by_ip[e["ip"]].append(e)
    for ip, records in by_ip.items():
        records.sort(key=lambda r: datetime.fromisoformat(r["timestamp"].replace('Z', '+00:00')))
        window: deque[dict] = deque()
        emitted: set[str] = set()
        for e in records:
            now = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            while window and now - datetime.fromisoformat(window[0]["timestamp"].replace("Z", "+00:00")) > timedelta(minutes=5):
                window.popleft()
            window.append(e)
            failures = [x for x in window if x["outcome"] == "failure" and x["action"] == "login"]
            logins = [x for x in window if x["action"] == "login"]
            users = {x["user"] for x in failures if x["user"]}
            port_events = [x for x in window if x["source"] in ("firewall", "suricata", "zeek") and x["port"]]
            ports = {x["port"] for x in port_events}
            web_events = [x for x in window if x["source"] == "web"]
            if len(failures) >= 10 and "AUTH-001" not in emitted:
                alerts.append(_alert("AUTH-001", failures, f"{len(failures)} failed authentications from {ip} within 5 minutes."))
                emitted.add("AUTH-001")
            if len(users) >= 5 and "AUTH-002" not in emitted:
                alerts.append(_alert("AUTH-002", failures, f"{len(users)} distinct targeted accounts from {ip} within 5 minutes."))
                emitted.add("AUTH-002")
            # Only failures that occur *before* successful authentication count.
            if e["action"] == "login" and e["outcome"] == "success" and len(failures) >= 3 and "AUTH-003" not in emitted:
                alerts.append(_alert("AUTH-003", failures[-3:] + [e], "Successful login after prior failures; investigate account and host."))
                emitted.add("AUTH-003")
            if len(ports) >= 10 and "NET-001" not in emitted:
                alerts.append(_alert("NET-001", port_events, f"{len(ports)} distinct destination ports in 5 minutes."))
                emitted.add("NET-001")
            if len(web_events) >= 100 and "WEB-002" not in emitted:
                alerts.append(_alert("WEB-002", web_events[-100:], "Unusually many web requests from one source in 5 minutes."))
                emitted.add("WEB-002")
    levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    event_levels = {}
    for alert in alerts:
        for event_id in alert['event_ids']:
            previous = event_levels.get(event_id)
            if previous is None or levels[alert['severity']] > levels[previous]:
                event_levels[event_id] = alert['severity']
    for e in events:
        e['severity'] = event_levels.get(e['event_id'])
    counts = Counter(e["source"] for e in events)
    severities = {a["severity"] for a in alerts}
    risk = "critical" if "critical" in severities else "high" if "high" in severities else "medium" if alerts else "low"
    return {
        "schema_version": "5.0", "sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
        "events": events, "alerts": alerts, "total": len(events), "sources": dict(counts),
        "unknown_timestamps": sum(e["timestamp"] is None for e in events),
        "risk": risk, "rules_checked": len(RULES),
        "limitations": ["Indicators are not proof of compromise.",
                        "Unknown timestamps are excluded from temporal correlation.",
                        "No live threat intelligence or external AI is used."]
    }
