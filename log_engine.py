import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

APACHE_REGEX = re.compile(r'^(\S+)\s+-\s+-\s+\[(.+?)\]\s+"(\S+)\s+(.+?)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+|-)')
AUTH_REGEX = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+(Failed|Accepted)\s+password.*from\s+(\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE,
)
FIREWALL_REGEX = re.compile(r'(DROP|ACCEPT).*(SRC=\d+\.\d+\.\d+\.\d+).*(DPT=\d+)', re.IGNORECASE)

SQLI_REGEX = re.compile(r'union\s+select|or\s+1=1|information_schema|sleep\(', re.IGNORECASE)
XSS_REGEX = re.compile(r'<script>|onerror=|javascript:', re.IGNORECASE)
TRAVERSAL_REGEX = re.compile(r'\.\.|/etc/passwd|win\.ini', re.IGNORECASE)

KNOWN_BAD_IP_REPUTATION = {
    '203.0.113.50': 92,
    '198.51.100.23': 85,
    '45.10.10.10': 88,
}


@dataclass
class ParsedLog:
    source: str
    raw: str
    ip: str
    timestamp: datetime
    request: str
    status: int
    login_failed: bool
    tags: List[str]


def parse_logs(raw_text: str) -> List[ParsedLog]:
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    parsed: List[ParsedLog] = []
    for line in lines:
        as_json = _safe_json_parse(line)
        if as_json is not None:
            parsed.append(_parse_json_line(line, as_json))
            continue

        apache = APACHE_REGEX.match(line)
        if apache:
            parsed.append(_parse_apache_line(line, apache))
            continue

        auth = AUTH_REGEX.match(line)
        if auth:
            parsed.append(_parse_auth_line(line, auth))
            continue

        fw = FIREWALL_REGEX.search(line)
        if fw:
            parsed.append(_parse_firewall_line(line, fw))
            continue

        parsed.append(
            ParsedLog(
                source='unknown',
                raw=line,
                ip=_extract_ip(line) or 'unknown',
                timestamp=datetime.now(UTC).replace(tzinfo=None),
                request=line[:80],
                status=500 if re.search(r'error|fail|denied', line, re.IGNORECASE) else 200,
                login_failed=bool(re.search(r'failed password|auth failed|invalid user', line, re.IGNORECASE)),
                tags=detect_attack_tags(line),
            )
        )
    return parsed


def analyze_logs(parsed_logs: List[ParsedLog]) -> Dict[str, Any]:
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_by_ip = Counter()
    hourly_traffic = [0] * 24
    alerts: List[Dict[str, Any]] = []

    error_count = 0
    failed_login = 0

    for log in parsed_logs:
        ip_counter[log.ip] += 1
        endpoint_counter[log.request] += 1
        hourly_traffic[log.timestamp.hour] += 1

        if log.status >= 400:
            error_count += 1

        if log.login_failed:
            failed_login += 1
            failed_by_ip[log.ip] += 1

        for tag in log.tags:
            alerts.append(
                {
                    'severity': 'high',
                    'reason': f'{tag} pattern detected',
                    'ip': log.ip,
                    'raw': log.raw,
                }
            )

    for ip, count in failed_by_ip.items():
        if count >= 10:
            alerts.append(
                {
                    'severity': 'high',
                    'reason': '10 failed login threshold exceeded',
                    'ip': ip,
                    'raw': f'Failed login count: {count}',
                }
            )

    for ip, count in ip_counter.items():
        if count >= 1000:
            alerts.append(
                {
                    'severity': 'high',
                    'reason': '1000 request/min threshold exceeded',
                    'ip': ip,
                    'raw': f'Request count: {count}',
                }
            )
        elif count >= 40:
            alerts.append(
                {
                    'severity': 'medium',
                    'reason': 'High request concentration from single IP',
                    'ip': ip,
                    'raw': f'Request count: {count}',
                }
            )

    night_traffic = sum(hourly_traffic[0:5])
    day_traffic = sum(hourly_traffic[8:22])
    if night_traffic > day_traffic * 0.45 and night_traffic > 5:
        alerts.append(
            {
                'severity': 'medium',
                'reason': 'Abnormal nighttime traffic',
                'ip': '-',
                'raw': f'Night traffic={night_traffic}, day traffic={day_traffic}',
            }
        )

    correlations = _build_correlations(parsed_logs)
    top_ips = ip_counter.most_common(10)
    top_endpoints = endpoint_counter.most_common(10)
    top_ip = top_ips[0][0] if top_ips else '-'
    error_rate = round((error_count / len(parsed_logs) * 100), 2) if parsed_logs else 0.0

    risk = _risk_level(alerts)
    reputation = _reputation_summary(top_ips)
    geo = _geo_summary(top_ips)
    anomaly = _anomaly_detection(hourly_traffic)

    return {
        'total': len(parsed_logs),
        'failed_login': failed_login,
        'error_rate': error_rate,
        'top_ip': top_ip,
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'top_endpoints': [{'endpoint': ep, 'count': count} for ep, count in top_endpoints],
        'alerts': alerts,
        'correlations': correlations,
        'hourly_traffic': hourly_traffic,
        'risk': risk,
        'ip_reputation': reputation,
        'geo_distribution': geo,
        'anomaly_detection': anomaly,
    }


def build_report(analysis: Dict[str, Any], report_type: str = 'Daily') -> str:
    lines = [
        f'{report_type} Security Report',
        '=' * 28,
        f"Total logs: {analysis.get('total', 0)}",
        f"Total alerts: {len(analysis.get('alerts', []))}",
        f"Failed login count: {analysis.get('failed_login', 0)}",
        f"Error rate: %{analysis.get('error_rate', 0)}",
        f"Risk level: {analysis.get('risk', 'low')}",
        f"Top IP: {analysis.get('top_ip', '-')}",
        '',
        'Suspicious IPs:',
    ]

    for row in analysis.get('top_ips', [])[:8]:
        lines.append(f"- {row['ip']} ({row['count']} requests)")

    lines.extend(['', 'Detected attack types:'])
    attack_types = sorted({a['reason'].split(' pattern')[0] for a in analysis.get('alerts', []) if 'pattern' in a['reason']})
    if attack_types:
        for attack in attack_types:
            lines.append(f'- {attack}')
    else:
        lines.append('- No signature-based attacks detected')

    lines.extend([
        '',
        'Recommendations:',
        '- Enforce MFA and strict lockout on login endpoints',
        '- Add WAF signatures for SQLi/XSS/traversal payloads',
        '- Use SIEM correlation rules for scan-then-auth patterns',
    ])

    return '\n'.join(lines)


def detect_attack_tags(text: str) -> List[str]:
    tags: List[str] = []
    if SQLI_REGEX.search(text):
        tags.append('SQL Injection')
    if XSS_REGEX.search(text):
        tags.append('XSS')
    if TRAVERSAL_REGEX.search(text):
        tags.append('Directory Traversal')
    return tags


def _safe_json_parse(line: str) -> Optional[Dict[str, Any]]:
    try:
        parsed = json.loads(line)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _parse_json_line(raw: str, payload: Dict[str, Any]) -> ParsedLog:
    msg = json.dumps(payload)
    timestamp = _parse_date_smart(str(payload.get('timestamp', '')))
    return ParsedLog(
        source='json',
        raw=raw,
        ip=str(payload.get('ip', 'unknown')),
        timestamp=timestamp,
        request=str(payload.get('endpoint', payload.get('message', 'api_event'))),
        status=int(payload.get('status', 200)),
        login_failed=bool(re.search(r'failed login|auth fail', msg, re.IGNORECASE)),
        tags=detect_attack_tags(msg),
    )


def _parse_apache_line(raw: str, match: re.Match[str]) -> ParsedLog:
    method = match.group(3)
    endpoint = match.group(4)
    status = int(match.group(5))
    timestamp = _parse_date_smart(match.group(2))
    return ParsedLog(
        source='web',
        raw=raw,
        ip=match.group(1),
        timestamp=timestamp,
        request=f'{method} {endpoint}',
        status=status,
        login_failed=(status == 401 and 'login' in endpoint.lower()),
        tags=detect_attack_tags(raw),
    )


def _parse_auth_line(raw: str, match: re.Match[str]) -> ParsedLog:
    status_text = match.group(3).lower()
    is_failed = status_text == 'failed'
    return ParsedLog(
        source='auth',
        raw=raw,
        ip=match.group(4),
        timestamp=_parse_date_smart(match.group(1)),
        request='AUTH_FAILED' if is_failed else 'AUTH_SUCCESS',
        status=401 if is_failed else 200,
        login_failed=is_failed,
        tags=detect_attack_tags(raw),
    )


def _parse_firewall_line(raw: str, match: re.Match[str]) -> ParsedLog:
    action = match.group(1).upper()
    ip = match.group(2).replace('SRC=', '')
    dpt = match.group(3).replace('DPT=', '')
    return ParsedLog(
        source='firewall',
        raw=raw,
        ip=ip,
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        request=f'PORT:{dpt}',
        status=403 if action == 'DROP' else 200,
        login_failed=False,
        tags=detect_attack_tags(raw),
    )


def _parse_date_smart(value: str) -> datetime:
    value = value.strip()
    formats = [
        '%d/%b/%Y:%H:%M:%S %z',
        '%b %d %H:%M:%S %Y',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is not None:
                return dt.astimezone().replace(tzinfo=None)
            return dt
        except ValueError:
            continue

    if re.match(r'^\w+\s+\d+\s+\d+:\d+:\d+$', value):
        current_year = datetime.now(UTC).year
        try:
            return datetime.strptime(f'{value} {current_year}', '%b %d %H:%M:%S %Y')
        except ValueError:
            pass

    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
    except ValueError:
        return datetime.now(UTC).replace(tzinfo=None)


def _extract_ip(text: str) -> Optional[str]:
    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
    return m.group(1) if m else None


def _build_correlations(parsed_logs: List[ParsedLog]) -> List[str]:
    by_ip: Dict[str, List[ParsedLog]] = defaultdict(list)
    for log in parsed_logs:
        by_ip[log.ip].append(log)

    scenarios: List[str] = []
    for ip, logs in by_ip.items():
        has_scan = any(re.search(r'wp-admin|phpmyadmin|\.\.', l.raw, re.IGNORECASE) for l in logs)
        failed_logins = sum(1 for l in logs if l.login_failed)
        if has_scan and failed_logins >= 3:
            scenarios.append(f'IP {ip}: scan then login attempts scenario detected')
    return scenarios


def _risk_level(alerts: List[Dict[str, Any]]) -> str:
    high = sum(1 for a in alerts if a.get('severity') == 'high')
    if high >= 3:
        return 'high'
    if high >= 1 or len(alerts) >= 3:
        return 'medium'
    return 'low'


def _reputation_summary(top_ips: List[Any]) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []
    for ip, count in top_ips[:8]:
        score = KNOWN_BAD_IP_REPUTATION.get(ip, 15)
        level = 'malicious' if score >= 80 else ('suspicious' if score >= 50 else 'clean')
        summary.append({'ip': ip, 'score': score, 'level': level, 'requests': count})
    return summary


def _geo_summary(top_ips: List[Any]) -> List[Dict[str, Any]]:
    country_counter = Counter()
    for ip, _ in top_ips:
        country_counter[_ip_country(ip)] += 1
    return [{'country': c, 'count': n} for c, n in country_counter.items()]


def _ip_country(ip: str) -> str:
    try:
        obj = ip_address(ip)
        if obj.is_private:
            return 'Private Network'
    except ValueError:
        return 'Unknown'

    first = int(ip.split('.')[0]) if ip and ip[0].isdigit() else 0
    if first < 64:
        return 'US'
    if first < 128:
        return 'EU'
    if first < 192:
        return 'APAC'
    return 'MENA'


def _anomaly_detection(hourly: List[int]) -> Dict[str, Any]:
    if not hourly:
        return {'method': 'z-score', 'anomalies': []}

    avg = sum(hourly) / len(hourly)
    variance = sum((x - avg) ** 2 for x in hourly) / len(hourly)
    std = math.sqrt(variance)
    anomalies = []

    if std == 0:
        return {'method': 'z-score', 'anomalies': anomalies}

    for hour, value in enumerate(hourly):
        z = (value - avg) / std
        if z >= 2.2:
            anomalies.append({'hour': hour, 'value': value, 'z_score': round(z, 2)})

    return {'method': 'z-score', 'anomalies': anomalies, 'avg': round(avg, 2), 'std': round(std, 2)}
