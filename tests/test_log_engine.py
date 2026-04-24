"""Unit tests for log_engine.py"""
import pytest
from datetime import datetime
from log_engine import (
    parse_logs,
    analyze_logs,
    build_report,
    detect_attack_tags,
    _anomaly_detection,
    _risk_level,
    _build_correlations,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_apache(ip="1.2.3.4", hour=10, status=200, path="/index"):
    ts = f"21/Apr/2026:{str(hour).zfill(2)}:00:00 +0300"
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 1024'


def _make_auth(ip="1.2.3.4", action="Failed", hour=10):
    ts = f"Apr 21 {str(hour).zfill(2)}:00:00"
    return f"{ts} srv01 sshd[100]: {action} password for invalid user root from {ip} port 22 ssh2"


def _make_firewall(ip="1.2.3.4", action="DROP", dpt=22):
    return f"KERNEL: {action} SRC={ip} DST=10.0.0.1 DPT={dpt} PROTO=TCP"


def _make_json(ip="1.2.3.4", status=200, message="ok"):
    import json
    return json.dumps({"ip": ip, "status": status, "message": message, "endpoint": "/api/test"})


# ── Parser Tests ──────────────────────────────────────────────────────────────

class TestParseApache:
    def test_basic_200(self):
        logs = parse_logs(_make_apache())
        assert len(logs) == 1
        assert logs[0].source == "web"
        assert logs[0].status == 200
        assert logs[0].ip == "1.2.3.4"

    def test_401_login_path(self):
        line = _make_apache(path="/login", status=401)
        logs = parse_logs(line)
        assert logs[0].login_failed is True

    def test_200_not_failed(self):
        logs = parse_logs(_make_apache(status=200))
        assert logs[0].login_failed is False

    def test_ip_extracted(self):
        logs = parse_logs(_make_apache(ip="203.0.113.50"))
        assert logs[0].ip == "203.0.113.50"


class TestParseAuth:
    def test_failed_password(self):
        logs = parse_logs(_make_auth(action="Failed"))
        assert logs[0].login_failed is True
        assert logs[0].status == 401

    def test_accepted_password(self):
        logs = parse_logs(_make_auth(action="Accepted"))
        assert logs[0].login_failed is False
        assert logs[0].status == 200

    def test_source_is_auth(self):
        logs = parse_logs(_make_auth())
        assert logs[0].source == "auth"


class TestParseFirewall:
    def test_drop(self):
        logs = parse_logs(_make_firewall(action="DROP"))
        assert logs[0].source == "firewall"
        assert logs[0].status == 403

    def test_accept(self):
        logs = parse_logs(_make_firewall(action="ACCEPT"))
        assert logs[0].status == 200

    def test_ip_and_port(self):
        logs = parse_logs(_make_firewall(ip="45.10.10.10", dpt=3306))
        assert logs[0].ip == "45.10.10.10"
        assert "3306" in logs[0].request


class TestParseJson:
    def test_json_source(self):
        logs = parse_logs(_make_json())
        assert logs[0].source == "json"

    def test_json_status(self):
        logs = parse_logs(_make_json(status=401))
        assert logs[0].status == 401

    def test_json_failed_login_message(self):
        logs = parse_logs(_make_json(message="auth fail"))
        assert logs[0].login_failed is True


class TestParseMultiline:
    def test_mixed_sources(self):
        raw = "\n".join([
            _make_apache(),
            _make_auth(),
            _make_firewall(),
            _make_json(),
        ])
        logs = parse_logs(raw)
        assert len(logs) == 4
        sources = {l.source for l in logs}
        assert sources == {"web", "auth", "firewall", "json"}

    def test_empty_input(self):
        assert parse_logs("") == []

    def test_blank_lines_ignored(self):
        raw = "\n\n" + _make_apache() + "\n\n"
        logs = parse_logs(raw)
        assert len(logs) == 1


# ── Attack Tag Tests ──────────────────────────────────────────────────────────

class TestAttackTags:
    def test_sqli_union(self):
        assert "SQL Injection" in detect_attack_tags("GET /?id=1 UNION SELECT username,password FROM users--")

    def test_sqli_or1(self):
        assert "SQL Injection" in detect_attack_tags("search?q=admin' OR 1=1")

    def test_sqli_sleep(self):
        assert "SQL Injection" in detect_attack_tags("?id=1 AND SLEEP(5)")

    def test_sqli_information_schema(self):
        assert "SQL Injection" in detect_attack_tags("FROM information_schema.tables")

    def test_xss_script(self):
        assert "XSS" in detect_attack_tags("<script>alert(1)</script>")

    def test_xss_onerror(self):
        assert "XSS" in detect_attack_tags("<img src=x onerror=alert(1)>")

    def test_xss_javascript(self):
        assert "XSS" in detect_attack_tags("href=javascript:void(0)")

    def test_traversal_dotdot(self):
        assert "Directory Traversal" in detect_attack_tags("GET /../../etc/passwd")

    def test_traversal_etc_passwd(self):
        assert "Directory Traversal" in detect_attack_tags("/etc/passwd")

    def test_traversal_win_ini(self):
        assert "Directory Traversal" in detect_attack_tags("../win.ini")

    def test_clean_line(self):
        assert detect_attack_tags("GET /index.html HTTP/1.1") == []

    def test_multiple_tags(self):
        tags = detect_attack_tags("?q=<script> UNION SELECT 1--")
        assert "SQL Injection" in tags
        assert "XSS" in tags


# ── Analyzer Tests ────────────────────────────────────────────────────────────

class TestAnalyzeLogs:
    def test_total_count(self):
        logs = parse_logs("\n".join([_make_apache() for _ in range(5)]))
        result = analyze_logs(logs)
        assert result["total"] == 5

    def test_failed_login_count(self):
        lines = "\n".join([_make_auth(action="Failed") for _ in range(3)])
        logs = parse_logs(lines)
        result = analyze_logs(logs)
        assert result["failed_login"] == 3

    def test_error_rate_all_errors(self):
        lines = "\n".join([_make_apache(status=500) for _ in range(4)])
        logs = parse_logs(lines)
        result = analyze_logs(logs)
        assert result["error_rate"] == 100.0

    def test_error_rate_no_errors(self):
        lines = "\n".join([_make_apache(status=200) for _ in range(4)])
        logs = parse_logs(lines)
        result = analyze_logs(logs)
        assert result["error_rate"] == 0.0

    def test_top_ip(self):
        lines = "\n".join([
            _make_apache(ip="1.1.1.1"),
            _make_apache(ip="1.1.1.1"),
            _make_apache(ip="2.2.2.2"),
        ])
        logs = parse_logs(lines)
        result = analyze_logs(logs)
        assert result["top_ip"] == "1.1.1.1"

    def test_brute_force_alert(self):
        """10+ failed logins from same IP → high alert."""
        lines = "\n".join([_make_auth(ip="9.9.9.9", action="Failed") for _ in range(12)])
        logs = parse_logs(lines)
        result = analyze_logs(logs)
        assert any("10 failed login" in a["reason"] for a in result["alerts"])

    def test_attack_alert_sqli(self):
        line = _make_apache(path="/?id=1 UNION SELECT username,password FROM users--")
        logs = parse_logs(line)
        result = analyze_logs(logs)
        assert any("SQL Injection" in a["reason"] for a in result["alerts"])

    def test_empty_logs(self):
        result = analyze_logs([])
        assert result["total"] == 0
        assert result["alerts"] == []
        assert result["risk"] == "low"

    def test_hourly_traffic_length(self):
        logs = parse_logs(_make_apache())
        result = analyze_logs(logs)
        assert len(result["hourly_traffic"]) == 24


# ── Risk Level Tests ──────────────────────────────────────────────────────────

class TestRiskLevel:
    def test_no_alerts_low(self):
        assert _risk_level([]) == "low"

    def test_one_high_medium(self):
        assert _risk_level([{"severity": "high"}]) == "medium"

    def test_three_high_is_high(self):
        alerts = [{"severity": "high"}] * 3
        assert _risk_level(alerts) == "high"

    def test_many_medium_alerts(self):
        alerts = [{"severity": "medium"}] * 5
        assert _risk_level(alerts) == "medium"


# ── Anomaly Detection Tests ───────────────────────────────────────────────────

class TestAnomalyDetection:
    def test_no_anomaly_flat(self):
        result = _anomaly_detection([10] * 24)
        assert result["anomalies"] == []

    def test_spike_detected(self):
        traffic = [5] * 24
        traffic[3] = 500  # massive spike at 3am
        result = _anomaly_detection(traffic)
        assert any(a["hour"] == 3 for a in result["anomalies"])

    def test_empty_returns_structure(self):
        result = _anomaly_detection([])
        assert "anomalies" in result
        assert result["method"] == "z-score"

    def test_all_zeros(self):
        result = _anomaly_detection([0] * 24)
        assert result["anomalies"] == []


# ── Correlation Tests ─────────────────────────────────────────────────────────

class TestCorrelation:
    def test_scan_then_login_detected(self):
        lines = "\n".join([
            _make_apache(ip="7.7.7.7", path="/wp-admin"),
            _make_auth(ip="7.7.7.7", action="Failed"),
            _make_auth(ip="7.7.7.7", action="Failed"),
            _make_auth(ip="7.7.7.7", action="Failed"),
        ])
        logs = parse_logs(lines)
        correlations = _build_correlations(logs)
        assert any("7.7.7.7" in c for c in correlations)

    def test_no_scan_no_correlation(self):
        lines = "\n".join([_make_apache(ip="8.8.8.8") for _ in range(5)])
        logs = parse_logs(lines)
        assert _build_correlations(logs) == []


# ── Report Tests ──────────────────────────────────────────────────────────────

class TestBuildReport:
    def setup_method(self):
        logs = parse_logs("\n".join([
            _make_apache(ip="1.1.1.1"),
            _make_auth(action="Failed"),
        ]))
        self.analysis = analyze_logs(logs)

    def test_daily_report_header(self):
        report = build_report(self.analysis, report_type="Daily")
        assert "Daily Security Report" in report

    def test_weekly_report_header(self):
        report = build_report(self.analysis, report_type="Weekly")
        assert "Weekly Security Report" in report

    def test_report_contains_totals(self):
        report = build_report(self.analysis)
        assert "Total logs:" in report
        assert "Risk level:" in report

    def test_report_recommendations(self):
        report = build_report(self.analysis)
        assert "Recommendations:" in report
