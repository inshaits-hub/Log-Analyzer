"""Pytest unit tests for threat detection, auth analytics and alert handling."""

from datetime import datetime, timedelta

from src import alert_manager, auth_analyzer, log_parser
from src.threat_detector import compute_ip_risk_scores, detect_threats

REQUIRED_KEYS = {"type", "ip", "severity", "details", "timestamp", "risk_score"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _types(threats):
    return {threat["type"] for threat in threats}


# --------------------------------------------------------------------------- #
# Rule 1: SSH brute-force
# --------------------------------------------------------------------------- #
def test_brute_force_triggers_above_threshold(brute_events):
    threats = detect_threats(brute_events, threshold=5)
    kinds = _types(threats)

    assert "SSH_BRUTE_FORCE" in kinds
    brute = next(t for t in threats if t["type"] == "SSH_BRUTE_FORCE")
    assert brute["ip"] == "203.0.113.9"
    assert brute["severity"] in {"HIGH", "CRITICAL"}
    assert "failed SSH login attempts" in brute["details"]
    assert brute["risk_score"] > 0


def test_brute_force_success_after_burst_is_critical(brute_events):
    threats = detect_threats(brute_events, threshold=5)
    success = [t for t in threats if t["type"] == "SSH_BRUTE_FORCE_SUCCESS"]

    assert success, "a successful login right after a burst must be flagged"
    assert success[0]["severity"] == "CRITICAL"
    assert "root" in success[0]["details"]


def test_no_brute_force_at_exact_threshold():
    """5 failures == threshold; the rule requires *more* than 5."""
    lines = [
        f"Sep 28 09:13:{10 + index * 7:02d} web01 sshd[2100]: Failed password for "
        f"root from 198.51.100.44 port {51000 + index} ssh2"
        for index in range(5)
    ]
    threats = detect_threats(log_parser.parse_lines(lines), threshold=5)
    assert "SSH_BRUTE_FORCE" not in _types(threats)


def test_no_brute_force_when_attempts_outside_window():
    """6 failures, but 30s apart -> never more than 3 inside 60s."""
    lines = []
    moment = datetime(2026, 9, 28, 9, 0, 0)
    for index in range(6):
        stamp = moment + timedelta(seconds=index * 30)
        lines.append(
            f"Sep 28 {stamp:%H:%M:%S} web01 sshd[2100]: Failed password for root "
            f"from 198.51.100.45 port {51000 + index} ssh2"
        )
    threats = detect_threats(log_parser.parse_lines(lines), threshold=5)
    assert "SSH_BRUTE_FORCE" not in _types(threats)


def test_threshold_is_configurable():
    lines = [
        f"Sep 28 09:13:{10 + index * 4:02d} web01 sshd[2100]: Failed password for "
        f"root from 198.51.100.46 port {51000 + index} ssh2"
        for index in range(3)
    ]
    events = log_parser.parse_lines(lines)

    assert "SSH_BRUTE_FORCE" in _types(detect_threats(events, threshold=2))
    assert "SSH_BRUTE_FORCE" not in _types(detect_threats(events, threshold=3))


# --------------------------------------------------------------------------- #
# Rule 2: web scans / exploits
# --------------------------------------------------------------------------- #
def test_sql_injection_detected(web_lines):
    threats = detect_threats(log_parser.parse_lines(web_lines))
    sqli = [t for t in threats if t["type"] == "SQL_INJECTION"]

    assert sqli, "UNION SELECT payload must be flagged"
    assert all(t["ip"] == "203.0.113.60" for t in sqli)
    assert all(t["severity"] in {"HIGH", "CRITICAL"} for t in sqli)
    assert all(t["risk_score"] > 0 for t in sqli)


def test_xss_detected(web_lines):
    threats = detect_threats(log_parser.parse_lines(web_lines))
    xss = [t for t in threats if t["type"] == "XSS_ATTEMPT"]

    assert xss, "<script> payload must be flagged"
    assert xss[0]["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert "<script>" in xss[0]["details"]


def test_directory_traversal_detected(web_lines):
    threats = detect_threats(log_parser.parse_lines(web_lines))
    traversal = [t for t in threats if t["type"] == "DIRECTORY_TRAVERSAL"]

    assert traversal, "../../etc/passwd payload must be flagged"
    assert traversal[0]["severity"] in {"HIGH", "CRITICAL"}


def test_clean_logs_produce_no_threats(clean_events):
    threats = detect_threats(clean_events, threshold=5)
    assert threats == []


def test_benign_login_failures_below_threshold_stay_quiet(clean_events, auth_lines):
    events = log_parser.parse_lines(auth_lines) + clean_events
    threats = detect_threats(events, threshold=5)
    assert "SSH_BRUTE_FORCE" not in _types(threats)


# --------------------------------------------------------------------------- #
# Rule 3: anomalies
# --------------------------------------------------------------------------- #
def test_request_spike_detected():
    lines = [
        f'198.51.100.50 - - [28/Sep/2026:15:00:{index % 60:02d} +0000] '
        f'"GET /p{index} HTTP/1.1" 200 512 "-" "curl/8.4.0"'
        for index in range(61)
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    spike = [t for t in threats if t["type"] == "TRAFFIC_SPIKE"]

    assert spike, "61 requests in one minute must exceed the 60/min threshold"
    assert spike[0]["ip"] == "198.51.100.50"
    assert spike[0]["severity"] in {"MEDIUM", "HIGH"}


def test_off_hour_admin_path_detected():
    lines = [
        '203.0.113.77 - - [28/Sep/2026:03:12:44 +0000] "GET /wp-admin/admin-ajax.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    off_hour = [t for t in threats if t["type"] == "OFF_HOUR_ADMIN"]

    assert off_hour, "03:12 wp-admin request must be flagged"
    assert off_hour[0]["severity"] == "MEDIUM"


def test_daytime_admin_path_not_flagged():
    lines = [
        '203.0.113.77 - - [28/Sep/2026:14:12:44 +0000] "GET /wp-admin/admin-ajax.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    assert "OFF_HOUR_ADMIN" not in _types(threats)


def test_off_hour_sensitive_login_detected():
    lines = [
        "Sep 28 03:20:00 web01 sshd[2999]: Accepted password for root from "
        "10.9.9.9 port 2222 ssh2"
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    off_hour = [t for t in threats if t["type"] == "OFF_HOUR_ADMIN"]

    assert off_hour, "03:20 root login must be flagged"
    assert "root" in off_hour[0]["details"]


# --------------------------------------------------------------------------- #
# Rule 4: scans
# --------------------------------------------------------------------------- #
def test_port_scan_detected():
    lines = []
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]):
        second = index * 4
        lines.append(
            f"Sep 28 09:25:{second:02d} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"MAC=00:11 SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP SPT=51{index:03d} "
            f"DPT={port} WINDOW=1024"
        )
    threats = detect_threats(log_parser.parse_lines(lines))
    scans = [t for t in threats if t["type"] == "PORT_SCAN"]

    assert scans, "12 distinct destination ports inside 60s must be flagged"
    assert scans[0]["ip"] == "198.51.100.7"
    assert scans[0]["severity"] == "HIGH"


def test_web_directory_scan_detected():
    lines = [
        f'64.66.66.66 - - [28/Sep/2026:16:00:{index % 60:02d} +0000] '
        f'"GET /hidden/dir{index} HTTP/1.1" 404 123 "-" "scanner/1.0"'
        for index in range(21)
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    scans = [t for t in threats if t["type"] == "WEB_DIRECTORY_SCAN"]

    assert scans, "21 distinct paths inside 60s must be flagged"


# --------------------------------------------------------------------------- #
# Rule 5: risk scoring + record shape
# --------------------------------------------------------------------------- #
def test_threat_record_shape(brute_events, web_lines):
    events = brute_events + log_parser.parse_lines(web_lines)
    threats = detect_threats(events)

    assert threats, "expected at least one threat"
    for threat in threats:
        assert REQUIRED_KEYS <= set(threat)
        assert threat["severity"] in SEVERITIES
        assert 0 <= threat["risk_score"] <= 100
        assert log_parser.parse_timestamp(threat["timestamp"]) is not None
    # chronological output
    moments = [log_parser.parse_timestamp(t["timestamp"]) for t in threats]
    assert moments == sorted(moments)


def test_risk_scores_are_bounded_and_cumulative(brute_events, web_lines):
    events = brute_events + log_parser.parse_lines(web_lines)
    threats = detect_threats(events)
    scores = compute_ip_risk_scores(events, threats)

    assert scores, "flagged IPs must receive a score"
    for ip, score in scores.items():
        assert 0 <= score <= 100

    brute_ip = scores.get("203.0.113.9", 0)
    assert brute_ip >= 50, "brute-force + success must push the IP into high risk"
    # every emitted threat carries its IP's reputation score
    for threat in threats:
        assert threat["risk_score"] == scores.get(threat["ip"], 0)


def test_clean_events_have_no_risk_scores(clean_events):
    assert compute_ip_risk_scores(clean_events, []) == {}


def test_failures_below_threshold_still_raise_baseline_risk():
    lines = [
        f"Sep 28 09:13:{10 + index * 7:02d} web01 sshd[2100]: Failed password for "
        f"root from 203.0.2.99 port {51000 + index} ssh2"
        for index in range(3)
    ]
    events = log_parser.parse_lines(lines)
    scores = compute_ip_risk_scores(events, [])
    assert 0 < scores.get("203.0.2.99", 0) < 50


# --------------------------------------------------------------------------- #
# Module 2: authentication analytics
# --------------------------------------------------------------------------- #
def test_analyze_authentication_counts_and_ratios(auth_lines):
    events = log_parser.parse_lines(auth_lines)
    stats = auth_analyzer.analyze_authentication(events)

    assert stats["total_auth_events"] == len(auth_lines)
    assert stats["successful_logins"] == 1
    # Invalid user + Failed password for that user collapse into one attempt.
    assert stats["failed_logins"] == 3
    assert stats["success_rate"] == 0.25
    assert stats["unique_ips"] == 3
    assert stats["unique_users"] == 4

    attacker = stats["by_ip"]["203.0.113.9"]
    assert attacker["failure"] == 2
    assert attacker["success"] == 0
    assert attacker["success_ratio"] == 0.0

    # ratios are aggregated per target username as well (spec)
    assert stats["by_user"]["alice"]["success_ratio"] == 1.0
    assert stats["by_user"]["root"]["success_ratio"] == 0.0
    assert stats["by_user"]["deploy"]["success_ratio"] == 0.0


def test_analyze_authentication_flags_high_risk_root(brute_events):
    stats = auth_analyzer.analyze_authentication(brute_events)
    names = [account["user"] for account in stats["high_risk_accounts"]]

    assert "root" in names
    root = next(a for a in stats["high_risk_accounts"] if a["user"] == "root")
    assert root["failures"] >= 3
    assert "203.0.113.9" in root["targeted_by_ips"]
    assert root["reasons"]


def test_distributed_targeting_of_admin_is_flagged():
    lines = []
    for index, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
        lines.append(
            f"Sep 28 10:0{index}:00 web01 sshd[2100]: Failed password for admin "
            f"from {ip} port {52000 + index} ssh2"
        )
    stats = auth_analyzer.analyze_authentication(log_parser.parse_lines(lines))
    admin = next(
        (a for a in stats["high_risk_accounts"] if a["user"] == "admin"), None
    )

    assert admin is not None, "3 IPs targeting 'admin' must be flagged"
    assert len(admin["targeted_by_ips"]) == 3


def test_ip_to_username_mapping(auth_lines):
    stats = auth_analyzer.analyze_authentication(log_parser.parse_lines(auth_lines))

    mapping = stats["ip_user_map"]
    assert mapping["203.0.113.9"]["root"]["failures"] == 1
    assert mapping["10.0.0.15"]["alice"]["successes"] == 1
    assert mapping["198.51.100.21"]["deploy"]["failures"] == 1


def test_session_windows_group_by_inactivity_gap(auth_lines):
    events = log_parser.parse_lines(auth_lines)
    stats = auth_analyzer.analyze_authentication(events)

    sessions = stats["sessions"]
    assert sessions, "sessions must be derived"
    by_ip = {session["ip"]: session for session in sessions}
    window = by_ip["203.0.113.9"]
    assert window["attempts"] == 3
    assert window["duration_seconds"] == 10  # 09:13:10 -> 09:13:20
    assert "root" in window["users"] and "oracle" in window["users"]

    # A 10 minute gap splits one IP into two sessions.
    gap_lines = [
        "Sep 28 09:00:00 web01 sshd[2100]: Accepted password for alice from "
        "10.1.1.1 port 51111 ssh2",
        "Sep 28 09:12:00 web01 sshd[2101]: Accepted password for alice from "
        "10.1.1.1 port 51112 ssh2",
    ]
    gap_stats = auth_analyzer.analyze_authentication(log_parser.parse_lines(gap_lines))
    assert len(gap_stats["sessions"]) == 2


def test_failure_events_deduplicates_invalid_user_pairs(auth_lines):
    events = log_parser.parse_lines(auth_lines)
    failures = auth_analyzer.failure_events(events)
    pairs = [
        event
        for event in failures
        if event["user"] == "oracle"
    ]

    assert len(pairs) == 1, "one attempt is reported by two auth.log lines"
    assert len(failures) == 3


# --------------------------------------------------------------------------- #
# Module 4: alert management
# --------------------------------------------------------------------------- #
def _raw_threats():
    return [
        {
            "type": "SSH_BRUTE_FORCE",
            "ip": "1.2.3.4",
            "severity": "HIGH",
            "details": "6 failed SSH login attempts",
            "timestamp": "2026-09-28 09:13:05",
            "risk_score": 60,
        },
        {
            "type": "SSH_BRUTE_FORCE",
            "ip": "1.2.3.4",
            "severity": "CRITICAL",
            "details": "12 failed SSH login attempts",
            "timestamp": "2026-09-28 09:13:45",
            "risk_score": 75,
        },
        {
            "type": "SSH_BRUTE_FORCE",
            "ip": "1.2.3.4",
            "severity": "HIGH",
            "details": "6 failed SSH login attempts",
            "timestamp": "2026-09-28 09:30:00",
            "risk_score": 60,
        },
        {
            "type": "SQL_INJECTION",
            "ip": "9.9.9.9",
            "severity": "MED",
            "details": "UNION SELECT payload",
            "timestamp": "2026-09-28 10:00:00",
            "risk_score": 45,
        },
    ]


def test_alerts_are_deduplicated_within_overlapping_windows():
    alerts = alert_manager.process_alerts(_raw_threats())

    # 09:13:05 + 09:13:45 merge (40s apart); 09:30:00 stays separate.
    brute_alerts = [a for a in alerts if a["type"] == "SSH_BRUTE_FORCE"]
    assert len(brute_alerts) == 2

    merged = brute_alerts[0]
    assert merged["occurrences"] == 2
    assert merged["severity"] == "CRITICAL", "keep the highest severity"
    assert merged["risk_score"] == 75, "keep the highest risk score"
    assert merged["timestamp"] == "2026-09-28 09:13:05", "keep the first timestamp"
    assert "deduplicated" in merged["details"]


def test_severity_normalization_and_aliases():
    assert alert_manager.normalize_severity("med") == "MEDIUM"
    assert alert_manager.normalize_severity("MED") == "MEDIUM"
    assert alert_manager.normalize_severity("high") == "HIGH"
    assert alert_manager.normalize_severity("crit") == "CRITICAL"
    # derived from risk score when the label is missing/garbage
    assert alert_manager.normalize_severity(None, risk_score=90) == "CRITICAL"
    assert alert_manager.normalize_severity(None, risk_score=65) == "HIGH"
    assert alert_manager.normalize_severity(None, risk_score=40) == "MEDIUM"
    assert alert_manager.normalize_severity("garbage", risk_score=0) == "LOW"


def test_badge_colors():
    assert alert_manager.badge_for("CRITICAL") == "red"
    assert alert_manager.badge_for("HIGH") == "orange"
    assert alert_manager.badge_for("MEDIUM") == "yellow"
    assert alert_manager.badge_for("LOW") == "blue"
    assert alert_manager.badge_for("med") == "yellow"


def test_alerts_sorted_by_severity_then_risk():
    alerts = alert_manager.process_alerts(_raw_threats())
    ranks = [
        alert_manager.SEVERITY_RANK[alert["severity"]] for alert in alerts
    ]

    assert ranks == sorted(ranks)
    assert alerts[0]["severity"] == "CRITICAL"


def test_alert_payload_structure():
    alerts = alert_manager.process_alerts(_raw_threats())
    payload = alerts[0]["payload"]

    assert payload["rule"] == alerts[0]["type"]
    assert payload["severity"] == alerts[0]["severity"]
    assert payload["badge"] == alert_manager.badge_for(alerts[0]["severity"])
    assert payload["ip"] == alerts[0]["ip"]
    assert "window" in payload and "span_seconds" in payload["window"]
    assert alerts[0]["title"]
    assert alerts[0]["badge"] in {"red", "orange", "yellow", "blue"}


def test_severity_counts():
    counts = alert_manager.severity_counts(alert_manager.process_alerts(_raw_threats()))
    assert counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0}


def test_process_alerts_handles_empty_input():
    assert alert_manager.process_alerts([]) == []
    assert alert_manager.process_alerts(None) == []


def test_merging_alerts_sums_attempts_without_losing_any():
    """Deduplication must never drop attempt counts, only regroup them."""
    raw = [
        {
            "type": "SQL_INJECTION",
            "ip": "1.2.3.4",
            "severity": "HIGH",
            "details": "probe",
            "timestamp": "2026-09-28 09:13:05",
            "risk_score": 40,
            "attempts": 3,
        },
        {
            "type": "SQL_INJECTION",
            "ip": "1.2.3.4",
            "severity": "HIGH",
            "details": "probe",
            "timestamp": "2026-09-28 09:13:45",
            "risk_score": 40,
            "attempts": 4,
        },
        {
            "type": "SQL_INJECTION",
            "ip": "1.2.3.4",
            "severity": "HIGH",
            "details": "probe",
            "timestamp": "2026-09-28 09:30:00",  # far away: separate alert
            "risk_score": 40,
            "attempts": 5,
        },
    ]
    alerts = alert_manager.process_alerts(raw)

    assert len(alerts) == 2
    assert sorted(a["attempts"] for a in alerts) == [5, 7]
    assert sum(a["attempts"] for a in alerts) == sum(t["attempts"] for t in raw)
    # occurrences counts the merged threats; attempts counts the log events.
    merged = [a for a in alerts if a["occurrences"] == 2][0]
    assert merged["attempts"] == 7


def test_alert_attempts_falls_back_to_one():
    alerts = alert_manager.process_alerts(
        [
            {
                "type": "PORT_SCAN",
                "ip": "1.2.3.4",
                "severity": "HIGH",
                "details": "scan",
                "timestamp": "2026-09-28 09:13:05",
                "risk_score": 30,
            }
        ]
    )
    assert alerts[0]["attempts"] == 1
    assert alerts[0]["payload"]["attempts"] == 1

