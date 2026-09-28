"""Pytest unit tests for regex parsing (src/log_parser.py)."""

from datetime import datetime

import pytest

from src import log_parser


# --------------------------------------------------------------------------- #
# auth.log
# --------------------------------------------------------------------------- #
def test_parse_accepted_password():
    line = (
        "Sep 28 09:12:01 web01 sshd[2145]: Accepted password for alice from "
        "10.0.0.15 port 51124 ssh2"
    )
    event = log_parser.parse_log_line(line)

    assert event is not None
    assert event["log_type"] == "auth"
    assert event["action"] == "ssh_login_success"
    assert event["ip"] == "10.0.0.15"
    assert event["user"] == "alice"
    assert event["status_code"] is None
    assert event["timestamp"] == "Sep 28 09:12:01"
    assert event["raw_line"] == line
    assert event["port"] == 51124
    assert event["host"] == "web01"


def test_parse_failed_password():
    line = (
        "Sep 28 09:13:10 web01 sshd[2146]: Failed password for root from "
        "203.0.113.9 port 50100 ssh2"
    )
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "auth"
    assert event["action"] == "ssh_login_failure"
    assert event["ip"] == "203.0.113.9"
    assert event["user"] == "root"


def test_parse_invalid_user():
    line = "Sep 28 09:13:20 web01 sshd[2147]: Invalid user oracle from 203.0.113.9 port 50101"
    event = log_parser.parse_log_line(line)

    assert event["action"] == "ssh_invalid_user"
    assert event["user"] == "oracle"
    assert event["ip"] == "203.0.113.9"


def test_parse_failed_password_for_invalid_user():
    line = (
        "Sep 28 09:13:20 web01 sshd[2147]: Failed password for invalid user oracle "
        "from 203.0.113.9 port 50101 ssh2"
    )
    event = log_parser.parse_log_line(line)

    assert event["action"] == "ssh_login_failure"
    assert event["user"] == "oracle"


def test_parse_pam_authentication_failure():
    line = (
        "Sep 28 09:14:00 web01 sshd[2148]: pam_unix(sshd:auth): authentication "
        "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.21  user=deploy"
    )
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "auth"
    assert event["action"] == "ssh_auth_failure"
    assert event["ip"] == "198.51.100.21"
    assert event["user"] == "deploy"


def test_parse_bare_line_without_syslog_header():
    line = "Failed password for root from 192.0.2.9 port 50022 ssh2"
    event = log_parser.parse_log_line(line)

    assert event is not None
    assert event["action"] == "ssh_login_failure"
    assert event["ip"] == "192.0.2.9"
    assert event["timestamp"] is None


# --------------------------------------------------------------------------- #
# Nginx / Apache access logs
# --------------------------------------------------------------------------- #
def test_parse_nginx_access_log():
    line = (
        '203.0.113.60 - - [28/Sep/2026:02:14:07 +0000] "GET /index.php?id=1 '
        'UNION SELECT username FROM users HTTP/1.1" 404 162 "-" "sqlmap/1.7.2"'
    )
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "web"
    assert event["action"] == "http_request"
    assert event["ip"] == "203.0.113.60"
    assert event["status_code"] == 404
    assert event["method"] == "GET"
    assert "UNION SELECT" in event["path"]
    assert event["timestamp"] == "28/Sep/2026:02:14:07 +0000"
    assert event["user_agent"] == "sqlmap/1.7.2"


def test_parse_apache_access_log():
    line = (
        '10.0.0.15 - - [28/Sep/2026:12:00:01 +0000] "POST /api/login HTTP/1.1" '
        '200 512 "https://example.test/login" "Mozilla/5.0"'
    )
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "web"
    assert event["status_code"] == 200
    assert event["method"] == "POST"
    assert event["path"] == "/api/login"
    assert event["referrer"] == "https://example.test/login"


def test_parse_web_line_without_referrer():
    line = '192.0.2.8 - - [28/Sep/2026:12:00:01 +0000] "GET /health HTTP/1.1" 200 2 "-"'
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "web"
    assert event["status_code"] == 200


# --------------------------------------------------------------------------- #
# Syslog
# --------------------------------------------------------------------------- #
def test_parse_generic_syslog():
    line = "Sep 28 09:20:00 fw01 kernel: CPU temperature above threshold"
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "syslog"
    assert event["action"] == "syslog_event"
    assert event["host"] == "fw01"
    assert event["process"] == "kernel"
    assert event["ip"] is None
    assert "thermal" in event["message"] or "temperature" in event["message"]


def test_parse_firewall_syslog_extracts_ip_and_port():
    line = (
        "Sep 28 09:21:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 "
        "SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=22 WINDOW=1024"
    )
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "syslog"
    assert event["action"] == "firewall_block"
    assert event["ip"] == "198.51.100.7"
    assert event["dst_port"] == 22


def test_parse_cron_syslog_line():
    line = "Sep 28 09:30:00 web01 CRON[3001]: (root) CMD (/usr/lib/check-passwords.sh)"
    event = log_parser.parse_log_line(line)

    assert event["log_type"] == "syslog"
    assert event["process"] == "CRON"
    assert event["pid"] == "3001"


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "\n",
        "this is not a log line at all",
        "2026-09-28 totally unrelated debug output",
    ],
)
def test_unparseable_lines_return_none(line):
    assert log_parser.parse_log_line(line) is None


def test_parse_text_and_parse_file_agree(tmp_path, mixed_lines):
    text = "\n".join(mixed_lines) + "\nnot a log line\n"
    target = tmp_path / "mixed.log"
    target.write_text(text, encoding="utf-8")

    from_text = log_parser.parse_text(text)
    from_file = log_parser.parse_file(str(target))

    assert from_text == from_file
    assert len(from_text) == len(mixed_lines)


def test_parse_file_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        log_parser.parse_file(str(tmp_path / "missing.log"))


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def test_parse_timestamp_web_format():
    moment = log_parser.parse_timestamp("28/Sep/2026:02:14:07 +0000")
    assert moment == datetime(2026, 9, 28, 2, 14, 7)


def test_parse_timestamp_syslog_format_injects_year():
    moment = log_parser.parse_timestamp("Sep 28 09:12:01", default_year=2026)
    assert moment == datetime(2026, 9, 28, 9, 12, 1)
    # ...and defaults to the current year when none is supplied
    assert log_parser.parse_timestamp("Sep 28 09:12:01").year == datetime.now().year


def test_parse_timestamp_iso_and_invalid():
    assert log_parser.parse_timestamp("2026-09-28T03:05:00") == datetime(
        2026, 9, 28, 3, 5, 0
    )
    assert log_parser.parse_timestamp("not-a-date") is None
    assert log_parser.parse_timestamp(None) is None
    assert log_parser.parse_timestamp("") is None


def test_event_time_helper():
    event = log_parser.parse_log_line(
        '10.0.0.1 - - [28/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 10 "-"'
    )
    assert log_parser.event_time(event) == datetime(2026, 9, 28, 12, 0, 1)
    assert log_parser.event_time({}) is None
