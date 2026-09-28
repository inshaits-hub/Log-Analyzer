"""Shared pytest fixtures for the backend test-suite."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def demo_log_path() -> Path:
    return ROOT / "samples" / "demo.log"


@pytest.fixture
def auth_lines():
    """auth.log style lines: 1 success, 3 deduplicated failures, 1 PAM failure."""
    return [
        "Sep 28 09:12:01 web01 sshd[2145]: Accepted password for alice from 10.0.0.15 port 51124 ssh2",
        "Sep 28 09:13:10 web01 sshd[2146]: Failed password for root from 203.0.113.9 port 50100 ssh2",
        "Sep 28 09:13:20 web01 sshd[2147]: Invalid user oracle from 203.0.113.9 port 50101",
        "Sep 28 09:13:20 web01 sshd[2147]: Failed password for invalid user oracle from 203.0.113.9 port 50101 ssh2",
        "Sep 28 09:14:00 web01 sshd[2148]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.21  user=deploy",
        "Sep 28 09:15:12 web01 sudo: pam_unix(sudo:session): session opened for user root by alice(uid=1000)",
    ]


@pytest.fixture
def web_lines():
    return [
        '203.0.113.60 - - [28/Sep/2026:02:14:07 +0000] "GET /index.php?id=1%20UNION%20SELECT%20username%20FROM%20users HTTP/1.1" 404 162 "-" "sqlmap/1.7.2"',
        '203.0.113.60 - - [28/Sep/2026:02:14:09 +0000] "GET /login.php?user=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 981 "-" "sqlmap/1.7.2"',
        '203.0.113.60 - - [28/Sep/2026:02:14:12 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '203.0.113.60 - - [28/Sep/2026:02:14:15 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 128 "-" "curl/8.4.0"',
        '10.0.0.15 - - [28/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '10.0.0.15 - - [28/Sep/2026:12:00:03 +0000] "GET /assets/app.css HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
    ]


@pytest.fixture
def syslog_lines():
    return [
        "Sep 28 09:20:00 fw01 kernel: CPU temperature above threshold",
        "Sep 28 09:21:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=22 WINDOW=1024",
        "Sep 28 09:30:00 web01 CRON[3001]: (root) CMD (/usr/lib/check-passwords.sh)",
    ]


@pytest.fixture
def mixed_lines(auth_lines, web_lines, syslog_lines):
    return auth_lines + web_lines + syslog_lines


@pytest.fixture
def mixed_events(mixed_lines):
    from src import log_parser

    return log_parser.parse_lines(mixed_lines)


@pytest.fixture
def brute_lines():
    """6 failed SSH logins from one IP inside 45s, then a successful login."""
    lines = []
    seconds = [5, 14, 23, 31, 40, 49]
    for index, second in enumerate(seconds):
        lines.append(
            f"Sep 28 09:13:{second:02d} web01 sshd[22{index:02d}]: Failed password "
            f"for root from 203.0.113.9 port {50100 + index} ssh2"
        )
    lines.append(
        "Sep 28 09:14:02 web01 sshd[2299]: Accepted password for root from "
        "203.0.113.9 port 50144 ssh2"
    )
    return lines


@pytest.fixture
def brute_events(brute_lines):
    from src import log_parser

    return log_parser.parse_lines(brute_lines)


@pytest.fixture
def clean_events():
    """Benign daytime traffic - must produce zero threats."""
    from src import log_parser

    lines = [
        '10.0.0.15 - - [28/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '10.0.0.15 - - [28/Sep/2026:12:00:03 +0000] "GET /assets/app.css HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '10.0.0.15 - - [28/Sep/2026:12:00:05 +0000] "POST /api/login HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        "Sep 28 12:01:00 web01 sshd[2301]: Accepted password for alice from 10.0.0.15 port 51200 ssh2",
    ]
    return log_parser.parse_lines(lines)


@pytest.fixture
def client(tmp_path):
    """Flask test client backed by a throwaway SQLite DB and reports folder."""
    from src.app import create_app

    application = create_app(
        db_path=tmp_path / "api.db", reports_dir=tmp_path / "reports"
    )
    application.config["TESTING"] = True
    return application.test_client()
