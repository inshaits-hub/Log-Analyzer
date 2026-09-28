"""Core Module 3 - Heuristic threat engine.

Rule set
--------
1. **SSH brute-force** - more than ``threshold`` failed SSH logins from the
   same IP inside a rolling 60 second window, plus a CRITICAL rule for a
   successful login immediately after a burst.
2. **Web scans / exploits** - SQL injection, XSS and directory traversal
   patterns hidden in HTTP request targets (URL-decoded before matching).
3. **Anomalies** - requests-per-minute spikes and off-hour admin activity
   (00:00-05:59 admin paths / sensitive-account logins).
4. **Scans** - many distinct URL paths in a short window (content scan) and
   many distinct destination ports in firewall records (port scan).
5. **IP reputation** - every IP receives a dynamic 0-100 risk score derived
   from the cumulative severity of its flags plus attempt frequency.

The module is pure Python: no Flask, no database.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

try:  # package import
    from .auth_analyzer import FAILURE_ACTIONS, SENSITIVE_ACCOUNTS, failure_events
    from .log_parser import event_time
except ImportError:  # script import (``python src/main.py``)
    from auth_analyzer import FAILURE_ACTIONS, SENSITIVE_ACCOUNTS, failure_events
    from log_parser import event_time

BRUTE_FORCE_WINDOW_SECONDS = 60
DEFAULT_THRESHOLD = 5
DEFAULT_SPIKE_THRESHOLD = 60  # requests per minute
DEFAULT_WEB_SCAN_THRESHOLD = 20  # distinct paths per 60s
DEFAULT_PORT_SCAN_THRESHOLD = 10  # distinct destination ports per 60s
OFF_HOURS = range(0, 6)  # 00:00 - 05:59

ADMIN_PATH_RE = re.compile(
    r"^/(?:admin|wp-admin|wp-login|phpmyadmin|pma|manager|console|dashboard|"
    r"setup|install|config|server-status|actuator|\.env|\.git)",
    re.IGNORECASE,
)

EXPLOIT_PATTERNS: Dict[str, List["re.Pattern[str]"]] = {
    "SQL_INJECTION": [
        re.compile(r"union\s+(?:all\s+)?select", re.I),
        re.compile(r"or\s+'?1'?\s*=\s*'?1'?", re.I),
        re.compile(r"(?:'|\")\s*or\s+\d+\s*=\s*\d+", re.I),
        re.compile(r"information_schema", re.I),
        re.compile(r"\bsleep\s*\(\s*\d", re.I),
        re.compile(r"benchmark\s*\(", re.I),
        re.compile(r"\b(?:drop|truncate)\s+table\b", re.I),
        re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.I),
    ],
    "XSS_ATTEMPT": [
        re.compile(r"<\s*script", re.I),
        re.compile(r"javascript\s*:", re.I),
        re.compile(r"\bon(?:error|load|click|mouseover|focus|submit)\s*=", re.I),
        re.compile(r"<\s*iframe", re.I),
        re.compile(r"alert\s*\(", re.I),
        re.compile(r"document\s*\.\s*cookie", re.I),
    ],
    "DIRECTORY_TRAVERSAL": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"/etc/(?:passwd|shadow|sudoers)"),
        re.compile(r"c:\\windows\\", re.I),
        re.compile(r"(?:^|/)(?:boot|win)\.ini"),
        re.compile(r"/proc/self/environ"),
    ],
}

SEVERITY_BY_EXPLOIT = {
    "SQL_INJECTION": "HIGH",
    "XSS_ATTEMPT": "MEDIUM",
    "DIRECTORY_TRAVERSAL": "HIGH",
}

EXPLOIT_LABEL = {
    "SQL_INJECTION": "SQL Injection",
    "XSS_ATTEMPT": "Cross-Site Scripting (XSS)",
    "DIRECTORY_TRAVERSAL": "Directory Traversal",
}

#: Contribution of each rule to an IP's cumulative reputation score.
RULE_WEIGHTS = {
    "SSH_BRUTE_FORCE": 35,
    "SSH_BRUTE_FORCE_SUCCESS": 45,
    "SQL_INJECTION": 30,
    "DIRECTORY_TRAVERSAL": 25,
    "XSS_ATTEMPT": 15,
    "WEB_DIRECTORY_SCAN": 20,
    "PORT_SCAN": 30,
    "TRAFFIC_SPIKE": 15,
    "OFF_HOUR_ADMIN": 10,
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _timeline(events: Iterable[Dict]) -> List[Tuple[Dict, datetime]]:
    """Pair each event with a monotonic datetime.

    Events without a parseable timestamp fall back to +1s steps so window
    algorithms still behave deterministically on header-less captures.
    """
    timeline: List[Tuple[Dict, datetime]] = []
    last: Optional[datetime] = None
    for index, event in enumerate(events):
        moment = event_time(event)
        if moment is None:
            moment = (
                last + timedelta(seconds=1)
                if last is not None
                else datetime(1970, 1, 1) + timedelta(seconds=index)
            )
        last = moment
        timeline.append((event, moment))
    return timeline


def _threat(kind: str, ip, severity: str, details: str, moment: datetime) -> Dict:
    return {
        "type": kind,
        "ip": ip,
        "severity": severity,
        "details": details,
        "timestamp": moment.isoformat(sep=" ") if isinstance(moment, datetime) else str(moment),
        "risk_score": 0,
    }


def matched_exploit(event: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(category, matched_text)`` if the request carries an attack pattern."""
    if event.get("log_type") != "web":
        return None, None
    decoded = unquote(event.get("path") or "")
    for category, patterns in EXPLOIT_PATTERNS.items():
        for pattern in patterns:
            found = pattern.search(decoded)
            if found:
                return category, found.group(0)
    return None, None


# --------------------------------------------------------------------------- #
# Rule 1: SSH brute-force
# --------------------------------------------------------------------------- #
def _detect_brute_force(timeline, threshold: int) -> List[Dict]:
    window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
    failures_by_ip: Dict[str, List[Tuple[datetime, Dict]]] = defaultdict(list)
    for event, moment in timeline:
        if event.get("action") in FAILURE_ACTIONS and event.get("ip"):
            failures_by_ip[event["ip"]].append((moment, event))

    threats: List[Dict] = []
    bursts_by_ip: Dict[str, List[Tuple[datetime, datetime, int]]] = defaultdict(list)

    for ip, items in failures_by_ip.items():
        items.sort(key=lambda pair: pair[0])
        start = 0
        last_alerted = -1
        for end in range(len(items)):
            while items[end][0] - items[start][0] > window:
                start += 1
            count = end - start + 1
            if count > threshold and start > last_alerted:
                segment = items[start : end + 1]
                users = Counter(
                    (event.get("user") or "?") for _moment, event in segment
                )
                top_users = ", ".join(name for name, _ in users.most_common(3))
                severity = (
                    "CRITICAL" if count >= max(threshold * 3, threshold + 5) else "HIGH"
                )
                details = (
                    f"{count} failed SSH login attempts from {ip} within "
                    f"{BRUTE_FORCE_WINDOW_SECONDS}s (threshold: >{threshold}); "
                    f"most targeted users: {top_users}"
                )
                threats.append(
                    _threat("SSH_BRUTE_FORCE", ip, severity, details, segment[0][0])
                )
                bursts_by_ip[ip].append((segment[0][0], segment[-1][0], count))
                last_alerted = end

    # A successful login right after a burst means the attack worked.
    for event, moment in timeline:
        if event.get("action") != "ssh_login_success" or not event.get("ip"):
            continue
        for _first, last, count in bursts_by_ip.get(event["ip"], []):
            if last <= moment <= last + window:
                threats.append(
                    _threat(
                        "SSH_BRUTE_FORCE_SUCCESS",
                        event["ip"],
                        "CRITICAL",
                        f"Successful SSH login for '{event.get('user') or '?'}' from "
                        f"{event['ip']} within {BRUTE_FORCE_WINDOW_SECONDS}s of "
                        f"{count} failed attempts",
                        moment,
                    )
                )
                break

    return threats


# --------------------------------------------------------------------------- #
# Rule 2: web exploits
# --------------------------------------------------------------------------- #
def _detect_web_exploits(timeline) -> List[Dict]:
    threats: List[Dict] = []
    for event, moment in timeline:
        if event.get("log_type") != "web" or not event.get("ip"):
            continue
        category, match = matched_exploit(event)
        if category is None:
            continue
        target = unquote(event.get("path") or "")[:120]
        details = (
            f"{EXPLOIT_LABEL[category]} attempt (matched '{match}') in "
            f"{event.get('method') or 'HTTP'} {target} "
            f"[status {event.get('status_code')}]"
        )
        threats.append(
            _threat(
                category,
                event["ip"],
                SEVERITY_BY_EXPLOIT[category],
                details,
                moment,
            )
        )
    return threats


# --------------------------------------------------------------------------- #
# Rule 3: anomalies (traffic spikes + off-hour admin activity)
# --------------------------------------------------------------------------- #
def _detect_anomalies(timeline, spike_threshold: int) -> List[Dict]:
    threats: List[Dict] = []

    buckets: Counter = Counter()
    for event, moment in timeline:
        if event.get("log_type") == "web" and event.get("ip"):
            buckets[(event["ip"], moment.replace(second=0, microsecond=0))] += 1
    for (ip, minute), count in sorted(buckets.items()):
        if count > spike_threshold:
            severity = "HIGH" if count > spike_threshold * 3 else "MEDIUM"
            threats.append(
                _threat(
                    "TRAFFIC_SPIKE",
                    ip,
                    severity,
                    f"{count} HTTP requests in a single minute from {ip} "
                    f"(threshold: {spike_threshold}/min)",
                    minute,
                )
            )

    for event, moment in timeline:
        if moment.hour not in OFF_HOURS:
            continue
        ip = event.get("ip")
        if not ip:
            continue
        if event.get("log_type") == "web":
            path = event.get("path") or ""
            if ADMIN_PATH_RE.match(path):
                threats.append(
                    _threat(
                        "OFF_HOUR_ADMIN",
                        ip,
                        "MEDIUM",
                        f"Admin-path request to {path[:100]} at {moment:%H:%M} "
                        f"from {ip}",
                        moment,
                    )
                )
        elif event.get("action") == "ssh_login_success":
            user = (event.get("user") or "").lower()
            if user in SENSITIVE_ACCOUNTS:
                threats.append(
                    _threat(
                        "OFF_HOUR_ADMIN",
                        ip,
                        "MEDIUM",
                        f"Off-hour successful login for sensitive account "
                        f"'{event.get('user')}' at {moment:%H:%M} from {ip}",
                        moment,
                    )
                )
    return threats


# --------------------------------------------------------------------------- #
# Rule 4: scans
# --------------------------------------------------------------------------- #
def _detect_scans(timeline, web_threshold: int, port_threshold: int) -> List[Dict]:
    threats: List[Dict] = []
    window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)

    paths_by_ip: Dict[str, List[Tuple[datetime, Dict]]] = defaultdict(list)
    ports_by_ip: Dict[str, List[Tuple[datetime, Dict]]] = defaultdict(list)
    for event, moment in timeline:
        ip = event.get("ip")
        if not ip:
            continue
        if event.get("log_type") == "web" and event.get("path"):
            paths_by_ip[ip].append((moment, event))
        elif event.get("action") == "firewall_block" and event.get("dst_port"):
            ports_by_ip[ip].append((moment, event))

    for ip, items in paths_by_ip.items():
        items.sort(key=lambda pair: pair[0])
        start = 0
        last_alerted = -1
        for end in range(len(items)):
            while items[end][0] - items[start][0] > window:
                start += 1
            distinct = len({event.get("path") for _m, event in items[start : end + 1]})
            if distinct > web_threshold and start > last_alerted:
                severity = "HIGH" if distinct > web_threshold * 3 else "MEDIUM"
                threats.append(
                    _threat(
                        "WEB_DIRECTORY_SCAN",
                        ip,
                        severity,
                        f"{distinct} distinct URL paths requested from {ip} within "
                        f"{BRUTE_FORCE_WINDOW_SECONDS}s (content/scan activity)",
                        items[start][0],
                    )
                )
                last_alerted = end

    for ip, items in ports_by_ip.items():
        items.sort(key=lambda pair: pair[0])
        start = 0
        last_alerted = -1
        for end in range(len(items)):
            while items[end][0] - items[start][0] > window:
                start += 1
            distinct = len(
                {event.get("dst_port") for _m, event in items[start : end + 1]}
            )
            if distinct > port_threshold and start > last_alerted:
                threats.append(
                    _threat(
                        "PORT_SCAN",
                        ip,
                        "HIGH",
                        f"{distinct} distinct destination ports probed from {ip} "
                        f"within {BRUTE_FORCE_WINDOW_SECONDS}s",
                        items[start][0],
                    )
                )
                last_alerted = end

    return threats


# --------------------------------------------------------------------------- #
# Rule 5: IP reputation scoring (0 - 100)
# --------------------------------------------------------------------------- #
def compute_ip_risk_scores(events: Iterable[Dict], threats: Iterable[Dict]) -> Dict[str, int]:
    """Dynamic per-IP risk score: cumulative flag severity + attempt frequency.

    * each distinct rule type fired for an IP adds its weight (repeats of the
      same rule do not stack),
    * failed logins add up to +25,
    * requests carrying exploit patterns add up to +15,
    * the final score is clamped to 0-100.
    """
    events = list(events)
    threats = list(threats)

    weighted: Dict[Tuple[str, str], int] = {}
    for threat in threats:
        ip = threat.get("ip")
        if not ip:
            continue
        key = (ip, threat.get("type"))
        weighted[key] = max(
            weighted.get(key, 0), RULE_WEIGHTS.get(threat.get("type"), 10)
        )

    base: Counter = Counter()
    for (ip, _kind), weight in weighted.items():
        base[ip] += weight

    failures: Counter = Counter()
    for event in failure_events(events):
        if event.get("ip"):
            failures[event["ip"]] += 1

    exploits: Counter = Counter()
    for event, _moment in _timeline(events):
        if matched_exploit(event)[0] is not None and event.get("ip"):
            exploits[event["ip"]] += 1

    scores: Dict[str, int] = {}
    for ip in set(base) | set(failures) | set(exploits):
        score = base[ip] + min(25, failures[ip] * 2) + min(15, exploits[ip])
        score = max(0, min(100, score))
        if score > 0:
            scores[ip] = score
    return scores


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def detect_threats(
    events: List[Dict],
    threshold: int = DEFAULT_THRESHOLD,
    spike_threshold: int = DEFAULT_SPIKE_THRESHOLD,
    web_scan_threshold: int = DEFAULT_WEB_SCAN_THRESHOLD,
    port_scan_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
) -> List[Dict]:
    """Run every heuristic rule over ``events``.

    Returns threat records shaped like::

        {'type': str, 'ip': str, 'severity': str, 'details': str,
         'timestamp': str, 'risk_score': int}

    sorted chronologically, where ``risk_score`` is the offending IP's
    reputation score (0-100).
    """
    timeline = _timeline(events)

    threats: List[Dict] = []
    threats.extend(_detect_brute_force(timeline, max(threshold, 0)))
    threats.extend(_detect_web_exploits(timeline))
    threats.extend(_detect_anomalies(timeline, spike_threshold))
    threats.extend(_detect_scans(timeline, web_scan_threshold, port_scan_threshold))

    scores = compute_ip_risk_scores(events, threats)
    for threat in threats:
        threat["risk_score"] = scores.get(threat.get("ip"), 0)

    threats.sort(key=lambda item: (item.get("timestamp") or "", item.get("type") or ""))
    return threats
