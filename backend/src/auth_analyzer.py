"""Core Module 2 - Authentication security analytics.

Pure-Python aggregation over the normalized events produced by
:mod:`log_parser`:

* success vs. failure ratios per source IP and per target username,
* high-risk target account flagging (``root``, ``admin``, ``system``, ...),
* dynamic IP -> username attempt relationships,
* active session time windows (events grouped by inactivity gaps).

``auth.log`` reports one physical login attempt as two lines (``Invalid user``
followed by ``Failed password for invalid user ...``), so ``failure_events``
collapses those pairs before anything is counted.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

try:  # package import (``from src import auth_analyzer``)
    from .log_parser import event_time
except ImportError:  # script import (``python src/main.py``)
    from log_parser import event_time

AUTH_ACTIONS = frozenset(
    {
        "ssh_login_success",
        "ssh_login_failure",
        "ssh_invalid_user",
        "ssh_auth_failure",
        "ssh_session_opened",
        "ssh_disconnect",
    }
)
FAILURE_ACTIONS = frozenset(
    {"ssh_login_failure", "ssh_invalid_user", "ssh_auth_failure"}
)
SUCCESS_ACTIONS = frozenset({"ssh_login_success"})

SENSITIVE_ACCOUNTS = frozenset(
    {
        "root",
        "admin",
        "administrator",
        "system",
        "oracle",
        "postgres",
        "mysql",
        "pi",
        "ubuntu",
        "test",
        "guest",
        "backup",
        "webmaster",
        "support",
    }
)

#: Idle gap that closes an active session window.
SESSION_GAP_SECONDS = 300
#: Two failure lines inside this window are treated as the same attempt.
FAILURE_PAIR_WINDOW_SECONDS = 10
#: Failures required before an ordinary account is flagged as high-risk.
DEFAULT_MIN_FAILURES = 3
#: Failures that make any account high-risk regardless of name.
ALERT_FAILURES = 10


def failure_events(events: Iterable[Dict]) -> List[Dict]:
    """Failed attempts with duplicate ``Invalid user``/``Failed password`` pairs
    for the same source IP + username collapsed into a single failure."""
    failures: List[Dict] = []
    last_seen: Dict[Tuple, Tuple[Optional[datetime], str, int]] = {}

    for index, event in enumerate(events):
        action = event.get("action")
        if action not in FAILURE_ACTIONS:
            continue

        key = (event.get("ip"), event.get("user"))
        moment = event_time(event)
        previous = last_seen.get(key)

        if previous is not None:
            previous_moment, previous_action, previous_index = previous
            if moment is not None and previous_moment is not None:
                close = (
                    abs((moment - previous_moment).total_seconds())
                    <= FAILURE_PAIR_WINDOW_SECONDS
                )
            else:
                # No timestamps: only consider near-adjacent lines.
                close = index - previous_index <= 2

            if close and {action, previous_action} == {
                "ssh_invalid_user",
                "ssh_login_failure",
            }:
                continue  # same attempt, reported twice by sshd

        failures.append(event)
        last_seen[key] = (moment, action, index)

    return failures


def _iso(moment: Optional[datetime], fallback) -> Optional[str]:
    if isinstance(moment, datetime):
        return moment.isoformat(sep=" ")
    return fallback


def analyze_authentication(
    parsed_events: Iterable[Dict],
    sensitive_accounts: Optional[Iterable[str]] = None,
    min_failures: int = DEFAULT_MIN_FAILURES,
) -> Dict:
    """Aggregate authentication posture across normalized events."""
    events = [e for e in parsed_events if e.get("action") in AUTH_ACTIONS]
    failure_ids = {id(e) for e in failure_events(events)}
    sensitive = {a.lower() for a in (sensitive_accounts or SENSITIVE_ACCOUNTS)}

    per_ip: Dict[str, Dict] = {}
    per_user: Dict[str, Dict] = {}
    ip_user_map: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(dict)
    ip_timeline: Dict[str, List[Tuple[Optional[datetime], int, Dict]]] = defaultdict(
        list
    )

    successful = 0
    failed = 0

    for index, event in enumerate(events):
        ip = event.get("ip")
        user = event.get("user")
        action = event.get("action")
        moment = event_time(event)
        is_failure = id(event) in failure_ids
        is_success = action in SUCCESS_ACTIONS

        if is_failure:
            failed += 1
        elif is_success:
            successful += 1

        if ip:
            bucket = per_ip.setdefault(
                ip,
                {
                    "ip": ip,
                    "success": 0,
                    "failure": 0,
                    "total": 0,
                    "success_ratio": 0.0,
                    "first_seen": None,
                    "last_seen": None,
                    "window_seconds": 0,
                },
            )
            bucket["total"] += 1
            if is_failure:
                bucket["failure"] += 1
            elif is_success:
                bucket["success"] += 1
            if moment is not None:
                if bucket["first_seen"] is None or moment < bucket["first_seen"]:
                    bucket["first_seen"] = moment
                if bucket["last_seen"] is None or moment > bucket["last_seen"]:
                    bucket["last_seen"] = moment

            ip_timeline[ip].append((moment, index, event))

            if user:
                relation = ip_user_map[ip].setdefault(
                    user, {"attempts": 0, "failures": 0, "successes": 0}
                )
                relation["attempts"] += 1
                if is_failure:
                    relation["failures"] += 1
                elif is_success:
                    relation["successes"] += 1

        if user:
            target = per_user.setdefault(
                user,
                {
                    "user": user,
                    "attempts": 0,
                    "failures": 0,
                    "successes": 0,
                    "ips": set(),
                },
            )
            target["attempts"] += 1
            if is_failure:
                target["failures"] += 1
            elif is_success:
                target["successes"] += 1
            if ip:
                target["ips"].add(ip)

    # ------------------------------------------------------------------ ratios
    for bucket in per_ip.values():
        settled = bucket["success"] + bucket["failure"]
        bucket["success_ratio"] = round(bucket["success"] / settled, 3) if settled else 0.0
        if bucket["first_seen"] and bucket["last_seen"]:
            bucket["window_seconds"] = int(
                (bucket["last_seen"] - bucket["first_seen"]).total_seconds()
            )
        bucket["first_seen"] = _iso(bucket["first_seen"], None)
        bucket["last_seen"] = _iso(bucket["last_seen"], None)

    by_user = {
        name: {
            "user": data["user"],
            "attempts": data["attempts"],
            "failures": data["failures"],
            "successes": data["successes"],
            "targeted_by_ips": sorted(data["ips"]),
        }
        for name, data in sorted(per_user.items())
    }
    for entry in by_user.values():
        settled = entry["successes"] + entry["failures"]
        entry["success_ratio"] = (
            round(entry["successes"] / settled, 3) if settled else 0.0
        )

    # ------------------------------------------------------- high-risk targets
    high_risk: List[Dict] = []
    for user, target in per_user.items():
        reasons: List[str] = []
        ips = sorted(target["ips"])
        if user.lower() in sensitive and target["failures"] >= min_failures:
            reasons.append(
                f"{target['failures']} failed attempts against a sensitive account"
            )
        if user.lower() in sensitive and len(ips) >= 3:
            reasons.append(f"targeted by {len(ips)} distinct source IPs")
        if target["failures"] >= ALERT_FAILURES:
            reasons.append(f"{target['failures']} failed attempts overall")
        if reasons:
            high_risk.append(
                {
                    "user": user,
                    "attempts": target["attempts"],
                    "failures": target["failures"],
                    "successes": target["successes"],
                    "targeted_by_ips": ips,
                    "reasons": reasons,
                }
            )
    high_risk.sort(key=lambda item: (-item["failures"], item["user"]))

    # ------------------------------------------------- active session windows
    sessions: List[Dict] = []
    for ip, items in ip_timeline.items():
        current: Optional[Dict] = None
        for moment, _index, event in sorted(items, key=lambda entry: entry[1]):
            gap = None
            if current is not None and moment is not None and current["_last"]:
                gap = (moment - current["_last"]).total_seconds()
            if current is None or (gap is not None and gap > SESSION_GAP_SECONDS):
                current = {
                    "ip": ip,
                    "_first": moment,
                    "_last": moment,
                    "attempts": 0,
                    "users": set(),
                }
                sessions.append(current)
            if moment is not None:
                if current["_first"] is None:
                    current["_first"] = moment
                current["_last"] = moment
            current["attempts"] += 1
            if event.get("user"):
                current["users"].add(event["user"])

    normalized_sessions = []
    for session in sessions:
        first = session["_first"]
        last = session["_last"]
        normalized_sessions.append(
            {
                "ip": session["ip"],
                "first_seen": _iso(first, None),
                "last_seen": _iso(last, None),
                "duration_seconds": (
                    int((last - first).total_seconds())
                    if isinstance(first, datetime) and isinstance(last, datetime)
                    else 0
                ),
                "attempts": session["attempts"],
                "users": sorted(session["users"]),
            }
        )
    normalized_sessions.sort(key=lambda s: (s["ip"], s["first_seen"] or ""))

    settled = successful + failed
    return {
        "total_auth_events": len(events),
        "successful_logins": successful,
        "failed_logins": failed,
        "success_rate": round(successful / settled, 3) if settled else 0.0,
        "unique_ips": len(per_ip),
        "unique_users": len(per_user),
        "by_ip": dict(sorted(per_ip.items())),
        "by_user": by_user,
        "ip_user_map": {ip: dict(users) for ip, users in sorted(ip_user_map.items())},
        "high_risk_accounts": high_risk,
        "sessions": normalized_sessions,
    }
