"""Standalone CLI entry point - full analysis without Flask running.

Examples
--------
    python src/main.py --log /path/to/auth.log --export html
    python src/main.py --log samples/demo.log --export both --threshold 5
    python src/main.py --log a.log b.log --export json --output reports --no-save
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional

try:  # package import (``python -m src.main`` / pytest)
    from . import (
        alert_manager,
        auth_analyzer,
        database,
        log_parser,
        report_generator,
        threat_detector,
    )
except ImportError:  # script import (``python src/main.py``)
    import alert_manager
    import auth_analyzer
    import database
    import log_parser
    import report_generator
    import threat_detector

RULE_WIDTH = 76


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber-log-analyzer",
        description="Cybersecurity Log Analyzer - standalone CLI (no Flask needed).",
    )
    parser.add_argument(
        "--log",
        "-l",
        nargs="+",
        required=True,
        metavar="FILE",
        help="One or more log files (auth.log, nginx/apache access logs, syslog).",
    )
    parser.add_argument(
        "--export",
        choices=("html", "json", "both", "none"),
        default="both",
        help="Report format to generate: html, json, both or none (default: both).",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Report output directory (default: reports/).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=int(os.environ.get("ANALYSIS_THRESHOLD", "5")),
        help="Brute-force threshold: alert when failures exceed this within 60s "
        "(default: 5).",
    )
    parser.add_argument(
        "--db", default=None, help="SQLite path (default: DB_PATH from .env)."
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Skip writing results to the database.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of alerts to print (default: 10).",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only print generated report paths."
    )
    return parser


def _print_summary(
    files: List[str],
    events: List[dict],
    alerts: List[dict],
    summary: dict,
    auth_stats: dict,
    top: int,
) -> None:
    severity = summary.get("severity_counts", {})
    riskiest = (summary.get("top_risk_ips") or [{}])[0]

    print("=" * RULE_WIDTH)
    print("  CYBERSECURITY LOG ANALYZER - EXECUTIVE SUMMARY")
    print("=" * RULE_WIDTH)
    print(f"  Log files           : {', '.join(files)}")
    print(f"  Parsed events       : {summary.get('total_events', len(events))}")
    print(f"  Unique IPs          : {summary.get('unique_ips', 0)}")
    print(
        f"  Auth success/fail   : {auth_stats['successful_logins']}/"
        f"{auth_stats['failed_logins']} "
        f"(rate {auth_stats['success_rate']:.0%})"
    )
    print(
        f"  Threats detected    : {summary.get('total_threats', len(alerts))}  "
        f"(CRITICAL {severity.get('CRITICAL', 0)} | HIGH {severity.get('HIGH', 0)} | "
        f"MEDIUM {severity.get('MEDIUM', 0)} | LOW {severity.get('LOW', 0)})"
    )
    if riskiest.get("ip"):
        print(
            f"  Riskiest IP         : {riskiest['ip']} "
            f"({riskiest.get('risk_score', 0)}/100)"
        )
    if auth_stats["high_risk_accounts"]:
        names = ", ".join(
            account["user"] for account in auth_stats["high_risk_accounts"][:5]
        )
        print(f"  High-risk accounts  : {names}")

    print("-" * RULE_WIDTH)
    print(f"  TOP ALERTS (showing {min(top, len(alerts))} of {len(alerts)})")
    if not alerts:
        print("  No threats detected.")
    for alert in alerts[:top]:
        print(
            f"  [{alert['severity']:<8}] {alert['title']} - {alert['ip']} "
            f"(risk {alert['risk_score']})"
        )
        details = alert["details"]
        if len(details) > RULE_WIDTH - 8:
            details = details[: RULE_WIDTH - 11] + "..."
        print(f"      {details}")
    print("=" * RULE_WIDTH)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    events: List[dict] = []
    loaded: List[str] = []
    failures: List[str] = []
    for filepath in args.log:
        try:
            events.extend(log_parser.parse_file(filepath))
            loaded.append(filepath)
        except OSError as exc:
            failures.append(f"{filepath} ({exc.strerror or exc})")

    if failures:
        for failure in failures:
            print(f"[error] cannot read log file: {failure}", file=sys.stderr)
        if not loaded:
            return 1

    threats = threat_detector.detect_threats(events, threshold=args.threshold)
    alerts = alert_manager.process_alerts(threats)
    summary = report_generator.build_summary(events, alerts)
    auth_stats = auth_analyzer.analyze_authentication(events)

    if not args.no_save:
        if args.db:
            database.set_db_path(args.db)
        database.init_db()
        # Single transaction so logs/threats/summary stay consistent.
        conn = database.get_connection()
        try:
            database.insert_logs(events, conn=conn)
            database.insert_threats(alerts, conn=conn)
            database.save_summary(summary, conn=conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    if not args.quiet:
        _print_summary(loaded, events, alerts, summary, auth_stats, args.top)

    if args.export != "none":
        output_dir = database.resolve_path(
            args.output or os.environ.get("REPORTS_DIR", "reports")
        )
        basename = datetime.now().strftime("report_%Y%m%d_%H%M%S")
        formats = ("html", "json") if args.export == "both" else (args.export,)
        written = []
        for fmt in formats:
            written.append(
                report_generator.generate_report(
                    summary, alerts, output_dir=str(output_dir), fmt=fmt,
                    basename=basename,
                )
            )
        if args.quiet:
            for path in written:
                print(path)
        else:
            print("  Report(s) written:")
            for path in written:
                print(f"    {path}")
            print("=" * RULE_WIDTH)

    return 0


if __name__ == "__main__":
    sys.exit(main())
