"""Pytest unit tests for report generation (src/report_generator.py)."""

import json
from pathlib import Path

import pytest

from src import report_generator
from src.alert_manager import process_alerts
from src.threat_detector import detect_threats


def _analysis(events):
    threats = detect_threats(events)
    alerts = process_alerts(threats)
    summary = report_generator.build_summary(parsed_events=events, threats=alerts)
    return summary, alerts


def test_build_summary_counts(mixed_events):
    summary, alerts = _analysis(mixed_events)

    assert summary["total_events"] == len(mixed_events)
    assert summary["total_threats"] == len(alerts)
    assert summary["critical_threats"] == sum(
        1 for alert in alerts if alert["severity"] == "CRITICAL"
    )
    assert summary["unique_ips"] == len(
        {event["ip"] for event in mixed_events if event.get("ip")}
    )
    assert summary["generated_at"]
    assert set(summary["severity_counts"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert summary["threat_types"]
    assert summary["top_risk_ips"]


def test_build_summary_from_counts():
    summary = report_generator.build_summary(
        threats=[],
        counts={
            "total_events": 42,
            "total_threats": 7,
            "critical_threats": 2,
            "unique_ips": 9,
        },
    )
    assert summary["total_events"] == 42
    assert summary["total_threats"] == 7
    assert summary["critical_threats"] == 2
    assert summary["unique_ips"] == 9
    assert summary["severity_counts"]["CRITICAL"] == 0


def test_generate_html_report(tmp_path, mixed_events):
    summary, alerts = _analysis(mixed_events)
    target = tmp_path / "reports" / "report.html"

    path = report_generator.generate_html_report(summary, alerts, str(target))

    assert path == str(target)
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "Cybersecurity Log Analysis" in text
    assert "Threat Severity Distribution" in text
    assert "Threat Type Breakdown" in text
    assert "Top Risk IPs" in text
    assert str(summary["total_events"]) in text
    for alert in alerts:
        assert alert["title"] in text or alert["type"] in text


def test_html_report_escapes_untrusted_content(tmp_path):
    threats = [
        {
            "type": "XSS_ATTEMPT",
            "ip": "1.1.1.1",
            "severity": "HIGH",
            "details": "payload <img src=x onerror=alert(1)> in GET /x",
            "timestamp": "2026-09-28 02:00:00",
            "risk_score": 70,
        }
    ]
    summary = report_generator.build_summary(
        threats=threats, counts={"total_events": 1, "unique_ips": 1}
    )
    target = tmp_path / "escape.html"

    report_generator.generate_html_report(summary, threats, str(target))
    text = target.read_text(encoding="utf-8")

    assert "<img src=x" not in text
    assert "&lt;img src=x" in text


def test_html_report_handles_empty_threat_list(tmp_path):
    summary = report_generator.build_summary(
        threats=[], counts={"total_events": 3, "unique_ips": 1}
    )
    target = tmp_path / "empty.html"

    report_generator.generate_html_report(summary, [], str(target))
    text = target.read_text(encoding="utf-8")

    assert "No threats detected" in text


def test_generate_json_report(tmp_path, mixed_events):
    summary, alerts = _analysis(mixed_events)
    target = tmp_path / "reports" / "report.json"

    path = report_generator.generate_json_report(summary, alerts, str(target))

    assert path == str(target)
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    assert set(payload) >= {"report", "summary", "statistics", "threats"}
    assert set(payload["summary"]) >= {
        "total_events",
        "total_threats",
        "critical_threats",
        "unique_ips",
    }
    assert payload["summary"]["total_events"] == len(mixed_events)
    assert payload["summary"]["total_threats"] == len(alerts)
    assert len(payload["threats"]) == len(alerts)
    assert payload["threats"][0]["badge"] in {"red", "orange", "yellow", "blue"}
    assert set(payload["statistics"]["severity_distribution"]) == {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }
    assert payload["report"]["generated_at"]


def test_generate_report_dispatch(tmp_path, mixed_events):
    summary, alerts = _analysis(mixed_events)

    html_path = report_generator.generate_report(summary, alerts, str(tmp_path), "html")
    json_path = report_generator.generate_report(summary, alerts, str(tmp_path), "json")

    assert html_path.endswith(".html") and Path(html_path).exists()
    assert json_path.endswith(".json") and Path(json_path).exists()

    with pytest.raises(ValueError):
        report_generator.generate_report(summary, alerts, str(tmp_path), "pdf")
