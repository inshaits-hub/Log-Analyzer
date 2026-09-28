"""Pytest integration tests for the Flask REST API (src/app.py)."""

import io
import json


def _upload(client, lines, filename="sample.log"):
    content = "\n".join(lines).encode("utf-8")
    return client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )


def test_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_summary_initially_zero(client):
    response = client.get("/api/v1/summary")
    assert response.status_code == 200
    assert response.get_json() == {
        "total_events": 0,
        "total_threats": 0,
        "critical_threats": 0,
        "unique_ips": 0,
    }


def test_upload_parses_detects_and_persists(client, auth_lines, web_lines):
    response = _upload(client, auth_lines + web_lines)
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "success"
    assert data["filename"] == "sample.log"
    assert data["parsed_events"] == len(auth_lines) + len(web_lines)
    assert data["threats_detected"] > 0

    summary = client.get("/api/v1/summary").get_json()
    assert summary["total_events"] == data["parsed_events"]
    assert summary["total_threats"] == data["threats_detected"]
    assert summary["unique_ips"] == 4

    threats = client.get("/api/v1/threats").get_json()
    assert len(threats) == data["threats_detected"]
    for threat in threats:
        assert {"type", "ip", "severity", "badge", "details"} <= set(threat)
        assert threat["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_upload_accumulates_across_files(client, auth_lines, web_lines):
    _upload(client, auth_lines)
    first = client.get("/api/v1/summary").get_json()
    _upload(client, web_lines)
    second = client.get("/api/v1/summary").get_json()

    assert second["total_events"] == first["total_events"] + len(web_lines)
    assert second["total_threats"] >= first["total_threats"]


def test_threats_filter_by_ip_and_severity(client, brute_lines):
    upload = _upload(client, brute_lines)
    assert upload.status_code == 200
    assert upload.get_json()["threats_detected"] >= 2

    everything = client.get("/api/v1/threats").get_json()
    assert len(everything) >= 2

    by_ip = client.get("/api/v1/threats?ip=203.0.113.9").get_json()
    assert by_ip and all(t["ip"] == "203.0.113.9" for t in by_ip)

    critical = client.get("/api/v1/threats?severity=CRITICAL").get_json()
    assert critical and all(t["severity"] == "CRITICAL" for t in critical)

    medium_alias = client.get("/api/v1/threats?severity=MED").get_json()
    assert isinstance(medium_alias, list)
    assert all(t["severity"] == "MEDIUM" for t in medium_alias)

    high = client.get("/api/v1/threats?severity=HIGH").get_json()
    assert all(t["severity"] == "HIGH" for t in high)


def test_threats_invalid_severity_rejected(client):
    response = client.get("/api/v1/threats?severity=NOPE")
    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_export_report_html(client, auth_lines):
    _upload(client, auth_lines)
    response = client.get("/api/v1/export/report?format=html")

    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/html")
    assert "attachment" in response.headers["Content-Disposition"]
    assert b"<!DOCTYPE html>" in response.data
    assert b"Cybersecurity Log Analysis" in response.data


def test_export_report_json(client, auth_lines, web_lines):
    _upload(client, auth_lines + web_lines)
    response = client.get("/api/v1/export/report?format=json")

    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    payload = json.loads(response.data)
    assert payload["report"]["format"] == "json"
    assert payload["summary"]["total_events"] == len(auth_lines) + len(web_lines)
    assert len(payload["threats"]) == payload["summary"]["total_threats"]


def test_export_rejects_unknown_format(client):
    response = client.get("/api/v1/export/report?format=pdf")
    assert response.status_code == 400


def test_upload_requires_file_field(client):
    response = client.post("/api/v1/upload", data={})
    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_upload_rejects_unsupported_extension(client):
    response = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO(b"MZ..."), "malware.exe")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "Unsupported" in response.get_json()["message"]


def test_upload_rejects_empty_file(client):
    response = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO(b""), "empty.log")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_events_endpoint(client, auth_lines):
    _upload(client, auth_lines)
    data = client.get("/api/v1/events").get_json()

    assert data["count"] == len(auth_lines)
    assert data["events"][0]["raw_line"]


def test_stats_endpoint(client, brute_lines):
    _upload(client, brute_lines)
    data = client.get("/api/v1/stats").get_json()

    assert data["severity_counts"]["CRITICAL"] >= 1
    assert data["top_risk_ips"]
    assert data["top_risk_ips"][0]["ip"] == "203.0.113.9"
    assert data["recent_summaries"]


def test_cors_headers_present(client):
    response = client.get("/api/v1/summary")
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_unknown_endpoint_returns_json_404(client):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["status"] == "error"
