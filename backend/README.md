# Cybersecurity Log Analyzer — Backend

Production-ready backend for the CS senior project. It ingests raw log files,
normalizes them with regex, runs a heuristic threat engine over the events,
prioritizes the resulting alerts, stores everything in SQLite and serves both
a REST API and a standalone CLI that writes executive HTML/JSON reports.

The **core analysis modules are pure Python** (no Flask, no DB imports), so the
same pipeline runs from `main.py`, `app.py` or pytest without modification.

---

## 1. Setup

```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

Dependencies: `Flask` (API) and `pytest` (tests). Everything else is stdlib.

## 2. Project structure

```
backend/
├── .env                    # DB_PATH, REPORTS_DIR, thresholds, bind host/port
├── requirements.txt
├── pytest.ini              # testpaths = tests
├── reports/                # generated HTML/JSON executive reports
├── samples/demo.log        # mixed auth.log + nginx + syslog capture
├── tests/
│   ├── conftest.py         # shared fixtures (sample logs, Flask test client)
│   ├── test_parser.py      # regex parsing unit tests
│   ├── test_threats.py     # threat rules, auth analytics, alert handling
│   ├── test_reports.py     # HTML/JSON report tests
│   ├── test_api.py         # REST API integration tests
│   └── test_cli.py         # end-to-end CLI tests
└── src/
    ├── app.py              # Flask REST API controller
    ├── main.py             # standalone CLI entry point
    ├── database.py         # SQLite connection, schema, queries (+ .env loader)
    ├── log_parser.py       # Core 1: regex log ingestion
    ├── auth_analyzer.py    # Core 2: authentication security analytics
    ├── threat_detector.py  # Core 3: heuristic threat engine + IP risk scoring
    ├── alert_manager.py    # Core 4: alert prioritization & badging
    └── report_generator.py # Core 5: HTML/JSON executive reporting
```

## 3. CLI (no server required)

```bash
python src/main.py --log samples/demo.log --export html
python src/main.py --log a.log b.log --export both --threshold 3
python src/main.py --log capture.log --export json --output reports --no-save -q
```

| Flag | Meaning |
|------|---------|
| `--log/-l` | one or more log files (auth.log, nginx/apache access, syslog) |
| `--export` | `html`, `json`, `both` (default) or `none` |
| `--output/-o` | report folder (default `reports/`) |
| `--threshold` | brute-force trigger: alert when failures **exceed** N in 60s (default 5) |
| `--db` | SQLite path (default `DB_PATH` from `.env`) |
| `--no-save` | analyze without writing to the database |
| `--top` | number of alerts printed (default 10) |
| `--quiet/-q` | print only report paths |

Typical output:

```
============================================================================
  CYBERSECURITY LOG ANALYZER - EXECUTIVE SUMMARY
============================================================================
  Parsed events       : 36
  Threats detected    : 7  (CRITICAL 1 | HIGH 4 | MEDIUM 2 | LOW 0)
  Riskiest IP         : 203.0.113.45 (92/100)
  High-risk accounts  : root
----------------------------------------------------------------------------
  TOP ALERTS (showing 7 of 7)
  [CRITICAL] Successful Brute-Force Login - 203.0.113.45 (risk 92)
  [HIGH    ] SSH Brute-Force Attack - 203.0.113.45 (risk 92)
  ...
============================================================================
  Report(s) written:
    reports/report_20260928_145113.html
```

## 4. REST API

```bash
python src/app.py            # http://localhost:5000  (HOST/PORT come from .env)
```

> **Deployment note:** `.env` ships `FLASK_ENV=development`, which enables
> debug mode (reloader + interactive Werkzeug debugger). That is intended for
> local use on `127.0.0.1`. If you change `HOST` so other machines can reach
> the API, also set `FLASK_ENV=production` — never expose the debugger.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/summary` | `{total_events, total_threats, critical_threats, unique_ips}` |
| POST | `/api/v1/upload` | multipart `file` (`.log`/`.txt`) → parse → detect → store |
| GET | `/api/v1/threats?ip=&severity=` | stored alerts (`severity=CRITICAL\|HIGH\|MED\|MEDIUM\|LOW`) |
| GET | `/api/v1/export/report?format=` | `html` or `json`, served as a download from `reports/` |
| GET | `/api/v1/events?limit=&ip=` | recent parsed events (live table) |
| GET | `/api/v1/stats` | severity distribution, top risk IPs, upload history |
| GET | `/api/v1/health` | service/DB status |

```bash
curl http://localhost:5000/api/v1/summary
curl -F "file=@samples/demo.log" http://localhost:5000/api/v1/upload
curl "http://localhost:5000/api/v1/threats?ip=203.0.113.45"
curl "http://localhost:5000/api/v1/threats?severity=CRITICAL"
curl "http://localhost:5000/api/v1/export/report?format=html" -o report.html
```

CORS is open (`Access-Control-Allow-Origin: *`) so a separate frontend can call
the API directly. Uploads are capped by `MAX_UPLOAD_MB` (default 16 MB) and
validated for the `.log`/`.txt` extension.

## 5. Threat rules (Core Module 3)

| Rule | Trigger | Severity |
|------|---------|----------|
| `SSH_BRUTE_FORCE` | >5 failed SSH logins from one IP inside 60s | HIGH (CRITICAL at volume) |
| `SSH_BRUTE_FORCE_SUCCESS` | successful login within 60s after a burst | CRITICAL |
| `SQL_INJECTION` | `UNION SELECT`, `' OR '1'='1`, `information_schema`, `sleep()`, ... | HIGH |
| `XSS_ATTEMPT` | `<script`, `javascript:`, `onerror=`, `document.cookie`, ... | MEDIUM |
| `DIRECTORY_TRAVERSAL` | `../`, `..\`, `/etc/passwd`, `win.ini`, ... | HIGH |
| `TRAFFIC_SPIKE` | >60 requests/min from one IP | MEDIUM/HIGH |
| `OFF_HOUR_ADMIN` | 00:00–05:59 admin paths (`/admin`, `/wp-admin`, `/phpmyadmin`, ...) or sensitive-account logins | MEDIUM |
| `WEB_DIRECTORY_SCAN` | >20 distinct URL paths in 60s | MEDIUM/HIGH |
| `PORT_SCAN` | >10 distinct destination ports in firewall records within 60s | HIGH |

**IP reputation:** every IP gets a 0–100 score = cumulative rule weights
(brute force 35, brute-force success 45, SQLi 30, traversal 25, port scan 30,
XSS 15, spike 15, scan 20, off-hour 10; a rule type counts once per IP) plus a
frequency bonus for failed logins (≤+25) and exploit attempts (≤+15), clamped
to 100.

**Badges** (`alert_manager.py`): `CRITICAL → red`, `HIGH → orange`,
`MEDIUM → yellow`, `LOW → blue`. Redundant alerts for the same IP + rule inside
overlapping 120s windows are merged into one alert with an `occurrences` count,
the highest severity/risk seen, and a structured `payload` for the frontend.

## 6. Database (SQLite)

Auto-initialized by `init_db()`; path from `DB_PATH` (default
`backend/instance/logs.db`).

```sql
logs     (id, timestamp, ip, user, action, log_type, raw_line)
threats  (id, type, ip, severity, details, timestamp, risk_score)
summary  (id, total_events, total_threats, critical_threats, unique_ips, created_at)
```

`GET /api/v1/summary` computes live aggregates from `logs`/`threats`;
`summary` keeps a per-upload snapshot for history.

## 7. Supported log formats (Core Module 1)

1. **Linux `auth.log`** — `Accepted password`, `Failed password`,
   `Invalid user`, PAM `authentication failure`, `session opened` (syslog
   framed or bare `sshd[...]` lines).
2. **Nginx / Apache** — Combined Log Format, including raw-space request
   targets and missing referrer/agent fields.
3. **Syslog** — `timestamp host process[pid]: message`, incl. `UFW BLOCK`/
   `iptables` records where `SRC=`/`DPT=` become the event's IP and
   destination port.

`parse_log_line()` returns `None` for anything unrecognized; `auth.log`'s
two-line attempt reports (`Invalid user` + `Failed password for invalid user`)
are collapsed into a single failure before counting.

## 8. Tests

```bash
cd backend
python -m pytest            # 84 tests
python -m pytest tests/test_threats.py -k brute -v
```

Coverage: regex parsing (all three formats + malformed input), brute-force
threshold/window boundaries, SQLi/XSS/traversal payloads, spike/off-hour/scan
rules, risk-score bounds, auth ratios/high-risk accounts/session windows,
alert deduplication + badge colors, report rendering (incl. HTML escaping),
every REST endpoint (upload, filters, exports, validation errors) and the CLI
end-to-end.

## 9. Configuration (`.env`)

```
DB_PATH=instance/logs.db     # SQLite location (relative to backend/)
REPORTS_DIR=reports          # generated reports
MAX_UPLOAD_MB=16             # POST /api/v1/upload cap
ANALYSIS_THRESHOLD=5         # brute-force rule threshold
HOST=127.0.0.1  PORT=5000    # API bind address
SECRET_KEY=...               # Flask secret
```

## 10. Notes for team members

* Backend only — no frontend/design files belong here.
* Core modules are import-safe: `from src import threat_detector` works from
  anywhere, and every module also runs as a plain script (`python src/main.py`).
* Alert objects from `/api/v1/threats` already carry `badge`, `title` and
  `severity`, so the UI can render chips without extra mapping.
