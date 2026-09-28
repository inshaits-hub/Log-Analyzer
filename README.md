# Insha — Cybersecurity Log Analyzer

Senior project: a log-analysis platform that ingests raw server logs, detects
threats with heuristic rules, and reports the results through both a REST API
and a standalone CLI.

- `backend/` — Flask REST API, heuristic threat engine, CLI, reports, tests
- `frontend/` — dashboard UI (not yet built)
- `index.html` — project landing page, module specs and the API contract

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

./run_web.sh --demo        # REST API on http://127.0.0.1:5000, seeded with demo data
./run_cli.sh               # or analyze from the terminal, no server needed
python -m pytest           # 90 tests
```

Or with Docker:

```bash
cd backend
docker compose up --build          # API on http://localhost:5000
docker compose run --rm cli        # one-shot CLI run
```

## Folder layout

```text
insha/
├── backend/                # see backend/README.md for the full map
│   ├── src/                # parser, analyzers, threat engine, alerts, reports, API, CLI
│   ├── tests/              # pytest suite
│   ├── samples/demo.log    # mixed auth.log + nginx + syslog capture
│   ├── scripts/            # demo database builder
│   ├── Dockerfile          # gunicorn image, non-root, HEALTHCHECK
│   └── run_cli.sh / run_web.sh
├── frontend/               # dashboard UI
├── index.html              # landing page + API contract
└── .gitignore
```

## API contract

The endpoints the dashboard consumes, all under `http://localhost:5000`:

| Method | Endpoint | Returns |
|--------|----------|---------|
| GET | `/api/v1/summary` | `{total_events, total_threats, critical_threats, unique_ips}` |
| POST | `/api/v1/upload` | multipart `file` → `{status, filename, parsed_events, threats_detected, ...}` |
| GET | `/api/v1/threats?ip=&severity=` | alert list with `badge`, `title`, `risk_score`, `attempts` |
| GET | `/api/v1/export/report?format=` | `html` or `json` report download |

Also available: `/api/v1/events`, `/api/v1/stats`, `/api/v1/health`.

## For team members

Read `backend/README.md` first — it documents every module, the threat rules,
the database schema and the configuration options. Secrets and local state
(`.env`, `instance/`, `reports/`, `.venv/`) stay out of Git via `.gitignore`.
