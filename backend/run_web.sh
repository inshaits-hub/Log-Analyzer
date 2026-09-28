#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_web.sh - start the Flask REST API consumed by the dashboard.
#
#   ./run_web.sh                 http://127.0.0.1:5000
#   HOST=0.0.0.0 PORT=8080 ./run_web.sh
#   ./run_web.sh --demo          seed the database first (36 events, 7 alerts)
#
# HOST/PORT/FLASK_ENV come from .env (see .env.example). This script forces
# FLASK_ENV=development so the local reloader and debugger are available; use
# the Dockerfile or export FLASK_ENV=production for anything shared.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [[ -x .venv/bin/python ]]; then
    PYTHON=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "[error] no python3 on PATH. Create a venv first: python3 -m venv .venv" >&2
    exit 1
fi

if [[ ! -f .env && ! -f .env.example ]]; then
    echo "[error] .env.example is missing, cannot infer defaults." >&2
    exit 1
fi
[[ -f .env ]] || cp .env.example .env

DEMO=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --demo) DEMO=1 ;;
        *)      ARGS+=("$arg") ;;
    esac
done

if [[ $DEMO -eq 1 ]]; then
    echo "[info] seeding the database from samples/demo.log ..."
    "$PYTHON" scripts/build_demo_db.py --fresh
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"

echo "[info] API      : http://${HOST}:${PORT}"
echo "[info] health   : curl http://${HOST}:${PORT}/api/v1/health"
echo "[info] summary  : curl http://${HOST}:${PORT}/api/v1/summary"
echo "[info] stopping : Ctrl+C"
echo

export FLASK_ENV="${FLASK_ENV:-development}"
# Note: never use "${ARGS[@]:-}" here - on an empty array that expands to a
# single empty-string argument, which would be passed through to app.py.
if [[ ${#ARGS[@]} -gt 0 ]]; then
    exec "$PYTHON" src/app.py "${ARGS[@]}"
fi
exec "$PYTHON" src/app.py
