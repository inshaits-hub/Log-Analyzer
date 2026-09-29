#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_cli.sh - start the standalone CLI (no web server needed).
#
#   ./run_cli.sh                          analyze samples/demo.log, both reports
#   ./run_cli.sh -l /var/log/auth.log      any CLI flags pass straight through
#   ./run_cli.sh -l a.log b.log --export json -o /tmp/out
#
# Uses .venv when present, otherwise whatever python3 is on PATH.
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

# Default to the shipped capture so a bare ./run_cli.sh - and any invocation
# that omits an explicit input - does something useful.
has_log=0
for arg in "$@"; do
    case "$arg" in
        -l|--log) has_log=1 ;;
        --log=*|--log*) has_log=1 ;;
    esac
done
if [[ $has_log -eq 0 ]]; then
    set -- --log samples/demo.log "$@"
fi

echo "[info] using $PYTHON ($("$PYTHON" --version 2>&1))"
exec "$PYTHON" src/main.py "$@"
