#!/usr/bin/env bash
# Baseline controls. Every instance must pass before a hunt track starts.
set -euo pipefail
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HARNESS_DIR/env.sh"

ID="${1:?usage: selftest.sh <ID>}"
read -r DATA_PORT ADMIN_PORT ORIGIN_PORT <<<"$(port_for "$ID")"
DIR="$AU_ROOT/$ID"
JAR="$DIR/cookies.json"

fail=0
say() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }

# C1: SQLi must be blocked and never reach the origin.
code=$(curl --noproxy "*" -s -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
  "http://127.0.0.1:$DATA_PORT/?q=1%20or%201%3D1--" || true)
if [[ "$code" == "403" ]] || [[ "$code" == "406" ]] || [[ "$code" == "451" ]] || [[ "$code" == "503" ]]; then
  say PASS C1 "sqli blocked ($code)"
else
  say FAIL C1 "sqli returned $code"; fail=1
fi
if grep -q '1%20or%201%3D1--\|1 or 1=1--\|1+or+1%3D1--' "$DIR/origin.jsonl" 2>/dev/null; then
  say FAIL C1 "sqli reached origin"; fail=1
fi

# C2: benign request must reach the origin.
code=$(curl --noproxy "*" -s -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
  "http://127.0.0.1:$DATA_PORT/?q=hello" || true)
if [[ "$code" == "200" ]] && grep -q 'q=hello' "$DIR/origin.jsonl" 2>/dev/null; then
  say PASS C2 "benign proxied ($code)"
else
  say FAIL C2 "benign returned $code or origin log missing"; fail=1
fi

# C3/C4: admin gate and login (skip on entry-gated instances).
ENTRY="false"
[[ -f "$DIR/instance.env" ]] && source "$DIR/instance.env"
if [[ "${ENTRY_ENABLED:-false}" == "true" ]]; then
  say SKIP C3 "security_entry enabled"
  say SKIP C4 "security_entry enabled"
else
  code=$(curl --noproxy "*" -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/api/system" || true)
  if [[ "$code" == "403" || "$code" == "401" ]]; then say PASS C3 "admin API closed ($code)"; else say FAIL C3 "admin API $code"; fail=1; fi
  if python3 "$HARNESS_DIR/client.py" login --admin-url "http://127.0.0.1:$ADMIN_PORT" \
      --user admin --password "$PASSWORD" --jar "$JAR" >/dev/null 2>&1; then
    code=$(python3 "$HARNESS_DIR/client.py" request --url "http://127.0.0.1:$ADMIN_PORT/api/system" \
      --jar "$JAR" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' 2>/dev/null || echo 0)
    if [[ "$code" == "200" ]]; then say PASS C4 "admin login ($code)"; else say FAIL C4 "admin session $code"; fail=1; fi
  else
    say FAIL C4 "login failed"; fail=1
  fi
fi

# C5: entry gate teapot (only when configured).
if [[ "${ENTRY_ENABLED:-false}" == "true" ]]; then
  code=$(curl --noproxy "*" -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/" || true)
  if [[ "$code" == "418" ]]; then say PASS C5 "entry teapot ($code)"; else say FAIL C5 "entry returned $code"; fail=1; fi
fi

exit "$fail"
