#!/usr/bin/env bash
# Shared constants for the CheeseWAF attack-chain audit harness.
set -euo pipefail

AU_ROOT="${AU_ROOT:-/tmp/cw-audit}"
BIN="${BIN:-$AU_ROOT/bin/cheesewaf}"
REPO="${REPO:-/Users/laoke/Dev/CheeseWAF}"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSWORD="${PASSWORD:-Audit-Password-9x!Qz}"

port_for() {
  case "$1" in
    T1)  echo "28081 29441 29091" ;;
    T2)  echo "28082 29442 29092" ;;
    T3)  echo "28083 29443 29093" ;;
    T4)  echo "28084 29444 29094" ;;
    T5a) echo "28085 29445 29095" ;;
    T5b) echo "28086 29446 29096" ;;
    T6)  echo "28087 29447 29097" ;;
    V1)  echo "28088 29448 29098" ;;
    V2)  echo "28089 29449 29099" ;;
    V3)  echo "28090 29450 29100" ;;
    *)   echo "unknown instance id: $1" >&2; return 1 ;;
  esac
}
