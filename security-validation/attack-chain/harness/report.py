#!/usr/bin/env python3
"""Validate track finding files against the audit schema."""
import json
import sys

REQUIRED_TOP = ["track", "commit", "instances", "findings", "coverage"]
REQUIRED_FINDING = ["id", "title", "severity", "cvss", "score", "asset", "preconditions", "chain", "status", "evidence", "impact", "repro"]


def validate(path):
    with open(path) as fh:
        data = json.load(fh)
    errors = []
    for k in REQUIRED_TOP:
        if k not in data:
            errors.append(f"missing top-level {k}")
    for i, f in enumerate(data.get("findings", [])):
        for k in REQUIRED_FINDING:
            if k not in f:
                errors.append(f"finding[{i}] missing {k}")
        if f.get("status") not in ("confirmed", "candidate", "refuted", "intermittent"):
            errors.append(f"finding[{i}] bad status {f.get('status')}")
        ev = f.get("evidence", {})
        for k in ("request", "response", "control"):
            if not ev.get(k):
                errors.append(f"finding[{i}] missing evidence.{k}")
    if not data.get("coverage"):
        errors.append("coverage is empty")
    return errors


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "validate":
        print("usage: report.py validate <T1.json>", file=sys.stderr)
        sys.exit(2)
    errs = validate(sys.argv[2])
    if errs:
        print("\n".join(errs), file=sys.stderr)
        sys.exit(1)
    print("VALID")
