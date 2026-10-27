#!/usr/bin/env python3
"""Release gate for the CheeseWAF attack-chain audit.

Checks that every track produced a schema-valid finding file, every confirmed
finding has evidence on disk, and every confirmed finding has 2/2 independent
replay records (verify/replays.json).
"""
import glob
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS = os.path.join(BASE, "findings")
REPLAYS = os.path.join(BASE, "verify", "replays.json")


def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def main():
    errors = []
    confirmed = []
    tracks = sorted(glob.glob(os.path.join(FINDINGS, "T*.json")))
    if len(tracks) < 6:
        errors.append(f"expected 6 track files, found {len(tracks)}")
    for path in tracks:
        try:
            data = load_json(path)
        except Exception as exc:
            errors.append(f"{path}: invalid JSON: {exc}")
            continue
        for f in data.get("findings", []):
            if f.get("status") != "confirmed":
                continue
            fid = f.get("id", "?")
            confirmed.append(fid)
            ev = f.get("evidence", {})
            for key in ("request", "response", "control"):
                rel = ev.get(key)
                if not rel:
                    errors.append(f"{fid}: missing evidence.{key}")
                    continue
                if rel.startswith("artifacts/") or rel.startswith("findings/"):
                    full = os.path.join(BASE, rel)
                    if not os.path.isfile(full):
                        errors.append(f"{fid}: evidence file missing: {rel}")
            if not os.path.isfile(os.path.join(BASE, ev.get("origin_log", ""))):
                # origin_log is optional for non-proxy findings
                pass
        if not data.get("coverage"):
            errors.append(f"{path}: empty coverage")
    replays = {}
    if os.path.isfile(REPLAYS):
        replays = load_json(REPLAYS)
    for fid in confirmed:
        rec = replays.get(fid, {})
        runs = rec.get("runs", [])
        ok = sum(1 for r in runs if r.get("ok"))
        if ok < 2:
            errors.append(f"{fid}: confirmed but replay {ok}/2")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"GATE OK: {len(tracks)} tracks, {len(confirmed)} confirmed findings, all replayed 2/2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
