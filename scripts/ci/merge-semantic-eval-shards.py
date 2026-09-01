#!/usr/bin/env python3
"""Merge per-shard semantic evaluation JSON reports into a single aggregate.

Each shard writes EVAL_REPORT_PATH=<dir>/report-shard-N.json. This script sums
source/category/paranoia counts and recomputes overall metrics so the shard run
produces one actionable report.
"""
import json
import math
import sys
from pathlib import Path


def nums_add(a, b):
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, (int, float)):
            out[k] = out.get(k, 0) + v
    return out


def failed_case_key(case):
    """Return a stable identity for one diagnostic failed-case entry."""
    try:
        return json.dumps(case, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return repr(case)


def wilson_99(successes, total):
    """Return one-sided 99% Wilson lower/upper bounds as fractions."""
    if not isinstance(successes, int) or isinstance(successes, bool):
        return None
    if not isinstance(total, int) or isinstance(total, bool):
        return None
    if total <= 0 or successes < 0 or successes > total:
        return None
    z = 2.3263478740408408
    n = float(total)
    p = float(successes) / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2.0 * n)
    half = z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))
    lower = max(0.0, min(1.0, (center - half) / denom))
    upper = max(0.0, min(1.0, (center + half) / denom))
    if successes == 0:
        lower = 0.0
    if successes == total:
        upper = 1.0
    return lower, upper


def add_confidence(metrics, benign_fp, benign_total, attack_hit, attack_total):
    fpr = wilson_99(benign_fp, benign_total)
    tpr = wilson_99(attack_hit, attack_total)
    if fpr is not None:
        metrics["fpr_upper_99_percent"] = round(fpr[1] * 100.0, 6)
    if tpr is not None:
        metrics["tpr_lower_99_percent"] = round(tpr[0] * 100.0, 6)


def main() -> int:
    files = sorted(Path(p) for p in sys.argv[1:])
    if not files:
        print("usage: merge-semantic-eval-shards.py report-shard-*.json", file=sys.stderr)
        return 2
    merged = {
        "timestamp": None,
        "shards": len(files),
        "sources": {},
        "by_category": {},
        "overall": {},
        "by_paranoia_level": {},
        "failed_cases": [],
    }
    source_totals = {}
    category_totals = {}
    paranoia_totals = {}
    failed_case_keys = set()
    for path in files:
        try:
            data = json.loads(path.read_text())
        except Exception as exc:  # noqa: BLE001
            print(f"failed to read {path}: {exc}", file=sys.stderr)
            return 1
        merged["timestamp"] = data.get("timestamp") or merged["timestamp"]
        for name, src in data.get("sources", {}).items():
            source_totals.setdefault(name, {})
            source_totals[name] = nums_add(source_totals[name], {k: v for k, v in src.items() if isinstance(v, (int, float))})
        for name, cat in data.get("by_category", {}).items():
            category_totals.setdefault(name, {})
            category_totals[name] = nums_add(category_totals[name], cat)
        for level, pm in data.get("by_paranoia_level", {}).items():
            paranoia_totals.setdefault(level, {})
            paranoia_totals[level] = nums_add(paranoia_totals[level], pm)
        for failed_case in data.get("failed_cases", []):
            key = failed_case_key(failed_case)
            if key in failed_case_keys:
                continue
            failed_case_keys.add(key)
            if len(merged["failed_cases"]) < 100:
                merged["failed_cases"].append(failed_case)

    for name, src in source_totals.items():
        b = src.get("benign_total", 0)
        fp = src.get("benign_fp", 0)
        a = src.get("attack_total", 0)
        hit = src.get("attack_hit", 0)
        src["metrics"] = {
            "fpr_percent": round(fp * 100 / b, 6) if b else 0.0,
            "tpr_percent": round(hit * 100 / a, 6) if a else 0.0,
            "precision_percent": round(hit * 100 / (hit + fp), 6) if hit + fp else 0.0,
            "f1_score": round(2 * ((hit / (hit + fp)) * (hit / a)) / ((hit / (hit + fp)) + (hit / a)), 6) if a and hit + fp else 0.0,
        }
        add_confidence(src["metrics"], fp, b, hit, a)
        merged["sources"][name] = src
    for name, cat in category_totals.items():
        a = cat.get("attack_total", 0)
        hit = cat.get("attack_hit", 0)
        cat["tpr_percent"] = round(hit * 100 / a, 6) if a else 0.0
        merged["by_category"][name] = cat

    total_b = sum(s.get("benign_total", 0) for s in source_totals.values())
    total_fp = sum(s.get("benign_fp", 0) for s in source_totals.values())
    total_a = sum(s.get("attack_total", 0) for s in source_totals.values())
    total_hit = sum(s.get("attack_hit", 0) for s in source_totals.values())
    fpr = round(total_fp * 100 / total_b, 6) if total_b else 0.0
    tpr = round(total_hit * 100 / total_a, 6) if total_a else 0.0
    precision = round(total_hit * 100 / (total_hit + total_fp), 6) if total_hit + total_fp else 0.0
    f1 = round(2 * (precision * tpr) / (precision + tpr), 6) if precision + tpr else 0.0
    merged["overall"] = {"fpr_percent": fpr, "tpr_percent": tpr, "precision_percent": precision, "f1_score": f1}
    add_confidence(merged["overall"], total_fp, total_b, total_hit, total_a)

    for level, pm in sorted(paranoia_totals.items(), key=lambda item: int(item[0])):
        b = pm.get("benign_total", 0)
        fp = pm.get("benign_fp", 0)
        a = pm.get("attack_total", 0)
        hit = pm.get("attack_hit", 0)
        pm["fpr"] = round(fp * 100 / b, 6) if b else 0.0
        pm["tpr"] = round(hit * 100 / a, 6) if a else 0.0
        add_confidence(pm, fp, b, hit, a)
        merged["by_paranoia_level"][level] = pm

    print(json.dumps(merged, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
