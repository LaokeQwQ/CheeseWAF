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


def source_scope(src):
    scope = src.get("scope", "request")
    if scope not in ("request", "payload-only"):
        raise ValueError(f"invalid source scope {scope!r}")
    return scope


def validate_source_metrics(src):
    """Validate source counters before they participate in any aggregate."""
    counter_names = ("benign_total", "benign_fp", "attack_total", "attack_hit")
    for name in counter_names:
        if name not in src:
            continue
        value = src[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"sources counter {name!r} must be a non-negative integer")
    benign_total = src.get("benign_total", 0)
    benign_fp = src.get("benign_fp", 0)
    attack_total = src.get("attack_total", 0)
    attack_hit = src.get("attack_hit", 0)
    if benign_fp > benign_total:
        raise ValueError("sources counter 'benign_fp' exceeds 'benign_total'")
    if attack_hit > attack_total:
        raise ValueError("sources counter 'attack_hit' exceeds 'attack_total'")
    for name, value in src.items():
        if name in ("scope", "metrics") or name in counter_names:
            continue
        if isinstance(value, (int, float)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"sources counter {name!r} must be a non-negative integer")


def scope_totals(sources, scope_filter=None):
    """Return denominators used to bound diagnostic counters."""
    totals = {"benign_total": 0, "benign_fp": 0, "attack_total": 0, "attack_hit": 0}
    for src in sources.values():
        if scope_filter is not None and src.get("scope", "request") != scope_filter:
            continue
        for key in totals:
            value = src.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool):
                totals[key] += value
    return totals


def request_scope_totals(sources):
    """Return request-scope denominators used by primary diagnostics."""
    return scope_totals(sources, "request")


def validate_primary_diagnostics(data):
    """Reject non-integer/negative/oversized primary diagnostic counts."""
    if not isinstance(data, dict):
        raise ValueError("report root must be an object")
    sources = data.get("sources", {})
    if not isinstance(sources, dict):
        raise ValueError("sources must be an object")
    for source_name, src in sources.items():
        if not isinstance(src, dict):
            raise ValueError(f"sources[{source_name!r}] must be an object")
    diagnostic_sections = (
        "by_category",
        "by_paranoia_level",
        "by_category_all_sources",
        "by_paranoia_level_all_sources",
    )
    for section in diagnostic_sections:
        values = data.get(section, {})
        if not isinstance(values, dict):
            raise ValueError(f"{section} must be an object")
        for label, metrics in values.items():
            if not isinstance(metrics, dict):
                raise ValueError(f"{section}[{label!r}] must be an object")
    request_limits = request_scope_totals(sources)
    all_limits = scope_totals(sources)
    fields = {
        "by_category": (("attack_total", "attack_hit"), request_limits),
        "by_paranoia_level": (("benign_total", "benign_fp", "attack_total", "attack_hit"), request_limits),
        "by_category_all_sources": (("attack_total", "attack_hit"), all_limits),
        "by_paranoia_level_all_sources": (("benign_total", "benign_fp", "attack_total", "attack_hit"), all_limits),
    }
    for section, (names, limits) in fields.items():
        for label, metrics in data.get(section, {}).items():
            for name in names:
                if name not in metrics:
                    continue
                value = metrics[name]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ValueError(f"{section}[{label!r}].{name} must be an integer count")
                if value < 0:
                    raise ValueError(f"{section}[{label!r}].{name} must not be negative")
                bound_name = {"benign_fp": "benign_total", "attack_hit": "attack_total"}.get(name, name)
                if value > limits[bound_name]:
                    limit_scope = "source" if section.endswith("_all_sources") else "request-scope"
                    raise ValueError(
                        f"{section}[{label!r}].{name} exceeds {limit_scope} total {limits[bound_name]}"
                    )


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


def f1_percent(attack_hit, benign_fp, attack_total):
    """Return F1 as a percentage, or zero when precision/recall is undefined."""
    precision = attack_hit / (attack_hit + benign_fp) if attack_hit + benign_fp else 0.0
    recall = attack_hit / attack_total if attack_total else 0.0
    if not precision + recall:
        return 0.0
    return round(2 * precision * recall / (precision + recall) * 100.0, 6)


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
        "all_sources": {},
        "by_paranoia_level": {},
        "by_paranoia_level_all_sources": {},
        "by_category_all_sources": {},
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
        try:
            validate_primary_diagnostics(data)
            for source_name, src in data.get("sources", {}).items():
                if not isinstance(src, dict):
                    raise ValueError(f"sources[{source_name!r}] must be an object")
                validate_source_metrics(src)
        except ValueError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 1
        merged["timestamp"] = data.get("timestamp") or merged["timestamp"]
        for name, src in data.get("sources", {}).items():
            try:
                scope = source_scope(src)
            except ValueError as exc:
                print(f"{path}: {exc}", file=sys.stderr)
                return 1
            current = source_totals.setdefault(name, {"scope": scope})
            if current.get("scope", "request") != scope:
                print(f"conflicting scope metadata for source {name!r}", file=sys.stderr)
                return 1
            current["scope"] = scope
            source_totals[name] = nums_add(current, {k: v for k, v in src.items() if isinstance(v, int) and not isinstance(v, bool)})
        for name, cat in data.get("by_category", {}).items():
            category_totals.setdefault(name, {})
            category_totals[name] = nums_add(category_totals[name], cat)
        for name, cat in data.get("by_category_all_sources", {}).items():
            all_cat = merged["by_category_all_sources"].setdefault(name, {})
            merged["by_category_all_sources"][name] = nums_add(all_cat, cat)
        for level, pm in data.get("by_paranoia_level", {}).items():
            paranoia_totals.setdefault(level, {})
            paranoia_totals[level] = nums_add(paranoia_totals[level], pm)
        for level, pm in data.get("by_paranoia_level_all_sources", {}).items():
            all_pm = merged["by_paranoia_level_all_sources"].setdefault(level, {})
            merged["by_paranoia_level_all_sources"][level] = nums_add(all_pm, pm)
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
            "f1_score": f1_percent(hit, fp, a),
        }
        add_confidence(src["metrics"], fp, b, hit, a)
        merged["sources"][name] = src
    for name, cat in category_totals.items():
        a = cat.get("attack_total", 0)
        hit = cat.get("attack_hit", 0)
        cat["tpr_percent"] = round(hit * 100 / a, 6) if a else 0.0
        merged["by_category"][name] = cat
    for name, cat in merged["by_category_all_sources"].items():
        a = cat.get("attack_total", 0)
        hit = cat.get("attack_hit", 0)
        cat["tpr_percent"] = round(hit * 100 / a, 6) if a else 0.0

    request_sources = [s for s in source_totals.values() if s.get("scope", "request") == "request"]
    total_b = sum(s.get("benign_total", 0) for s in request_sources)
    total_fp = sum(s.get("benign_fp", 0) for s in request_sources)
    total_a = sum(s.get("attack_total", 0) for s in request_sources)
    total_hit = sum(s.get("attack_hit", 0) for s in request_sources)
    fpr = round(total_fp * 100 / total_b, 6) if total_b else 0.0
    tpr = round(total_hit * 100 / total_a, 6) if total_a else 0.0
    precision = round(total_hit * 100 / (total_hit + total_fp), 6) if total_hit + total_fp else 0.0
    f1 = f1_percent(total_hit, total_fp, total_a)
    merged["overall"] = {"benign_total": total_b, "benign_fp": total_fp, "attack_total": total_a, "attack_hit": total_hit, "fpr_percent": fpr, "tpr_percent": tpr, "precision_percent": precision, "f1_score": f1}
    add_confidence(merged["overall"], total_fp, total_b, total_hit, total_a)

    all_b = sum(s.get("benign_total", 0) for s in source_totals.values())
    all_fp = sum(s.get("benign_fp", 0) for s in source_totals.values())
    all_a = sum(s.get("attack_total", 0) for s in source_totals.values())
    all_hit = sum(s.get("attack_hit", 0) for s in source_totals.values())
    all_fpr = round(all_fp * 100 / all_b, 6) if all_b else 0.0
    all_tpr = round(all_hit * 100 / all_a, 6) if all_a else 0.0
    all_precision = round(all_hit * 100 / (all_hit + all_fp), 6) if all_hit + all_fp else 0.0
    all_f1 = f1_percent(all_hit, all_fp, all_a)
    merged["all_sources"] = {"benign_total": all_b, "benign_fp": all_fp, "attack_total": all_a, "attack_hit": all_hit, "fpr_percent": all_fpr, "tpr_percent": all_tpr, "precision_percent": all_precision, "f1_score": all_f1}
    add_confidence(merged["all_sources"], all_fp, all_b, all_hit, all_a)

    for level, pm in sorted(paranoia_totals.items(), key=lambda item: int(item[0])):
        b = pm.get("benign_total", 0)
        fp = pm.get("benign_fp", 0)
        a = pm.get("attack_total", 0)
        hit = pm.get("attack_hit", 0)
        pm["fpr"] = round(fp * 100 / b, 6) if b else 0.0
        pm["tpr"] = round(hit * 100 / a, 6) if a else 0.0
        add_confidence(pm, fp, b, hit, a)
        merged["by_paranoia_level"][level] = pm

    for level, pm in sorted(merged["by_paranoia_level_all_sources"].items(), key=lambda item: int(item[0])):
        b = pm.get("benign_total", 0)
        fp = pm.get("benign_fp", 0)
        a = pm.get("attack_total", 0)
        hit = pm.get("attack_hit", 0)
        pm["fpr"] = round(fp * 100 / b, 6) if b else 0.0
        pm["tpr"] = round(hit * 100 / a, 6) if a else 0.0
        add_confidence(pm, fp, b, hit, a)

    print(json.dumps(merged, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
