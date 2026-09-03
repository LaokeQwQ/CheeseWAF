#!/usr/bin/env python3
"""Regression coverage for semantic shard-report merging."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("merge-semantic-eval-shards.py")


def report_with_failed_cases(cases):
    return {
        "timestamp": "2026-08-24T00:00:00Z",
        "sources": {},
        "by_category": {},
        "by_paranoia_level": {},
        "failed_cases": cases,
    }


class MergeSemanticEvalShardsTests(unittest.TestCase):
    def test_primary_diagnostics_accept_valid_overlap_and_omitted_scope(self):
        report = {
            "sources": {"requests": {"benign_total": 10, "benign_fp": 2, "attack_total": 10, "attack_hit": 7}},
            "by_category": {"sqli": {"attack_total": 10, "attack_hit": 7}, "xss": {"attack_total": 10, "attack_hit": 10}},
            "by_paranoia_level": {"0": {"benign_total": 10, "benign_fp": 2, "attack_total": 10, "attack_hit": 7}},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            completed = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=True, capture_output=True, text=True)
        output = json.loads(completed.stdout)
        self.assertEqual(7, output["by_category"]["sqli"]["attack_hit"])
        self.assertEqual(2, output["by_paranoia_level"]["0"]["benign_fp"])

    def test_primary_category_and_paranoia_contamination_rejected(self):
        base = {
            "sources": {"requests": {"scope": "request", "benign_total": 10, "benign_fp": 2, "attack_total": 10, "attack_hit": 7}},
            "by_category": {},
            "by_paranoia_level": {},
        }
        invalid = [
            ("by_category", {"sqli": {"attack_total": 10.5}}),
            ("by_category", {"sqli": {"attack_hit": -1}}),
            ("by_category", {"sqli": {"attack_total": 11}}),
            ("by_paranoia_level", {"0": {"benign_fp": 11}}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for section, diagnostics in invalid:
                report = dict(base)
                report[section] = diagnostics
                path.write_text(json.dumps(report), encoding="utf-8")
                rejected = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
                self.assertNotEqual(0, rejected.returncode, msg=(section, diagnostics))

    def test_all_source_diagnostics_are_bounded_by_all_source_totals(self):
        report = {
            "sources": {"requests": {"scope": "request", "benign_total": 2, "attack_total": 2, "attack_hit": 1}},
            "by_category_all_sources": {"sqli": {"attack_total": 3, "attack_hit": 1}},
            "by_paranoia_level_all_sources": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            rejected = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
        self.assertNotEqual(0, rejected.returncode)

    def test_source_counters_must_be_non_negative_integers_and_consistent(self):
        base = {
            "sources": {"requests": {"scope": "request", "benign_total": 10, "benign_fp": 2, "attack_total": 10, "attack_hit": 7}},
            "by_category": {},
            "by_paranoia_level": {},
        }
        invalid_sources = [
            {"benign_total": -1},
            {"benign_fp": 2.5},
            {"attack_hit": True},
            {"benign_total": 1, "benign_fp": 2},
            {"attack_total": 1, "attack_hit": 2},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for changes in invalid_sources:
                report = json.loads(json.dumps(base))
                report["sources"]["requests"].update(changes)
                path.write_text(json.dumps(report), encoding="utf-8")
                rejected = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
                self.assertNotEqual(0, rejected.returncode, msg=changes)

    def test_scope_aggregates_and_conflicting_scope_rejected(self):
        def report(scope):
            return {"sources": {"shared": {"scope": scope, "benign_total": 10, "benign_fp": 1, "attack_total": 10, "attack_hit": 8}}, "by_category": {}, "by_paranoia_level": {}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b = root / "a.json", root / "b.json"
            a.write_text(json.dumps(report("request")), encoding="utf-8")
            b.write_text(json.dumps({"sources": {"payload": {"scope": "payload-only", "benign_total": 10, "benign_fp": 5, "attack_total": 10, "attack_hit": 2}}, "by_category": {}, "by_paranoia_level": {}}), encoding="utf-8")
            merged = json.loads(subprocess.run([sys.executable, str(SCRIPT), str(a), str(b)], check=True, capture_output=True, text=True).stdout)
            self.assertEqual(84.210526, merged["sources"]["shared"]["metrics"]["f1_score"])
            self.assertEqual(10.0, merged["overall"]["fpr_percent"])
            self.assertEqual(80.0, merged["overall"]["tpr_percent"])
            self.assertEqual(84.210526, merged["overall"]["f1_score"])
            self.assertEqual(30.0, merged["all_sources"]["fpr_percent"])
            self.assertEqual(55.555556, merged["all_sources"]["f1_score"])
            b.write_text(json.dumps(report("payload-only")), encoding="utf-8")
            rejected = subprocess.run([sys.executable, str(SCRIPT), str(a), str(b)], capture_output=True, text=True)
            self.assertNotEqual(0, rejected.returncode)

    def test_f1_is_zero_for_zero_hits_and_100_for_perfect_metrics(self):
        report = {
            "sources": {
                "zero-hit": {"scope": "request", "benign_total": 5, "benign_fp": 2, "attack_total": 5, "attack_hit": 0},
                "perfect": {"scope": "request", "benign_total": 5, "benign_fp": 0, "attack_total": 5, "attack_hit": 5},
            },
            "by_category": {},
            "by_paranoia_level": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            merged = json.loads(subprocess.run([sys.executable, str(SCRIPT), str(path)], check=True, capture_output=True, text=True).stdout)

        self.assertEqual(0.0, merged["sources"]["zero-hit"]["metrics"]["f1_score"])
        self.assertEqual(100.0, merged["sources"]["perfect"]["metrics"]["f1_score"])
        self.assertEqual(58.823529, merged["overall"]["f1_score"])
        self.assertEqual(58.823529, merged["all_sources"]["f1_score"])

    def test_aggregate_f1_uses_unrounded_precision_and_recall(self):
        report = {
            "sources": {
                "fractional": {"scope": "request", "benign_total": 1, "benign_fp": 0, "attack_total": 7, "attack_hit": 2},
            },
            "by_category": {},
            "by_paranoia_level": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            merged = json.loads(subprocess.run([sys.executable, str(SCRIPT), str(path)], check=True, capture_output=True, text=True).stdout)

        self.assertEqual(44.444444, merged["overall"]["f1_score"])
        self.assertEqual(44.444444, merged["all_sources"]["f1_score"])

    def test_failed_cases_are_globally_deduplicated_and_capped(self):
        duplicate = {"type": "FN", "name": "duplicate", "expected": "sqli", "payload": "x"}
        first = [duplicate, *({"type": "FN", "name": f"case-{i}", "expected": "sqli"} for i in range(75))]
        second = [duplicate, *({"type": "FN", "name": f"case-{i}", "expected": "sqli"} for i in range(75, 160))]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_path = root / "report-shard-0.json"
            second_path = root / "report-shard-1.json"
            first_path.write_text(json.dumps(report_with_failed_cases(first)), encoding="utf-8")
            second_path.write_text(json.dumps(report_with_failed_cases(second)), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(first_path), str(second_path)],
                check=True,
                capture_output=True,
                text=True,
            )

        merged = json.loads(completed.stdout)
        failed_cases = merged["failed_cases"]
        identities = {json.dumps(case, sort_keys=True, separators=(",", ":")) for case in failed_cases}
        self.assertEqual(100, len(failed_cases))
        self.assertEqual(len(failed_cases), len(identities))
        self.assertEqual(1, sum(case.get("name") == "duplicate" for case in failed_cases))


if __name__ == "__main__":
    unittest.main()
