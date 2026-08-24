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
