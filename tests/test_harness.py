import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import guardrails_test_suite as suite


class HarnessTests(unittest.TestCase):
    def test_suite_has_20_scenarios_with_machine_checkable_expectations(self):
        self.assertEqual(len(suite.CASES), 20)
        self.assertEqual(len({c["id"] for c in suite.CASES}), 20)
        for case in suite.CASES:
            self.assertTrue(case["expect"].get("final_in"), case["id"])

    def test_harness_really_executes_the_pipeline_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            j, t = Path(tmp) / "r.json", Path(tmp) / "r.txt"
            suite.main(["--mode", "offline", "--json", str(j), "--txt", str(t)])
            report = json.loads(j.read_text())
            self.assertTrue(t.exists())
        results = report["modes"]["offline"]["results"]
        self.assertEqual(len([r for r in results if r["suite"] == "core"]), 20)
        self.assertEqual(len([r for r in results if r["suite"] == "additional"]), len(suite.ADDITIONAL_CASES))
        self.assertTrue(all(r["observed"] and r["observed"]["stages"] for r in results))   # real audit traces captured
        self.assertTrue(all(r["observed"]["groq_calls"] == 0 for r in results))
        self.assertTrue(all(r["observed"]["latency_ms"] > 0 for r in results))

    def test_mock_mode_uses_no_network(self):
        with patch("requests.post", side_effect=AssertionError("network used")), tempfile.TemporaryDirectory() as tmp:
            suite.main(["--mode", "mock", "--json", str(Path(tmp) / "r.json"), "--txt", str(Path(tmp) / "r.txt")])

    def test_live_mode_without_key_is_not_testable_not_a_pass(self):
        with patch.object(suite, "live_available", return_value=False):
            report = suite.build_report(["live"], "t")
        self.assertEqual(report["modes"]["live"]["status"], "NOT_TESTABLE")
        self.assertEqual(report["modes"]["live"]["summary"]["pass"], 0)

    def test_failures_are_reported_not_hidden(self):
        case = {"id": "x", "category": "c", "request": "r", "document": "", "expect": {"final_in": ["BLOCK"]}}
        obs = {"final_decision": "ALLOW", "reason_category": None, "planning_occurred": False, "tool_executed": False, "executed_tool_name": None,
               "planned_tool": None, "groq_calls": 0, "quarantined_count": 0, "output_blob": "", "document_inspected": False, "stages": []}
        self.assertFalse(all(c["ok"] for c in suite.evaluate(case, obs, "mock")))


if __name__ == "__main__":
    unittest.main()
