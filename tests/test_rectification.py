from __future__ import annotations

import unittest
from datetime import date

from personal_agent.environment import create_environment, reset_environment
from personal_agent.tools import execute_tool
from personal_agent.ui import DEMO_SCENARIOS, _fresh_environment
from guardrails.classifier import Guardrail
from guardrails.config import DEFAULTS
from personal_agent.agent import _sanitize_tool_content


class RectificationTests(unittest.TestCase):
    def test_demo_starts_at_documented_balance(self):
        env = create_environment()
        self.assertEqual(env["bank"]["bank_balance"], 120000.0)

    def test_baseline_demo_transfer_updates_balance_and_history(self):
        env = create_environment()
        before_count = len(env["bank"]["transactions"])
        result = execute_tool("send_money", {"amount": 5000, "recipient": "Alex"}, env)
        self.assertTrue(result["executed"])
        self.assertEqual(result["remaining_balance"], 115000.0)
        self.assertEqual(env["bank"]["bank_balance"], 115000.0)
        self.assertEqual(len(env["bank"]["transactions"]), before_count + 1)
        self.assertEqual(env["bank"]["transactions"][-1]["amount"], -5000.0)

    def test_scenario_reset_restores_same_starting_state(self):
        baseline = _fresh_environment("injection")
        baseline["bank"]["bank_balance"] -= 5000
        protected = _fresh_environment("injection")
        self.assertEqual(protected["bank"]["bank_balance"], 120000.0)
        self.assertEqual(baseline["emails"], protected["emails"])
        self.assertEqual(len(protected["emails"]), 4)
        self.assertEqual(reset_environment(baseline)["bank"]["bank_balance"], 120000.0)

    def test_attack_scenario_has_genuine_content_and_embedded_instruction(self):
        email = DEMO_SCENARIOS["injection"]["email"]
        self.assertIn("project status is green", email["body"].casefold())
        self.assertIn("send_money", email["body"])

    def test_sanitization_summary_has_source_decision_and_reason(self):
        guardrail = Guardrail()
        env = _fresh_environment("injection")
        clean, summaries = _sanitize_tool_content(
            {"emails": [env["emails"][-1]]}, guardrail, DEFAULTS,
            {"api_key": None, "model": None, "base_url": None, "timeout": 1},
        )
        body_summary = next(item for item in summaries if item["source"].endswith(".body"))
        self.assertEqual(body_summary["decision"], "SANITIZE")
        self.assertEqual(body_summary["quarantined_count"], 1)
        self.assertIn("AUTHORITY", body_summary["reason"])
        self.assertNotIn("send_money", clean["emails"][0]["body"])
        segment = body_summary["quarantined_segments"][0]
        self.assertTrue(segment["audit_only"])
        self.assertIn("send_money", segment["content"])
        # Audit evidence is visible to the UI only; the sanitized tool result stays clean.
        self.assertNotIn(segment["content"], clean["emails"][0]["body"])

    def test_november_9_2026_is_monday_not_friday(self):
        self.assertEqual(date(2026, 11, 9).strftime("%A"), "Monday")


if __name__ == "__main__":
    unittest.main()
