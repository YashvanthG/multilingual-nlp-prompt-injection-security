"""End-to-end assertions for the six Testing Lab scenarios."""
import unittest
from guardrails.classifier import Guardrail
from simulation.agent import DemoAgent
from simulation.scenarios import SCENARIOS


class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = Guardrail()
        cls.agent = DemoAgent(api_key="", model="")

    def run_scenario(self, name):
        scenario = next(item for item in SCENARIOS if item["name"] == name)
        kwargs = {}
        for source, target in (("forced_action", "force_action"), ("scenario_stage", "scenario_stage"), ("untrusted_content", "untrusted_content"), ("injected_output", "injected_output")):
            if source in scenario:
                kwargs[target] = scenario[source]
        result = self.agent.run(scenario["request"], self.guard, mode="Local guardrail", **kwargs)
        return result, [item.get("stage") for item in result.get("audit", [])]

    def test_benign_scenario_succeeds(self):
        result, stages = self.run_scenario("Benign weather request")
        self.assertEqual(result["final_decision"]["decision"], "ALLOW")
        self.assertIsNotNone(result["tool_output"])
        self.assertIn("output_guard", stages)

    def test_direct_injection_stops_before_tool(self):
        result, stages = self.run_scenario("Prompt injection attempt")
        self.assertIn(result["final_decision"]["decision"], {"BLOCK", "ESCALATE"})
        self.assertIsNone(result["tool_output"])
        self.assertIn("input", stages)

    def test_misaligned_action_reaches_action_guard(self):
        result, stages = self.run_scenario("Misaligned tool action")
        self.assertIn("action_guard", stages)
        self.assertEqual(result["final_decision"]["decision"], "BLOCK")
        self.assertIsNone(result["tool_output"])

    def test_unauthorized_tool_is_rejected(self):
        result, stages = self.run_scenario("Unauthorized tool")
        action = next(item["result"] for item in result["audit"] if item.get("stage") == "action_guard")
        self.assertIn("action_guard", stages)
        self.assertEqual(action["reason_category"], "UNAUTHORIZED_TOOL")
        self.assertIsNone(result["tool_output"])

    def test_sensitive_output_is_inspected_and_sanitized(self):
        result, stages = self.run_scenario("Sensitive simulated output")
        self.assertIn("output_guard", stages)
        self.assertNotEqual(result.get("tool_output", {}).get("api_key"), "FAKE-DEMO-KEY-NOT-A-CREDENTIAL")

    def test_indirect_injection_is_inspected_before_planning(self):
        result, stages = self.run_scenario("Indirect prompt injection in document")
        self.assertIn("untrusted_content_inspection", stages)
        doc = next(i for i in result["audit"] if i.get("stage") == "untrusted_content_inspection")
        self.assertGreaterEqual(doc["quarantined_line_count"], 1)          # the malicious sentence is isolated
        self.assertNotIn("system prompt", result["answer"].lower())         # and never reaches the answer
        self.assertNotIn("tool_execution", stages)                          # document text is never given to a tool
        self.assertIsNone(result["tool_output"])


if __name__ == "__main__":
    unittest.main()
