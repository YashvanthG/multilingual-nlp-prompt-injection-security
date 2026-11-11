"""Shared test helpers. FixedModel makes the classifier probability controllable so that pipeline-logic
tests do not depend on the trained model (the 20-scenario harness covers the real model)."""
from pathlib import Path
from unittest.mock import patch

from guardrails.classifier import Guardrail
from simulation.agent import DemoAgent

ROOT = Path(__file__).resolve().parents[1]


class FixedModel:
    classes_ = [0, 1]

    def __init__(self, p):
        self.p = p

    def predict_proba(self, texts):
        return [[1 - self.p, self.p] for _ in texts]


def guard_with(p):
    guard = Guardrail(model_path=ROOT / "models" / "guardrail_tfidf.joblib")
    guard.model = FixedModel(p)
    return guard


def groq_result(decision="ALLOW", status="success", used=True):
    return {"provider": "GroqCloud", "model": "mock", "status": status, "decision": decision, "reason": "mock",
            "latency_ms": 1.0, "request_sent": used, "used": used}


def agent(key="mock-key"):
    return DemoAgent(api_key=key, model="mock-model" if key else "")


def stage(result, name):
    return next((x for x in result["audit"] if x.get("stage") == name), None)


def stages(result):
    return [x.get("stage") for x in result["audit"]]


def patch_groq(decision="ALLOW", **kw):
    return patch("simulation.agent.review_with_groq", return_value=groq_result(decision, **kw))
