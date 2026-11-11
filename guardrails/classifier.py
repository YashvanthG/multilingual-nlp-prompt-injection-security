from pathlib import Path
import re
import joblib

from guardrails import rules
from guardrails.config import ALLOWED_TOOLS, DEFAULTS, with_overrides

ROOT = Path(__file__).resolve().parents[1]

def _normalise_key(key):
    return re.sub(r"[^a-z0-9]", "", str(key).casefold())

SENSITIVE_KEYS = {
    "password", "passwd", "apikey", "secret", "bankbalance", "accountnumber",
    "ssn", "socialsecuritynumber", "creditcard", "recenttransactions",
    "privatekey", "token", "authorization", "accesstoken", "refreshtoken",
}
SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

class Guardrail:
    def __init__(self, model_path=None, block_threshold=None, escalate_threshold=None):
        """Thresholds default to guardrails.config.DEFAULTS; per-call `config` arguments override them."""
        overrides = {}
        if block_threshold is not None:
            overrides["block_threshold"] = block_threshold
        if escalate_threshold is not None:
            overrides["escalate_threshold"] = escalate_threshold
        self.config = with_overrides(DEFAULTS, **overrides)  # validates the threshold relationship
        path = Path(model_path) if model_path else ROOT / "models" / "guardrail_tfidf.joblib"
        if not path.exists():
            raise FileNotFoundError("Trained model not found. Run: python train.py")
        self.model = joblib.load(path)
        self.block_threshold = float(self.config.block_threshold)
        self.escalate_threshold = float(self.config.escalate_threshold)

    def inspect_content(self, text, config=None):
        """Classifier-only inspection using the thresholds of `config` (or this guard's defaults)."""
        cfg = config or self.config
        text = str(text or "").strip()
        if not text:
            return {
                "decision": "ESCALATE", "risk": "MEDIUM", "confidence": 0.0,
                "injection_probability": 0.0, "reason_category": "EMPTY_INPUT",
            }
        probabilities = self.model.predict_proba([text])
        classes = list(self.model.classes_)
        if 1 not in classes:
            raise ValueError("Classifier model must include injection label 1.")
        injection_probability = float(probabilities[0][classes.index(1)])
        if injection_probability >= cfg.block_threshold:
            decision, risk, reason = "BLOCK", "HIGH", "PROMPT_INJECTION_PROBABILITY"
        elif injection_probability >= cfg.escalate_threshold:
            decision, risk, reason = "ESCALATE", "MEDIUM", "UNCERTAIN_CLASSIFICATION"
        else:
            decision, risk, reason = "ALLOW", "LOW", "LOW_INJECTION_PROBABILITY"
        return {
            "decision": decision, "risk": risk,
            "confidence": round(max(injection_probability, 1 - injection_probability), 4),
            "injection_probability": round(injection_probability, 4),
            "reason_category": reason,
        }

    def inspect_request(self, text, config=None, use_classifier=True):
        """User-request inspection: deterministic rules first (hard BLOCK, never overridable by Groq),
        then the classifier. `use_classifier=False` is only for test fixtures that isolate later stages."""
        hits = rules.scan(text)
        if hits:
            reason, explanation = rules.primary_reason(hits)
            return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0, "injection_probability": None,
                    "reason_category": reason, "explanation": explanation, "deterministic": True,
                    "rule_categories": rules.categories(hits)}
        if not use_classifier:
            return {"decision": "ALLOW", "risk": "LOW", "confidence": 0.0, "injection_probability": None,
                    "reason_category": "CLASSIFIER_SKIPPED_BY_FIXTURE", "deterministic": False, "rule_categories": []}
        result = self.inspect_content(text, config)
        result.update({"deterministic": False, "rule_categories": []})
        return result

    def inspect_untrusted_content(self, content, config=None):
        """Inspect retrieved/tool/document text before it can reach a later stage: shared deterministic
        rules (BLOCK) plus the classifier. Defense in depth, not a guarantee against novel attacks."""
        text = str(content or "").strip()
        if not text:
            return {"decision": "ALLOW", "risk": "LOW", "reason_category": "EMPTY_UNTRUSTED_CONTENT", "explanation": "No text to inspect."}
        hits = rules.scan(text)
        if hits:
            return {"decision": "BLOCK", "risk": "HIGH", "reason_category": "UNTRUSTED_INSTRUCTION_PATTERN",
                    "rule_categories": rules.categories(hits), "deterministic": True,
                    "explanation": "Untrusted text contains an instruction-like pattern; it is not trusted as policy."}
        try:
            result = self.inspect_content(text, config)
        except Exception:
            return {"decision": "ESCALATE", "risk": "MEDIUM", "reason_category": "UNTRUSTED_CLASSIFIER_UNAVAILABLE",
                    "explanation": "Classifier inspection failed; untrusted text is not cleared."}
        if result["decision"] == "ALLOW":
            return {"decision": "ALLOW", "risk": "LOW", "reason_category": "UNTRUSTED_TEXT_LOW_SCORE",
                    "injection_probability": result.get("injection_probability"),
                    "explanation": "No rule matched and the classifier score was below the escalation threshold."}
        return {"decision": result["decision"], "risk": result["risk"],
                "reason_category": "UNTRUSTED_" + result.get("reason_category", "CLASSIFIER_REVIEW"),
                "injection_probability": result.get("injection_probability"),
                "explanation": "Untrusted text was flagged by the classifier and is not automatically trusted."}

    def inspect_action(self, user_goal, action, config=None):
        enabled = set((config or self.config).enabled_tools) & ALLOWED_TOOLS
        if not isinstance(action, dict):
            return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                    "reason_category": "INVALID_ACTION", "explanation": "Action must be a dictionary."}
        tool = action.get("tool")
        args = action.get("arguments", {})
        if not isinstance(args, dict):
            return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                    "reason_category": "INVALID_ARGUMENTS", "explanation": "Tool arguments must be an object."}
        if tool not in enabled:
            return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                    "reason_category": "UNAUTHORIZED_TOOL", "explanation": "Tool is not allow-listed."}

        goal = str(user_goal or "").casefold()
        if rules.mentions_sensitive_target(goal) or "recent transactions" in goal:
            return {"decision": "BLOCK", "risk": "HIGH", "confidence": 0.99,
                    "reason_category": "SENSITIVE_OR_UNSUPPORTED_REQUEST",
                    "explanation": "The demo has no authorization for private data or credential access."}

        weather_terms = ("weather", "temperature", "forecast", "mausam", "मौसम")
        math_terms = ("calculate", "compute", "percent", "plus", "minus", "multiply", "divide", "sum", "total")
        if tool == "get_weather":
            if not any(term in goal for term in weather_terms):
                return {"decision": "BLOCK", "risk": "HIGH", "confidence": 0.98,
                        "reason_category": "ACTION_MISALIGNMENT", "explanation": "Weather tool does not match the request."}
            if not str(args.get("city", "")).strip():
                return {"decision": "ESCALATE", "risk": "MEDIUM", "confidence": 0.7,
                        "reason_category": "MISSING_ARGUMENT", "explanation": "Weather request needs a city."}
        elif tool == "calculator":
            arithmetic_intent = any(term in goal for term in math_terms) or bool(re.search(r"\d\s*[+*/%]\s*\d", goal))
            if not arithmetic_intent:
                return {"decision": "BLOCK", "risk": "HIGH", "confidence": 0.9,
                        "reason_category": "ACTION_MISALIGNMENT", "explanation": "Calculator tool does not match the request."}
            if not str(args.get("expression", "")).strip():
                return {"decision": "ESCALATE", "risk": "MEDIUM", "confidence": 0.7,
                        "reason_category": "MISSING_ARGUMENT", "explanation": "Calculator request needs an expression."}
        elif tool == "public_lookup":
            if not str(args.get("query", "")).strip():
                return {"decision": "ESCALATE", "risk": "MEDIUM", "confidence": 0.7,
                        "reason_category": "MISSING_ARGUMENT", "explanation": "Lookup request needs a query."}
            if rules.scan(goal):
                return {"decision": "BLOCK", "risk": "HIGH", "confidence": 0.99,
                        "reason_category": "MALICIOUS_GOAL", "explanation": "The requested goal is not supported."}

        return {"decision": "ALLOW", "risk": "LOW", "confidence": 0.95,
                "reason_category": "ACTION_ALLOWED", "explanation": "Allow-listed action appears aligned."}

    def inspect_output(self, output):
        found = []
        def walk(value, path=""):
            if isinstance(value, dict):
                for key, child in value.items():
                    current = f"{path}.{key}" if path else str(key)
                    if _normalise_key(key) in SENSITIVE_KEYS:
                        found.append(current)
                    walk(child, current)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")
            elif isinstance(value, str):
                if any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS):
                    found.append(path or "$")
        walk(output)
        return {"decision": "BLOCK" if found else "ALLOW",
                "risk": "HIGH" if found else "LOW",
                "reason_category": "SENSITIVE_OUTPUT" if found else "OUTPUT_CLEAN",
                "sensitive_fields": found}

    def sanitize_output(self, output):
        if isinstance(output, dict):
            return {key: self.sanitize_output(value) for key, value in output.items()
                    if _normalise_key(key) not in SENSITIVE_KEYS}
        if isinstance(output, list):
            return [self.sanitize_output(value) for value in output]
        if isinstance(output, str) and any(pattern.search(output) for pattern in SECRET_VALUE_PATTERNS):
            return "[REDACTED: credential-like value]"
        return output
