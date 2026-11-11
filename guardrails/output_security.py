"""Unified tool-output inspection.

EVERY string in a tool output (plain string, nested dict values, list items; not just one field) is
checked by three independent checks and the STRICTEST decision wins, so an ALLOW from one check can
never override an ESCALATE/BLOCK from another:
  1. sensitive data   - sensitive keys / credential-looking values
  2. deterministic rules - the shared instruction/exfiltration rules (guardrails/rules.py)
  3. classifier        - strings of >= MIN_CLASSIFIED_WORDS words, using the active thresholds
Values that merely echo a validated tool argument are skipped (they carry no new content).
"""
from guardrails import rules
from guardrails.config import MIN_CLASSIFIED_WORDS

_ORDER = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
BLOCKED_TEXT = "[BLOCKED: untrusted tool text requires review]"


def walk_strings(value, path="$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from walk_strings(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            yield from walk_strings(child, f"{path}[{i}]")


def _redact(value, bad, path="$"):
    if isinstance(value, str):
        return BLOCKED_TEXT if path in bad else value
    if isinstance(value, dict):
        return {k: _redact(v, bad, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, bad, f"{path}[{i}]") for i, v in enumerate(value)]
    return value


def inspect_tool_output(guardrail, output, config=None, echoed_values=()):
    echoed = {str(v) for v in echoed_values if isinstance(v, str)}
    components, flagged = [], {}

    sensitive = guardrail.inspect_output(output)
    components.append({"check": "sensitive_data", "decision": sensitive["decision"],
                       "reason_category": sensitive["reason_category"], "paths": sensitive.get("sensitive_fields", [])})

    rule_paths, class_rows = [], []
    for path, text in walk_strings(output):
        if text in echoed:
            continue
        hits = rules.scan(text)
        if hits:
            rule_paths.append(path)
            flagged[path] = "rule"
            continue
        if len(text.split()) >= MIN_CLASSIFIED_WORDS:
            res = guardrail.inspect_untrusted_content(text, config)
            if res["decision"] != "ALLOW":
                class_rows.append({"path": path, "decision": res["decision"], "reason_category": res["reason_category"],
                                   "injection_probability": res.get("injection_probability")})
                flagged[path] = "classifier"
    components.append({"check": "instruction_rules", "decision": "BLOCK" if rule_paths else "ALLOW",
                       "reason_category": "UNTRUSTED_INSTRUCTION_PATTERN" if rule_paths else "NO_RULE_HIT", "paths": rule_paths})
    worst_class = max(class_rows, key=lambda r: _ORDER[r["decision"]], default=None)
    components.append({"check": "classifier", "decision": worst_class["decision"] if worst_class else "ALLOW",
                       "reason_category": worst_class["reason_category"] if worst_class else "LOW_INJECTION_PROBABILITY",
                       "paths": [r["path"] for r in class_rows]})

    winner = max(components, key=lambda c: _ORDER[c["decision"]])  # first strictest component
    decision = winner["decision"]
    if decision == "ALLOW":
        safe_output, risk, explanation = output, "LOW", "All output checks passed."
    else:
        safe_output = _redact(guardrail.sanitize_output(output), set(flagged))
        risk = "HIGH" if decision == "BLOCK" else "MEDIUM"
        explanation = f"Strictest output check: {winner['check']} -> {decision}."
    return {"decision": decision, "risk": risk, "reason_category": winner["reason_category"],
            "decided_by": f"output_guard:{winner['check']}", "explanation": explanation,
            "components": components, "safe_output": safe_output}
