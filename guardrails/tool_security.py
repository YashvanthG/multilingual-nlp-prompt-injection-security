"""Independent tool authorization: the hard allow-list is enforced before any heuristic alignment logic.
The UI can only narrow `config.enabled_tools`; it can never add a tool outside ALLOWED_TOOLS."""
from guardrails.config import ALLOWED_TOOLS


def inspect_action(guardrail, user_goal, action, config=None):
    if not isinstance(action, dict) or action.get("tool") not in ALLOWED_TOOLS:
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "UNAUTHORIZED_TOOL", "explanation": "Tool is not allow-listed."}
    return guardrail.inspect_action(user_goal, action, config)

# Separate, fixed registry for the personal-agent demonstration client. The original
# ALLOWED_TOOLS set above remains unchanged for the research pipeline.
PERSONAL_AGENT_SAFE_TOOLS = frozenset({
    "list_emails", "create_task", "list_tasks", "create_calendar_event",
    "list_calendar_events", "search_knowledge_base", "calculate", "draft_email_reply",
})
PERSONAL_AGENT_SENSITIVE_TOOLS = frozenset({
    "check_bank_balance", "retrieve_bank_details", "send_money", "approve_transaction",
    "load_funds", "get_customer_records", "send_information_to_server",
})
PERSONAL_AGENT_TOOLS = PERSONAL_AGENT_SAFE_TOOLS | PERSONAL_AGENT_SENSITIVE_TOOLS

_AGENT_INTENT = {
    "list_emails": ("email", "e-mail", "mail", "inbox", "message"),
    "create_task": ("task", "todo", "to-do", "action item", "follow-up", "follow up", "reminder", "assignment"),
    "list_tasks": ("task", "todo", "to-do", "action item", "follow-up", "follow up"),
    "create_calendar_event": ("calendar", "event", "meeting", "schedule", "appointment"),
    "list_calendar_events": ("calendar", "event", "meeting", "schedule", "appointment"),
    "check_bank_balance": ("bank", "balance", "account balance", "demo balance"),
    "search_knowledge_base": ("knowledge", "notes", "handbook", "policy", "documentation", "search", "look up", "find"),
    "calculate": ("calculate", "compute", "plus", "minus", "multiply", "divide", "sum", "total"),
    "draft_email_reply": ("draft", "reply", "respond", "response", "email"),
}


def inspect_personal_agent_action(user_goal, action, *, enabled_tools=None, input_decision="ALLOW"):
    """Authorize a personal-agent tool proposal using a small extension to the existing guardrail.

    This is intentionally separate from ``inspect_action``: that original hard allow-list is
    preserved for the research agent. Sensitive demo tools are denied in Protected mode, except a read-only bank-balance lookup
    that directly matches the user's explicit goal; the remaining sensitive tools are Baseline-only.
    """
    if not isinstance(action, dict) or not isinstance(action.get("tool"), str):
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "INVALID_ACTION", "explanation": "Tool proposal must contain a tool name."}
    name = action["tool"]
    if name not in PERSONAL_AGENT_TOOLS:
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "UNAUTHORIZED_TOOL", "explanation": "Tool is not in the fixed personal-agent registry."}
    if not isinstance(action.get("arguments", {}), dict):
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "INVALID_ARGUMENTS", "explanation": "Tool arguments must be a JSON object."}
    if enabled_tools is not None and name not in set(enabled_tools):
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "TOOL_DISABLED", "explanation": "This tool is disabled in the playground."}
    if input_decision != "ALLOW":
        return {"decision": input_decision if input_decision in {"BLOCK", "ESCALATE"} else "BLOCK",
                "risk": "HIGH" if input_decision == "BLOCK" else "MEDIUM", "confidence": 1.0,
                "reason_category": "INPUT_NOT_CLEARED", "explanation": "The request was not cleared by the input security checks."}
    # A read-only balance lookup is permitted when it directly matches the user's explicit goal. Money movement, account-detail disclosure, approvals, customer
    # records and receiver writes remain denied in Protected mode.
    if name in PERSONAL_AGENT_SENSITIVE_TOOLS and name != "check_bank_balance":
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 1.0,
                "reason_category": "SENSITIVE_TOOL_DENIED", "explanation": "This sensitive synthetic operation is denied in Protected mode."}
    goal = str(user_goal or "").casefold()
    if name == "calculate":
        import re
        has_math = bool(re.search(r"\d\s*[+*/%]\s*\d", goal))
    else:
        has_math = False
    intents = _AGENT_INTENT.get(name, ())
    if not has_math and not any(term in goal for term in intents):
        return {"decision": "BLOCK", "risk": "HIGH", "confidence": 0.95,
                "reason_category": "ACTION_MISALIGNMENT", "explanation": "The proposed tool does not match the user's stated goal."}
    return {"decision": "ALLOW", "risk": "LOW", "confidence": 0.95,
            "reason_category": "AGENT_TOOL_ALLOWED", "explanation": "The tool is in the fixed safe registry and matches the user's stated goal."}
