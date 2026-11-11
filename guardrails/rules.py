"""Shared deterministic security rules (single copy used by every stage).

These rules are *independent of the classifier and of Groq*: a rule hit is a hard local BLOCK /
quarantine that no LLM review can override. They are heuristics with known gaps (paraphrase,
other languages). Spanish coverage is a small illustrative set, NOT a multilingual guarantee.

Matched text is never returned, so rule hits can be written to traces without echoing content.
"""
from __future__ import annotations

import re

_F = re.I | re.M


def _c(pattern):
    return re.compile(pattern, _F)


# --- sensitive targets (centralised list) ----------------------------------------------------
SENSITIVE_TARGET = (
    r"(?:bank\s+(?:details|accounts?|account\s+(?:details|numbers?)|balances?|statements?)"
    r"|account\s+(?:numbers?|details|balances?)|credit\s+cards?(?:\s+numbers?)?|card\s+numbers?"
    r"|social\s+security(?:\s+numbers?)?|ssn|passwords?|passwd|passcodes?|api[\s_-]?keys?|access\s+tokens?"
    r"|auth(?:entication)?\s+tokens?|secret\s+(?:keys?|tokens?)|private\s+keys?|credentials?"
    r"|login\s+(?:details|credentials)|secrets"
    r"|(?:customer|client|user|employee|patient)s?['’]?\s+(?:records?|database|list|account\s+details)"
    r"|(?:private|confidential|personal|sensitive)(?:\s+(?:customer|client|account|financial))?\s+(?:information|data|records?|details|files?)"
    r"|payroll\s+records?|customer\s+database"
    # Spanish (small illustrative set)
    r"|contraseñas?|claves?(?:\s+(?:de\s+)?(?:api|secretas?))?|credenciales|datos\s+bancarios|cuentas?\s+bancarias?)"
)
_REQUEST_VERBS = (
    r"(?:find|get|send|give|show|tell|reveal|disclose|retrieve|fetch|search(?:\s+for)?|look\s*up|list|dump|extract|"
    r"steal|exfiltrate|leak|e-?mail|forward|print|share|provide|include|export|download|access|obtain|collect|read|"
    r"output|display|expose|copy|"
    r"revela|muestra|env[ií]a|dame|comparte|divulga)"
)
_NEGATION = re.compile(r"\b(?:never|not|n['’]t|avoid|without|no\s+one|nobody|cannot|can['’]t)\b[^.!?\n]{0,25}$", re.I)

# --- rule table: (category, rule_id, pattern) ------------------------------------------------
_RULES = [
    # instruction override / forget / disregard
    ("OVERRIDE", "override_instructions", _c(
        r"\b(?:ignore|disregard|forget|override|bypass|discard|drop|skip|stop\s+following)\b[^.!?\n]{0,40}?"
        r"\b(?:all|any|every|the|your|my|these|those|previous|prior|above|earlier|preceding|former|current|existing|safety|security|rules?\s+you)\b"
        r"[^.!?\n]{0,40}?\b(?:instructions?|rules?|restrictions?|guidelines?|polic(?:y|ies)|directives?|prompts?|guardrails?|constraints?|context|safeguards?)\b")),
    ("OVERRIDE", "ignore_the_user", _c(
        r"\b(?:ignore|disregard|forget)\s+(?:the\s+|this\s+|that\s+)?(?:user|human|operator|developer)(?:['’]s)?"
        r"(?:\s+(?:request|question|message|prompt|instructions?))?\b")),
    ("OVERRIDE", "disable_protections", _c(
        r"\b(?:override|bypass|circumvent|disable|turn\s+off)\b[^.!?\n]{0,30}?\b(?:system|safety|security|guardrails?|filters?|restrictions?|safeguards?)\b")),
    ("OVERRIDE", "replacement_instructions", _c(
        r"\b(?:follow|obey)\s+(?:these|the\s+following|my)\s+(?:new\s+)?instructions?\s+instead\b"
        r"|\b(?:your|the)\s+(?:new|real|true|actual)\s+(?:instructions?|task|goal|purpose)\b"
        r"|\b(?:from\s+now\s+on|henceforth),?\s+you\s+(?:will|must|shall|are|only)\b"
        r"|\bpay\s+no\s+attention\s+to\b[^.!?\n]{0,30}\b(?:instructions?|directions?|rules?)\b"
        r"|\b(?:instructions?|rules?|guidelines?|restrictions?)\s+(?:no\s+longer\s+apply|do(?:es)?\s+not\s+apply)\b")),
    # fake authority / administrator notices
    ("AUTHORITY", "fake_notice_header", _c(
        r"^\W{0,4}(?:system|administrator|admin|developer|root|security\s+team|ai)\b[^\n]{0,40}?\b(?:notice|override|directive|announcement|broadcast|instructions?)\b")),
    ("AUTHORITY", "system_override_phrase", _c(
        r"\b(?:system|admin(?:istrator)?|developer|root)\s+(?:administrator\s+|admin\s+)?(?:override|notice|directive|broadcast)\b")),
    ("AUTHORITY", "ai_assistant_banner", _c(r"\b(?:ai\s+assistant|ai\s+agent|llm|chatbot)\s*[—–:-]")),
    ("AUTHORITY", "authorization_claim", _c(
        r"\b(?:administrator|admin|system|developer)\s+(?:authori[sz]ation|approval|access|clearance)\s+(?:has\s+been\s+|is\s+|was\s+)?(?:granted|given|confirmed|verified|approved)\b")),
    ("AUTHORITY", "new_system_instructions", _c(
        r"\b(?:new|updated|revised)\s+system\s+(?:instructions?|prompt|rules|policy|polic(?:y|ies)|directives?)\b")),
    ("AUTHORITY", "restrictions_obsolete", _c(
        r"\b(?:previous|prior|earlier|existing|all)\s+(?:\w+\s+){0,2}(?:restrictions?|rules|instructions|polic(?:y|ies)|limitations?)\s+(?:are|were|have\s+been)\s+(?:now\s+)?"
        r"(?:obsolete|void|revoked|lifted|removed|cancell?ed|invalid|no\s+longer\s+(?:apply|valid))\b")),
    ("AUTHORITY", "role_takeover", _c(
        r"\byou\s+are\s+now\s+(?:the\s+|an?\s+)?(?:system|admin(?:istrator)?|developer|root|unrestricted|dan)\b|\bdeveloper\s+mode\b|\bjailbreak(?:en)?\b")),
    ("AUTHORITY", "vocative_command", _c(
        r"\bassistant\s*,\s*(?:please\s+)?(?:you\s+(?:must|should|need\s+to)\s+)?(?:email|send|forward|ignore|reveal|disclose|delete|transfer|retrieve|search|print|output|list|give|share|post|upload|execute|run)\b"
        r"|\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|llm|agent|model)\b")),
    # revealing hidden instructions / configuration
    ("REVEAL_HIDDEN", "reveal_hidden_instructions", _c(
        r"\b(?:reveal|disclose|show|print|output|display|expose|leak|dump|repeat|tell\s+me|share|give\s+me|muestra|revela)\b[^.!?\n]{0,50}?"
        r"\b(?:system\s+prompt|hidden\s+(?:prompt|instructions?|rules)|internal\s+(?:configuration|config|instructions?|settings|rules)|"
        r"developer\s+(?:instructions?|prompt|message)|(?:initial|original|secret)\s+(?:instructions?|prompt)|"
        r"your\s+(?:own\s+)?(?:instructions|prompt|configuration|rules)|instrucciones\s+ocultas)\b")),
    # concealment / answer-injection directives
    ("DIRECTIVE", "conceal_from_user", _c(
        r"\b(?:do\s+not|don['’]t|never)\s+(?:reveal|mention|tell|disclose|inform|let)\b[^.!?\n]{0,40}\b(?:instructions?|the\s+user|this|that|anyone)\b"
        r"|\bkeep\s+(?:this|these|it)\b[^.!?\n]{0,20}\bsecret\b")),
    ("DIRECTIVE", "include_in_answer", _c(
        r"\binclude\s+(?:them|it|this|these|the\s+(?:results?|details|information|data))\s+in\s+your\s+(?:answer|response|reply|summary|output)\b")),
    # exfiltration of bulk data to an outside destination
    ("EXFIL", "send_everything_out", _c(
        r"\b(?:e-?mail|send|forward|post|upload|transfer|exfiltrate|leak|copy)\b[^.!?\n]{0,60}?\b(?:all|every|entire|full|whole|complete|everything)\b"
        r"[^.!?\n]{0,50}?\b(?:to|at|via)\b\s+(?:[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+|me\b|an?\s+external|this\s+address|an\s+outside)")),
    # Spanish override (small set)
    ("OVERRIDE", "override_es", _c(r"\b(?:ignora|olvida|omite|descarta)\s+(?:todas?\s+)?(?:las\s+)?(?:instrucciones|reglas|indicaciones)(?:\s+(?:anteriores|previas))?\b")),
]

# category -> (reason_category, human explanation)
CATEGORY_REASON = {
    "SENSITIVE_REQUEST": ("SENSITIVE_DATA_REQUEST", "Asks to retrieve or reveal protected data (bank details, customer records, credentials, keys)."),
    "OVERRIDE": ("INSTRUCTION_OVERRIDE", "Tries to override, forget or replace the agent's instructions."),
    "AUTHORITY": ("FAKE_AUTHORITY_NOTICE", "Claims administrator/system authority or announces new system instructions."),
    "REVEAL_HIDDEN": ("HIDDEN_INSTRUCTION_REQUEST", "Asks the agent to reveal hidden instructions or internal configuration."),
    "EXFIL": ("DATA_EXFILTRATION_INSTRUCTION", "Instructs the agent to send bulk data to an outside destination."),
    "DIRECTIVE": ("CONCEALMENT_DIRECTIVE", "Directs the agent to hide instructions or inject data into its answer."),
}
_PRIORITY = ["SENSITIVE_REQUEST", "OVERRIDE", "AUTHORITY", "REVEAL_HIDDEN", "EXFIL", "DIRECTIVE"]

_SENSITIVE_RE = re.compile(SENSITIVE_TARGET, re.I)
_SENSITIVE_REQ_RE = re.compile(rf"\b{_REQUEST_VERBS}\b[^.!?\n]{{0,80}}?\b{SENSITIVE_TARGET}\b", re.I)


def mentions_sensitive_target(text: str) -> bool:
    return bool(_SENSITIVE_RE.search(str(text or "")))


def _sensitive_request_hits(text: str):
    hits = []
    for m in _SENSITIVE_REQ_RE.finditer(text):
        before = text[max(0, m.start() - 30):m.start()]
        if _NEGATION.search(before):  # e.g. "never share passwords by email" is a warning, not a request
            continue
        hits.append(m)
    return hits


def scan(text: str) -> list:
    """Return [{category, rule}] for every deterministic rule that fires. Never returns matched text."""
    text = str(text or "")
    hits = []
    if _sensitive_request_hits(text):
        hits.append({"category": "SENSITIVE_REQUEST", "rule": "sensitive_data_request"})
    for category, rule_id, pattern in _RULES:
        if pattern.search(text):
            hits.append({"category": category, "rule": rule_id})
    return hits


def categories(hits) -> list:
    present = {h["category"] for h in hits}
    return [c for c in _PRIORITY if c in present]


def primary_reason(hits):
    """(reason_category, explanation) for the highest-priority category, or None."""
    cats = categories(hits)
    return CATEGORY_REASON[cats[0]] if cats else None
