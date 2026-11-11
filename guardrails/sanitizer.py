"""Block/clause-level document sanitizer.

Isolation strategy (no reliance on a single marker or on line boundaries):
1. A *notice block* (a header line such as "[SYSTEM ADMINISTRATOR NOTICE]") is quarantined from the
   header to the end of its paragraph or an explicit "[END ...]"/divider line.
2. Otherwise every sentence/clause is scanned with the shared deterministic rules
   (guardrails/rules.py) and only the offending clauses are quarantined, so a malicious sentence
   hidden inside a benign paragraph is isolated while the rest is kept.
Quarantined text is returned for internal use only; the trace stores counts and categories, never text.
"""
from __future__ import annotations

import re

from guardrails import rules
from guardrails.config import MIN_SAFE_WORDS

_CLAUSE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9¡¿\[\"'“‘(])")
_NOTICE_HEADER = re.compile(
    r"^\W{0,4}(?:system|administrator|admin|developer|root|security\s+team|ai)\b[^\n]{0,40}?"
    r"\b(?:notice|override|directive|announcement|broadcast|instructions?|message|alert)\b\W{0,4}$", re.I)
_END_MARKER = re.compile(r"^\W{0,4}(?:end|fin)\b[^\n]{0,30}$|^\s*(?:[-=_*#]{3,})\s*$", re.I)


def _word_count(text: str) -> int:
    return len(re.findall(r"\w+", text, re.U))


def sanitize_document(text: str) -> dict:
    text = str(text or "")
    quarantined = []  # internal: {"kind","categories","text"}
    kept_paragraphs = []
    for paragraph in re.split(r"\n\s*\n", text):
        kept_lines, in_notice = [], False
        for line in paragraph.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if in_notice:
                quarantined[-1]["text"] += "\n" + stripped
                if _END_MARKER.match(stripped):
                    in_notice = False
                continue
            if _NOTICE_HEADER.match(stripped):
                quarantined.append({"kind": "notice_block", "categories": ["AUTHORITY"], "text": stripped})
                in_notice = True
                continue
            kept_clauses = []
            for clause in _CLAUSE_SPLIT.split(stripped):
                hits = rules.scan(clause)
                if hits:
                    quarantined.append({"kind": "clause", "categories": rules.categories(hits), "text": clause})
                else:
                    kept_clauses.append(clause)
            if kept_clauses:
                kept_lines.append(" ".join(kept_clauses))
        if kept_lines:
            kept_paragraphs.append("\n".join(kept_lines))
    safe_text = "\n\n".join(kept_paragraphs)
    cats = sorted({c for q in quarantined for c in q["categories"]})
    return {
        "safe_text": safe_text,
        "quarantined": quarantined,
        "quarantined_count": len(quarantined),
        "categories": cats,
        "retained_words": _word_count(safe_text),
        "has_safe_remainder": _word_count(safe_text) >= MIN_SAFE_WORDS,
        "status": "quarantined" if quarantined else "unchanged",
    }
