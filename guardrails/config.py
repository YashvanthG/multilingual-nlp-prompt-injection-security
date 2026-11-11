"""Single source of truth for security defaults, validation and temporary overrides.

* Code-level defaults live ONLY here (`DEFAULTS`).
* The Streamlit UI builds a *temporary* `SecurityConfig` via `with_overrides()`; nothing is ever
  written to disk, `.env` or this file, so restarting the app restores `DEFAULTS`.
* Hard boundaries are deliberately NOT fields of `SecurityConfig` and so cannot be changed from
  the UI: deterministic rules (guardrails/rules.py), the approved tool universe `ALLOWED_TOOLS`,
  tool-output inspection and sensitive-output redaction.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, fields, replace

# Approved simulated tools. The UI may only NARROW the enabled subset, never extend it.
ALLOWED_TOOLS = frozenset({"get_weather", "calculator", "public_lookup"})
HYBRID, LOCAL_ONLY = "Hybrid cascade", "Local guardrail"
MODES = (HYBRID, LOCAL_ONLY)
UNGUARDED = "Unguarded baseline"  # experimental comparison only (evaluate_agent.py); never selectable in the UI

MIN_THRESHOLD_GAP = 0.01
DOC_CHARS_RANGE = (200, 2000)

# Fixed tuning constants (single definition, deliberately NOT exposed in the UI).
GROQ_REQUEST_CHARS = 2500            # max characters of a user request (+ sanitized context) sent to a Groq review
TOOL_QUERY_MAX_CHARS = 160           # max length of a simulated public_lookup query
MAX_UPLOAD_BYTES = 1_000_000         # .txt upload limit
MIN_SAFE_WORDS = 3                   # fewer retained words after quarantine = "no safe remainder"
RETAINED_PARAGRAPH_MIN_WORDS = 12    # paragraphs at least this long are also classified on their own
MIN_CLASSIFIED_WORDS = 4             # tool-output strings shorter than this skip the classifier (rules still run)


@dataclass(frozen=True)
class SecurityConfig:
    block_threshold: float = 0.72            # classifier probability >= this -> BLOCK
    escalate_threshold: float = 0.42         # classifier probability >= this -> ESCALATE
    mode: str = HYBRID                       # HYBRID may ask Groq about uncertain items; LOCAL_ONLY never does
    groq_request_review: bool = True         # Hybrid only: allow Groq review of an uncertain user request
    groq_document_review: bool = True        # Hybrid only: allow Groq review of uncertain sanitized document text
    groq_document_chars: int = 1000          # max characters of sanitized document text sent to Groq
    enabled_tools: tuple = tuple(sorted(ALLOWED_TOOLS))  # subset of ALLOWED_TOOLS the agent may use

    # ---- derived helpers -------------------------------------------------------------------
    @property
    def groq_allowed_for_requests(self) -> bool:
        return self.mode == HYBRID and self.groq_request_review

    @property
    def groq_allowed_for_documents(self) -> bool:
        return self.mode == HYBRID and self.groq_document_review

    @property
    def guarded(self) -> bool:
        return self.mode != UNGUARDED

    def as_dict(self) -> dict:
        data = asdict(self)
        data["enabled_tools"] = list(self.enabled_tools)
        return data


def validate(cfg: SecurityConfig, allow_experimental: bool = False) -> SecurityConfig:
    """Return `cfg` if valid, else raise ValueError with a readable message."""
    for name in ("block_threshold", "escalate_threshold"):
        value = getattr(cfg, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number.")
    if not 0.0 < cfg.escalate_threshold < cfg.block_threshold <= 1.0:
        raise ValueError("Thresholds must satisfy 0 < escalate_threshold < block_threshold <= 1.")
    if cfg.block_threshold - cfg.escalate_threshold < MIN_THRESHOLD_GAP:
        raise ValueError(f"block_threshold must exceed escalate_threshold by at least {MIN_THRESHOLD_GAP}.")
    allowed_modes = MODES + ((UNGUARDED,) if allow_experimental else ())
    if cfg.mode not in allowed_modes:
        raise ValueError(f"mode must be one of {allowed_modes}.")
    for name in ("groq_request_review", "groq_document_review"):
        if not isinstance(getattr(cfg, name), bool):
            raise ValueError(f"{name} must be true or false.")
    lo, hi = DOC_CHARS_RANGE
    if isinstance(cfg.groq_document_chars, bool) or not isinstance(cfg.groq_document_chars, int) or not lo <= cfg.groq_document_chars <= hi:
        raise ValueError(f"groq_document_chars must be an integer between {lo} and {hi}.")
    tools = tuple(cfg.enabled_tools)
    if not set(tools) <= ALLOWED_TOOLS:
        raise ValueError(f"enabled_tools may only contain approved simulated tools: {sorted(ALLOWED_TOOLS)}.")
    return replace(cfg, enabled_tools=tuple(sorted(set(tools))))


DEFAULTS = validate(SecurityConfig())


def with_overrides(base: SecurityConfig = DEFAULTS, allow_experimental: bool = False, **overrides) -> SecurityConfig:
    """Temporary, validated copy of `base`. Unknown keys are rejected."""
    known = {f.name for f in fields(SecurityConfig)}
    unknown = set(overrides) - known
    if unknown:
        raise ValueError(f"Unknown setting(s): {sorted(unknown)}")
    if "enabled_tools" in overrides:
        overrides["enabled_tools"] = tuple(overrides["enabled_tools"])
    return validate(replace(base, **overrides), allow_experimental=allow_experimental)


def modified_fields(cfg: SecurityConfig) -> list:
    return [f.name for f in fields(SecurityConfig) if getattr(cfg, f.name) != getattr(DEFAULTS, f.name)]


def describe(cfg: SecurityConfig) -> list:
    """Rows of {setting, default, effective, modified} for the UI and the trace."""
    changed = set(modified_fields(cfg))
    rows = []
    for f in fields(SecurityConfig):
        default, effective = getattr(DEFAULTS, f.name), getattr(cfg, f.name)
        rows.append({"setting": f.name, "default": list(default) if isinstance(default, tuple) else default,
                     "effective": list(effective) if isinstance(effective, tuple) else effective,
                     "modified": f.name in changed})
    return rows
