# Architecture

See the flow diagram and rules in `README.md`. Summary of responsibilities:

| Module | Responsibility |
|---|---|
| `guardrails/config.py` | Only place with defaults (0.72 / 0.42 …). `SecurityConfig` is frozen; `with_overrides()` returns a validated temporary copy; `ALLOWED_TOOLS` is a constant the UI cannot extend. |
| `guardrails/rules.py` | Deterministic rule table + sensitive-term list. Returns `{category, rule}` only (never matched text). |
| `guardrails/sanitizer.py` | Quarantines (a) notice blocks from a header line to the paragraph end / `[END …]` marker, (b) any clause that hits a rule. Returns retained text, counts, categories. |
| `guardrails/classifier.py` | Loads the sklearn pipeline. `inspect_request` (rules → classifier), `inspect_untrusted_content`, `inspect_action`, sensitive-output helpers. Thresholds come from the per-call config. |
| `guardrails/output_security.py` | `inspect_tool_output`: sensitive-data, rule and classifier checks over every string; strictest verdict; redaction of flagged strings. |
| `guardrails/tool_security.py` | Hard allow-list authorization, independent of every other stage. |
| `simulation/agent.py` | Orchestration, uncertainty policy, Groq calls, strictest-verdict aggregation, audit trace. |
| `simulation/extraction.py` | Local date/time extraction (original string preserved, numeric ambiguity flagged) and extractive summary. |
| `simulation/tools.py` | Synthetic weather/calculator/lookup; independently re-checks the allow-list. |

Fixed tuning constants (Groq request limit, lookup query length, upload limit, word-count minimums) are defined once in `guardrails/config.py` and imported by the modules that use them; only the settings in `SecurityConfig` are changeable at runtime.

Data sent to Groq (Hybrid mode, uncertain items only): the user request and a bounded, redacted excerpt of the *sanitized* retained document text. Local extraction/summarization itself never calls an LLM. See README, "What is processed locally and what can leave the machine".

Trace stages (when applicable): `provider_configuration`, `effective_configuration`, `input`, `untrusted_content_inspection`, `groq_document_review`, `groq_security_review`, `planner`, `local_processing`, `action_guard`, `tool_execution`, `output_guard`, `final_verdict`.

## Separate personal-agent demonstration client

`personal_agent/` is a separate Groq-powered tool-calling client mounted as one additional Streamlit page. It does not replace `simulation/agent.py` or alter the research pipeline. The client shares the existing `effective_config()` resolver and `guardrails.llm_checker.review()` security reviewer; the Groq tool-calling request itself uses the same configured model and OpenAI-compatible chat-completions endpoint because the existing reviewer only returns security decisions and does not expose an agent tool-calling interface.

| Module | Responsibility |
|---|---|
| `personal_agent/agent.py` | Same bounded Groq agent for both modes; request/document inspection, tool-call orchestration, output checks and trace |
| `personal_agent/tools.py` | Static JSON tool schemas, argument validation and local synthetic implementations |
| `personal_agent/environment.py` | Resettable fake inbox/tasks/calendar/bank/customer/receiver state |
| `personal_agent/scenarios.py` | Internal deterministic fixtures retained for offline security tests; the UI exposes only two guided scenarios |
| `personal_agent/ui.py` | Single chat-first Demo Agent page with two scenarios, two modes, tool cards and a concise run outcome |
| `guardrails/tool_security.py::inspect_personal_agent_action` | Small fixed-registry extension for the new tool names; sensitive operations are denied in Protected mode |

Protected flow: inspect the request using `Guardrail.inspect_request`; sanitize supplied text using `sanitize_document`; re-inspect retained text using `Guardrail.inspect_untrusted_content`; for an eligible uncertain item, use the existing Groq reviewer according to the current Security Settings; authorize each proposed safe tool using the fixed personal-agent adapter; sanitize retrieved email/knowledge text; inspect the resulting tool output with `inspect_tool_output`; return only accepted output to Groq. Sensitive tools are never authorized in Protected mode. Baseline uses the same prompt, model, tool schemas and synthetic data but skips these application-level guard checks.

The original `ALLOWED_TOOLS` constant, original `inspect_action`, classifier, training data, model artifact, thresholds, and existing evaluation/test expectations are unchanged. The two guided scenarios are a normal balance lookup and an email containing a synthetic transfer instruction. The page never reports an attack as successful or prevented unless the actual tool proposal, execution status, and trace support that statement. The trace execution field is synchronized with the action card; regression tests cover the previously inconsistent `not_run`/`executed` display.
