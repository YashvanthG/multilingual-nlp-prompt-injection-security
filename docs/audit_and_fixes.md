# Audit findings and how each was addressed

Audit evidence came from running the unmodified code (see `reports/baseline_before/`). "Verified by" names the test or run.

| # | Finding (audit) | Change | Verified by |
|---|---|---|---|
| F2 | Tool output inspected only if a dict with a `summary` key; string/other-key output with injection returned ALLOW | `output_security.inspect_tool_output` inspects every string; sensitive, rule and classifier checks combined, strictest wins; old separate `tool_text_injection_inspection` stage removed | `tests/test_output_security.py`; suite T09, T20 |
| F3 | All retained lines had to score < 0.42 individually, *before* the Groq document review → benign mail rejected, Groq review unreachable | Retained text is inspected as a whole (+ per paragraph for multi-paragraph text); uncertainty goes to Groq (Hybrid) or ESCALATE (local); classifier/rule BLOCK is final | `tests/test_pipeline_regressions.py::UncertaintyPolicy` |
| F4 | Classifier domain shift on short agent-style requests/emails | Added 833 synthetic labelled agent-style training rows (held-out 303 rows with disjoint wording, never fitted); retrained; before/after reported | `reports/policy_evaluation.*` |
| F5 | Clause-level sanitizer left residual attack sentences; no block isolation | `guardrails/sanitizer.py`: notice-block and clause-level isolation using shared rules | `tests/test_rules_sanitizer.py`; observed Cases 1 and 5 |
| F6 | Pattern gaps (override/forget, fake admin notices, hidden instructions, bank details) and duplicated pattern lists | `guardrails/rules.py` single shared rule set; entirely malicious documents → `BLOCK / MALICIOUS_DOCUMENT` | same; suite T03, T10 |
| F7 | Planner fell back to `public_lookup` for every unrecognised task | Planner returns local / tool / unsupported; documents answered locally and never given to tools | `PlanningAndRouting` tests; suite T01, T06, T07… |
| F8 | Numeric dates not extracted; no ambiguity flag | `simulation/extraction.py` | `tests/test_extraction.py`; suite T06 (mock) |
| F9 | No deterministic block for direct sensitive-data requests (Groq-only) | Rule-based hard BLOCK at the input stage, before any Groq call | Case 4 test; suite T04 (`groq_calls == 0`) |
| F10 | Whole-document BLOCK did not stop a run | Retained text judged as a whole; classifier BLOCK of retained text is final | `test_classifier_block_on_retained_text_not_overridable` |
| F11 | Conflicting ALLOW/ESCALATE stage verdicts displayed | Single strictest verdict; `final_verdict` stage lists every stage verdict and `decided_by` | `VerdictConsistency` tests |
| F12 | Stale docs/test counts/messages; duplicate `ALLOWED_TOOLS`; Home Hybrid vs Testing Lab Local | Docs rewritten; `ALLOWED_TOOLS` and thresholds centralized; Home and Testing Lab share the Security Settings | `tests/test_config.py` |
| — | 20-scenario script did not execute anything | `guardrails_test_suite.py` runs the real pipeline, machine-checkable expectations, TXT/JSON reports | `tests/test_harness.py` |
| — | Reported metrics were at a 0.5 cutoff only | `evaluate_policy.py` evaluates the deployed 3-decision policy; per-request p50/p95/p99 | `reports/policy_evaluation.json` |

Not changed: the Groq provider/model (`openai/gpt-oss-120b`), the hard tool allow-list, independent authorization, the safe AST calculator, the thresholds (0.72 / 0.42 kept).

## Final verification pass
| Item | Outcome |
|---|---|
| Request-review Groq excerpt | **Fixed:** the sanitized document excerpt sent with an uncertain *request* was not redacted (only the separate document review redacted e-mail/phone/credential patterns). It now goes through the same minimization (`tests/test_pipeline_regressions.py::test_request_review_excerpt_is_redacted_like_document_review`, and a UI-level check). |
| Duplicated constants | **Fixed:** 1000/2500-character Groq limits, 160-character query limit, word-count minimums and upload limit now have one definition in `guardrails/config.py`; `train.py`/`evaluate_policy.py`/`app.py` take 0.42/0.72 from `DEFAULTS` instead of literals. |
| Fake-admin-notice case | Added to the harness as additional case R21 (core suite stays 20); passes offline and mock with the real model. |
| T06/T14/T15, T11 | Root cause diagnosed (feature contributions in README); **not** changed — no thresholds lowered, no allow-list, no retraining. |
| Settings controls | Verified by headless `AppTest`: a threshold and a second numeric setting changed in the sidebar alter the trace, the Groq call/no-call decision and the excerpt length; Testing Lab uses the same configuration; Reset and a fresh session restore defaults. |
| Documentation | README, evaluation report, architecture and summaries corrected (Hybrid data flow, test count, categories of results, limitations). No project PDF exists in the repository, so none was changed. |
