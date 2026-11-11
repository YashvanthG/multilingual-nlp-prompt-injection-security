# Release notes — security and reliability pass

## Changes
- Reject non-finite, boolean, zero, negative, and out-of-range synthetic money amounts.
- Validate the demo balance and transaction sequence before a money operation.
- Prepare each transaction record before committing the balance and history update.
- Record `load_funds` as a credit transaction so the synthetic ledger remains auditable.
- Use source-neutral alert wording for quarantined retrieved content; identify email only when the source is an email.
- Replace the absolute `.env` filesystem path in provider diagnostics with a safe project-level label.
- Add regression tests for invalid numeric values, invalid transaction counters, atomicity, and load-funds history.

## Verification in this build environment
- `python -m pytest -q`: 150 passed, 5 skipped, 19 subtests passed.
- `python -m compileall -q app.py guardrails personal_agent simulation tests`: passed.
- `python guardrails_test_suite.py`: 20/21 scenarios passed in offline mode and 20/21 in mocked mode. T11 remains a known benign-text false positive and is documented rather than hidden by lowering thresholds or weakening policy.
- Live Groq requests and a real browser interaction were not tested in this pass.

## Scope and limitations
This is a local academic security demonstration with synthetic email and banking data. It is not suitable for real financial actions, real inbox access, or production deployment. Existing classifier limitations and the T11 false positive remain. Per-run tool idempotency remains in the agent orchestration layer; the synthetic tool functions themselves are not a persistent transaction service.
