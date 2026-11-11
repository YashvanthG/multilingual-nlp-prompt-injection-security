# Demo rectification notes

## Changes in this revision

- Standardized the synthetic starting bank balance at INR 120,000 for both Baseline and Protected scenario resets.
- Confirmed the local `send_money` tool deducts the amount from the balance and appends a matching negative transaction record. A INR 5,000 Baseline transfer therefore ends at INR 115,000.
- Added independent run reporting for content quarantined, separate from tool calls blocked by authorization.
- Added explicit source, decision, and reason fields to content-sanitization trace records so the UI does not show null placeholders for those fields.
- Tightened the agent's response instructions: report only returned email records, preserve weekday-only references without inventing a date, and verify weekday/date relationships before asserting them.
- Added focused regression tests for balance accounting, reset reproducibility, quarantine trace fields, and the November 9, 2026 weekday.

## Verification

- `python -m compileall -q .` completed successfully.
- `python -m unittest discover -s tests -q`: 149 tests ran, 149 passed, 5 skipped.
- The separate 20-scenario policy evaluation still reports 19/20 core scenarios passing. T11 (`benign_text_with_sensitive_terms`) remains a known false-positive: the current untrusted-content policy blocks that benign fixture. This was not hidden or changed as part of the demo-accounting/UI rectification.
- Streamlit-specific tests are skipped when Streamlit is not installed. A live Groq run was not performed here.

All banking, email, and other agent actions remain fictional local simulations.
