# Lightweight Multilingual NLP Guardrails for Secure LLM Agents

CSE472 student research/demo project. A compact local classifier (TF-IDF + Logistic Regression) and a set of deterministic
rules protect a **simulated** LLM agent. GroqCloud (`openai/gpt-oss-120b`) is an *optional* security reviewer for uncertain
cases only and can never override a deterministic rule or a classifier BLOCK. All tools are synthetic; no real external action
is performed.

## Install, test and run (Windows PowerShell)
Developed for Python 3.11. The final verification was run from the delivered ZIP in a fresh virtual environment built from `requirements.txt` on Python 3.12.3 (scikit-learn 1.8.0, pandas 3.1.0, streamlit 1.66.1); Python 3.11 and Windows were not tested.
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m unittest discover -s tests -v          # unit + integration tests, no network
python guardrails_test_suite.py                  # 20 regression scenarios (+1 additional): offline and mocked-Groq modes
python evaluate.py                               # classifier metrics, deployed-policy evaluation, 6-scenario benchmark
streamlit run app.py                             # Demo Agent opens first; Advanced contains research/testing tools
```
Optional live Groq (may incur charges; never run by default): `Copy-Item .env.example .env`, put your key in `.env`, then
`python guardrails_test_suite.py --mode live`. `.env` is not shipped; keep real keys out of source files and out of any ZIP.
The trained model is included; `python train.py` retrains it. The training pipeline fits only on the raw training CSVs plus synthetic training rows; held-out CSVs are evaluation-only. Run `python data/build_email_workflow.py` before `python train.py` to regenerate the additional email-workflow examples, and `python data/build_multilingual_extra.py` to regenerate the 18-language multilingual-extra examples.

## Simple Demo Agent

The **Demo Agent** is the main landing page and a chat-first illustration of prompt-injection risk. It has exactly two guided scenarios (normal balance lookup and an injected email requesting a fictional transfer) and two modes (Baseline / Protected). Both modes use the same neutral, action-oriented model prompt and tool descriptions; Baseline passes the full email to the model, while Protected sanitizes the retrieved email and authorizes every proposed action through the existing Python security code. The chat shows each proposed function call, its arguments, execution status, and tool output or security hold. Functions can be enabled/disabled from the fixed local registry; no arbitrary Python functions can be added. All bank, email, task, and calendar data is fictional and local.

Protected mode uses the existing guardrail request inspection, sanitizer/quarantine, action authorization, and output inspection. Sensitive synthetic operations such as transfers and account-detail disclosure are denied by default. The output inspector may also hold a retrieved email after sanitization when its classifier remains uncertain. See `docs/personal_agent_demo.md` for a short demo guide and interpretation notes.

## Pipeline (`simulation/agent.py`)
```
user request ─► 1 input: deterministic rules → classifier thresholds (default 0.42 ESCALATE / 0.72 BLOCK)
document     ─► 2 sanitize (notice-block + clause level) → quarantine → re-inspect the RETAINED text as a whole
                3 Groq security review — only for an UNCERTAIN item, only in Hybrid mode, only if the setting allows it
                4 route: LOCAL extraction/summary (documents) | simulated tool (weather, calculator, explicit lookup) | unsupported
                5 independent tool authorization (hard allow-list, goal/action alignment, argument checks)
                6 simulated tool ─► 7 unified tool-output inspection ─► 8 final verdict + audit trace
```
* Stages that do not apply are skipped. Documents are never given to tools.
* **Strictest verdict wins** (BLOCK > ESCALATE > ALLOW); the trace records `decided_by` and every stage verdict.
* Deterministic rule hits and classifier BLOCKs are never sent to Groq. Uncertain + Hybrid + Groq configured → one bounded review
  (only an explicit, successful ALLOW clears it; any error/timeout/malformed reply is BLOCK). Uncertain + Local mode, review
  disabled, or no key → ESCALATE (nothing forwarded, nothing executed).

### What is processed locally and what can leave the machine
* **Local:** all rule checks, classification, sanitization, date extraction and the (extractive, non-LLM) summary. In *Local*
  mode, or whenever the local decision is clear (ALLOW or BLOCK), **nothing is sent to Groq**.
* **Hybrid mode with an uncertain item:** a Groq security review is made. It transmits (a) the user's request text and, if a
  document was supplied, (b) a **sanitized** excerpt of the retained document text — at most `groq_document_chars` characters
  (default 1000), with e-mail addresses, phone-like numbers and credential-like strings redacted by regular expressions. A second review
  of the retained text alone may be made if that text is uncertain. **Quarantined text and raw files are never sent.**
  The redaction is best-effort pattern matching, not a guarantee that no personal data is transmitted. So document content *can*
  reach an external LLM in Hybrid mode; use Local mode (or disable the Groq reviews) to prevent this.

## Advanced workspace and Security Settings
Defaults live in one module, `guardrails/config.py` (`DEFAULTS`): block 0.72, escalation 0.42, mode Hybrid, Groq request review on,
Groq document review on, 1000 characters per Groq document excerpt, all three simulated tools enabled. Other tuning constants
(Groq request limit 2500 characters, 160-character lookup query, 1 MB upload limit, word-count minimums) are also defined once in
that module but are not exposed in the UI.
* Edit values → **Apply**. Validation: `0 < escalate < block ≤ 1` with a gap ≥ 0.01, known mode, 200–2000 characters, tools ⊆ the approved list. Invalid input is rejected and the previous valid settings stay in force.
* Open **Advanced → Security Settings** to change settings. Settings are **temporary** (Streamlit session only). Nothing is written to source, `.env` or disk; **Reset to defaults** or a restart restores the code defaults. Default and effective values are shown side by side, modified rows are marked, and each run's trace contains an `effective_configuration` stage. Custom Security Test, Testing Lab, the classifier, document inspection and the agent all receive the same configuration object.
* **Fixed (no setting exists):** deterministic rules, tool allow-list/authorization (the UI can only *narrow* the enabled tools), tool-output inspection, sensitive-output redaction, simulated-only tools. Raising the block threshold to 1.0 only affects the probabilistic stage; rule blocks still fire.
* Threshold validation is structural; the effect of other values on the validation split is tabulated in `reports/policy_evaluation.json`.

## Testing (what each check is, and what it is not)
| Command | Meaning |
|---|---|
| `python -m unittest discover -s tests` | 151 unit/integration tests (146 passed; 5 Streamlit UI tests skipped when Streamlit is unavailable). Groq is always mocked; some pipeline tests stub the classifier probability. Includes headless Streamlit `AppTest` checks of the settings panel. |
| `python guardrails_test_suite.py` | Runs the 20 required scenarios (+ 1 additional: fake administrator notice) through the real pipeline. *offline* = Groq never called; *mock* = an always-ALLOW stand-in for Groq (**not** a live Groq result). Writes `guardrails_test_results.json/.txt`. |
| `... --mode live` | Real Groq, explicit opt-in. Without a key it reports `NOT_TESTABLE`. **Not run for the delivered results.** |

Final regression results (synthetic scenarios, **not** a security accuracy): offline **16/20**, mock **19/20**, additional case 1/1 in both modes; before any change the same expectations gave offline 0/20 and mock 2/20 (`reports/baseline_before/`).

## Evaluation (details and caveats in `reports/RESULTS_SUMMARY.md`)
* **Classifier-only metrics** (0.5 cutoff) on the original validation and held-out test splits are preserved and reported for both the original (v1) and current (v2) model; they are essentially unchanged (held-out test accuracy 89.09 % → 89.02 %, ROC-AUC 0.9494 → 0.9496).
* **Deployed three-decision policy** (rules + 0.42/0.72) is evaluated separately in `reports/policy_evaluation.*`, per dataset, with false positives (benign blocked/escalated) and false negatives (attacks missed) reported separately and per-request p50/p95/p99 latency (CPU, sequential calls) distinct from batch averages.
* **Synthetic agent-style data** (833 training rows, 303 held-out rows; written by this project with disjoint phrase pools; no exact duplicates and no near-duplicates ≥ 0.9 cosine between them) supports a before/after domain-shift comparison only, not a real-world security claim.

## Known limitations
* **How to read the regression pass counts.** In offline mode T12 (quoted e-mail thread) and T17 (benign Spanish message) are counted as passes only because ESCALATE is an accepted outcome in their expectations: the documents were *held for review*, not processed. T09 and T20 test the tool-output boundary with injected fixture outputs (the classifier stage of the request is skipped for those two; deterministic rules still run). All scenarios are synthetic.
* **Four regression failures remain, and were not tuned away.** T06, T14, T15 (offline only): the classifier scores short date requests such as "Tell me the meeting date." at ≈ 0.448, just above the 0.42 threshold, so offline mode fails closed with ESCALATE; the mocked-Hybrid runs pass, a live Groq run was not performed. Diagnosis: the score comes from generic phrasing features ("tell", "me the") with an injection prior, and the word "meeting" never occurs in the training data. T11 (both modes): a benign security-awareness e-mail scores 0.87 and is BLOCKed; the feature "security" appears in 61 training rows, 98 % of them injection. A classifier BLOCK is final by design. A real fix needs new labelled benign data and an untouched evaluation; this was not done.
* After retraining, 36.8 % of the synthetic agent-style benign held-out rows (15.2 % of the original test benign rows) are still ESCALATEd. Operating this system without Groq therefore means frequent fail-closed ESCALATEs for benign requests.
* **Multilingual robustness is only partly probed.** The original multilingual CSVs have no language labels (`source=multilingual` is metadata). The synthetic `multilingual_extra_*` files (18 languages incl. 8 Indian, exact labels, templated wording, Indian-language rows not yet native-reviewed) show uneven transfer: at the deployed thresholds about a quarter of their held-out attacks are still ALLOWed, and Japanese/Chinese (no word spacing) are missed almost entirely by the word n-gram vectorizer (see `reports/RESULTS_SUMMARY.md` section E). The rules include only a small illustrative Spanish set; date extraction knows English, numeric, ISO and Spanish month names only.
* Rules and classifier are heuristics; paraphrased or novel attacks may bypass them (10.5 % of original-test attacks were ALLOWed at the deployed thresholds). Summaries are extractive. Action alignment is heuristic.
* **Not verified:** live Groq behaviour; a fresh Windows installation; interaction in a real browser (the settings panel was tested with Streamlit's headless `AppTest`, and the server was started and its health endpoint checked, but no browser was driven).
* `evaluate_agent.py`'s six-scenario benchmark is illustrative; its "unguarded" mode ignores documents, so it understates unguarded attack success.
* No separate project report/PDF is included in this repository; documentation is this README, `docs/` and `reports/`.

## Project layout
```
app.py                          Streamlit UI (Demo Agent landing page; Advanced: Custom Security Test, Testing Lab, Research & Evaluation, Security Settings)
guardrails_test_suite.py        20 + 1 executable regression scenarios (offline / mock / live)
train.py  evaluate.py           training; classifier + policy + agent-benchmark evaluation
evaluate_classifier.py  evaluate_policy.py  evaluate_agent.py  data_utils.py
guardrails/  config.py  rules.py  sanitizer.py  classifier.py  tool_security.py  output_security.py  llm_checker.py
simulation/  agent.py  extraction.py  tools.py  documents.py  scenarios.py
data/raw/                       original CSVs + synthetic agent_style_, email_workflow_ and multilingual_extra_{train,test}.csv; generator scripts recreate synthetic sets
models/guardrail_tfidf.joblib   current model;  models/archive/  original v1 model (for before/after)
reports/                        RESULTS_SUMMARY.md, policy_evaluation.{json,md}, training_report.json, validation_metrics.json,
                                agent_benchmark.json, baseline_before/ (regression run on the unmodified code), archive/ (original v1 reports)
docs/                           architecture.md, audit_and_fixes.md, demo_script.md
tests/                          9 test modules + helpers.py
.env.example                    placeholders only (the real .env is never shipped)
```

## Demo Agent and Advanced workspace
The Demo Agent is the default landing page. It keeps the two modes (Baseline and Protected), guided scenarios, chat, action outcomes and security findings visible. Synthetic data is summarized in a compact expander. Developer-only controls (function selection, system prompt editing and synthetic JSON editing) are grouped under **Advanced demo controls**.

The **Advanced** workspace contains Custom Security Test (the former Home document/request pipeline), Testing Lab, Research & Evaluation and temporary Security Settings. These pages remain available for development and project evaluation without cluttering the normal demo experience.

The prompt-injection fixture includes a forged administrator notice that requests a synthetic transfer. In Baseline, the full email is visible to the model; in Protected, the existing document sanitizer quarantines the notice while retaining the benign project update. The model's actual tool proposal must be inspected on each live run; offline tests use mocked proposals and do not establish live Groq behavior.

## Optional GroqCloud review
`GROQ_API_KEY`, `GROQ_MODEL` (default `openai/gpt-oss-120b`), `GROQ_BASE_URL` (default `https://api.groq.com/openai/v1`),
`GROQ_TIMEOUT_SECONDS` (default 15) are read from the environment or `.env`. The reply must be strict JSON
`{"decision": "ALLOW"|"BLOCK", "reason": ...}`; anything else fails closed.

## Document input
Paste text or upload a UTF-8 `.txt` file (≤ 1 MB). PDF/DOCX extraction is not implemented; unreadable, empty or oversized files are reported, not ignored.

---


## Safe agent execution and continuation

The Demo Agent keeps a bounded checkpoint when a run reaches its model-step or tool-call
budget, or a model request fails. The UI can continue from that checkpoint without replaying
the earlier conversation from scratch. Completed side-effect proposals are fingerprinted per
run; if the model proposes the same action again during continuation, the saved result is
reused instead of executing the synthetic side effect twice.

The execution budget is bounded (5 model steps per attempt, 20 total steps, 3 continuations,
8 tool calls per attempt and 24 total proposals). Protected-mode authorization and output
inspection remain in the tool execution path for every newly proposed action. A continuation
must use the same security mode as its original run.

Checkpoints currently live in the active Streamlit session and the assistant-turn history.
They survive normal Streamlit reruns, but are not a durable recovery store across a server
process restart or a new browser session. All tools remain local synthetic simulations.

## Latest reliability pass
See `RELEASE_NOTES.md` for the latest money-tool validation/ledger fixes, source-aware security alert wording, diagnostic path redaction, and the verification results for this archive. Money operations remain synthetic and local. The known T11 benign-text false positive remains documented; no thresholds were weakened to improve the scenario score.
