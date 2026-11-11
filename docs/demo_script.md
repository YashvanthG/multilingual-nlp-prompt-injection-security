# Faculty demonstration guide

## Optional advanced research walkthrough (5-8 minutes)

1. Install dependencies and run `python -m unittest discover -s tests`.
2. Open **Advanced → Custom Security Test** and run a benign request such as `What is the weather in Tokyo?` and expand the trace.
3. Submit a mixed benign/injection document and show the quarantined instruction and retained content.
4. Submit a direct sensitive-data request and show that the deterministic rule blocks it.
5. Open **Advanced → Testing Lab** and **Advanced → Research & Evaluation** to explain the metrics and the known false-positive/false-negative limitations.

## Main Demo Agent (2-3 minutes)

1. The app opens directly to **Demo Agent** and select **1. Normal assistant**. In Protected mode ask `What is my demo balance?` and inspect the proposed function, execution status, and output inspection result.
2. Select **2. Prompt-injection attack** and press **Load / reset scenario**. Choose **Baseline — Without Guardrails** and use the suggested prompt. Inspect the actual tool proposal and the fictional balance/transaction changes. If `send_money` was not proposed and executed, explain that this run did not reproduce the attack; do not claim that it succeeded.
3. Press **Load / reset scenario** again, switch to **Protected — With Guardrails**, and use the same prompt. Show the email sanitization record: the legitimate project update is retained while the injected transfer/concealment clauses are quarantined. If the agent proposes a sensitive function anyway, show the Python-side authorization denial.
4. Point to the **Run outcome** summary. It distinguishes a reproduced attack, a blocked action, and a run where the model did not propose the attack. Expand the security trace to show the matching execution status.

All personal-agent functions operate on synthetic local data. No real account, payment, e-mail, customer database, or external server is connected. Baseline model behavior is probabilistic; the tool-call tests use a mock model and do not guarantee how live Groq will behave.
