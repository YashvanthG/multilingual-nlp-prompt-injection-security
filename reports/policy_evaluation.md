# Deployed-policy evaluation (before vs after retraining)

Policy: deterministic rules -> classifier thresholds 0.42 (ESCALATE) / 0.72 (BLOCK). Request-level text classification only.

## original_validation

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 1260 | 555/95/4 | 41/257/308 | 0.6% | 14.5% | 6.8% | 27.9% |
| before | rules_plus_classifier | 1260 | 555/95/4 | 41/256/309 | 0.6% | 14.5% | 6.8% | 27.9% |
| after | classifier_only | 1260 | 563/88/3 | 43/258/305 | 0.5% | 13.5% | 7.1% | 27.5% |
| after | rules_plus_classifier | 1260 | 563/88/3 | 43/257/306 | 0.5% | 13.5% | 7.1% | 27.4% |

## original_held_out_test

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 1585 | 689/129/5 | 80/301/381 | 0.6% | 15.7% | 10.5% | 27.1% |
| before | rules_plus_classifier | 1585 | 689/129/5 | 80/299/383 | 0.6% | 15.7% | 10.5% | 27.0% |
| after | classifier_only | 1585 | 694/125/4 | 80/303/379 | 0.5% | 15.2% | 10.5% | 27.0% |
| after | rules_plus_classifier | 1585 | 694/125/4 | 80/302/380 | 0.5% | 15.2% | 10.5% | 26.9% |

## agent_style_held_out_synthetic

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 303 | 19/124/9 | 0/44/107 | 5.9% | 81.6% | 0.0% | 55.5% |
| before | rules_plus_classifier | 303 | 19/124/9 | 0/5/146 | 5.9% | 81.6% | 0.0% | 42.6% |
| after | classifier_only | 303 | 95/56/1 | 0/17/134 | 0.7% | 36.8% | 0.0% | 24.1% |
| after | rules_plus_classifier | 303 | 95/56/1 | 0/3/148 | 0.7% | 36.8% | 0.0% | 19.5% |

**before**: model 884.5 KB; per-request p50/p95/p99 = 0.482/0.783/1.066 ms (400 sequential calls); peak RSS 234.6 MB.
**after**: model 940.5 KB; per-request p50/p95/p99 = 0.49/0.776/1.115 ms (400 sequential calls); peak RSS 251.3 MB.
