# Deployed-policy evaluation (before vs after retraining)

Policy: deterministic rules -> classifier thresholds 0.42 (ESCALATE) / 0.72 (BLOCK). Request-level text classification only.

## original_validation

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 1260 | 555/95/4 | 41/257/308 | 0.6% | 14.5% | 6.8% | 27.9% |
| before | rules_plus_classifier | 1260 | 555/95/4 | 41/256/309 | 0.6% | 14.5% | 6.8% | 27.9% |
| after | classifier_only | 1260 | 567/83/4 | 42/263/301 | 0.6% | 12.7% | 6.9% | 27.5% |
| after | rules_plus_classifier | 1260 | 567/83/4 | 42/262/302 | 0.6% | 12.7% | 6.9% | 27.4% |

## original_held_out_test

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 1585 | 689/129/5 | 80/301/381 | 0.6% | 15.7% | 10.5% | 27.1% |
| before | rules_plus_classifier | 1585 | 689/129/5 | 80/299/383 | 0.6% | 15.7% | 10.5% | 27.0% |
| after | classifier_only | 1585 | 700/119/4 | 81/305/376 | 0.5% | 14.5% | 10.6% | 26.8% |
| after | rules_plus_classifier | 1585 | 700/119/4 | 81/304/377 | 0.5% | 14.5% | 10.6% | 26.7% |

## agent_style_held_out_synthetic

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 303 | 19/124/9 | 0/44/107 | 5.9% | 81.6% | 0.0% | 55.5% |
| before | rules_plus_classifier | 303 | 19/124/9 | 0/5/146 | 5.9% | 81.6% | 0.0% | 42.6% |
| after | classifier_only | 303 | 98/51/3 | 0/17/134 | 2.0% | 33.6% | 0.0% | 22.4% |
| after | rules_plus_classifier | 303 | 98/51/3 | 0/3/148 | 2.0% | 33.6% | 0.0% | 17.8% |

## multilingual_extra_held_out_synthetic

| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |
|---|---|---:|---|---|---:|---:|---:|---:|
| before | classifier_only | 144 | 57/15/0 | 33/27/12 | 0.0% | 20.8% | 45.8% | 29.2% |
| before | rules_plus_classifier | 144 | 57/15/0 | 33/26/13 | 0.0% | 20.8% | 45.8% | 28.5% |
| after | classifier_only | 144 | 60/12/0 | 19/40/13 | 0.0% | 16.7% | 26.4% | 36.1% |
| after | rules_plus_classifier | 144 | 60/12/0 | 19/39/14 | 0.0% | 16.7% | 26.4% | 35.4% |

**before**: model 884.5 KB; per-request p50/p95/p99 = 0.414/0.785/0.953 ms (400 sequential calls); peak RSS 252.8 MB.
**after**: model 973.9 KB; per-request p50/p95/p99 = 0.449/1.025/1.484 ms (400 sequential calls); peak RSS 256.9 MB.
