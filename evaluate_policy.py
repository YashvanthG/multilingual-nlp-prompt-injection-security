"""Evaluate the DEPLOYED three-decision policy (ALLOW / ESCALATE / BLOCK) before vs after retraining.

Policy per text = deterministic rules (hard BLOCK) -> classifier thresholds (default 0.42 / 0.72).
This is request-level text classification: it does not run the document sanitizer, Groq or the agent.
It reports false positives (benign that is ESCALATEd/BLOCKed) and false negatives (attacks ALLOWed)
separately, per-request latency percentiles (not just batch averages), and model size / memory.

Usage: python evaluate_policy.py            # compares models/archive v1 vs current model
"""
import argparse
import json
import resource
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from data_utils import AGENT_TEST, ROOT, load_agent_style, prepare_training_data
from guardrails import rules
from guardrails.classifier import Guardrail
from guardrails.config import DEFAULTS

NON_ASCII = lambda t: any(ord(c) > 127 for c in t)


def decide(prob, hit, esc, blk):
    if hit:
        return "BLOCK"
    return "BLOCK" if prob >= blk else "ESCALATE" if prob >= esc else "ALLOW"


def summarize(frame, probs, esc, blk, use_rules):
    hits = [bool(rules.scan(t)) if use_rules else False for t in frame["text"]]
    dec = np.array([decide(p, h, esc, blk) for p, h in zip(probs, hits)])
    y = frame["label"].values
    n0, n1 = int((y == 0).sum()), int((y == 1).sum())
    c = lambda lab, d: int(((y == lab) & (dec == d)).sum())
    out = {"rows": int(len(frame)), "benign": n0, "attack": n1,
           "benign_allow": c(0, "ALLOW"), "benign_escalate": c(0, "ESCALATE"), "benign_block": c(0, "BLOCK"),
           "attack_allow_missed": c(1, "ALLOW"), "attack_escalate": c(1, "ESCALATE"), "attack_block": c(1, "BLOCK")}
    out.update({"false_positive_rate_block": round(out["benign_block"] / n0, 4), "benign_escalation_rate": round(out["benign_escalate"] / n0, 4),
                "false_negative_rate_missed": round(out["attack_allow_missed"] / n1, 4), "attack_hard_block_rate": round(out["attack_block"] / n1, 4),
                "groq_call_share_of_rows": round((out["benign_escalate"] + out["attack_escalate"]) / len(frame), 4),
                "roc_auc_classifier_only": round(float(roc_auc_score(y, probs)), 4)})
    return out


def evaluate_model(label, path, esc=DEFAULTS.escalate_threshold, blk=DEFAULTS.block_threshold):
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    guard = Guardrail(path)
    train, val, test, _ = prepare_training_data(include_agent_style=False)
    agent = load_agent_style(AGENT_TEST)
    datasets = {"original_validation": val, "original_held_out_test": test, "agent_style_held_out_synthetic": agent}
    result = {"label": label, "model": str(Path(path).relative_to(ROOT)), "model_size_kb": round(Path(path).stat().st_size / 1024, 1),
              "thresholds": {"escalate": esc, "block": blk}, "datasets": {}}
    idx = list(guard.model.classes_).index(1)
    for name, frame in datasets.items():
        t0 = time.perf_counter()
        probs = guard.model.predict_proba(frame["text"])[:, idx]
        batch_ms = (time.perf_counter() - t0) * 1000 / len(frame)
        entry = {"classifier_only_policy": summarize(frame, probs, esc, blk, False),
                 "rules_plus_classifier_policy": summarize(frame, probs, esc, blk, True), "batch_ms_per_row": round(batch_ms, 4)}
        if name.startswith("agent"):
            entry["by_language"] = {lang: summarize(frame[frame["language"] == lang], probs[(frame["language"] == lang).values], esc, blk, True)
                                    for lang in sorted(frame["language"].unique())}
            entry["note"] = "SYNTHETIC set authored by this project; English plus a handful of Spanish rows. Not evidence of multilingual robustness."
        else:
            entry["non_ascii_share"] = round(float(frame["text"].map(NON_ASCII).mean()), 3)
        result["datasets"][name] = entry
    sample = list(test["text"].sample(300, random_state=1)) + list(agent["text"].sample(100, random_state=1))
    times = []
    for t in sample:
        t0 = time.perf_counter()
        guard.inspect_request(t)
        times.append((time.perf_counter() - t0) * 1000)
    q = np.percentile(times, [50, 95, 99])
    result["per_request_latency_ms"] = {"samples": len(times), "p50": round(float(q[0]), 3), "p95": round(float(q[1]), 3), "p99": round(float(q[2]), 3),
                                        "note": "Sequential single-text calls to Guardrail.inspect_request (rules + classifier), CPU only, no Groq."}
    result["peak_rss_mb_after_eval"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    result["peak_rss_mb_before_load"] = round(rss0, 1)
    return result


def sweep(path):
    """Threshold trade-off on the ORIGINAL VALIDATION split (tuning data; never the held-out test)."""
    guard = Guardrail(path)
    _, val, _, _ = prepare_training_data(include_agent_style=False)
    probs = guard.model.predict_proba(val["text"])[:, list(guard.model.classes_).index(1)]
    rows = []
    for esc in (0.30, DEFAULTS.escalate_threshold, 0.50):
        for blk in (0.60, DEFAULTS.block_threshold, 0.85, 0.95):
            s = summarize(val, probs, esc, blk, False)
            rows.append({"escalate": esc, "block": blk, **{k: s[k] for k in ("false_positive_rate_block", "benign_escalation_rate", "false_negative_rate_missed", "attack_hard_block_rate", "groq_call_share_of_rows")}})
    return rows


def markdown(report):
    lines = ["# Deployed-policy evaluation (before vs after retraining)", "",
             f"Policy: deterministic rules -> classifier thresholds {DEFAULTS.escalate_threshold} (ESCALATE) / {DEFAULTS.block_threshold} (BLOCK). Request-level text classification only.", ""]
    for ds in ("original_validation", "original_held_out_test", "agent_style_held_out_synthetic"):
        lines += [f"## {ds}", "", "| model | policy | rows | benign ALLOW/ESC/BLOCK | attacks MISSED / ESC / BLOCK | FP(block) | benign esc. | FN(missed) | Groq-call share |", "|---|---|---:|---|---|---:|---:|---:|---:|"]
        for tag in ("before", "after"):
            for pol in ("classifier_only_policy", "rules_plus_classifier_policy"):
                s = report[tag]["datasets"][ds][pol]
                lines.append(f"| {tag} | {pol.replace('_policy','')} | {s['rows']} | {s['benign_allow']}/{s['benign_escalate']}/{s['benign_block']} | {s['attack_allow_missed']}/{s['attack_escalate']}/{s['attack_block']} | {s['false_positive_rate_block']:.1%} | {s['benign_escalation_rate']:.1%} | {s['false_negative_rate_missed']:.1%} | {s['groq_call_share_of_rows']:.1%} |")
        lines.append("")
    for tag in ("before", "after"):
        r = report[tag]
        lines.append(f"**{tag}**: model {r['model_size_kb']} KB; per-request p50/p95/p99 = {r['per_request_latency_ms']['p50']}/{r['per_request_latency_ms']['p95']}/{r['per_request_latency_ms']['p99']} ms ({r['per_request_latency_ms']['samples']} sequential calls); peak RSS {r['peak_rss_mb_after_eval']} MB.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", default=str(ROOT / "models" / "archive" / "guardrail_tfidf_v1_original.joblib"))
    ap.add_argument("--after", default=str(ROOT / "models" / "guardrail_tfidf.joblib"))
    ap.add_argument("--out", default=str(ROOT / "reports" / "policy_evaluation.json"))
    args = ap.parse_args(argv)
    report = {"before": evaluate_model("v1 original model", args.before), "after": evaluate_model("v2 model (+ synthetic agent-style training rows)", args.after),
              "threshold_sweep_on_validation_after_model": sweep(args.after),
              "caveats": ["Synthetic agent-style data is authored by this project and shares an author with the 20 regression scenarios.",
                          "Request-level classification; the sanitizer, Groq and agent are not part of these numbers.",
                          "Groq-call share is the fraction of rows that would be ESCALATEd; live Groq behaviour was not measured here."]}
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = markdown(report)
    Path(args.out).with_suffix(".md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
