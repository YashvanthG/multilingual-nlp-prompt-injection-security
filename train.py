import argparse
import json
import time
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score
from guardrails.config import DEFAULTS
from data_utils import AGENT_TEST, EMAIL_WORKFLOW_TEST, MULTILINGUAL_EXTRA_TEST, ROOT, load_agent_style, load_multilingual_extra, prepare_training_data, _read_csv

def evaluate(model, frame, name):
    start = time.perf_counter()
    pred = model.predict(frame["text"])
    probabilities = model.predict_proba(frame["text"])
    elapsed = time.perf_counter() - start
    classes = list(model.classes_)
    positive_index = classes.index(1)
    result = {
        "dataset": name,
        "rows": int(len(frame)),
        "accuracy": round(float(accuracy_score(frame["label"], pred)), 4),
        "classification_report": classification_report(
            frame["label"], pred, labels=[0, 1], target_names=["benign", "injection"],
            output_dict=True, zero_division=0
        ),
        "confusion_matrix_labels_0_1": confusion_matrix(frame["label"], pred, labels=[0, 1]).tolist(),
        "roc_auc": round(float(roc_auc_score(frame["label"], probabilities[:, positive_index])), 4),
        "batch_mean_ms_per_example": round(elapsed * 1000 / max(1, len(frame)), 4),  # batch timing only (predict + predict_proba); per-request p50/p95 is in evaluate_policy.py
    }
    return result

def threshold_analysis(model, frame, thresholds=(DEFAULTS.escalate_threshold, 0.50, DEFAULTS.block_threshold)):
    """Threshold study on validation only; never uses the held-out test for tuning."""
    probabilities = model.predict_proba(frame["text"])
    positive_index = list(model.classes_).index(1)
    scores = probabilities[:, positive_index]
    truth = frame["label"].to_numpy()
    results = []
    for threshold in thresholds:
        predicted = (scores >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[0, 1]).ravel()
        results.append({
            "threshold": float(threshold),
            "precision_injection": round(float(precision_score(truth, predicted, zero_division=0)), 4),
            "recall_injection": round(float(recall_score(truth, predicted, zero_division=0)), 4),
            "f1_injection": round(float(f1_score(truth, predicted, zero_division=0)), 4),
            "false_positive_rate": round(float(fp / max(1, fp + tn)), 4),
            "false_negative_rate": round(float(fn / max(1, fn + tp)), 4),
            "confusion_matrix_labels_0_1": [[int(tn), int(fp)], [int(fn), int(tp)]],
        })
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-agent-style", action="store_true", help="reproduce the original v1 training set")
    parser.add_argument("--model-out", default=str(ROOT / "models" / "guardrail_tfidf.joblib"))
    parser.add_argument("--report-out", default=str(ROOT / "reports" / "training_report.json"))
    args = parser.parse_args()
    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    train, val, test, stats = prepare_training_data(include_agent_style=not args.no_agent_style)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), min_df=2, max_features=180000,
            strip_accents="unicode", sublinear_tf=True, dtype=float
        )),
        ("clf", LogisticRegression(
            max_iter=1500, class_weight="balanced", random_state=42,
            solver="liblinear"
        )),
    ])
    start = time.perf_counter()
    model.fit(train["text"], train["label"])
    fit_seconds = time.perf_counter() - start
    joblib.dump(model, args.model_out)
    # Report validation and held-out test separately. Do not use test results for tuning.
    report = {
        "model": "TF-IDF word n-grams + Logistic Regression",
        "label_mapping": {"0": "benign/safe", "1": "prompt injection"},
        "random_state": 42,
        "validation_fraction": 0.2,
        "fit_seconds": round(fit_seconds, 3),
        "data_cleaning": stats,
        "validation": evaluate(model, val, "internal stratified validation"),
        "validation_threshold_analysis": threshold_analysis(model, val),
        "held_out_test": evaluate(model, test, "provided held-out CSV test"),
        "agent_style_held_out_test": evaluate(model, load_agent_style(AGENT_TEST), "synthetic agent-style held-out (never fitted on)"),
        "email_workflow_held_out_test": evaluate(model, _read_csv(EMAIL_WORKFLOW_TEST, "email_workflow_test"), "synthetic email-workflow held-out (never fitted on)"),
        "multilingual_extra_held_out_test": evaluate(model, load_multilingual_extra(MULTILINGUAL_EXTRA_TEST), "synthetic multilingual (18 languages) held-out (never fitted on)"),
        "metrics_note": f"All metrics here use the 0.5 argmax operating point. The DEPLOYED policy uses thresholds {DEFAULTS.escalate_threshold}/{DEFAULTS.block_threshold} plus deterministic rules; see reports/policy_evaluation.json (evaluate_policy.py).",
        "caution": "The provided multilingual test file has 11 normalized texts overlapping the raw training CSV; those rows were removed from training. Agent-style and email-workflow held-out files are never fitted on. Use all held-out results as initial estimates, not a security guarantee. Tune thresholds on validation only.",
    }
    Path(args.report_out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
