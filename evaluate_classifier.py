import json
import time
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from data_utils import ROOT, prepare_training_data
from guardrails.classifier import Guardrail

def main():
    _, validation, _, stats = prepare_training_data()
    model_path = ROOT / "models" / "guardrail_tfidf.joblib"
    if not model_path.exists():
        raise SystemExit("Model not found. Run `python train.py` first.")
    guardrail = Guardrail(model_path=model_path)
    start = time.perf_counter()
    predictions = guardrail.model.predict(validation["text"])
    probabilities = guardrail.model.predict_proba(validation["text"])
    elapsed = time.perf_counter() - start
    positive_index = list(guardrail.model.classes_).index(1)
    report = {
        "dataset": "internal stratified validation (not held-out test)",
        "rows": int(len(validation)),
        "accuracy": float(accuracy_score(validation["label"], predictions)),
        "classification_report": classification_report(validation["label"], predictions, labels=[0,1], target_names=["benign","injection"], output_dict=True, zero_division=0),
        "confusion_matrix_labels_0_1": confusion_matrix(validation["label"], predictions, labels=[0,1]).tolist(),
        "roc_auc": float(roc_auc_score(validation["label"], probabilities[:, positive_index])),
        "batch_mean_ms_per_example": elapsed * 1000 / max(1, len(validation)),
        "data_cleaning": stats,
    }
    out = ROOT / "reports" / "validation_metrics.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
