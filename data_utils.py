from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"

def normalise_text(value):
    return " ".join(str(value).casefold().split())

def _read_csv(path, split):
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")
    frame = pd.read_csv(path)
    if "text" not in frame.columns or "label" not in frame.columns:
        raise ValueError(f"{path.name} must contain 'text' and 'label' columns.")
    out = frame[["text", "label"]].copy()
    out["text"] = out["text"].fillna("").astype(str)
    out = out[out["text"].str.strip().ne("")].copy()
    labels = set(out["label"].dropna().unique().tolist())
    if not labels.issubset({0, 1, 0.0, 1.0, "0", "1"}):
        raise ValueError(f"Unexpected labels in {path.name}: {labels}")
    out["label"] = out["label"].astype(int)
    if "source" in frame.columns:
        out["source"] = frame.loc[out.index, "source"].fillna("unknown").astype(str)
    else:
        out["source"] = "unknown"
    out["text_key"] = out["text"].map(normalise_text)
    out["split"] = split
    return out.reset_index(drop=True)

AGENT_TRAIN = RAW / "agent_style_train.csv"
AGENT_TEST = RAW / "agent_style_test.csv"
EMAIL_WORKFLOW_TRAIN = RAW / "email_workflow_train.csv"
EMAIL_WORKFLOW_TEST = RAW / "email_workflow_test.csv"


def load_agent_style(path):
    """Synthetic agent-style rows (benign + malicious requests/emails). Extra columns kept for reporting."""
    frame = pd.read_csv(path)
    out = _read_csv(path, "agent_style")
    for col in ("language", "kind", "pool"):
        out[col] = frame.loc[:, col].astype(str).values[: len(out)] if col in frame.columns else "unknown"
    return out


def prepare_training_data(validation_size=0.2, random_state=42, include_agent_style=True):
    full_train = _read_csv(RAW / "multilingual_train.csv", "train")
    test = _read_csv(RAW / "multilingual_test.csv", "test")

    # Remove duplicate training rows and any normalized text found in the held-out test set.
    before = len(full_train)
    full_train = full_train.drop_duplicates("text_key", keep="first").copy()
    duplicate_removed = before - len(full_train)
    test_keys = set(test["text_key"])
    overlap_mask = full_train["text_key"].isin(test_keys)
    overlap_removed = int(overlap_mask.sum())
    full_train = full_train.loc[~overlap_mask].copy()

    train, validation = train_test_split(
        full_train, test_size=validation_size, random_state=random_state,
        stratify=full_train["label"]
    )
    agent_added = 0
    if include_agent_style and AGENT_TRAIN.exists():
        # Added to the FIT set only: validation and the original held-out test stay untouched, so the
        # original validation/test numbers remain comparable before vs after. Held-out agent-style rows
        # live in a separate file that is never fitted on.
        agent = load_agent_style(AGENT_TRAIN)
        agent = agent[~agent["text_key"].isin(test_keys | set(validation["text_key"]))]
        agent_added = int(len(agent))
        train = pd.concat([train, agent[["text", "label", "source", "text_key", "split"]]], ignore_index=True)
    email_added = 0
    if include_agent_style and EMAIL_WORKFLOW_TRAIN.exists():
        email = _read_csv(EMAIL_WORKFLOW_TRAIN, "email_workflow")
        email = email[~email["text_key"].isin(test_keys | set(validation["text_key"]))]
        email_added = int(len(email))
        train = pd.concat([train, email[["text", "label", "source", "text_key", "split"]]], ignore_index=True)
    stats = {
        "agent_style_rows_added_to_fit_set": agent_added,
        "email_workflow_rows_added_to_fit_set": email_added,
        "source_train_rows": int(before),
        "duplicate_train_rows_removed": int(duplicate_removed),
        "train_test_overlap_rows_removed_from_training": overlap_removed,
        "clean_train_pool_rows": int(len(full_train)),
        "fit_train_rows": int(len(train)),
        "validation_rows": int(len(validation)),
        "held_out_test_rows": int(len(test)),
        "fit_train_label_counts": {str(k): int(v) for k,v in train["label"].value_counts().sort_index().items()},
        "validation_label_counts": {str(k): int(v) for k,v in validation["label"].value_counts().sort_index().items()},
        "test_label_counts": {str(k): int(v) for k,v in test["label"].value_counts().sort_index().items()},
        "source_counts": {str(k): int(v) for k,v in full_train["source"].value_counts().items()},
        "test_sources": {str(k): int(v) for k,v in test["source"].value_counts().items()},
    }
    return train.reset_index(drop=True), validation.reset_index(drop=True), test.reset_index(drop=True), stats
