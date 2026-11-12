"""Dataset Overview page: row and language counts computed directly from data/raw/*.csv."""
from __future__ import annotations

from pathlib import Path
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

RAW = Path(__file__).resolve().parent / "data" / "raw"

# (file stem, display name, has a 'language' column)
FILES = [
    ("agent_style_train", "Agent-style · train", True),
    ("agent_style_test", "Agent-style · test", True),
    ("email_workflow_train", "Email-workflow · train", True),
    ("email_workflow_test", "Email-workflow · test", True),
    ("multilingual_train", "Multilingual · train", False),
    ("multilingual_test", "Multilingual · test", False),
    ("multilingual_extra_train", "Multilingual-extra (synthetic) · train", True),
    ("multilingual_extra_test", "Multilingual-extra (synthetic) · held-out test", True),
]
LANG_NAMES = {
    "en": "English", "de": "German", "pt": "Portuguese", "hi": "Hindi", "fr": "French",
    "ja": "Japanese", "vi": "Vietnamese", "th": "Thai", "it": "Italian", "es": "Spanish",
    "zh-cn": "Chinese", "zh": "Chinese", "ko": "Korean", "mr": "Marathi",
    "hi-Latn": "Hinglish (Latin script)", "bn": "Bengali", "ta": "Tamil", "te": "Telugu", "gu": "Gujarati", "pa": "Punjabi",
}


def _detect(text: str) -> str:
    from langdetect import detect
    try:
        return detect(str(text))
    except Exception:
        return "unk"


def _fingerprint():
    """Return lightweight file fingerprints so we can detect changed CSVs without rereading them."""
    result = {}
    for stem, _, _ in FILES:
        path = RAW / f"{stem}.csv"
        if path.exists():
            stat = path.stat()
            result[path.name] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    return result


CACHE_PATH = RAW.parent / "dataset_overview_cache.json"


def _compute_counts():
    """Compute counts once; the result is persisted so normal page loads are immediate."""
    try:
        from langdetect import DetectorFactory
        DetectorFactory.seed = 0
        detector = True
    except ImportError:
        detector = False

    summary, langs = [], {}
    for stem, label, has_lang in FILES:
        path = RAW / f"{stem}.csv"
        if not path.exists():
            continue
        df = pd.read_csv(path)
        benign = int((df["label"] == 0).sum())
        attack = int((df["label"] == 1).sum())
        summary.append({
            "File": path.name,
            "Rows": len(df),
            "Benign (0)": benign,
            "Injection (1)": attack,
            "Language source": "CSV column" if has_lang else ("Detected (langdetect)" if detector else "Not available"),
        })
        if has_lang:
            langs[label] = {str(k): int(v) for k, v in df["language"].astype(str).value_counts().items()}
        elif detector:
            from langdetect import detect
            def detect_one(text):
                try:
                    return detect(str(text))
                except Exception:
                    return "unk"
            langs[label] = {str(k): int(v) for k, v in df["text"].map(detect_one).value_counts().items()}

    payload = {
        "version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "language_counts": langs,
        "fingerprint": _fingerprint(),
        "detector_available": detector,
    }
    CACHE_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def _load_saved_counts():
    if not CACHE_PATH.exists():
        return None
    try:
        payload = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        if not payload.get("summary"):
            return None
        return payload
    except (OSError, ValueError, TypeError):
        return None


def _cache_is_current(payload):
    return payload.get("fingerprint", {}) == _fingerprint()


def load_counts(force_refresh=False):
    """Load the saved snapshot immediately; only recompute when requested or missing."""
    if not force_refresh:
        saved = _load_saved_counts()
        if saved is not None:
            return saved
    return _compute_counts()


def render_dataset_overview():
    st.title("Dataset Overview")
    st.write("Saved dataset statistics are shown immediately. Use refresh only when the CSV files change or you want to recompute language detection.")

    saved = _load_saved_counts()
    refresh = st.button("↻ Refresh dataset counts", type="secondary", help="Re-read every CSV, recompute language detection, and save the new snapshot.")
    if refresh:
        with st.spinner("Refreshing dataset counts and language detection…"):
            payload = load_counts(force_refresh=True)
        st.success("Dataset overview refreshed and saved.")
    else:
        payload = load_counts()

    summary = payload.get("summary", [])
    langs = {label: pd.Series(counts) for label, counts in payload.get("language_counts", {}).items()}
    detector = bool(payload.get("detector_available"))
    current = _cache_is_current(payload)
    generated = payload.get("generated_at_utc")
    if generated:
        try:
            generated_display = datetime.fromisoformat(generated).astimezone().strftime("%d %b %Y, %I:%M:%S %p")
        except ValueError:
            generated_display = generated
        status_text = "up to date" if current else "CSV files changed — refresh recommended"
        st.caption(f"Saved snapshot: {generated_display} · {status_text}")
    if not current and not refresh:
        st.warning("The CSV files have changed since this snapshot was saved. The saved numbers are shown now for speed; click **Refresh dataset counts** to update them.")
    if not summary:
        st.error(f"No dataset files found in {RAW}.")
        return
    total = sum(r["Rows"] for r in summary)
    cols = st.columns(3)
    cols[0].metric("Total rows", f"{total:,}")
    cols[1].metric("Files", len(summary))
    cols[2].metric("Main languages", len({LANG_NAMES[k] for s in langs.values() for k in s.index if k in LANG_NAMES}))

    st.markdown("### Rows per file")
    st.dataframe(summary, hide_index=True, width="stretch")

    st.markdown("### Rows per language")
    table = pd.DataFrame(langs).fillna(0).astype(int)
    minor = table[~table.index.isin(LANG_NAMES)]
    main = table.drop(minor.index)
    main = main.rename(index=LANG_NAMES).groupby(level=0).sum()
    if len(minor):
        main.loc["Other / uncertain"] = minor.sum()
    main = main.loc[main.sum(axis=1).sort_values(ascending=False).index]
    main.loc["TOTAL"] = main.sum()
    st.dataframe(main, width="stretch")
    st.bar_chart(main.drop("TOTAL"), horizontal=True)

    st.markdown("### How to read this")
    st.caption("• Agent-style, email-workflow and multilingual-extra files use the exact `language` column in the CSV (agent-style and email-workflow are English except 11 Spanish rows).")
    st.caption("• Multilingual-extra is synthetic and templated: 18 languages (8 Indian, incl. Hinglish) with the same semantic patterns per language; its held-out file uses different wording from its train file. Indian-language rows still need native-speaker review.")
    if detector:
        st.caption("• The multilingual files have no language column, so their language is **detected automatically** (langdetect). "
                   "Short or mixed-language rows can be misclassified, so these counts are close but not exact; "
                   "the 13 main languages are listed and the tail of tiny or misdetected languages is grouped as “Other / uncertain”.")
        st.caption("• Hinglish/transliterated text inside the original multilingual files is not counted separately (the detector would call it English, Hindi or another language); only multilingual-extra labels Hinglish exactly.")
    else:
        st.warning("`langdetect` is not installed, so multilingual language counts are unavailable. Run `pip install langdetect`.")
