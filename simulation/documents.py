"""Small, dependency-free parser for the demo's untrusted text uploads."""
from pathlib import Path

from guardrails.config import MAX_UPLOAD_BYTES

SUPPORTED_UPLOAD_SUFFIXES = {".txt"}


def extract_uploaded_document(uploaded, max_bytes=MAX_UPLOAD_BYTES):
    """Extract UTF-8 .txt content and return an explicit status for every outcome."""
    if uploaded is None:
        return {"ok": True, "text": "", "filename": None, "status": "No uploaded file."}
    filename = str(getattr(uploaded, "name", "") or "uploaded-file")
    if Path(filename).suffix.casefold() not in SUPPORTED_UPLOAD_SUFFIXES:
        return {"ok": False, "text": "", "filename": filename,
                "status": "Unsupported format. Currently supported upload format: .txt only."}
    try:
        raw = uploaded.getvalue()
    except Exception:
        return {"ok": False, "text": "", "filename": filename, "status": "The uploaded file could not be read."}
    if len(raw) > max_bytes:
        return {"ok": False, "text": "", "filename": filename,
                "status": f"File exceeds the 1 MB limit ({len(raw):,} bytes)."}
    if not raw:
        return {"ok": False, "text": "", "filename": filename, "status": "The uploaded file is empty."}
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return {"ok": False, "text": "", "filename": filename,
                "status": "Could not decode this file as UTF-8 text. Save it as UTF-8 or paste the text."}
    if not text.strip():
        return {"ok": False, "text": "", "filename": filename, "status": "The file contains no readable text."}
    return {"ok": True, "text": text, "filename": filename,
            "status": f"Extracted UTF-8 text successfully ({len(raw):,} bytes)."}
