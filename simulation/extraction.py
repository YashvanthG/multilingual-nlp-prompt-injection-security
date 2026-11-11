"""Local (no tool, no LLM) processing of an already-approved document: date/time extraction and
an extractive summary. Original date strings are preserved; numeric dates whose format cannot be
established are flagged as ambiguous instead of being silently converted."""
from __future__ import annotations

import re

_MONTHS_EN = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?"
_MONTHS_ES = r"(?:enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|setiembre|octubre|noviembre|diciembre)"
_WEEKDAY = r"(?:(?:Mon|Tues?|Wed(?:nes)?|Thu(?:rs)?|Fri|Sat(?:ur)?|Sun)(?:day)?,?\s+)?"
_NAMED = re.compile(
    rf"\b{_WEEKDAY}(?:\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTHS_EN}(?:,?\s+\d{{4}})?|{_MONTHS_EN}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{4}})?"
    rf"|\d{{1,2}}\s+de\s+{_MONTHS_ES}(?:\s+de\s+\d{{4}})?)\b", re.I)
_NUMERIC = re.compile(r"(?<![\d/.\-])(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?!\d|[/\-]\d|\.\d)")
_ISO = re.compile(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)")
_TIME = re.compile(r"\b(?:\d{1,2}:\d{2}\s?(?:[AP]\.?M\.?)?|\d{1,2}\s?[AP]\.?M\.?)(?!\w)", re.I)
_MEETING = re.compile(r"\b(?:meeting|review|demo|event|scheduled|workshop|conference|call|session|lunch|appointment|webinar|sync|stand-?up|reuni[oó]n|planning|retrospective|training)\b", re.I)
_DEADLINE_BEFORE = re.compile(r"\b(?:by|before|until|due|deadline|no later than)\W+(?:\w+\W+){0,2}$", re.I)
_DEADLINE_WORDS = re.compile(r"\b(?:send|submit|reply|confirm|deliver|rsvp|respond|deadline)\b", re.I)
_GREETING = re.compile(r"^(?:hi|hello|dear|regards|thanks|thank you|best|sincerely|cheers|kind regards|good (?:morning|afternoon)|hola|saludos|gracias)\b[\w ,!.]{0,30}$", re.I)
_NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}


def _numeric_ambiguity(a: int, b: int):
    if a > 12 and b <= 12:
        return False, "DD/MM"
    if b > 12 and a <= 12:
        return False, "MM/DD"
    if a == b:
        return False, "same either way"
    return True, None


def find_dates(text: str) -> list:
    dates = []
    for m in _NAMED.finditer(text):
        dates.append({"original": m.group(0).strip(), "kind": "named", "ambiguous": False, "start": m.start(), "end": m.end()})
    for m in _ISO.finditer(text):
        dates.append({"original": m.group(0), "kind": "iso", "ambiguous": False, "start": m.start(), "end": m.end()})
    for m in _NUMERIC.finditer(text):
        a, b = int(m.group(1)), int(m.group(3))
        if a == 0 or b == 0 or a > 31 or b > 31 or (a > 12 and b > 12):
            continue
        ambiguous, fmt = _numeric_ambiguity(a, b)
        dates.append({"original": m.group(0), "kind": "numeric", "ambiguous": ambiguous, "format": fmt, "start": m.start(), "end": m.end()})
    return sorted(dates, key=lambda d: d["start"])


def _sentence_bounds(text: str, pos: int):
    start = max(text.rfind(".", 0, pos), text.rfind("\n", 0, pos)) + 1
    ends = [i for i in (text.find(".", pos), text.find("\n", pos)) if i != -1]
    return start, (min(ends) if ends else len(text))


def _score(text: str, d: dict) -> int:
    s, e = _sentence_bounds(text, d["start"])
    sentence, score = text[s:e], 0
    if _MEETING.search(sentence):
        score += 3
    if re.match(r"\s*(?:date|when|fecha)\s*:", sentence, re.I):
        score += 2
    if _DEADLINE_BEFORE.search(text[max(0, d["start"] - 30):d["start"]]):
        score -= 3
    if _DEADLINE_WORDS.search(sentence):
        score -= 1
    return score


def find_times(text: str) -> list:
    return [{"original": m.group(0).strip().rstrip("."), "start": m.start()} for m in _TIME.finditer(text)]


def extract_datetime(text: str) -> dict:
    dates = find_dates(text)
    result = {"dates_found": [d["original"] for d in dates], "selected_date": None, "time": None, "ambiguous": False, "notes": []}
    if not dates:
        return result
    best = max(dates, key=lambda d: (_score(text, d), -d["start"]))
    result["selected_date"] = best["original"]
    result["ambiguous"] = best["ambiguous"]
    if best["ambiguous"]:
        result["notes"].append("Numeric date format is ambiguous (could be DD/MM/YYYY or MM/DD/YYYY); the original string is preserved and not converted.")
    s, e = _sentence_bounds(text, best["start"])
    times = [t for t in find_times(text) if not _DEADLINE_BEFORE.search(text[max(0, t["start"] - 20):t["start"]])]
    same = [t for t in times if s <= t["start"] <= e]
    chosen = (same or times or [None])[0]
    result["time"] = chosen["original"] if chosen else None
    others = [d["original"] for d in dates if d is not best]
    if others:
        result["notes"].append("Other dates mentioned: " + ", ".join(others) + ".")
    return result


def _sentences(text: str, min_words: int = 4) -> list:
    out = []
    for line in text.splitlines():
        for part in re.split(r"(?<=[.!?])\s+", line.strip()):
            part = re.sub(r"^(?:hi|hello|dear|hola)\b[^,.:]{0,25}[,:]\s*", "", part.strip(), flags=re.I)
            if part and len(part.split()) >= min_words and not _GREETING.match(part):
                out.append(part[0].upper() + part[1:])
    return out


def wanted_bullets(request: str) -> int:
    m = re.search(r"\b(\d|one|two|three|four|five)\b[ -]*(?:bullet|point|sentence)", request, re.I)
    if not m:
        return 2
    tok = m.group(1).lower()
    return int(tok) if tok.isdigit() else _NUMBER_WORDS.get(tok, 2)


def extractive_summary(text: str, n: int = 2) -> list:
    found = _sentences(text) or _sentences(text, min_words=2)  # short fragments: fall back to 2+ word pieces
    return found[:max(1, min(n, 5))]


def process(request: str, safe_text: str) -> dict:
    """Run the local operations the request asks for, using ONLY the approved safe text."""
    lower = request.casefold()
    want_summary = bool(re.search(r"summar|key points|main points|bullet|tl;?dr|overview|gist|resumen|resume", lower))
    want_dt = bool(re.search(r"\b(?:date|when|day|time|fecha)\b", lower))
    if not want_summary and not want_dt:
        want_summary = True
    lines, out = [], {"operations": [], "extraction": None, "summary": None}
    if want_dt:
        info = extract_datetime(safe_text)
        out["operations"].append("extract_datetime")
        out["extraction"] = info
        if info["selected_date"]:
            line = f"Meeting date: {info['selected_date']}"
            if info["ambiguous"]:
                line += " (ambiguous numeric format)"
            lines.append(line)
            if info["time"]:
                lines.append(f"Time: {info['time']}")
            lines += [f"Note: {n}" for n in info["notes"]]
        else:
            lines.append("No meeting date is specified in the document.")
    if want_summary:
        bullets = extractive_summary(safe_text, wanted_bullets(request))
        out["operations"].append("summarize")
        out["summary"] = bullets
        lines.append("Summary (extractive, taken only from the approved text):")
        lines += [f"- {b}" for b in bullets] or ["- (no summarizable sentences found)"]
    out["answer"] = "\n".join(lines)
    return out
