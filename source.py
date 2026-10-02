from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from normalize import group_matches, clean_text

PERIOD_RE = re.compile(
    r"(?:период\s+с\s*)?(\d{2})\.(\d{2})\.(\d{4})\s*(?:по|[-–—])\s*(\d{2})\.(\d{2})\.(\d{4})",
    re.IGNORECASE,
)


@dataclass
class Candidate:
    url: str
    label: str
    period_start: str | None = None
    period_end: str | None = None


def _parse_period_text(text: str):
    m = PERIOD_RE.search(clean_text(text))
    if not m:
        return None
    d1, m1, y1, d2, m2, y2 = map(int, m.groups())
    return date(y1, m1, d1), date(y2, m2, d2)


def discover_candidates(html: str, page_url: str, stable_group: str) -> list[Candidate]:
    """Find schedule links without depending on CSS classes/colors.

    For every matching link, we look backwards through nearby headings/text for a
    period. This tolerates moderate changes in the college page layout.
    """
    soup = BeautifulSoup(html, "html.parser")
    result = []
    for a in soup.find_all("a", href=True):
        label = clean_text(a.get_text(" ", strip=True))
        href = a.get("href", "")
        combined = f"{label} {href}"
        if not group_matches(combined, stable_group):
            continue

        period = None
        node = a
        # Walk back through nearby visible elements, not CSS-specific containers.
        for _ in range(30):
            node = node.find_previous()
            if node is None:
                break
            text = clean_text(node.get_text(" ", strip=True)) if hasattr(node, "get_text") else ""
            period = _parse_period_text(text)
            if period:
                break

        result.append(Candidate(
            url=urljoin(page_url, href),
            label=label,
            period_start=period[0].isoformat() if period else None,
            period_end=period[1].isoformat() if period else None,
        ))
    return result


def choose_candidate(candidates: list[Candidate], target: date) -> Candidate | None:
    dated = []
    unknown = []
    for c in candidates:
        if c.period_start and c.period_end:
            start, end = date.fromisoformat(c.period_start), date.fromisoformat(c.period_end)
            if start <= target <= end:
                return c
            dated.append((start, c))
        else:
            unknown.append(c)
    future = sorted((x for x in dated if x[0] > target), key=lambda x: x[0])
    if future:
        return future[0][1]
    past = sorted((x for x in dated if x[0] <= target), key=lambda x: x[0], reverse=True)
    if past:
        return past[0][1]
    return unknown[0] if unknown else None


class HttpClient:
    def __init__(self, attempts: int = 3, timeout: int = 20):
        self.attempts = attempts
        self.timeout = timeout
        self.session = requests.Session()
        if os.getenv('SCHEDULE_DIRECT', '0') == '1':
            self.session.trust_env = False
        self.session.headers.update({
            "User-Agent": "VBA25ScheduleBot/1.0 (+student timetable helper)"
        })

    def get(self, url: str) -> requests.Response:
        last = None
        for attempt in range(self.attempts):
            try:
                r = self.session.get(url, timeout=self.timeout)
                r.raise_for_status()
                return r
            except requests.RequestException as exc:
                last = exc
                if attempt + 1 < self.attempts:
                    time.sleep(1.5 * (attempt + 1))
        raise last  # type: ignore[misc]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_state(path: str | Path, state: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import tempfile
    with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=path.parent,prefix=path.name+'.',delete=False) as file:
        json.dump(state,file,ensure_ascii=False,indent=2)
        temporary=Path(file.name)
    try: temporary.replace(path)
    finally: temporary.unlink(missing_ok=True)


def load_state(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError,OSError):
        return {'ok':False,'last_error':'Status file unavailable'}
