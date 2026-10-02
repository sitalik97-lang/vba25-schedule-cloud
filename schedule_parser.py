from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pdfplumber

from constants import WEEKDAYS_RU
from normalize import clean_text

PERIOD_RE = re.compile(r"(\d{2})\.(\d{2})\s*-\s*(\d{2})\.(\d{2})\.?(\d{4})")
PAIR_RE = re.compile(r"(\d+)\s*пара", re.IGNORECASE)


def _compact(value: str | None) -> str:
    return re.sub(r"\s+", "", value or "")


def parse_period(value: str | None):
    # PDFs sometimes extract the year as '20 26'.
    text = _compact(value)
    match = PERIOD_RE.search(text)
    if not match:
        raise ValueError(f"Не удалось определить период: {value!r}")
    d1, m1, d2, m2, year = map(int, match.groups())
    return datetime(year, m1, d1).date(), datetime(year, m2, d2).date()


def _normalize_entry(subject: str, teacher: str, room: str) -> dict[str, str]:
    return {
        "subject": clean_text(subject),
        "teacher": clean_text(teacher),
        "room": clean_text(room),
    }


def _fill_merged_cells(a: dict[str, str], b: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """pdfplumber may expose a merged teacher cell only in the first subgroup.

    We only inherit teacher when the subjects are the same; we never invent a
    subject or room for a subgroup that is actually empty.
    """
    a = dict(a)
    b = dict(b)
    if a["subject"] and a["subject"] == b["subject"]:
        if a["teacher"] and not b["teacher"]:
            b["teacher"] = a["teacher"]
        elif b["teacher"] and not a["teacher"]:
            a["teacher"] = b["teacher"]
    return a, b


def _day_start_indices(rows: list[list[str | None]], body_start: int = 2) -> list[int]:
    starts = []
    for i in range(body_start, len(rows)):
        row = rows[i]
        if row and clean_text(row[0]):
            # The date/day name is printed vertically in the first column.
            starts.append(i)
    return starts


def _parse_day(rows: list[list[str | None]], date, day_index: int) -> dict[str, Any]:
    pairs = []
    i = 0
    while i < len(rows):
        row = rows[i]
        pair_label = clean_text(row[1] if len(row) > 1 else "")
        match = PAIR_RE.search(pair_label)
        if not match:
            i += 1
            continue

        number = int(match.group(1))
        subject_row = row
        teacher_row = rows[i + 1] if i + 1 < len(rows) else [None] * 4
        room_row = rows[i + 2] if i + 2 < len(rows) else [None] * 4

        entries = []
        for col in (2, 3):
            subject = subject_row[col] if len(subject_row) > col else ""
            teacher = teacher_row[col] if len(teacher_row) > col else ""
            room = room_row[col] if len(room_row) > col else ""
            entries.append(_normalize_entry(subject or "", teacher or "", room or ""))
        entries[0], entries[1] = _fill_merged_cells(entries[0], entries[1])
        pairs.append({"number": number, "subgroups": entries})
        i += 3

    return {
        "date": date.isoformat(),
        "weekday": WEEKDAYS_RU[day_index] if day_index < len(WEEKDAYS_RU) else "",
        "pairs": pairs,
    }


def parse_pdf(path: str | Path) -> dict[str, Any]:
    """Parse a timetable PDF.

    Supports one or multiple pages/weeks. It does not assume exactly six pairs:
    pair rows are discovered from labels such as '1 пара', '7 пара'.
    """
    path = Path(path)
    result: dict[str, Any] = {"source_file": path.name, "weeks": []}

    with pdfplumber.open(path) as pdf:
        for page_number, page in enumerate(pdf.pages, 1):
            tables = page.find_tables(table_settings={
                "vertical_strategy": "lines",
                "horizontal_strategy": "lines",
            })
            if not tables:
                continue
            rows = tables[0].extract()
            if len(rows) < 3:
                continue

            start, end = parse_period(rows[0][0])
            week_type = clean_text(rows[0][1] if len(rows[0]) > 1 else "")
            group = clean_text(rows[0][2] if len(rows[0]) > 2 else "")

            starts = _day_start_indices(rows)
            if not starts:
                continue

            days = []
            for di, start_idx in enumerate(starts):
                stop_idx = starts[di + 1] if di + 1 < len(starts) else len(rows)
                date = start + timedelta(days=di)
                # Do not manufacture days outside the page period.
                if date > end:
                    break
                days.append(_parse_day(rows[start_idx:stop_idx], date, di))

            result["weeks"].append({
                "page": page_number,
                "from": start.isoformat(),
                "to": end.isoformat(),
                "week_type": week_type,
                "group": group,
                "days": days,
            })

    if not result["weeks"]:
        raise ValueError("В PDF не найдено ни одной таблицы расписания")
    return result


def save_json(schedule: dict[str, Any], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(schedule, ensure_ascii=False, indent=2), encoding="utf-8")


def flatten_days(schedule: dict[str, Any]) -> dict[str, dict[str, Any]]:
    days = {}
    for week in schedule.get("weeks", []):
        for day in week.get("days", []):
            days[day["date"]] = day
    return days
