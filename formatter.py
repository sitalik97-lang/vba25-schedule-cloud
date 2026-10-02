from __future__ import annotations

from datetime import date
from typing import Any

from constants import PAIR_TIMES, WEEKDAYS_RU


def _is_empty(entry: dict[str, str]) -> bool:
    return not any((entry.get("subject"), entry.get("teacher"), entry.get("room")))


def _same(a: dict[str, str], b: dict[str, str]) -> bool:
    return (
        a.get("subject", "").strip() == b.get("subject", "").strip()
        and a.get("teacher", "").strip() == b.get("teacher", "").strip()
        and a.get("room", "").strip() == b.get("room", "").strip()
    )


def _entry_lines(pair_no: int, entry: dict[str, str]) -> list[str]:
    start, end = PAIR_TIMES.get(pair_no, ("?", "?"))
    title = f"{pair_no}. {start}-{end}"
    subject = entry.get("subject", "").strip()
    teacher = entry.get("teacher", "").strip()
    room = entry.get("room", "").strip()
    details = " · ".join(x for x in (teacher, room) if x)
    return [f"{title} — {subject}" + (f" ({details})" if details else "")]


def day_mode(day: dict[str, Any]) -> str:
    """Return 'combined' when both subgroups have exactly the same actual lessons."""
    for pair in day.get("pairs", []):
        a, b = pair["subgroups"]
        if _is_empty(a) and _is_empty(b):
            continue
        if not _same(a, b):
            return "split"
    return "combined"


def render_day(day: dict[str, Any] | None) -> str:
    if not day:
        return "На эту дату расписание в текущем файле не найдено."

    d = date.fromisoformat(day["date"])
    weekday = WEEKDAYS_RU[d.weekday()].capitalize()
    header = f"📅 {weekday}, {d.strftime('%d.%m.%Y')}"
    actual_pairs = [p for p in day.get("pairs", []) if not all(_is_empty(x) for x in p["subgroups"])]
    if not actual_pairs:
        return header + "\nПар нет."

    if day_mode(day) == "combined":
        lines = [header]
        for pair in actual_pairs:
            a, b = pair["subgroups"]
            entry = a if not _is_empty(a) else b
            lines.extend(_entry_lines(pair["number"], entry))
        return "\n".join(lines)

    lines = [header, "", "👥 1 подгруппа"]
    found = False
    for pair in actual_pairs:
        entry = pair["subgroups"][0]
        if not _is_empty(entry):
            found = True
            lines.extend(_entry_lines(pair["number"], entry))
    if not found:
        lines.append("Пар нет.")

    lines.extend(["", "👥 2 подгруппа"])
    found = False
    for pair in actual_pairs:
        entry = pair["subgroups"][1]
        if not _is_empty(entry):
            found = True
            lines.extend(_entry_lines(pair["number"], entry))
    if not found:
        lines.append("Пар нет.")
    return "\n".join(lines)
