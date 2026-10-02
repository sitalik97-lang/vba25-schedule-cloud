from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Any

from schedule_parser import parse_pdf, flatten_days
from normalize import group_matches
from constants import PAIR_TIMES
from domain import safe_text
from source import (
    HttpClient,
    choose_candidate,
    discover_candidates,
    load_state,
    save_state,
    sha256_bytes,
)

DEFAULT_PAGE_URL = "https://mauniver.ru/structure/branches/mmrc/timetable/opr/"
DEFAULT_GROUP = "М9-ВБА25О-1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", delete=False
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def validate_schedule(schedule, stable_group):
    weeks = schedule.get('weeks', [])
    if not weeks or not flatten_days(schedule):
        raise ValueError('Расписание пустое')
    found = False
    for week in weeks:
        if week.get('group') and not group_matches(week['group'], stable_group):
            raise ValueError('В таблице другая группа')
        start, end = date.fromisoformat(week['from']), date.fromisoformat(week['to'])
        if start > end: raise ValueError('Некорректный период')
        for day in week['days']:
            if not start <= date.fromisoformat(day['date']) <= end:
                raise ValueError('Дата вне периода')
            for pair in day['pairs']:
                if pair['number'] not in PAIR_TIMES or len(pair['subgroups']) != 2:
                    raise ValueError('Неизвестная структура пары')
                found |= any(e.get('subject') for e in pair['subgroups'])
    if not found: raise ValueError('Не удалось прочитать ни одного занятия')


def refresh_schedule(
    *,
    page_url: str = DEFAULT_PAGE_URL,
    stable_group: str = DEFAULT_GROUP,
    target: date | None = None,
    schedule_path: str | Path = "data/schedule.json",
    state_path: str | Path = "data/state.json",
    client: HttpClient | None = None,
) -> dict[str, Any]:
    """Refresh the timetable while preserving the last known-good schedule.

    The existing schedule JSON is replaced only after a candidate file has been
    downloaded and parsed successfully. Any network or PDF parsing error is
    recorded in state.json and then re-raised, leaving the old timetable intact.
    """
    target = target or datetime.now(ZoneInfo(os.getenv("BOT_TIMEZONE", "Europe/Moscow"))).date()
    schedule_path = Path(schedule_path)
    state_path = Path(state_path)
    client = client or HttpClient()

    state = load_state(state_path)
    state["last_check"] = _utc_now()
    state["page_url"] = page_url
    state["stable_group"] = stable_group

    try:
        page = client.get(page_url)
        candidates = discover_candidates(page.text, page_url, stable_group)
        candidate = choose_candidate(candidates, target)
        if not candidate:
            raise RuntimeError(f"На странице не найден файл для группы {stable_group}")

        response = client.get(candidate.url)
        pdf_bytes = response.content
        if not pdf_bytes:
            raise RuntimeError("Файл расписания скачался пустым")

        digest = sha256_bytes(pdf_bytes)
        unchanged = digest == state.get("file_sha256") and schedule_path.exists()

        # Even if the file is unchanged, update freshness/status metadata.
        if unchanged:
            state.update({
                "ok": True,
                "last_success": _utc_now(),
                "last_error": None,
                "candidate": asdict(candidate),
                "file_sha256": digest,
                "changed": False,
            })
            save_state(state_path, state)
            return {"changed": False, "candidate": candidate, "schedule": None, "state": state}

        with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as tmp:
            tmp.write(pdf_bytes)
            pdf_path = Path(tmp.name)
        try:
            schedule = parse_pdf(pdf_path)
        finally:
            pdf_path.unlink(missing_ok=True)

        validate_schedule(schedule, stable_group)

        # The temp file name is meaningless to users; record the source label/url.
        schedule["source_file"] = candidate.label or Path(candidate.url).name
        schedule["source_url"] = candidate.url
        schedule["download_sha256"] = digest
        schedule["updated_at"] = _utc_now()

        if schedule_path.exists():
            old_bytes = schedule_path.read_bytes()
            archive = schedule_path.parent / 'schedule_archive' / (sha256_bytes(old_bytes) + '.json')
            if not archive.exists():
                old_schedule = json.loads(old_bytes)
                _write_json_atomic(archive, old_schedule)
        _write_json_atomic(schedule_path, schedule)
        state.update({
            "ok": True,
            "last_success": _utc_now(),
            "last_error": None,
            "candidate": asdict(candidate),
            "file_sha256": digest,
            "changed": True,
        })
        save_state(state_path, state)
        return {"changed": True, "candidate": candidate, "schedule": schedule, "state": state}

    except Exception as exc:
        state.update({
            "ok": False,
            "last_error": safe_text(f"{type(exc).__name__}: {exc}"),
            "changed": False,
        })
        save_state(state_path, state)
        raise


def main() -> None:
    page_url = os.getenv("SCHEDULE_PAGE_URL", DEFAULT_PAGE_URL)
    stable_group = os.getenv("STABLE_GROUP", DEFAULT_GROUP)
    schedule_path = os.getenv("SCHEDULE_JSON", "data/schedule.json")
    state_path = os.getenv("SCHEDULE_STATE", "data/state.json")
    result = refresh_schedule(
        page_url=page_url,
        stable_group=stable_group,
        schedule_path=schedule_path,
        state_path=state_path,
    )
    print("Расписание обновлено." if result["changed"] else "Изменений нет.")


if __name__ == "__main__":
    main()
