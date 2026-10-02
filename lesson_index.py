"""Structured lesson access reusing the existing parser output, with exact subject keys."""
from datetime import datetime
from zoneinfo import ZoneInfo
from normalize import clean_text
from schedule_parser import flatten_days
from constants import PAIR_TIMES


def subject_key(name):
    return clean_text(name).casefold().replace('ё', 'е')


def lessons(schedule, subgroup=0):
    result = []
    for day in flatten_days(schedule).values():
        for pair in day.get('pairs', []):
            if pair['number'] not in PAIR_TIMES:
                continue
            for i, entry in enumerate(pair['subgroups'], 1):
                if subgroup not in (0, i) or not entry.get('subject'):
                    continue
                result.append({'subject': entry['subject'], 'subject_key': subject_key(entry['subject']),
                    'subgroup': i, 'date': day['date'], 'pair': pair['number'],
                    'at': datetime.fromisoformat(day['date'] + 'T' + PAIR_TIMES[pair['number']][0]).replace(
                        tzinfo=ZoneInfo('Europe/Moscow')).isoformat(),
                    'teacher': entry.get('teacher', ''), 'room': entry.get('room', '')})
    return sorted(result, key=lambda item: (item['at'], item['pair'], item['subgroup']))


def next_lesson(schedule, subject, anchor, subgroup=0):
    after = datetime.fromisoformat(anchor)
    if after.tzinfo is None:
        raise ValueError('Anchor must include timezone')
    candidates = [lesson for lesson in lessons(schedule, subgroup)
                  if lesson['subject_key'] == subject_key(subject)
                  and datetime.fromisoformat(lesson['at']) > after]
    return candidates[0] if candidates else None
