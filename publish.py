"""Fetch the real PDF, render it, and upload without exposing secrets in logs."""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from updater import refresh_schedule
from formatter import render_day
from schedule_parser import flatten_days


def main():
    with tempfile.TemporaryDirectory() as tmp:
        result = refresh_schedule(schedule_path=Path(tmp) / 'schedule.json', state_path=Path(tmp) / 'state.json')
        data = result['schedule']
        payload = {
            'from': data['weeks'][0]['from'], 'to': data['weeks'][-1]['to'],
            'checked_at': datetime.now(timezone.utc).isoformat(),
            'days': {key: render_day(day) for key, day in flatten_days(data).items()},
        }
        print('PDF downloaded and parsed successfully.')
        secret=os.environ.get('UPDATE_SECRET')
        if not secret and os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL'):
            from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
            url=urlsplit(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'])
            query=parse_qsl(url.query)+[('audience','vba25-schedule-update')]
            response=requests.get(urlunsplit((url.scheme,url.netloc,url.path,urlencode(query),url.fragment)),headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']},timeout=20)
            response.raise_for_status(); secret=response.json()['value']
        if not secret:
            print('Connectivity check only: cloud publication is not configured yet.')
            return
        response = requests.post(os.environ['WORKER_URL'].rstrip('/') + '/schedule',
            headers={'Authorization': 'Bearer ' + secret}, json=payload, timeout=30)
        response.raise_for_status()
        print('Schedule published successfully.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Update failed ({type(exc).__name__}); previous cloud schedule is retained.')
        raise SystemExit(1) from None
