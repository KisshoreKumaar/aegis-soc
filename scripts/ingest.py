#!/usr/bin/env python3
"""Send canonical JSON/JSONL telemetry to a local AEGIS server."""
import argparse
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from run import load_environment

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('file', type=Path)
parser.add_argument('--url', default='http://127.0.0.1:8000')
args = parser.parse_args()
load_environment()
url = urlsplit(args.url)
if url.scheme not in ('http', 'https') or url.username or url.password or url.query or url.fragment:
    parser.error('Use a plain http(s) server URL')
if url.scheme == 'http' and url.hostname not in ('127.0.0.1', 'localhost', '::1'):
    parser.error('Remote ingestion requires HTTPS to protect the token')
if args.file.stat().st_size > 1048576:
    parser.error('File exceeds 1 MiB')
text = args.file.read_text()
try:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = [json.loads(line) for line in text.splitlines() if line.strip()]
    events = parsed if isinstance(parsed, list) else parsed.get('events', [parsed])
    payload = json.dumps({'events': events}).encode()
    request = Request(args.url.rstrip('/') + '/api/events/batch', payload, {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + os.environ.get('AEGIS_API_TOKEN', '')}, method='POST')
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    print(json.dumps({'processed': len(result['results']), 'duplicates': sum(r['duplicate'] for r in result['results'])}))
except HTTPError as error:
    raise SystemExit(f'Ingestion rejected (HTTP {error.code}); check schema, permissions, and event IDs.') from None
except (ValueError, AttributeError, URLError):
    raise SystemExit('Invalid telemetry or server unavailable; no successful ingestion was confirmed.') from None
