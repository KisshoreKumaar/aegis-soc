#!/usr/bin/env python3
"""Create private local demo configuration once and start AEGIS."""
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load_environment():
    os.chdir(ROOT)
    path = ROOT / '.env'
    if not path.exists():
        content = f'AEGIS_API_TOKEN={secrets.token_urlsafe(32)}\nAEGIS_AUDIT_KEY={secrets.token_urlsafe(32)}\nAEGIS_HOST=127.0.0.1\nAEGIS_PORT=8000\nAEGIS_DB=data/aegis.db\n'
        # Existing unkeyed databases must retain their audit key mode.
        if (ROOT / 'data/aegis.db').exists():
            content = '\n'.join(line for line in content.splitlines() if not line.startswith('AEGIS_AUDIT_KEY=')) + '\n'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        print('Created private .env configuration. View your dashboard token locally with: python3 scripts/manage.py token')
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not key.startswith('AEGIS_'):
            raise SystemExit('Invalid .env entry; use AEGIS_NAME=value without shell expressions')
        os.environ.setdefault(key, value)


if __name__ == '__main__':
    load_environment()
    from aegis.server import main
    main()
