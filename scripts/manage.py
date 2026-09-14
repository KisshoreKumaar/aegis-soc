#!/usr/bin/env python3
"""Local token retrieval, consistent database backup, and audit verification."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
from run import load_environment

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('command', choices=['token', 'verify-audit', 'backup'])
parser.add_argument('--output', help='New backup database path')
args = parser.parse_args()
load_environment()
if args.command == 'token':
    print(os.environ.get('AEGIS_API_TOKEN', 'Use the assigned token from AEGIS_IDENTITIES'))
else:
    from aegis.config import Settings
    from aegis.store import Store
    settings = Settings.from_env()
    source = os.environ.get('AEGIS_DB', 'data/aegis.db')
    if args.command == 'verify-audit':
        result = Store(source, settings.audit_key).verify_audit()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['valid'] else 1)
    if not args.output:
        parser.error('--output is required for backup')
    target = Path(args.output)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        original = sqlite3.connect(source)
        backup = sqlite3.connect(target)
        original.backup(backup)
    finally:
        if 'backup' in locals():
            backup.close()
        if 'original' in locals():
            original.close()
    print(f'Created consistent SQLite backup at {target}. Keep the matching audit key separately.')
