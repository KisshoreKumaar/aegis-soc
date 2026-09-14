#!/usr/bin/env python3
"""Repeatable synthetic scenario checks, not a real-world accuracy benchmark."""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegis.demo import scenario
from aegis.store import Store

expectations = {'attack-chain': (1, {'AUTH-001', 'AUTH-002', 'PROC-001', 'NET-001'}),
                'benign': (0, set()), 'late-arrival': (1, {'AUTH-001', 'AUTH-002'}), 'indicator': (1, {'SOURCE-002'})}
results = []
for name, (count, rules) in expectations.items():
    with tempfile.TemporaryDirectory() as folder:
        store = Store(str(Path(folder) / 'evaluation.db'))
        events = scenario(name)
        store.ingest_many(events)
        state = store.snapshot()
        observed = {d['rule_id'] for i in state['incidents'] for d in i['analysis']['detections']}
        passed = state['metrics']['incidents'] == count and observed == rules and store.verify_audit()['valid']
        results.append({'scenario': name, 'events': len(events), 'incidents': state['metrics']['incidents'], 'rules': sorted(observed), 'passed': passed})
print(json.dumps({'scope': 'Synthetic functional evaluation only; not precision/recall on real security data', 'results': results}, indent=2))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
