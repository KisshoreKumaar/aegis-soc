"""Pure normalization and evidence-backed detection; never executes log content."""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import re

KINDS = {'auth_failure', 'auth_success', 'suspicious_process', 'malicious_indicator',
         'process_start', 'network_connection', 'file_change'}
RULES = [
    {'id': 'AUTH-001', 'name': 'Repeated authentication failures', 'threshold': '5 failures / 10 minutes / asset + user + source + IP', 'technique': 'T1110'},
    {'id': 'AUTH-002', 'name': 'Success following repeated failures', 'threshold': 'Success after AUTH-001 within 10 minutes', 'technique': None},
    {'id': 'PROC-001', 'name': 'Encoded PowerShell invocation', 'threshold': 'PowerShell executable with encoded-command argument', 'technique': 'T1059.001'},
    {'id': 'NET-001', 'name': 'Possible network service discovery', 'threshold': '10 distinct destination IP/port pairs / 5 minutes / asset + user', 'technique': 'T1046'},
    {'id': 'SOURCE-001', 'name': 'Upstream suspicious process alert', 'threshold': 'Source-reported alert', 'technique': None},
    {'id': 'SOURCE-002', 'name': 'Upstream malicious indicator alert', 'threshold': 'Source-reported alert; reputation unverified', 'technique': None},
]


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError('Event must be a JSON object')
    allowed = {'source', 'asset', 'user', 'kind', 'timestamp', 'source_ip', 'details', 'criticality', 'privileged',
               'event_id', 'process_name', 'command_line', 'destination_ip', 'destination_port', 'file_path'}
    if set(raw) - allowed:
        raise ValueError('Unknown event fields')
    event = dict(raw)
    for key in ('source', 'asset', 'user', 'kind'):
        if not isinstance(event.get(key), str) or not 1 <= len(event[key].strip()) <= 200:
            raise ValueError(f'{key} must be a nonempty string of at most 200 characters')
        event[key] = event[key].strip()
    if event['kind'] not in KINDS:
        raise ValueError('Unsupported event kind')
    event.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
    try:
        stamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp > datetime.now(timezone.utc):
            raise ValueError()
        event['timestamp'] = stamp.astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, TypeError, AttributeError):
        raise ValueError('timestamp must be a timezone-aware ISO date at or before now') from None
    event.setdefault('details', '')
    for key, limit in [('details', 4000), ('command_line', 4000), ('process_name', 200), ('event_id', 200), ('file_path', 1000)]:
        if key in event and (not isinstance(event[key], str) or len(event[key]) > limit or (key != 'details' and not event[key].strip())):
            raise ValueError(f'{key} must be a string of at most {limit} characters')
    event.setdefault('criticality', 1)
    if type(event['criticality']) is not int or event['criticality'] not in range(1, 6):
        raise ValueError('criticality must be an integer from 1 to 5')
    event.setdefault('privileged', False)
    if type(event['privileged']) is not bool:
        raise ValueError('privileged must be boolean')
    for key in ('source_ip', 'destination_ip'):
        if key in event:
            try:
                if not isinstance(event[key], str):
                    raise ValueError()
                event[key] = str(ipaddress.ip_address(event[key]))
            except (ValueError, TypeError):
                raise ValueError(f'{key} must be an IP address') from None
    if 'destination_port' in event and (type(event['destination_port']) is not int or not 1 <= event['destination_port'] <= 65535):
        raise ValueError('destination_port must be an integer from 1 to 65535')
    required = {'process_start': ('process_name', 'command_line'), 'network_connection': ('destination_ip', 'destination_port'), 'file_change': ('file_path',)}
    if any(k not in event for k in required.get(event['kind'], ())):
        raise ValueError('Missing fields for event kind')
    return event


def seconds(event):
    return datetime.fromisoformat(event['timestamp']).timestamp()


def assess(events):
    events = sorted(events, key=lambda e: (e['timestamp'], e['id']))
    detections, stages = [], []
    techniques = {}

    def detect(rule, evidence, stage, mapping=None):
        ids = sorted({e['id'] for e in evidence})
        detections.append({'rule_id': rule, 'evidence_ids': ids})
        if stage not in stages:
            stages.append(stage)
        if mapping:
            tid, name, tactic = mapping
            entry = techniques.setdefault(tid, {'id': tid, 'name': name, 'tactic': tactic, 'evidence': [], 'status': 'Candidate mapping; analyst validation required'})
            entry['evidence'] = sorted(set(entry['evidence']) | set(ids))

    buckets = defaultdict(list)
    for e in events:
        if e['kind'] in ('auth_failure', 'auth_success'):
            buckets[(e['asset'], e['user'], e['source'], e.get('source_ip'))].append(e)
    brute_evidence, success_evidence = {}, {}
    for bucket in buckets.values():
        window = []
        for e in bucket:
            window = [f for f in window if seconds(e) - seconds(f) <= 600]
            if e['kind'] == 'auth_failure':
                window.append(e)
            if len(window) >= 5:
                brute_evidence.update({f['id']: f for f in window})
                if e['kind'] == 'auth_success' and sum(f['timestamp'] < e['timestamp'] for f in window) >= 5:
                    success_evidence[e['id']] = e
    if brute_evidence:
        detect('AUTH-001', brute_evidence.values(), 'Credential Access', ('T1110', 'Brute Force', 'Credential Access'))
    if success_evidence:
        detect('AUTH-002', [*brute_evidence.values(), *success_evidence.values()], 'Possible account access')
    encoded = [e for e in events if e['kind'] == 'process_start'
               and re.split(r'[/\\]', e['process_name'].lower())[-1] in ('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe')
               and re.search(r'(?:^|\s)-(?:enc|encodedcommand|e)\s+\S+', e['command_line'], re.I)]
    if encoded:
        detect('PROC-001', encoded, 'Execution', ('T1059.001', 'PowerShell', 'Execution'))
    network, scan = [], {}
    for e in events:
        if e['kind'] == 'network_connection':
            network = [n for n in network if seconds(e) - seconds(n) <= 300]
            network.append(e)
            if len({(n['destination_ip'], n['destination_port']) for n in network}) >= 10:
                scan.update({n['id']: n for n in network})
    if scan:
        detect('NET-001', scan.values(), 'Discovery', ('T1046', 'Network Service Discovery', 'Discovery'))
    for kind, rule in [('suspicious_process', 'SOURCE-001'), ('malicious_indicator', 'SOURCE-002')]:
        matching = [e for e in events if e['kind'] == kind]
        if matching:
            detect(rule, matching, 'Source-reported suspicious activity')
    if not detections:
        return None
    indicator = any(d['rule_id'] == 'SOURCE-002' for d in detections)
    confidence = 80 if success_evidence or (encoded and scan) else 75 if brute_evidence else 65 if encoded or scan else 50
    factors = {'threat_severity': 25 if indicator or encoded else 20,
               'detection_confidence': round(confidence * .2), 'asset_criticality': max(e['criticality'] for e in events) * 3,
               'user_privilege': 10 if any(e['privileged'] for e in events) else 0,
               'attack_progression': min(15, max(0, len(stages) - 1) * 5),
               'correlated_events': min(10, len(events)), 'known_indicator_reported': 5 if indicator else 0,
               'potential_impact': 5 if encoded or indicator else 0}
    score = min(100, sum(factors.values()))
    hypotheses = []
    if success_evidence:
        hypotheses.append({'label': 'HYPOTHESIS', 'statement': 'A successful login following repeated failures may indicate account compromise.'})
    if encoded or scan:
        hypotheses.append({'label': 'HYPOTHESIS', 'statement': 'Execution or discovery may be unauthorized; verify the user and maintenance schedule.'})
    return {'verdict': 'Suspicious', 'severity': 'CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW',
            'risk_score': score, 'risk_factors': factors, 'confidence': confidence, 'analysis_mode': 'deterministic',
            'detections': detections, 'mitre_attack': list(techniques.values()), 'attack_chain': stages,
            'evidence': [{'label': 'FACT', 'event_id': e['id'], 'statement': f"Source {e['source']} reported {e['kind']} for {e['user']} on {e['asset']}"} for e in events],
            'inferences': [{'label': 'INFERENCE', 'statement': 'The detection thresholds are met; legitimate administration or user error may also explain the activity.'}],
            'hypotheses': hypotheses,
            'unknowns': [{'label': 'UNKNOWN', 'statement': 'Source reliability, user intent, authorization, and actual compromise are unverified.'}],
            'recommended_actions': ['Preserve raw authentication and endpoint records.', 'Validate source telemetry and contact the asset owner.',
                                    'Investigate process ancestry, user authorization, and destination reputation.', 'Request reversible containment if compromise is confirmed.'],
            'missing_evidence': ['Original source records', 'Endpoint process tree', 'User authorization context', 'Indicator provenance and reputation']}
