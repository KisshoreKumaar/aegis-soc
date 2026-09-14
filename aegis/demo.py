"""Synthetic data only. These scenarios do not issue network or shell commands."""
from datetime import datetime, timedelta, timezone
import uuid

SCENARIOS = [
    {'id': 'attack-chain', 'name': 'Account compromise → execution → discovery', 'description': 'Five failed logins, a successful login, encoded PowerShell, then ten service connections. One correlated incident.'},
    {'id': 'benign', 'name': 'Benign workday', 'description': 'Isolated login mistakes, successful access and ordinary processes across separate users. No detection expected.'},
    {'id': 'late-arrival', 'name': 'Out-of-order authentication logs', 'description': 'The successful login arrives first; earlier failures arrive later. Detection still reconstructs the sequence.'},
    {'id': 'indicator', 'name': 'Upstream indicator alert', 'description': 'A source-reported indicator creates a case without inventing an ATT&CK mapping or verified malicious verdict.'},
]


def scenario(name):
    if name not in {s['id'] for s in SCENARIOS}:
        raise ValueError('Unknown demo scenario')
    run = uuid.uuid4().hex[:8]
    base = datetime.now(timezone.utc) - timedelta(minutes=3)
    events = []

    def add(kind, **extra):
        index = len(events)
        events.append({'source': 'demo-auth', 'asset': 'lab-ws-' + run, 'user': 'alex', 'event_id': f'{run}-{index}',
                       'source_ip': '192.0.2.42', 'criticality': 4, 'privileged': True, 'kind': kind,
                       'timestamp': (base + timedelta(seconds=index * 5)).isoformat(),
                       'details': 'SYNTHETIC DEMO — no real activity occurred.', **extra})
    if name in ('attack-chain', 'late-arrival'):
        for _ in range(5):
            add('auth_failure')
        add('auth_success')
        if name == 'attack-chain':
            add('process_start', source='demo-endpoint', process_name='powershell.exe', command_line='powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAGQAZQBtAG8AIgA=')
            for port in range(8000, 8010):
                add('network_connection', source='demo-network', destination_ip='198.51.100.20', destination_port=port)
        else:
            events.reverse()
    elif name == 'benign':
        for user in ('sam', 'jordan', 'riley'):
            add('auth_failure', user=user, privileged=False, criticality=1)
            add('auth_success', user=user, privileged=False, criticality=1)
            add('process_start', user=user, privileged=False, criticality=1, process_name='python3', command_line='python3 report.py')
    else:
        add('malicious_indicator', source='demo-edr', details='SYNTHETIC: upstream alert reported 203.0.113.99 as suspicious; no external reputation lookup was performed.')
    return events
