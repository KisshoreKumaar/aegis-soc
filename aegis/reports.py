"""Portable incident reports with source evidence and review provenance."""
from .store import now


def report(incident):
    return {'report_version': 1, 'generated_at': now(), 'mode': 'offline-deterministic',
            'warning': 'Source reports and candidate detections are not proof of compromise. Response actions are simulations.',
            'incident': incident}


def markdown(incident):
    def safe(text):
        return str(text).replace('\\', '\\\\').replace('`', '\\`').replace('<', '&lt;').replace('>', '&gt;').replace('*', '\\*').replace('_', '\\_').replace('[', '\\[').replace(']', '\\]').replace('#', '\\#').replace('\n', ' ')
    a = incident['analysis']
    lines = ['# AEGIS Incident Report', '', f"Generated: {now()}", '', 'Offline deterministic analysis. All response actions are simulated.', '',
             f"Incident: {incident['id']}", f"Status: {incident.get('status', 'OPEN')}", f"Asset: {safe(incident['asset'])}", f"User: {safe(incident['user'])}",
             f"Verdict: {a['verdict']} | Severity: {a['severity']} | Risk: {a['risk_score']}/100 | Heuristic confidence: {a['confidence']}%", '', '## Evidence', '']
    lines.extend(f"- FACT: {safe(e['statement'])} (event {e['event_id']})" for e in a['evidence'])
    for title, items in [('Inferences', a['inferences']), ('Hypotheses', a['hypotheses']), ('Unknowns', a['unknowns'])]:
        lines += ['', '## ' + title, ''] + [f"- {safe(i['statement'])}" for i in items]
    lines += ['', '## Risk factors', ''] + [f'- {safe(k)}: {v}' for k, v in a['risk_factors'].items()]
    lines += ['', '## Candidate MITRE ATT&CK mappings', ''] + [f"- {t['id']} {t['name']} ({t['tactic']}), evidence: {', '.join(t['evidence'])}" for t in a['mitre_attack']]
    if not a['mitre_attack']:
        lines.append('No supported mapping.')
    lines += ['', '## Recommended actions', ''] + [f'- {safe(i)}' for i in a['recommended_actions']]
    lines += ['', '## Missing evidence', ''] + [f'- {safe(i)}' for i in a['missing_evidence']]
    lines += ['', '## Timeline', ''] + [f"- {e['timestamp']} — {safe(e['kind'])}: {safe(e['details'])} ({e['id']})" for e in incident['events']]
    lines += ['', '## Analyst notes', ''] + [f"- {n['timestamp']} / {safe(n['actor'])}: {safe(n['text'])}" for n in incident.get('notes', [])]
    lines += ['', '## Response audit summary', ''] + [f"- {safe(r['action'])}: {r['status']}. Requested by {safe(r.get('requested_by', 'legacy operator'))}. {safe(r.get('verification', 'No execution recorded.'))}" for r in incident.get('responses', [])]
    return '\n'.join(lines) + '\n'
