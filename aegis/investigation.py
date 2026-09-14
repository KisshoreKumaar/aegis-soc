"""Offline investigation: deterministic evidence retrieval, never a simulated LLM."""
import logging
import threading
from .engine import RULES

RULE_EXPLANATIONS = {
    'AUTH-001': 'At least five authentication failures occurred within ten minutes for the same asset, user, source and source IP. User error and automation failures remain alternatives.',
    'AUTH-002': 'A successful login occurred after at least five failures in the same authentication context within ten minutes. This raises concern but does not prove compromise.',
    'PROC-001': 'The reported PowerShell process includes an encoded-command argument. This can conceal command content, but legitimate administration also uses encoding. No command was executed or decoded by AEGIS.',
    'NET-001': 'At least ten distinct destination IP/port pairs were contacted within five minutes. Discovery is a candidate explanation; authorized scanners can produce the same pattern.',
    'SOURCE-001': 'The upstream source flagged a suspicious process. AEGIS has not independently established maliciousness.',
    'SOURCE-002': 'The upstream source flagged an indicator as malicious. Indicator reputation and provenance require independent confirmation.',
}


def investigate(incident, question):
    analysis, events = incident['analysis'], incident['events']
    facts = analysis['evidence']
    why = [{'label': 'INFERENCE', 'statement': RULE_EXPLANATIONS[d['rule_id']], 'evidence_ids': d['evidence_ids']} for d in analysis['detections']]
    query = question.casefold()
    if any(word in query for word in ('risk', 'score', 'priority', 'severity')):
        focus = 'risk'
        answer = f"The heuristic risk score is {analysis['risk_score']}/100 ({analysis['severity']}). It is a capped sum of published factors, not a probability of compromise."
    elif any(word in query for word in ('mitre', 'technique', 'attack chain')):
        focus = 'techniques'
        answer = 'Candidate ATT&CK mappings are derived from observed rule evidence. Stages describe candidate activity, not a proven attack path.'
    elif any(word in query for word in ('next', 'recommend', 'contain', 'remedia', 'action')):
        focus = 'actions'
        answer = 'Preserve evidence and validate authorization before containment. All available response playbooks affect only the virtual endpoint registry.'
    elif any(word in query for word in ('why', 'suspicious', 'evidence', 'happen', 'summar', 'investigate')):
        focus = 'evidence'
        answer = f"{len(events)} events on {incident['asset']} for {incident['user']} triggered {len(analysis['detections'])} deterministic rules. The current assessment is {analysis['verdict']}; actual compromise is unverified."
    else:
        focus = 'unsupported'
        answer = 'UNKNOWN: The offline investigator supports evidence summaries, risk explanations, ATT&CK candidates, and recommended next actions. It cannot answer arbitrary questions or look up external facts.'
    return {'mode': 'offline-deterministic', 'model_used': False, 'question': question, 'focus': focus, 'answer': answer,
            'incident_id': incident['id'], 'analyzed_revision': incident.get('revision', 0),
            'facts': facts, 'inferences': why, 'hypotheses': analysis['hypotheses'], 'unknowns': analysis['unknowns'],
            'risk_factors': analysis['risk_factors'], 'techniques': analysis['mitre_attack'],
            'next_actions': analysis['recommended_actions'], 'missing_evidence': analysis['missing_evidence'],
            'possible_next_steps': [{'label': 'HYPOTHESIS', 'statement': 'If account compromise is confirmed, investigate subsequent credential access or lateral movement; neither is established by this report.'}],
            'evidence_ids': [e['id'] for e in events]}


class Investigator:
    def __init__(self, store):
        self.store = store
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, name='aegis-investigator', daemon=True)

    def start(self):
        self.store.recover_jobs()
        self.thread.start()

    def process_one(self):
        job = self.store.claim_job()
        if not job:
            return False
        try:
            result = investigate(self.store.incident(job['incident_id']), job['question'])
            self.store.finish_job(job, result)
        except Exception:
            logging.error('Offline investigation failed for job %s', job['id'])
            self.store.finish_job(job)
        return True

    def loop(self):
        while not self.stop_event.is_set():
            try:
                if not self.process_one():
                    self.stop_event.wait(.25)
            except Exception:
                logging.error('Investigation worker unavailable; retrying')
                self.stop_event.wait(1)

    def close(self):
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
