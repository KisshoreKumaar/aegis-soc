"""Transactional SQLite event store, incident workflow, and simulation policy."""
import hashlib
import hmac
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .engine import normalize, assess


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def entity_key(event):
    return packed([event['asset'], event['user']])


def require_text(value, name, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'{name} must be nonempty text (maximum {limit} characters)')
    return value.strip()


class Store:
    def __init__(self, path, audit_key=''):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path, self.audit_key = path, audit_key.encode()
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, correlation TEXT NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS responses (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS event_index (id TEXT PRIMARY KEY REFERENCES events(id), entity TEXT NOT NULL, timestamp TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_event_entity_time ON event_index(entity, timestamp);
                CREATE INDEX IF NOT EXISTS ix_event_time ON event_index(timestamp);
                CREATE TABLE IF NOT EXISTS raw_events (id TEXT PRIMARY KEY REFERENCES events(id), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS dedup (source TEXT NOT NULL, external_id TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES events(id), digest TEXT NOT NULL, PRIMARY KEY(source, external_id));
                CREATE TABLE IF NOT EXISTS incident_events (incident_id TEXT NOT NULL REFERENCES incidents(id), event_id TEXT NOT NULL REFERENCES events(id), PRIMARY KEY(incident_id,event_id));
                CREATE INDEX IF NOT EXISTS ix_event_incident ON incident_events(event_id);
                CREATE TABLE IF NOT EXISTS audit_proofs (seq INTEGER PRIMARY KEY REFERENCES audit(seq), previous TEXT NOT NULL, digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS virtual_endpoints (asset TEXT PRIMARY KEY, state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, created TEXT NOT NULL, body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_job_status ON jobs(status,created);
            ''')
            fingerprint = hashlib.sha256(self.audit_key).hexdigest() if self.audit_key else 'unkeyed-sha256'
            saved = db.execute("SELECT value FROM metadata WHERE key='audit_key_fingerprint'").fetchone()
            if saved and saved[0] != fingerprint:
                raise ValueError('Audit key does not match this database; restore the original configuration')
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('audit_key_fingerprint',?)", (fingerprint,))
            for event_id, body in db.execute('SELECT id,body FROM events WHERE id NOT IN (SELECT id FROM event_index)').fetchall():
                e = json.loads(body)
                e['timestamp'] = datetime.fromisoformat(e['timestamp']).astimezone(timezone.utc).isoformat(timespec='microseconds')
                db.execute('UPDATE events SET body=? WHERE id=?', (packed(e), event_id))
                db.execute('INSERT INTO event_index VALUES (?,?,?)', (event_id, entity_key(e), e['timestamp']))
            for iid, body in db.execute('SELECT id,body FROM incidents').fetchall():
                incident = json.loads(body)
                for eid in incident['event_ids']:
                    db.execute('INSERT OR IGNORE INTO incident_events VALUES (?,?)', (iid, eid))
            # Existing prototype audit entries become a labelled legacy baseline once.
            if not db.execute("SELECT 1 FROM metadata WHERE key='schema_version'").fetchone():
                for iid, serialized in db.execute('SELECT id,body FROM incidents').fetchall():
                    legacy = json.loads(serialized)
                    legacy.setdefault('status', 'OPEN')
                    legacy.setdefault('revision', 1)
                    legacy.setdefault('created', legacy['updated'])
                    legacy.setdefault('owner', '')
                    legacy.setdefault('notes', [])
                    legacy['analysis'] = assess(self._events(db, legacy['event_ids'])) or legacy['analysis']
                    self._save_incident(db, legacy)
                for row in db.execute('SELECT seq,timestamp,action,body FROM audit ORDER BY seq').fetchall():
                    self._proof(db, *row)
                db.execute("INSERT INTO metadata VALUES ('schema_version','2')")
                self.audit(db, 'schema.initialized', {'version': 2, 'legacy_audit_baseline': True, 'actor': 'system'})

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def _digest(self, value):
        data = packed(value).encode()
        return hmac.new(self.audit_key, data, hashlib.sha256).hexdigest() if self.audit_key else hashlib.sha256(data).hexdigest()

    def _proof(self, db, seq, timestamp, action, body):
        row = db.execute('SELECT digest FROM audit_proofs WHERE seq < ? ORDER BY seq DESC LIMIT 1', (seq,)).fetchone()
        previous = row[0] if row else '0' * 64
        digest = self._digest([seq, timestamp, action, body, previous])
        db.execute('INSERT INTO audit_proofs VALUES (?,?,?)', (seq, previous, digest))

    def audit(self, db, action, body):
        timestamp, serialized = now(), packed(body)
        seq = db.execute('INSERT INTO audit(timestamp,action,body) VALUES (?,?,?)', (timestamp, action, serialized)).lastrowid
        self._proof(db, seq, timestamp, action, serialized)

    def verify_audit(self):
        with self.connect() as db:
            previous, count = '0' * 64, 0
            for seq, stamp, action, body, prev, digest in db.execute('SELECT a.seq,a.timestamp,a.action,a.body,p.previous,p.digest FROM audit a LEFT JOIN audit_proofs p ON p.seq=a.seq ORDER BY a.seq'):
                if prev != previous or digest != self._digest([seq, stamp, action, body, previous]):
                    return {'valid': False, 'failed_sequence': seq, 'records': count}
                previous, count = digest, count + 1
            return {'valid': True, 'records': count, 'head': previous, 'mode': 'HMAC-SHA256' if self.audit_key else 'SHA256',
                    'limitation': 'Export and retain the head externally to detect whole-chain replacement or tail truncation.'}

    def ingest(self, raw, actor='local-admin'):
        return self.ingest_many([raw], actor)[0]

    def ingest_many(self, raw_events, actor='local-admin'):
        if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= 100:
            raise ValueError('Batch must contain 1–100 events')
        normalized = [normalize(raw) for raw in raw_events]
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            return [self._ingest(db, raw, event, actor) for raw, event in zip(raw_events, normalized)]

    def _ingest(self, db, raw, event, actor):
        digest = hashlib.sha256(packed(raw).encode()).hexdigest()
        if 'event_id' in event:
            prior = db.execute('SELECT event_id,digest FROM dedup WHERE source=? AND external_id=?', (event['source'], event['event_id'])).fetchone()
            if prior:
                if prior[1] != digest:
                    raise ValueError('event_id already exists with different content')
                saved = json.loads(db.execute('SELECT body FROM events WHERE id=?', (prior[0],)).fetchone()[0])
                return {'event': saved, 'incident': None, 'duplicate': True}
        event['id'] = str(uuid.uuid4())
        stamp = datetime.fromisoformat(event['timestamp'])
        key = entity_key(event)
        db.execute('INSERT INTO events VALUES (?,?)', (event['id'], packed(event)))
        db.execute('INSERT INTO raw_events VALUES (?,?)', (event['id'], packed(raw)))
        db.execute('INSERT INTO event_index VALUES (?,?,?)', (event['id'], key, event['timestamp']))
        if 'event_id' in event:
            db.execute('INSERT INTO dedup VALUES (?,?,?,?)', (event['source'], event['event_id'], event['id'], digest))
        # Re-evaluate neighbors on both sides so late arrivals can complete a detection.
        related = [json.loads(r[0]) for r in db.execute('SELECT e.body FROM events e JOIN event_index x ON e.id=x.id WHERE x.entity=? AND x.timestamp BETWEEN ? AND ? ORDER BY x.timestamp LIMIT 2001',
                   (key, (stamp - timedelta(minutes=10)).isoformat(timespec='microseconds'), (stamp + timedelta(minutes=10)).isoformat(timespec='microseconds')))]
        if len(related) > 2000:
            raise ValueError('Correlation window exceeds demo capacity (2000 events); split sources or archive to a larger backend')
        ids = {e['id'] for e in related}
        marks = ','.join('?' for _ in ids)
        existing = [json.loads(r[0]) for r in db.execute(f'SELECT DISTINCT i.body FROM incidents i JOIN incident_events l ON l.incident_id=i.id WHERE l.event_id IN ({marks})', tuple(ids))]
        existing = [i for i in existing if i.get('status', 'OPEN') != 'MERGED']
        for old in existing:
            ids.update(old['event_ids'])
        if len(ids) > 2000:
            raise ValueError('Incident exceeds demo capacity (2000 events)')
        related = self._events(db, ids)
        analysis = assess(related)
        incident = None
        if analysis:
            existing.sort(key=lambda i: (i.get('created', i['updated']), i['id']))
            old = existing[0] if existing else {}
            incident = {**old, 'id': old.get('id', str(uuid.uuid4())), 'asset': event['asset'], 'user': event['user'],
                        'created': old.get('created', old.get('updated', now())), 'updated': now(),
                        'status': old.get('status', 'OPEN'), 'owner': old.get('owner', ''), 'notes': old.get('notes', []),
                        'revision': old.get('revision', 0) + 1, 'event_ids': [e['id'] for e in related], 'analysis': analysis}
            if incident['status'] in ('RESOLVED', 'FALSE_POSITIVE'):
                incident['status'] = 'OPEN'
                self.audit(db, 'incident.reopened', {'incident_id': incident['id'], 'reason': 'New correlated evidence', 'actor': actor})
            self._save_incident(db, incident, key)
            for merged in existing[1:]:
                merged['status'], merged['merged_into'] = 'MERGED', incident['id']
                self._save_incident(db, merged, key)
                self._cancel_responses(db, merged['id'], actor, 'Incident merged')
                self.audit(db, 'incident.merged', {'incident_id': merged['id'], 'merged_into': incident['id'], 'actor': actor})
            self._cancel_responses(db, incident['id'], actor, 'New evidence requires a new recommendation')
            self.audit(db, 'incident.updated' if old else 'incident.created', {'incident_id': incident['id'], 'revision': incident['revision'], 'actor': actor})
        self.audit(db, 'event.ingested', {'event_id': event['id'], 'actor': actor})
        return {'event': event, 'incident': incident, 'duplicate': False}

    def _events(self, db, ids):
        if not ids:
            return []
        marks = ','.join('?' for _ in ids)
        return [json.loads(r[0]) for r in db.execute(f'SELECT body FROM events WHERE id IN ({marks}) ORDER BY json_extract(body,\'$.timestamp\'),id', tuple(ids))]

    def _save_incident(self, db, body, key=None):
        key = key or packed([body['asset'], body['user']])
        db.execute('INSERT INTO incidents VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET correlation=excluded.correlation,updated=excluded.updated,body=excluded.body', (body['id'], key, body['updated'], packed(body)))
        db.executemany('INSERT OR IGNORE INTO incident_events VALUES (?,?)', [(body['id'], eid) for eid in body['event_ids']])

    def _incident(self, db, iid):
        require_text(iid, 'incident_id', 100)
        row = db.execute('SELECT body FROM incidents WHERE id=?', (iid,)).fetchone()
        if not row:
            raise ValueError('Unknown incident')
        return json.loads(row[0])

    def incident(self, iid):
        with self.connect() as db:
            incident = self._incident(db, iid)
            return {**incident, 'events': self._events(db, incident['event_ids']),
                    'responses': [json.loads(r[0]) for r in db.execute("SELECT body FROM responses WHERE json_extract(body,'$.incident_id')=? ORDER BY rowid", (iid,))],
                    'investigations': [json.loads(r[0]) for r in db.execute("SELECT body FROM jobs WHERE json_extract(body,'$.incident_id')=? ORDER BY created DESC LIMIT 20", (iid,))]}

    def update_incident(self, payload, actor):
        if set(payload) - {'incident_id', 'status', 'owner', 'note', 'revision'}:
            raise ValueError('Unknown incident update fields')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            body = self._incident(db, payload.get('incident_id'))
            if type(payload.get('revision')) is not int or payload['revision'] != body.get('revision', 0):
                raise ValueError('Incident changed; refresh before updating')
            if body.get('status') == 'MERGED':
                raise ValueError('Update the merged destination incident')
            if 'status' in payload:
                status = payload['status']
                if status not in ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'):
                    raise ValueError('Invalid incident status')
                if status in ('RESOLVED', 'FALSE_POSITIVE'):
                    require_text(payload.get('note'), 'Resolution note')
                    self._cancel_responses(db, body['id'], actor, 'Incident closed')
                body['status'] = status
            if 'owner' in payload:
                body['owner'] = require_text(payload['owner'], 'owner', 100)
            if 'note' in payload:
                note = require_text(payload['note'], 'note')
                if len(body.get('notes', [])) >= 200:
                    raise ValueError('Incident note limit reached')
                body.setdefault('notes', []).append({'text': note, 'actor': actor, 'timestamp': now()})
            body['revision'] = body.get('revision', 0) + 1
            body['updated'] = now()
            self._cancel_responses(db, body['id'], actor, 'Incident review changed')
            self._save_incident(db, body)
            self.audit(db, 'incident.reviewed', {'incident_id': body['id'], 'status': body.get('status'), 'actor': actor, 'revision': body['revision']})
            return body

    def snapshot(self):
        with self.connect() as db:
            incidents = [json.loads(r[0]) for r in db.execute('SELECT body FROM incidents ORDER BY updated DESC LIMIT 100')]
            total_incidents, open_incidents, highest = db.execute("SELECT count(*),sum(CASE WHEN coalesce(json_extract(body,'$.status'),'OPEN') IN ('OPEN','INVESTIGATING') THEN 1 ELSE 0 END),max(json_extract(body,'$.analysis.risk_score')) FROM incidents WHERE coalesce(json_extract(body,'$.status'),'OPEN') != 'MERGED'").fetchone()
            return {'events': [json.loads(r[0]) for r in db.execute('SELECT e.body FROM events e JOIN event_index x ON x.id=e.id ORDER BY x.timestamp DESC LIMIT 200')],
                    'incidents': incidents,
                    'responses': [json.loads(r[0]) for r in db.execute('SELECT body FROM responses ORDER BY rowid DESC LIMIT 100')],
                    'audit': [{'seq': r[0], 'timestamp': r[1], 'action': r[2], 'data': json.loads(r[3])} for r in db.execute('SELECT seq,timestamp,action,body FROM audit ORDER BY seq DESC LIMIT 100')],
                    'jobs': [json.loads(r[0]) for r in db.execute('SELECT body FROM jobs ORDER BY created DESC LIMIT 25')],
                    'metrics': {'events': db.execute('SELECT count(*) FROM events').fetchone()[0], 'incidents': total_incidents,
                                'open_incidents': open_incidents or 0, 'highest_risk': highest or 0},
                    'virtual_endpoints': [{'asset': r[0], 'state': r[1]} for r in db.execute('SELECT * FROM virtual_endpoints')]}

    def search(self, resource, query='', offset=0, limit=50, status=''):
        if resource not in ('events', 'incidents', 'audit') or not 0 <= offset <= 1000000 or not 1 <= limit <= 100:
            raise ValueError('Invalid pagination')
        if not isinstance(query, str) or len(query) > 200:
            raise ValueError('Search text too long')
        pattern = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        order = 'seq' if resource == 'audit' else 'rowid'
        condition, args = "body LIKE ? ESCAPE '\\'", [pattern]
        if resource == 'incidents':
            condition += " AND coalesce(json_extract(body,'$.status'),'OPEN') != 'MERGED'"
            if status:
                if status not in ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'):
                    raise ValueError('Invalid status filter')
                condition += " AND coalesce(json_extract(body,'$.status'),'OPEN')=?"
                args.append(status)
        with self.connect() as db:
            count = db.execute(f"SELECT count(*) FROM {resource} WHERE {condition}", args).fetchone()[0]
            rows = db.execute(f"SELECT * FROM {resource} WHERE {condition} ORDER BY {order} DESC LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
            items = [{'seq': r[0], 'timestamp': r[1], 'action': r[2], 'data': json.loads(r[3])} for r in rows] if resource == 'audit' else [json.loads(r[-1]) for r in rows]
            return {'items': items, 'total': count, 'offset': offset, 'limit': limit}

    def _cancel_responses(self, db, iid, actor, reason):
        for rid, serialized in db.execute('SELECT id,body FROM responses').fetchall():
            body = json.loads(serialized)
            if body['incident_id'] == iid and body['status'] in ('PENDING', 'APPROVED'):
                body.update(status='CANCELLED', reason=reason)
                db.execute('UPDATE responses SET body=? WHERE id=?', (packed(body), rid))
                self.audit(db, 'response.cancelled', {'response_id': rid, 'reason': reason, 'actor': actor})

    def response(self, operation, payload, actor='local-admin', two_person=False):
        if set(payload) - {'incident_id', 'response_id', 'action', 'confirmation', 'reason'}:
            raise ValueError('Unknown response fields')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if operation == 'recommend':
                incident = self._incident(db, payload.get('incident_id'))
                if incident.get('status', 'OPEN') not in ('OPEN', 'INVESTIGATING'):
                    raise ValueError('Responses require an active incident')
                action = payload.get('action', 'simulate_endpoint_isolation')
                if action not in ('simulate_endpoint_isolation', 'simulate_restore_connectivity', 'simulate_collect_evidence'):
                    raise ValueError('Response action is not allowlisted')
                body = {'id': str(uuid.uuid4()), 'incident_id': incident['id'], 'incident_revision': incident.get('revision', 0),
                        'asset': incident['asset'], 'action': action, 'status': 'PENDING', 'mode': 'simulation', 'created': now(), 'requested_by': actor}
            else:
                require_text(payload.get('response_id'), 'response_id', 100)
                row = db.execute('SELECT body FROM responses WHERE id=?', (payload['response_id'],)).fetchone()
                if not row:
                    raise ValueError('Unknown response')
                body = json.loads(row[0])
                allowed = {'approve': ('PENDING',), 'reject': ('PENDING', 'APPROVED'), 'execute': ('APPROVED',)}
                if operation not in allowed or body['status'] not in allowed[operation]:
                    raise ValueError('Invalid response state transition')
                incident = self._incident(db, body['incident_id'])
                if operation == 'reject':
                    body.update(status='REJECTED', reason=require_text(payload.get('reason'), 'Rejection reason'), rejected_by=actor)
                else:
                    if incident.get('status', 'OPEN') not in ('OPEN', 'INVESTIGATING') or incident.get('revision', 0) != body.get('incident_revision'):
                        raise ValueError('Incident changed; create a new recommendation')
                    if operation == 'approve':
                        if payload.get('confirmation') != 'APPROVE SIMULATION':
                            raise ValueError('Explicit confirmation required')
                        if two_person and body['requested_by'] == actor:
                            raise ValueError('A different operator must approve this request')
                        body.update(status='APPROVED', approved_by=actor, approved_at=now(),
                                    expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat())
                    else:
                        if datetime.fromisoformat(body['expires_at']) < datetime.now(timezone.utc):
                            raise ValueError('Approval expired; reject and recommend again')
                        previous = db.execute('SELECT state FROM virtual_endpoints WHERE asset=?', (body['asset'],)).fetchone()
                        previous = previous[0] if previous else 'CONNECTED'
                        target = {'simulate_endpoint_isolation': 'ISOLATED', 'simulate_restore_connectivity': 'CONNECTED'}.get(body['action'], previous)
                        db.execute('INSERT INTO virtual_endpoints VALUES (?,?) ON CONFLICT(asset) DO UPDATE SET state=excluded.state', (body['asset'], target))
                        verified = db.execute('SELECT state FROM virtual_endpoints WHERE asset=?', (body['asset'],)).fetchone()[0]
                        body.update(status='SIMULATED', executed_by=actor, executed_at=now(), simulation_result={'before': previous, 'after': verified, 'verified': verified == target},
                                    verification='Virtual endpoint state verified in SQLite. No real endpoint action was performed or verified.')
                        if body['action'] == 'simulate_collect_evidence':
                            body['evidence_manifest'] = [{'event_id': e['id'], 'sha256': hashlib.sha256(packed(e).encode()).hexdigest()} for e in self._events(db, incident['event_ids'])]
            db.execute('INSERT INTO responses VALUES (?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body', (body['id'], packed(body)))
            self.audit(db, f'response.{operation}', {**body, 'actor': actor})
            return body

    def create_job(self, iid, question, actor):
        question = require_text(question, 'question', 1000)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            incident = self._incident(db, iid)
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('QUEUED','RUNNING')").fetchone()[0] >= 50:
                raise ValueError('Investigation queue is full')
            body = {'id': str(uuid.uuid4()), 'incident_id': iid, 'revision': incident.get('revision', 0), 'question': question,
                    'status': 'QUEUED', 'created': now(), 'actor': actor, 'mode': 'offline'}
            db.execute('INSERT INTO jobs VALUES (?,?,?,?)', (body['id'], body['status'], body['created'], packed(body)))
            self.audit(db, 'investigation.queued', {'job_id': body['id'], 'incident_id': iid, 'actor': actor})
            return body

    def claim_job(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT body FROM jobs WHERE status='QUEUED' ORDER BY created LIMIT 1").fetchone()
            if not row:
                return None
            body = json.loads(row[0])
            body.update(status='RUNNING', started=now())
            db.execute('UPDATE jobs SET status=?,body=? WHERE id=?', ('RUNNING', packed(body), body['id']))
            return body

    def finish_job(self, body, result=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            body.update(status='COMPLETED' if result else 'FAILED', finished=now())
            body['result'] = result or {'error': 'Investigation failed; original evidence is preserved. Retry the request.'}
            db.execute('UPDATE jobs SET status=?,body=? WHERE id=?', (body['status'], packed(body), body['id']))
            self.audit(db, 'investigation.' + body['status'].lower(), {'job_id': body['id'], 'incident_id': body['incident_id'], 'actor': 'offline-investigator'})

    def recover_jobs(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT body FROM jobs WHERE status='RUNNING'").fetchall():
                body = json.loads(row[0])
                body['status'] = 'QUEUED'
                db.execute("UPDATE jobs SET status='QUEUED',body=? WHERE id=?", (packed(body), body['id']))
                self.audit(db, 'investigation.requeued', {'job_id': body['id'], 'actor': 'system'})

    def job(self, jid):
        with self.connect() as db:
            row = db.execute('SELECT body FROM jobs WHERE id=?', (jid,)).fetchone()
            if not row:
                raise ValueError('Unknown investigation job')
            return json.loads(row[0])
