import json
import secrets
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from aegis.engine import normalize
from aegis.store import Store
from aegis.server import handler


def event(kind='auth_failure', **changes):
    return {'source': 'test', 'asset': 'host-1', 'user': 'alice', 'kind': kind, **changes}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / 'test.db'))

    def tearDown(self):
        self.tmp.cleanup()

    def test_attack_chain_and_evidence(self):
        for _ in range(4):
            self.assertIsNone(self.store.ingest(event())['incident'])
        first = self.store.ingest(event())['incident']
        final = self.store.ingest(event('auth_success'))['incident']
        self.assertEqual(first['id'], final['id'])
        self.assertEqual(len(final['event_ids']), 6)
        self.assertGreater(final['analysis']['risk_score'], first['analysis']['risk_score'])
        self.assertEqual(final['analysis']['mitre_attack'][0]['id'], 'T1110')
        self.assertEqual({e['event_id'] for e in final['analysis']['evidence']}, set(final['event_ids']))
        self.assertEqual(len(Store(self.store.path).snapshot()['incidents']), 1)

    def test_unrelated_users_do_not_correlate(self):
        for i in range(8):
            self.assertIsNone(self.store.ingest(event(user=f'user-{i}'))['incident'])

    def test_old_failures_do_not_trigger(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        for _ in range(4):
            self.store.ingest(event(timestamp=old))
        self.assertIsNone(self.store.ingest(event())['incident'])

    def test_source_ip_isolates_correlation(self):
        for i in range(8):
            self.assertIsNone(self.store.ingest(event(source_ip=f'192.0.2.{i}'))['incident'])

    def test_response_requires_approval_and_cannot_repeat(self):
        incident = self.store.ingest(event('suspicious_process'))['incident']
        response = self.store.response('recommend', {'incident_id': incident['id']})
        body = {'response_id': response['id']}
        with self.assertRaises(ValueError):
            self.store.response('execute', body)
        with self.assertRaises(ValueError):
            self.store.response('approve', body)
        self.store.response('approve', {**body, 'confirmation': 'APPROVE SIMULATION'})
        result = self.store.response('execute', body)
        self.assertEqual(result['status'], 'SIMULATED')
        with self.assertRaises(ValueError):
            self.store.response('execute', body)
        actions = [r['action'] for r in self.store.snapshot()['audit']]
        self.assertEqual(actions.count('response.execute'), 1)

    def test_strict_validation(self):
        for changes in [{'criticality': True}, {'privileged': 'yes'}, {'kind': 'unknown'}, {'source_ip': 'bad'}, {'timestamp': '2026-01-01'}, {'details': 'x' * 4001}, {'token': 'secret'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                normalize(event(**changes))

    def test_no_invented_technique(self):
        analysis = self.store.ingest(event('suspicious_process'))['incident']['analysis']
        self.assertEqual(analysis['mitre_attack'], [])
        self.assertEqual(analysis['analysis_mode'], 'deterministic')


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.token = secrets.token_urlsafe(32)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), handler(Store(str(Path(cls.tmp.name) / 'api.db')), cls.token))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, auth=True):
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + self.token
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = (response.status, response.read(), dict(response.getheaders()))
        conn.close()
        return result

    def test_auth_required(self):
        self.assertEqual(self.request('GET', '/api/state', auth=False)[0], 401)
        self.assertEqual(self.request('POST', '/api/events', json.dumps(event()), auth=False)[0], 401)

    def test_ingestion_and_state(self):
        self.assertEqual(self.request('POST', '/api/events', json.dumps(event()))[0], 201)
        status, body, _ = self.request('GET', '/api/state')
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)['ai']['configured'])

    def test_invalid_and_oversized_requests(self):
        self.assertEqual(self.request('POST', '/api/events', '{')[0], 400)
        self.assertEqual(self.request('POST', '/api/events', '[]')[0], 400)
        self.assertEqual(self.request('POST', '/api/events', 'x' * 65537)[0], 413)

    def test_dashboard_and_path_traversal(self):
        status, body, headers = self.request('GET', '/', auth=False)
        self.assertEqual(status, 200)
        self.assertIn(b'Operations overview', body)
        self.assertIn('Content-Security-Policy', headers)
        self.assertEqual(self.request('GET', '/../../.env', auth=False)[0], 404)


if __name__ == '__main__':
    unittest.main()
