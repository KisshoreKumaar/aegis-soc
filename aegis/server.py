"""Bounded local HTTP service for the offline AEGIS demo."""
import json
import logging
import os
import socket
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .config import Settings, PERMISSIONS
from .demo import SCENARIOS, scenario
from .engine import RULES
from .investigation import Investigator
from .reports import report, markdown
from .store import Store

STATIC = Path(__file__).resolve().parent.parent / 'static'


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Limiter:
    def __init__(self, limit):
        self.limit, self.buckets, self.lock = limit, {}, threading.Lock()

    def allow(self, address):
        with self.lock:
            stamp = time.monotonic()
            if len(self.buckets) > 4096:
                self.buckets = {k: v for k, v in self.buckets.items() if v and v[-1] > stamp - 60}
                if address not in self.buckets and len(self.buckets) > 4096:
                    return False
            bucket = self.buckets.setdefault(address, deque())
            while bucket and bucket[0] <= stamp - 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(stamp)
            return True


def handler(store, token=None, settings=None):
    settings = settings or Settings(identities=[{'name': 'local-admin', 'role': 'admin', 'token': token}])
    settings.validate()
    limiter = Limiter(settings.rate_limit)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'AEGIS/1.0'
        sys_version = ''

        def setup(self):
            self.request.settimeout(10)
            super().setup()

        def log_message(self, fmt, *args):
            logging.info('request method=%s status=%s', self.command, args[1] if len(args) > 1 else '-')

        def send(self, status, body, mime='application/json'):
            data = json.dumps(body, allow_nan=False).encode() if mime == 'application/json' else body
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if status == 429:
                self.send_header('Retry-After', '60')
            self.end_headers()
            self.wfile.write(data)

        def authorized(self, permission):
            if not limiter.allow(self.client_address[0]):
                self.send(429, {'error': 'Request rate exceeded; retry in 60 seconds'})
                return False
            self.actor = settings.authenticate(self.headers.get('Authorization', ''))
            if not self.actor:
                self.send(401, {'error': 'A valid bearer token is required'})
                return False
            if permission not in PERMISSIONS[self.actor['role']]:
                self.send(403, {'error': 'This role does not have permission for this action'})
                return False
            return True

        def do_GET(self):
            try:
                route = urlsplit(self.path)
                path = route.path
                if path == '/healthz':
                    self.send(200, {'status': 'ok', 'mode': 'offline'})
                    return
                if path.startswith('/api/'):
                    if not self.authorized('read'):
                        return
                    params = parse_qs(route.query)
                    if path == '/api/state':
                        self.send(200, {**store.snapshot(), **settings.public(), 'identity': self.actor,
                                        'permissions': sorted(PERMISSIONS[self.actor['role']]), 'scenarios': SCENARIOS})
                    elif path == '/api/rules':
                        self.send(200, {'rules': RULES})
                    elif path == '/api/audit/verify':
                        self.send(200, store.verify_audit())
                    elif path in ('/api/events', '/api/incidents', '/api/audit'):
                        self.send(200, store.search(path.rsplit('/', 1)[1], params.get('q', [''])[0], int(params.get('offset', ['0'])[0]), int(params.get('limit', ['50'])[0]), params.get('status', [''])[0]))
                    elif path.startswith('/api/incidents/'):
                        parts = path.strip('/').split('/')
                        incident = store.incident(parts[2])
                        if len(parts) == 3:
                            self.send(200, incident)
                        elif len(parts) == 4 and parts[3] == 'report':
                            if params.get('format', ['json'])[0] == 'markdown':
                                self.send(200, markdown(incident).encode(), 'text/markdown; charset=utf-8')
                            else:
                                self.send(200, report(incident))
                        else:
                            self.send(404, {'error': 'Not found'})
                    elif path.startswith('/api/jobs/'):
                        self.send(200, store.job(path.rsplit('/', 1)[1]))
                    else:
                        self.send(404, {'error': 'Not found'})
                    return
                files = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
                if path not in files:
                    self.send(404, {'error': 'Not found'})
                    return
                filename, mime = files[path]
                self.send(200, (STATIC / filename).read_bytes(), mime)
            except ValueError as exc:
                self.send(400, {'error': str(exc)})
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                return
            except Exception:
                logging.error('GET request failed')
                self.send(500, {'error': 'Internal server error'})

        def do_POST(self):
            permissions = {'/api/events': 'ingest', '/api/events/batch': 'ingest', '/api/demo': 'ingest', '/api/incidents/update': 'investigate',
                           '/api/investigate': 'investigate', '/api/responses/recommend': 'recommend', '/api/responses/approve': 'approve',
                           '/api/responses/reject': 'approve', '/api/responses/execute': 'execute'}
            permission = permissions.get(self.path)
            if not permission:
                self.send(404, {'error': 'Not found'})
                return
            if not self.authorized(permission):
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                max_size = 1048576 if self.path == '/api/events/batch' else 65536
                if length <= 0 or length > max_size or self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
                    self.send(413, {'error': f'Request must be between 1 and {max_size} bytes with one Content-Length'})
                    return
                if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
                    self.send(415, {'error': 'Content-Type must be application/json'})
                    return
                def reject_constant(value):
                    raise ValueError('Non-finite numbers are not valid JSON')
                def unique_fields(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError('Duplicate JSON fields are not permitted')
                        result[key] = value
                    return result
                payload = json.loads(self.rfile.read(length), parse_constant=reject_constant, object_pairs_hook=unique_fields)
                if not isinstance(payload, dict):
                    raise ValueError('Request must be a JSON object')
                actor = self.actor['name']
                def ingestion_result(result):
                    if self.actor['role'] == 'ingest':
                        return {'event': {'id': result['event']['id']}, 'incident': {'id': result['incident']['id']} if result['incident'] else None, 'duplicate': result['duplicate']}
                    return result
                if self.path == '/api/events':
                    result = store.ingest(payload, actor)
                    self.send(200 if result['duplicate'] else 201, ingestion_result(result))
                elif self.path == '/api/events/batch':
                    if set(payload) != {'events'}:
                        raise ValueError('Batch body must contain only events')
                    self.send(201, {'results': [ingestion_result(r) for r in store.ingest_many(payload['events'], actor)]})
                elif self.path == '/api/demo':
                    if set(payload) != {'scenario'} or not isinstance(payload['scenario'], str):
                        raise ValueError('Provide a scenario name')
                    results = store.ingest_many(scenario(payload['scenario']), actor)
                    self.send(201, {'ingested': len(results), 'incident_ids': sorted({r['incident']['id'] for r in results if r['incident']}), 'synthetic': True})
                elif self.path == '/api/incidents/update':
                    self.send(200, store.update_incident(payload, actor))
                elif self.path == '/api/investigate':
                    if set(payload) != {'incident_id', 'question'}:
                        raise ValueError('Provide incident_id and question')
                    self.send(202, store.create_job(payload['incident_id'], payload['question'], actor))
                else:
                    self.send(200, store.response(self.path.rsplit('/', 1)[1], payload, actor, settings.two_person))
            except (ValueError, UnicodeError, RecursionError) as exc:
                self.send(400, {'error': 'Invalid JSON nesting' if isinstance(exc, RecursionError) else str(exc)})
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                return
            except Exception:
                logging.error('POST request processing failed')
                self.send(500, {'error': 'Internal server error'})
    return Handler


def main():
    os.umask(0o077)
    try:
        settings = Settings.from_env()
        host, port = os.getenv('AEGIS_HOST', '127.0.0.1'), int(os.getenv('AEGIS_PORT', '8000'))
        store = Store(os.getenv('AEGIS_DB', 'data/aegis.db'), settings.audit_key)
        if not store.verify_audit()['valid']:
            raise ValueError('Audit verification failed; preserve and investigate this database before starting')
    except (ValueError, TypeError):
        raise SystemExit('Invalid configuration or audit integrity failure. Check environment and database using the README instructions.') from None
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    server = BoundedServer((host, port), handler(store, settings=settings))
    worker = Investigator(store)
    worker.start()
    logging.info('AEGIS listening at http://%s:%s; offline investigation; virtual responses only', host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        worker.close()


if __name__ == '__main__':
    main()
