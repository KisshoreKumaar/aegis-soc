# REST API

Base URL: `http://127.0.0.1:8000`. All `/api/*` routes require `Authorization: Bearer <operator-token>`. POST routes require `Content-Type: application/json`. Credentials belong in headers, never query parameters.

## Read routes

| Method / path | Result |
| --- | --- |
| `GET /healthz` | Public liveness and offline-mode indicator; no telemetry |
| `GET /api/state` | Global metrics, latest records, identity, permissions, scenarios, virtual endpoints |
| `GET /api/events?q=&offset=0&limit=50` | Paginated normalized events |
| `GET /api/incidents?q=&offset=0&limit=50&status=OPEN` | Paginated cases; merged source cases excluded |
| `GET /api/incidents/{id}` | Complete case, full event timeline, responses, latest 20 investigation jobs |
| `GET /api/incidents/{id}/report` | Structured JSON report |
| `GET /api/incidents/{id}/report?format=markdown` | Markdown report |
| `GET /api/audit?q=&offset=0&limit=50` | Paginated audit records |
| `GET /api/audit/verify` | Full integrity verification and current chain head |
| `GET /api/rules` | Detection catalog and thresholds |
| `GET /api/jobs/{id}` | QUEUED / RUNNING / COMPLETED / FAILED investigation job |

Read routes require the `read` permission. Search is literal case-insensitive substring matching over stored JSON. Limits are 1–100, offsets 0–1,000,000. The state endpoint returns at most 200 events, 100 incidents/responses/audit entries and 25 jobs; its `metrics` are database totals. For more records use pagination. A report includes the full bounded case timeline, independent of state-page limits.

## Ingestion

`POST /api/events` requires `ingest` permission. Required fields are `source`, `asset`, `user`, `kind`: nonempty strings up to 200 characters.

| Optional field | Constraint |
| --- | --- |
| `timestamp` | ISO 8601 with timezone, at or before now; defaults to server time |
| `event_id` | Nonempty source event ID, up to 200 characters |
| `details` | String, up to 4,000 characters |
| `source_ip`, `destination_ip` | IPv4 or IPv6 strings |
| `criticality` | Integer 1–5, default 1 |
| `privileged` | Boolean, default false |
| `process_name` | Nonempty string, up to 200 characters |
| `command_line` | Nonempty string, up to 4,000 characters |
| `destination_port` | Integer 1–65535 |
| `file_path` | Nonempty string, up to 1,000 characters |

Kinds: `auth_failure`, `auth_success`, `suspicious_process`, `malicious_indicator`, `process_start`, `network_connection`, `file_change`. A process start requires `process_name` and `command_line`; a network connection requires destination IP and port; a file change requires `file_path`.

A new event returns HTTP 201:

```json
{"event":{"id":"internal-uuid","source":"lab-auth","asset":"host-01","user":"alex","kind":"auth_failure"},"incident":null,"duplicate":false}
```

This example omits default normalized fields for brevity. When detection triggers, `incident` contains the case and assessment. An identical retry with a source event ID returns HTTP 200, the original event, `incident: null`, and `duplicate: true`. Reusing the source event ID with different content returns 400.

The **ingest-only role** receives event and incident IDs only, not correlated evidence. Analyst/admin identities receive the full result. Ingestion-only clients cannot use read routes to inspect other telemetry.

`POST /api/events/batch` accepts `{"events":[<event>, ...]}` with 1–100 events and a maximum HTTP body of 1 MiB. Validation and persistence are atomic; an invalid or conflicting event rolls back the batch. Success returns HTTP 201 with a `results` array. No independent background ingestion acknowledgement is implied.

`POST /api/demo` accepts `{"scenario":"attack-chain"}`. Valid scenarios: `attack-chain`, `benign`, `late-arrival`, `indicator`. Returns `ingested`, `incident_ids`, and `synthetic: true`.

## Case review

`POST /api/incidents/update` requires `investigate` permission:

```json
{"incident_id":"<id>","revision":13,"status":"INVESTIGATING","owner":"Alex","note":"Preserved evidence and contacted the asset owner."}
```

Only `incident_id` and `revision` are mandatory. Optional status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE. Closing a case requires a nonempty note. Owner is nonempty text up to 100 characters. Notes are at most 2,000 characters, with a 200-note cap per case. Every update increments revision; stale updates fail. New correlated events reopen closed cases and preserve review history.

## Offline investigation

`POST /api/investigate` requires `investigate` permission:

```json
{"incident_id":"<id>","question":"Why is this suspicious?"}
```

Returns HTTP 202 and a durable job ID. Questions are at most 1,000 characters. Poll `GET /api/jobs/{id}`. Completed results include mode, actual analyzed revision, evidence IDs, facts, inferences, hypotheses, unknowns, risk factors and recommended actions. The job analyzes the case revision available when the worker reads it, which may be newer than the revision at enqueue time. The actual analyzed revision is explicit.

Unknown question types produce an explicit unsupported/UNKNOWN answer. There is no generative model or tool execution. At most 50 queued/running jobs are accepted; interrupted jobs are requeued on server restart.

## Response state machine

All playbooks are simulated; none accepts arbitrary commands or destination URLs.

1. `POST /api/responses/recommend` (`recommend` permission):

   `{"incident_id":"<id>","action":"simulate_endpoint_isolation"}`

   Actions: `simulate_endpoint_isolation`, `simulate_restore_connectivity`, `simulate_collect_evidence`. Returns a PENDING request bound to the case revision and virtual asset.

2. `POST /api/responses/approve` (`approve` permission):

   `{"response_id":"<id>","confirmation":"APPROVE SIMULATION"}`

   Returns APPROVED with a 15-minute expiry. With two-person mode, requester and approver must differ.

3. `POST /api/responses/execute` (`execute` permission):

   `{"response_id":"<id>"}`

   Rechecks approval, expiry, case status and revision. Updates the virtual registry and reads it back in the same transaction. Returns SIMULATED plus a virtual verification result. Evidence collection returns a hash manifest, not real endpoint data.

4. `POST /api/responses/reject` (`approve` permission):

   `{"response_id":"<id>","reason":"Authorized maintenance; containment is unnecessary."}`

   Rejects a PENDING or APPROVED request with a mandatory reason. There is no delete or undo-audit route.

New evidence, case changes and merges cancel related pending/approved requests. Execution cannot repeat. Expired approvals fail execution and must be rejected and recommended again; they do not silently renew.

## Errors

Errors use `{"error":"description"}`. HTTP 400: invalid schema, stale revision, invalid transition, missing resource ID or capacity boundary; 401: invalid authentication; 403: insufficient permission; 404: unknown route; 413: body size/framing limit; 415: wrong content type; 429: per-IP request rate exceeded; 500: unexpected server failure. Error text never includes authorization tokens or stack traces.

## Example

With the token exported in your local shell:

```sh
curl --fail-with-body http://127.0.0.1:8000/api/events \
  -H "Authorization: Bearer $AEGIS_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"source":"lab-auth","asset":"host-01","user":"alex","kind":"auth_failure","event_id":"auth-01"}'
```

The Python server does not require a client library. Prefer the provided ingestion CLI when using the generated `.env` so shell interpolation is unnecessary.
