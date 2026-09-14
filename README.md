# AEGIS SOC — Offline Edition

A complete local cybersecurity hackathon demo: ingest events, detect known patterns, correlate incidents, inspect evidence, explain risk, review cases, approve virtual containment, verify the result, and export the audit trail.

**This edition works entirely offline.** The investigation assistant uses deterministic evidence retrieval and rule explanations. It does not call an LLM, imitate model output, execute log contents, query external threat intelligence, or change real endpoints. It is a hackathon application, not a production endpoint security product.

## Start in one command

Requires **Python 3.11+** and a modern browser. No Python packages, JavaScript build tools, API subscriptions, or internet connection are required for the local application.

```sh
cd /Users/apple/Developer/gpt/soc
python3 scripts/run.py
```

The first run creates a private `.env` with random operator and audit secrets. Open [the dashboard](http://127.0.0.1:8000). In a second terminal, retrieve your token locally:

```sh
cd /Users/apple/Developer/gpt/soc
python3 scripts/manage.py token
```

Paste the token into **Operator token**, click **Connect**, then **Load scenario**. Do not put the token in a URL, screenshot, repository, or shared report. The browser holds it in page memory only; **Lock workspace** clears the session by reloading. Stop the server with Ctrl+C.

## What is included

- Authenticated single-event and atomic batch ingestion; JSON/JSONL import from the UI or CLI.
- Strict validation, normalized UTC timestamps, original submitted JSON records, and source-scoped event-ID deduplication.
- Six deterministic detection rules, cross-source correlation by asset/user, sliding time windows, and late-arrival processing.
- Evidence-linked ATT&CK candidates, a 0–100 risk score with individual factors, and FACT / INFERENCE / HYPOTHESIS / UNKNOWN distinctions.
- Overview metrics, paginated incident/event searches, a candidate attack sequence, and a complete incident timeline.
- Offline investigation jobs with persistence, restart recovery, structured reports, and visible source references.
- Incident ownership, review notes, optimistic revision checks, resolution, false-positive review, and reopening on new evidence.
- Allowlisted virtual isolation, connectivity restoration, and evidence-manifest playbooks.
- Explicit approval, optional two-person review, 15-minute approval expiry, cancellation when a case changes, and single execution.
- Transactional audit records, optional keyed integrity proofs, verification, and external checkpoint exports.
- JSON and Markdown incident reports, consistent database backups, Docker configuration, tests, and CI configuration.

## Demo scenarios

| Scenario | Expected result |
| --- | --- |
| Account compromise → execution → discovery | 17 events → one incident; authentication, encoded PowerShell, and service discovery candidates |
| Benign workday | 9 events → no rule detections; absence of detection is not a verified benign verdict |
| Out-of-order authentication logs | 6 events arrive in reverse order → one incident including success-after-failures |
| Upstream indicator alert | One source-reported alert → one suspicious case; no invented ATT&CK technique or reputation verification |

Follow the [five-minute demo script](docs/DEMO.md). Each run uses a new synthetic asset, so prior demonstrations do not inflate the new scenario's risk.

## Architecture

```text
JSON / JSONL sources
        ↓
Authenticated REST ingestion → strict validation → raw + normalized event storage
        ↓
Indexed temporal correlation → deterministic rule evaluation → explainable risk
        ↓
Incident + event references + audit (one SQLite transaction)
        ↓
Dashboard / persistent offline investigation worker / exportable report
        ↓
Analyst recommendation → explicit approval → virtual endpoint action
        ↓
Verify virtual state + evidence manifest → audit + external checkpoint
```

| File | Responsibility |
| --- | --- |
| `aegis/engine.py` | Schema validation, sliding-window detection, candidate techniques, risk factors |
| `aegis/store.py` | Schema migration, indexed storage, deduplication, correlation, case/response transitions, audit, jobs |
| `aegis/config.py` | Environment configuration, named roles and permission mapping |
| `aegis/investigation.py` | Offline evidence analysis and durable background worker |
| `aegis/demo.py` | Synthetic scenarios; no attack execution |
| `aegis/reports.py` | Portable reports with evidence and response history |
| `aegis/server.py` | Bounded local HTTP service, authentication, request limits, REST endpoints |
| `static/` | Dashboard, case workbench, import, reports, approvals and audit UI |
| `scripts/` | Startup, ingestion, demo generation, evaluation, backup and verification |
| `tests/` | Detection, workflow, concurrency, integrity and HTTP integration checks |

Detailed behavior and trust boundaries: [Architecture](docs/ARCHITECTURE.md). All routes and payloads: [API reference](docs/API.md) and [OpenAPI document](docs/openapi.json).

## Configuration

`python3 scripts/run.py` reads simple `AEGIS_NAME=value` entries from `.env`; existing process variables take precedence. Values are literal—do not use shell expressions or wrap values in quotes. `python3 -m aegis.server` reads only process environment variables.

| Variable | Default / purpose |
| --- | --- |
| `AEGIS_API_TOKEN` | Random token of at least 32 ASCII characters; enables `local-admin` |
| `AEGIS_IDENTITIES` | JSON array of named identities with `name`, `role`, `token`; defaults to `[]` |
| `AEGIS_AUDIT_KEY` | Optional secret of at least 32 characters for HMAC-SHA256; generated on fresh quick start |
| `AEGIS_HOST` | `127.0.0.1` |
| `AEGIS_PORT` | `8000` |
| `AEGIS_DB` | `data/aegis.db` |
| `AEGIS_TWO_PERSON` | `false`; set `true` to prohibit approving your own request |
| `AEGIS_RATE_LIMIT` | `240` API requests per source IP per minute |

Roles: `viewer` reads; `ingest` submits telemetry; `analyst` reads, ingests, investigates, and recommends; `approver` reads, approves/rejects, and executes simulations; `admin` has all permissions. The ingestion role is intended for API clients and cannot open dashboard data. Token possession establishes the configured identity; this demo does not implement an identity provider.

For two-person demonstrations, configure different named analyst and approver tokens and set `AEGIS_TWO_PERSON=true`. Lock and reconnect with the other operator's token to approve. Do not use a shared token to represent multiple people.

## Ingest your own lab telemetry

Only use synthetic or authorized lab records. Canonical event format:

```json
{
  "event_id": "auth-0001",
  "source": "lab-auth",
  "asset": "host-01",
  "user": "alex",
  "kind": "auth_failure",
  "source_ip": "192.0.2.10",
  "criticality": 3,
  "privileged": false,
  "details": "Synthetic failed login"
}
```

The timestamp defaults to ingestion time. Supply timezone-aware ISO timestamps to preserve event-time ordering. A source `event_id` makes retries idempotent: identical submitted JSON returns the original event, while reuse with different content is rejected. Without an event ID, each submission is a new observation. A duplicate returns `incident: null`; use incident search for the latest case.

Generate and ingest a JSONL file:

```sh
python3 scripts/generate_demo.py --scenario attack-chain > /tmp/aegis-demo.jsonl
python3 scripts/ingest.py /tmp/aegis-demo.jsonl
```

The CLI reads the same private `.env` and submits one atomic batch. The event explorer also accepts pasted JSON and local JSON/JSONL files. Files must contain at most 100 events and be at most 1 MiB.

## Docker

Docker needs to be installed and its daemon running. The first image build requires internet access to obtain the Python base image; the built app runs offline.

Initialize configuration with `python3 scripts/manage.py token`, then:

```sh
docker compose up --build
```

The service is published only on `127.0.0.1:8000`. It runs as a non-root user with a read-only root filesystem, dropped capabilities, and a persistent data volume. Local Python and Docker use separate databases by default. Stop one before running the other on the same port. Do not use `docker compose down -v` if you need to retain the database.

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 scripts/evaluate.py
python3 -m compileall -q aegis scripts
node --check static/app.js
```

Node is optional and used only for syntax checking. Automated tests use temporary databases and localhost ports. The scenario evaluator verifies expected synthetic outcomes; it is not a real-world precision/recall benchmark. A GitHub Actions workflow runs Python tests and JavaScript syntax checks after the project is pushed to GitHub.

## Backup and audit verification

```sh
python3 scripts/manage.py verify-audit
python3 scripts/manage.py backup --output /tmp/aegis-backup.db
```

Backup uses SQLite's consistent backup API and refuses to overwrite an existing file. Keep the matching audit key separately with protected backups. Never rotate the audit key for an existing database without a migration procedure. Startup rejects a mismatched key or a broken audit chain. The dashboard can export an audit page plus the chain head; retain that checkpoint externally to detect later truncation or replacement.

## Practical boundaries

This edition deliberately contains no live LLM or real endpoint connector, as requested. Source criticality, privilege and upstream reputation labels are reported inputs, not independently verified facts. Correlation by shared asset/user and temporal proximity is a candidate relationship; authorized scanners, shared accounts, and legitimate encoded scripts can trigger detections.

The local server bounds request sizes, concurrent connections and API rates, but is not an internet-facing production service. Run one server process per database. Correlation windows/incidents are capped at 2,000 events and pending investigation jobs at 50; excess ingestion fails atomically. Search scans JSON bodies; use indexed structured search and a production database for larger workloads. Records are retained until an operator archives the database; there is no automatic deletion.

Before production use, add an audited identity provider, TLS termination, dedicated source adapters, calibrated detection datasets, capacity planning, protected audit storage and verified endpoint connectors. See [security and deployment notes](docs/SECURITY.md). No claim is made that a real security action was executed.
