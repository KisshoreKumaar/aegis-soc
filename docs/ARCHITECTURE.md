# Architecture and invariants

## Why this stack

Python standard library + SQLite + browser JavaScript gives this offline demo zero package downloads and no paid API dependency. Detection and workflow rules are pure Python and independently testable. SQLite transactions make event, incident, response and audit updates atomic. The tradeoff is single-process deployment and limited analytical search throughput; these are explicit capacity boundaries, not enterprise-scale claims.

## Ingestion and preservation

The schema permits authentication observations, process starts, network connections, file changes, and upstream alerts. Unknown fields, malformed IP addresses, non-boolean privileges, out-of-range ports/criticality, timezone-free dates and future timestamps are rejected. Input JSON field duplication and non-finite numeric values are rejected at the HTTP boundary.

`raw_events` preserves the submitted JSON object; `events` contains its normalized representation and internal UUID. It is semantic JSON preservation, not a byte-for-byte capture of the original network payload. Prototype-era records retain their normalized data but do not retroactively acquire unavailable raw input.

An explicit source event ID is unique within a source. The deduplication digest uses canonical JSON of the submitted object, so key ordering does not matter. Omitted versus explicit fields are different content. One failed member rolls back the entire batch.

## Correlation and rules

An index on normalized asset/user and event time identifies observations within ten minutes before or after an incoming event. Existing incidents sharing those event references are connected; their evidence is retained. Late observations therefore re-evaluate later activity. When previously separate cases join, the older case remains canonical, the others become MERGED, and their pending responses are cancelled.

Shared asset/user and temporal proximity are the stated correlation evidence, not proof that the same attacker caused every event. Assets with shared accounts need stronger identity/session evidence before real deployment. Cases retain the original source records and all candidate rule references so analysts can evaluate that assumption.

Authentication failures are additionally bucketed by source and source IP; failures from different IPs cannot combine to trigger the brute-force rule. Detection uses sliding windows even when a case spans a longer time. Network discovery counts distinct destination IP/port pairs. Generic source alerts receive no invented technique mapping. File changes are stored for context but have no default standalone rule.

Candidate references are checked against primary MITRE definitions:

- [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

## Risk and reasoning

Risk is the sum of threat severity, detection confidence, source-reported asset criticality and privilege, distinct candidate stages, event count, reported indicator status, and potential impact. The score is capped at 100. Each factor is returned. Confidence values are heuristic, not learned or statistically calibrated.

A FACT says a source reported an event; it does not assert that source content is truthful. INFERENCE describes what a rule threshold suggests. HYPOTHESIS describes a possible explanation or subsequent attack step. UNKNOWN lists missing context. Suspicious detections remain Suspicious until an analyst investigates; resolving a case as FALSE_POSITIVE is recorded separately from the original assessment.

## Offline investigation

The persisted job queue separates investigation requests from the request thread. A background worker claims jobs transactionally, applies deterministic evidence retrieval, and stores the structured result. A restart requeues interrupted jobs. Every result identifies the actual analyzed revision. The dashboard warns when the current case has a newer revision.

The assistant supports evidence summaries, risk explanations, ATT&CK candidates and next actions. Unsupported prompts return UNKNOWN and an explicit capability description. Event contents are never interpreted as instructions. No network client, model SDK, tool execution or shell invocation exists in the investigator.

## Human review and response

Named token identities carry explicit permissions. A case review must provide its current revision, and closure requires a note. New correlated evidence reopens a resolved case while preserving notes. Review or evidence changes cancel existing pending/approved response requests.

Response actions are an allowlist of virtual operations. Approval binds the incident revision, asset, action, approver and expiry. Optional two-person policy prevents a requester approving their own request. Execution rechecks the state and revision inside the same write transaction, updates the virtual endpoint, reads it back, and records the simulated result. Repeated execution is rejected. The evidence-collection simulation produces event hashes; it does not acquire data from a real endpoint.

## Audit and recovery

Every successful mutation appends an audit record in its transaction. Integrity proofs hash sequence, timestamp, action, serialized body and previous digest. A configured audit key uses HMAC-SHA256; otherwise SHA256 detects accidental edits but is easy for a database writer to recompute. Fresh quick-start installations generate a key. Legacy records become a labelled baseline during migration.

Verification checks the whole chain. Startup rejects broken chains and mismatched keys. Retain checkpoints outside the database: a chain alone cannot prove that its tail or entire file was not replaced. SQLite backup preserves a consistent snapshot while the service runs. Do not copy just the main `.db` file during a WAL write.
