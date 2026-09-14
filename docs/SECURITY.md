# Security and deployment notes

## Intended boundary

AEGIS Offline Edition is a local hackathon application. Defaults bind only to loopback. There is no real endpoint connector, generative AI provider, threat-intelligence lookup, remote execution, or automatic destructive action. Code never evaluates or runs a command from telemetry.

## Controls implemented

- Random environment-only tokens; no default password or committed secret.
- Named roles enforced on every API route, not just hidden UI buttons.
- Constant-time comparison of token digests; supplied credentials are not logged.
- 10-second socket timeout, 32 concurrent request threads, per-IP API limits, 64 KiB ordinary bodies and 1 MiB batches.
- SQL parameters for data, strict route/resource allowlists, strict schema types and bounded event sizes.
- UI text nodes for untrusted content, restrictive content security policy, no framing, no external assets, no browser token persistence.
- Transactional incident revisions, explicit response approval, optional separate approver, expiry, and cancellation on evidence changes.
- Virtual actions only, with verified virtual state and an explicit distinction from real execution.
- Keyed audit integrity when configured, whole-chain verification, and consistent backup tooling.
- Non-root Docker image, loopback publishing, read-only root filesystem, dropped capabilities and persistent volume.

## Residual risks

The host account that can read `.env` can impersonate its configured operators. Token identities do not provide SSO, MFA, individual revocation history or session management. Configuration changes require a restart. Do not share an admin token among analysts.

Sources can lie about telemetry, user privilege or asset criticality. Canonical schemas validate shape, not truth. Shared asset/user values can over-correlate activity. Thresholds and confidence values require real-world evaluation before operational use.

The audit chain is not immutable storage. A party with both database and audit key can rewrite it. External checkpoints are necessary to detect truncation or replacement. SQLite data, exports, notes and raw events may contain sensitive material; protect their filesystem permissions and backups. The application has no automatic secret detection, redaction or deletion policy.

Pagination uses offsets and can shift while data is ingested. Searches inspect JSON text. The worker and HTTP server are intended to run as one process; horizontal scaling and multi-server job recovery are out of scope. Capacity errors preserve atomicity but need an upstream retry/archive strategy at scale.

Rejected authentication and malformed requests appear as status-only server logs; they are not committed as full audit events. This avoids storing attacker-controlled credentials or filling the audit database with unauthenticated input. Successful state changes are audited.

## Deployment guidance

Use the default loopback interface for the demo. If the application is later exposed beyond the host, place it behind a hardened TLS reverse proxy, configure an identity provider, revisit source isolation and rate limits, and test authorization across tenants. Do not expose this HTTP service directly to the internet.

For recovery, stop the application, preserve the failing database and matching key, and restore a known consistent backup to a new path. Verify its audit chain before resuming. Do not disable integrity checks to bypass a failure. Rotate API tokens through protected configuration; retain the original audit key for existing databases.
