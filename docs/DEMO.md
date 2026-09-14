# Five-minute demo

## Before presenting

1. Run `python3 scripts/run.py` and connect at http://127.0.0.1:8000 using your local token.
2. Run `python3 scripts/evaluate.py` once. All four synthetic scenarios should pass.
3. Keep the token and `.env` out of screen sharing. The connected dashboard never displays the token.

## 0:00 — Explain the problem

“Analysts receive isolated alerts. AEGIS preserves the evidence, correlates related activity, explains its risk, and keeps humans in control of response.”

State clearly: this is the offline edition. Its investigation assistant is deterministic, and all containment is virtual.

## 0:30 — Load the attack chain

On Overview, load **Account compromise → execution → discovery**. Seventeen events become one incident. Point out the sources: authentication, endpoint and network records share the same asset and user.

Open the timeline. Show repeated failures, a later success, encoded PowerShell, and ten destination services. Nothing in the demo executed an attack command.

## 1:15 — Explain the assessment

Show the score and its separate factors. The provided synthetic chain should score 93/100. This is a prioritization heuristic, not a 93% chance of compromise.

Show candidate T1110, T1059.001 and T1046 mappings and their supporting event IDs. Candidate stages do not prove an attack path.

Click **Why suspicious?**, then **Next actions**. The offline assistant explains the thresholds, alternative explanations, and missing evidence. It does not invent new observations.

## 2:15 — Record human review

Assign an analyst, set the status to INVESTIGATING, and add a note about the synthetic evidence. Save the review. This increments the incident revision and records the actor.

## 2:45 — Approve and verify containment

Choose **Isolate virtual endpoint** and request approval. In Response center, approve the request and execute the simulation. Show the resulting ISOLATED virtual state and the explicit statement that no real endpoint was changed.

For a two-person demonstration, use separate analyst and approver tokens with `AEGIS_TWO_PERSON=true`. An operator cannot approve their own request in that mode.

Optionally recommend **Restore virtual connectivity**, approve and execute it. This shows reversible containment.

## 3:45 — Prove traceability

Open Audit trail and verify integrity. Show the actor, timestamps and approval/execution records. Export the JSON or Markdown report from the case. The report includes evidence, review notes and response history.

## 4:15 — Show that not every log is an alert

Load **Benign workday**. Nine events should produce no new incident. Explain that “no rule triggered” is different from proving the activity benign.

Load **Out-of-order authentication logs** to show that late telemetry can still complete the detection.

## Closing statement

“AEGIS is an analyst workflow, not a chatbot. The evidence, rules, scoring, approval policy, verification and audit remain authoritative. A future model can add contextual reasoning without gaining execution authority.”

## Recovery

- Connection error: ensure the server is running and the port matches.
- Invalid token: retrieve it locally with `python3 scripts/manage.py token`; never regenerate secrets merely to fix a login typo.
- Approval cancelled: new evidence or case review changed the revision. Create a new recommendation.
- Rate limit: wait one minute or turn off auto refresh while demonstrating many API calls.
- Old demo cases: each scenario uses a distinct synthetic asset; prior data need not be deleted.
