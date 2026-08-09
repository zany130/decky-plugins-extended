# Security review state

This directory is the store-owned reviewer workflow layered on top of the standalone auditor.

- `queue.json` is the durable list of **currently unresolved artifacts** that need a human review decision.
- `queue.md` is the human-readable rendering of that queue.
- `decisions.json` is append-only review history keyed to an exact repository + artifact SHA-256.

The queue and decisions are deliberately separate from `security-baselines/accepted.json`:

- the accepted baseline answers **what artifact is/was distributed by the live store**;
- the review queue answers **what artifact still needs a human decision**;
- decision history answers **what exact artifact a reviewer approved or rejected**.

This separation matters because the store currently auto-refreshes upstream releases. A candidate can therefore become the currently distributed baseline before a reviewer has made a decision. An unresolved queue item is preserved when that happens, so baseline advancement cannot silently erase pending review work.

A pending exact-artifact queue item is also a stable review snapshot. Later self-comparisons do not replace the original accepted baseline or capability delta that caused the artifact to enter the queue. The item remains unchanged until a human decision or a newer artifact supersedes it, except that a later `BLOCK`/`AUDIT_ERROR` can promote the existing item to critical priority.

## What enters the queue

A configured repository is queued when the current audit report represents any of these conditions:

- `AUDIT_ERROR` or `BLOCK` — **critical** priority;
- no accepted baseline exists — **high** priority;
- a same-artifact comparison reports meaningful analysis/coverage drift — **high** priority;
- a new artifact introduces reviewer-attention capability changes — **high** priority;
- a new artifact has no reviewer-attention delta — **normal** priority so the release remains visible but does not drown out more important changes.

An unchanged accepted artifact is not queued merely because its standing audit classification is `MANUAL_REVIEW`. Existing accepted plugins can legitimately have privileged, command-execution, native-code, or network capabilities; the queue is about unresolved **artifact review**, not replaying every historical finding forever.

The queue copies only compact reviewer metadata and comparison summaries. It does not persist raw findings, snippets, scanner payloads, or full evidence arrays.

## Decision semantics

A decision record contains:

- repository;
- exact release label for reviewer context;
- exact 64-character artifact SHA-256;
- `approved` or `rejected`;
- reviewer GitHub username;
- timezone-aware decision timestamp;
- human rationale.

A decision for one artifact never applies to a later artifact from the same repository. Rejection also resolves the *review task* for that exact artifact; future publication enforcement will separately decide what a rejection means for catalog eligibility.

Decision history is not an allowlist. `security-allowlist.yml` narrowly permits specific audit rules for specific artifacts. A review approval records the human outcome for the whole candidate artifact and does not alter scanner findings or classification.

Pull-request CI protects this state as an append-only ledger. Existing decisions must remain byte-for-byte unchanged, every newly appended decision must target an exact artifact that was pending in the PR base queue, and the queue change must be exactly the deterministic removal produced by the decision helper. A PR cannot silently delete/rewrite old decisions, invent an approval for an unqueued SHA, or modify an unrelated pending item while recording a decision.

## Recording a decision

Use the helper so the exact queued artifact is removed and the append-only history is updated together:

```sh
python review_queue.py decide \
  --decisions security-review/decisions.json \
  --queue security-review/queue.json \
  --queue-markdown security-review/queue.md \
  --repository https://github.com/owner/plugin \
  --artifact-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --decision approved \
  --reviewer zany130 \
  --reason "Reviewed the capability delta and expected network change."
```

Commit the resulting `decisions.json`, `queue.json`, and `queue.md` together and review the change through the normal pull-request path. The helper refuses decisions for an artifact that is not currently pending.

## Scheduled workflow behavior

The scheduled audit produces the full report artifact first. Queue generation runs from that artifact even when the audit job is red, so scanner failures such as an `AUDIT_ERROR` can themselves become critical review items.

Accepted-baseline persistence remains fail-closed and still requires a successful scheduled audit. Queue persistence is independent: it may persist a validated queue from a failed audit report while leaving the accepted baseline untouched.

The queue writer runs in a separate clean job with `contents: write`; scanner jobs remain read-only. It also refuses a stale write if either the committed queue or decision history changed after the audit started.

No publication enforcement is enabled by this review state. This milestone records and prioritizes human decisions first; catalog gating will be designed only after the remaining scanner issues and false-positive review are complete.
