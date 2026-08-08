# Accepted security baseline

`accepted.json` is the store-owned, durable input for reviewer capability comparisons.

For this store, **accepted means currently distributed by the live stable catalog**. The scheduled audit may advance a repository's baseline only when all of the following are true:

- the repository is still configured in `additional_plugins.txt`;
- the full audit completed with reviewer capability data and no report errors;
- the audited release/version is the live stable catalog's currently selected version; and
- the audited artifact SHA-256 exactly matches the live catalog hash.

The snapshot is intentionally immutable for a given artifact hash. Re-auditing the same bytes with changed scanners, rules, or policy does not rewrite history. A baseline advances only when a different artifact hash is actually distributed.

The committed snapshot is a sanitized projection, not a raw audit report. It retains the capability states and the full comparison inventories needed by `decky-plugin-auditor --baseline-report`, while omitting raw findings, snippets, scanner payloads, artifact URLs, and detailed source-diff paths.

Normal audits automatically pass this snapshot to the pinned auditor. Pull-request audits do not trust a baseline from the proposed branch: they extract `accepted.json` and its validator from the PR's base commit before comparison, so a submission cannot redefine its own accepted history. Scheduled audits compare against the committed baseline that existed when the run started and only consider advancing that baseline after the audit completes.

Accepted-baseline changes do not invalidate the scan cache. The standalone auditor attaches comparisons after cached audit data is loaded, so the same expensive scan result can be compared against newer accepted history without rescanning plugin bytes.

The scheduled scanner job has read-only repository permissions. It produces a candidate baseline as an artifact. A separate persistence job, which does not execute or scan plugin content, validates that candidate before updating `accepted.json` on `main`.
