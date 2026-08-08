# Accepted security baseline

`accepted.json` is the store-owned, durable input for reviewer capability comparisons.

For this store, **accepted means currently distributed by the live stable catalog**. The scheduled audit may advance a repository's baseline only when all of the following are true:

- the repository is still configured in `additional_plugins.txt`;
- the full audit completed with reviewer capability data and no report errors;
- the audited release/version exists in the live stable catalog; and
- the audited artifact SHA-256 exactly matches the live catalog hash.

The snapshot is intentionally immutable for a given artifact hash. Re-auditing the same bytes with changed scanners, rules, or policy does not rewrite history. A baseline advances only when a different artifact hash is actually distributed.

The committed snapshot is a sanitized projection, not a raw audit report. It retains the capability states and the full comparison inventories needed by `decky-plugin-auditor --baseline-report`, while omitting raw findings, snippets, scanner payloads, artifact URLs, and detailed source-diff paths.

The scheduled scanner job has read-only repository permissions. It produces a candidate baseline as an artifact. A separate persistence job, which does not execute or scan plugin content, validates that candidate before updating `accepted.json` on `main`.
