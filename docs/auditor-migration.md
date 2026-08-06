# Standalone auditor migration

This document defines the history-preserving extraction of the security auditor
from `zany130/decky-plugins-extended` into a standalone repository, provisionally
named `zany130/decky-plugin-auditor`.

## Goals

- Keep the current `main` auditor behavior unchanged during extraction.
- Preserve authorship and commit history for auditor-owned files.
- Keep the unmerged capa work as a separate experimental branch.
- Prove report parity before the store consumes the standalone auditor.
- Avoid combining extraction, packaging, report-schema changes, and new features
  in one migration.

## Non-goals for the extraction

The extraction itself does not:

- move code into `src/decky_audit/`;
- introduce a new CLI contract;
- change classifications, scoring, policies, or report schemas;
- enable capa on `main`;
- remove the embedded auditor from the store repository;
- decide the standalone repository's final long-term license.

Those changes belong in later, reviewable commits after parity is established.

## Repository creation

Create an empty public repository named `decky-plugin-auditor` under `zany130`.
Do not initialize it with a README, `.gitignore`, or license because the filtered
history must be pushed into an empty repository.

The extraction currently preserves the existing MIT license and copyright
notice. A later licensing decision must preserve the rights already granted to
existing copies and any required attribution.

## Extraction

Install `git-filter-repo`, then run:

```bash
scripts/extract_auditor_history.sh \
  https://github.com/zany130/decky-plugins-extended.git \
  git@github.com:zany130/decky-plugin-auditor.git
```

The script keeps two branches:

- `main`: the stable auditor exactly as it exists on the source repository's
  `main` branch;
- `experimental/capa-binary-analysis`: the filtered history from
  `agent/capa-binary-capabilities`.

The capa branch is intentionally not merged into the standalone baseline.

## Initial compatibility boundary

For the first parity run, the standalone repository temporarily retains:

- `additional_plugins.txt`;
- `security-policy.yml`;
- `security-allowlist.yml`;
- the existing audit workflows.

These are retained only to reproduce the current behavior. After parity passes,
the store should own its plugin list, policy and allowlist, while the auditor
accepts them as explicit inputs.

## Validation gates

### 1. Structural validation

Confirm the extracted `main` contains auditor code, rules, fixtures, tests and
audit workflows, but not catalog generation or deployment code such as:

- `generate_json.py`;
- `check_for_updates.py`;
- `functions/`;
- `static/`;
- `schema.sql`;
- `.github/workflows/generate.yml`;
- store-only tests.

### 2. Unit tests

Run the complete extracted test suite:

```bash
uv sync --dev
uv run pytest -q
```

The test count should match the audit-only subset from the source repository.

### 3. Report parity

Run the embedded and standalone `main` auditors against the same cacheless input
set and compare security-relevant output:

- repository and release selection;
- artifact hashes;
- classifications and risk scores;
- findings and scanner statuses;
- native binary inventory;
- source-versus-artifact comparison;
- network destinations and provenance;
- immutable source links;
- Markdown section structure.

Timestamps, temporary paths and ordering that is explicitly nondeterministic may
differ. Security conclusions must not.

### 4. Capa branch validation

Open `experimental/capa-binary-analysis` as a draft PR against the new `main`.
The PR description must retain the full-store findings discovered during run
`31064244018`:

- unsuitable cold full-store runtime;
- frequent timeouts on large native binaries;
- orphaned capa processes after timeout;
- incomplete coverage;
- intended future role as optional deep analysis for new binary hashes.

## Follow-up sequence

After parity passes:

1. Add an auditor-specific README and security model.
2. Establish a proper Python package and `decky-audit` CLI.
3. Make plugin list, policy and allowlist explicit inputs.
4. Publish a pinned release or immutable reusable workflow.
5. Update `decky-plugins-extended` to consume that pinned auditor.
6. Run old and new implementations in parallel for a transition period.
7. Remove the duplicated auditor from the store only after equivalent reports
   are confirmed.
8. Build reviewer capability grouping and update-aware comparisons in the new
   repository.
9. Revisit capa after the core reviewer workflow is complete.

## Rollback

The extraction does not change the source repository's runtime. Until the store
consumer migration is merged, rollback consists of deleting or archiving the new
repository; the existing auditor continues to operate unchanged.
