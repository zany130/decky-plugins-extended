"""Store-owned security review queue and immutable artifact decision history.

The standalone auditor owns detection and comparison. This module turns those
reports into a durable store review workflow without changing enforcement:

* pending review items are keyed to exact release artifact identity whenever a
  SHA-256 is available;
* human decisions are append-only history and are also artifact-scoped;
* an unresolved item survives accepted-baseline advancement to the same bytes;
* a decision for one artifact never applies to a later artifact from the repo;
* raw findings/evidence are intentionally not copied into the committed queue.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import accepted_baseline

QUEUE_SCHEMA_VERSION = "1"
DECISIONS_SCHEMA_VERSION = "1"
MAX_ITEMS = 10_000
MAX_REASON_LENGTH = 2_000

PRIORITY_ORDER = {"critical": 0, "high": 1, "normal": 2}
DECISION_VALUES = {"approved", "rejected"}
REASON_VALUES = {
    "artifact_identity_unavailable",
    "audit_error",
    "baseline_unavailable",
    "blocked_by_policy",
    "new_artifact",
    "pending_review",
    "same_artifact_analysis_drift",
    "security_delta",
}

_DECISIONS_TOP_KEYS = {"schema_version", "decisions"}
_DECISION_KEYS = {
    "repository",
    "release",
    "artifact_sha256",
    "decision",
    "decided_by",
    "decided_at",
    "reason",
}
_QUEUE_TOP_KEYS = {
    "schema_version",
    "generated_at",
    "source_run_url",
    "item_count",
    "items",
}
_QUEUE_ITEM_KEYS = {
    "repository",
    "plugin_name",
    "release",
    "artifact_sha256",
    "source_commit",
    "final_classification",
    "risk_score",
    "priority",
    "reasons",
    "first_seen_at",
    "baseline_release",
    "baseline_artifact_sha256",
    "comparison_status",
    "same_artifact",
    "reviewer_attention_count",
    "changed_capabilities",
    "error_count",
}
_CHANGED_CAPABILITY_KEYS = {
    "id",
    "title",
    "status_change",
    "summary",
    "reviewer_attention",
}

_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
)
_GITHUB_USER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _safe_text(value: object) -> str:
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return re.sub(r"[\x00-\x1f\x7f]", " ", text).strip()


def _contains_secret(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_secret(k) or _contains_secret(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return isinstance(value, str) and any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def _parse_time(value: object, *, allow_empty: bool = False) -> datetime | None:
    text = str(value or "").strip()
    if not text and allow_empty:
        return None
    if not text:
        raise ValueError("timestamp must not be empty")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {text}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_sha256(value: object) -> bool:
    return bool(_SHA256.fullmatch(str(value or "").casefold()))


def _repo_key(value: object) -> str:
    return accepted_baseline.normalize_repository(value)


def empty_decisions() -> dict[str, Any]:
    return {"schema_version": DECISIONS_SCHEMA_VERSION, "decisions": []}


def empty_queue() -> dict[str, Any]:
    return {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "generated_at": "",
        "source_run_url": "",
        "item_count": 0,
        "items": [],
    }


def validate_decisions(payload: object) -> None:
    if not isinstance(payload, dict) or set(payload) != _DECISIONS_TOP_KEYS:
        raise ValueError("review decisions top-level shape is invalid")
    if payload.get("schema_version") != DECISIONS_SCHEMA_VERSION:
        raise ValueError("unsupported review decisions schema")
    decisions = payload.get("decisions")
    if not isinstance(decisions, list) or len(decisions) > MAX_ITEMS:
        raise ValueError("review decisions must be a bounded list")

    seen: set[tuple[str, str, str]] = set()
    for item in decisions:
        if not isinstance(item, dict) or set(item) != _DECISION_KEYS:
            raise ValueError("review decision shape is invalid")
        repository = _repo_key(item.get("repository"))
        digest = str(item.get("artifact_sha256") or "").casefold()
        decided_at = str(item.get("decided_at") or "")
        if not repository:
            raise ValueError("review decision repository must not be empty")
        if not str(item.get("release") or "").strip():
            raise ValueError("review decision release must not be empty")
        if not _is_sha256(digest):
            raise ValueError("review decision artifact SHA-256 is invalid")
        if item.get("decision") not in DECISION_VALUES:
            raise ValueError("review decision must be approved or rejected")
        if not _GITHUB_USER.fullmatch(str(item.get("decided_by") or "")):
            raise ValueError("review decision reviewer is not a valid GitHub username")
        _parse_time(decided_at)
        reason = str(item.get("reason") or "").strip()
        if not reason or len(reason) > MAX_REASON_LENGTH:
            raise ValueError("review decision reason is empty or too long")
        identity = (repository, digest, decided_at)
        if identity in seen:
            raise ValueError("duplicate review decision record")
        seen.add(identity)

    if _contains_secret(payload):
        raise ValueError("review decisions contain secret-shaped text")


def validate_queue(payload: object) -> None:
    if not isinstance(payload, dict) or set(payload) != _QUEUE_TOP_KEYS:
        raise ValueError("review queue top-level shape is invalid")
    if payload.get("schema_version") != QUEUE_SCHEMA_VERSION:
        raise ValueError("unsupported review queue schema")
    if not isinstance(payload.get("item_count"), int):
        raise ValueError("review queue item_count must be an integer")
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ValueError("review queue items must be a bounded list")
    if payload.get("item_count") != len(items):
        raise ValueError("review queue item_count does not match items")
    if items:
        _parse_time(payload.get("generated_at"))
    else:
        _parse_time(payload.get("generated_at"), allow_empty=True)

    seen: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != _QUEUE_ITEM_KEYS:
            raise ValueError("review queue item shape is invalid")
        repository = _repo_key(item.get("repository"))
        if not repository:
            raise ValueError("review queue repository must not be empty")
        release = str(item.get("release") or "").strip()
        digest = str(item.get("artifact_sha256") or "").casefold()
        classification = str(item.get("final_classification") or "")
        if digest and not _is_sha256(digest):
            raise ValueError("review queue artifact SHA-256 is invalid")
        if not digest and classification != "AUDIT_ERROR":
            raise ValueError("only AUDIT_ERROR queue items may lack artifact identity")
        if not digest and "artifact_identity_unavailable" not in (item.get("reasons") or []):
            raise ValueError("identity-less audit error must explain missing artifact identity")
        if item.get("source_commit") and not _SHA40.fullmatch(str(item.get("source_commit"))):
            raise ValueError("review queue source commit is invalid")
        baseline_digest = str(item.get("baseline_artifact_sha256") or "").casefold()
        if baseline_digest and not _is_sha256(baseline_digest):
            raise ValueError("review queue baseline SHA-256 is invalid")
        if item.get("priority") not in PRIORITY_ORDER:
            raise ValueError("review queue priority is invalid")
        reasons = item.get("reasons")
        if not isinstance(reasons, list) or not reasons or len(reasons) != len(set(reasons)):
            raise ValueError("review queue reasons must be a non-empty unique list")
        if set(reasons) - REASON_VALUES:
            raise ValueError("review queue contains an unsupported reason")
        if not isinstance(item.get("risk_score"), int) or item.get("risk_score") < 0:
            raise ValueError("review queue risk score is invalid")
        if not isinstance(item.get("error_count"), int) or item.get("error_count") < 0:
            raise ValueError("review queue error count is invalid")
        if not isinstance(item.get("reviewer_attention_count"), int) or item.get("reviewer_attention_count") < 0:
            raise ValueError("review queue reviewer attention count is invalid")
        if not isinstance(item.get("same_artifact"), bool):
            raise ValueError("review queue same_artifact must be boolean")
        _parse_time(item.get("first_seen_at"))

        changed = item.get("changed_capabilities")
        if not isinstance(changed, list) or len(changed) > 64:
            raise ValueError("review queue changed capabilities are invalid")
        changed_ids: set[str] = set()
        for capability in changed:
            if not isinstance(capability, dict) or set(capability) != _CHANGED_CAPABILITY_KEYS:
                raise ValueError("review queue changed capability shape is invalid")
            capability_id = str(capability.get("id") or "")
            if not capability_id or capability_id in changed_ids:
                raise ValueError("review queue changed capability identifiers must be unique")
            changed_ids.add(capability_id)
            if not isinstance(capability.get("reviewer_attention"), bool):
                raise ValueError("review queue reviewer_attention must be boolean")

        identity = (repository, digest if digest else f"release:{release}")
        if identity in seen:
            raise ValueError("review queue contains duplicate artifact identity")
        seen.add(identity)

    if _contains_secret(payload):
        raise ValueError("review queue contains secret-shaped text")


def _latest_decisions(payload: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    validate_decisions(payload)
    latest: dict[tuple[str, str], tuple[datetime, dict[str, Any]]] = {}
    for item in payload["decisions"]:
        key = (_repo_key(item["repository"]), item["artifact_sha256"].casefold())
        when = _parse_time(item["decided_at"])
        assert when is not None
        previous = latest.get(key)
        if previous is None or when > previous[0]:
            latest[key] = (when, item)
    return {key: value[1] for key, value in latest.items()}


def validate_state(decisions: dict[str, Any], queue: dict[str, Any]) -> None:
    validate_decisions(decisions)
    validate_queue(queue)
    latest = _latest_decisions(decisions)
    for item in queue["items"]:
        digest = item.get("artifact_sha256") or ""
        if digest and (_repo_key(item["repository"]), digest.casefold()) in latest:
            raise ValueError("review queue contains an artifact that already has a decision")


def _report_index(audit_payload: object) -> dict[str, dict[str, Any]]:
    if not isinstance(audit_payload, dict):
        raise ValueError("audit report must be a JSON object")
    reports = audit_payload.get("reports")
    if not isinstance(reports, list) or len(reports) > MAX_ITEMS:
        raise ValueError("audit report must contain a bounded reports list")
    indexed: dict[str, dict[str, Any]] = {}
    for report in reports:
        if not isinstance(report, dict):
            raise ValueError("audit report contains a non-object report")
        key = _repo_key(report.get("repository"))
        if not key:
            continue
        if key in indexed:
            raise ValueError("audit report contains duplicate repositories")
        indexed[key] = report
    return indexed


def _baseline_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    accepted_baseline.validate_baseline(payload)
    return {
        _repo_key(item.get("repository")): item
        for item in payload.get("reports") or []
        if isinstance(item, dict) and _repo_key(item.get("repository"))
    }


def _queue_key(item: dict[str, Any]) -> tuple[str, str]:
    digest = str(item.get("artifact_sha256") or "").casefold()
    release = _safe_text(item.get("release"))
    return (_repo_key(item.get("repository")), digest if digest else f"release:{release}")


def _comparison(report: dict[str, Any]) -> dict[str, Any]:
    value = report.get("reviewer_capability_comparison")
    return value if isinstance(value, dict) else {}


def _changed_capabilities(comparison: dict[str, Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in comparison.get("capabilities") or []:
        if not isinstance(item, dict) or not item.get("changed"):
            continue
        projected.append(
            {
                "id": _safe_text(item.get("id")),
                "title": _safe_text(item.get("title") or item.get("id")),
                "status_change": _safe_text(item.get("status_change")),
                "summary": _safe_text(item.get("summary")),
                "reviewer_attention": bool(item.get("reviewer_attention")),
            }
        )
    projected.sort(key=lambda item: item["id"])
    return projected


def _error_count(report: dict[str, Any]) -> int:
    errors = report.get("errors")
    return len(errors) if isinstance(errors, list) else (1 if errors else 0)


def _build_item(
    report: dict[str, Any],
    baseline: dict[str, Any] | None,
    existing: dict[str, Any] | None,
    observed_at: str,
) -> dict[str, Any] | None:
    repository = _safe_text(report.get("repository"))
    release = _safe_text(report.get("release"))
    digest = str(report.get("artifact_sha256") or "").casefold()
    classification = _safe_text(report.get("final_classification"))
    comparison = _comparison(report)
    comparison_status = _safe_text(comparison.get("status")) or "not_available"
    changed = _changed_capabilities(comparison)
    attention_count = int(comparison.get("attention_count") or 0)
    changed_count = int(comparison.get("changed_count") or 0)
    comparison_same_artifact = bool(comparison.get("same_artifact"))

    baseline_digest = str((baseline or {}).get("artifact_sha256") or "").casefold()
    baseline_release = _safe_text((baseline or {}).get("release"))
    has_identity = _is_sha256(digest)
    baseline_missing = baseline is None or comparison_status == "baseline_not_found"
    new_artifact = has_identity and bool(baseline_digest) and digest != baseline_digest
    same_artifact_drift = comparison_same_artifact and changed_count > 0
    critical = classification in {"AUDIT_ERROR", "BLOCK"}

    queue_worthy = bool(existing) or critical or baseline_missing or new_artifact or same_artifact_drift
    if not queue_worthy:
        return None
    if not has_identity and classification != "AUDIT_ERROR":
        # Human decisions must never be inferred against mutable release labels.
        return None

    reasons: list[str] = []
    if classification == "AUDIT_ERROR":
        reasons.append("audit_error")
    if classification == "BLOCK":
        reasons.append("blocked_by_policy")
    if not has_identity:
        reasons.append("artifact_identity_unavailable")
    if baseline_missing:
        reasons.append("baseline_unavailable")
    if new_artifact:
        reasons.append("new_artifact")
    if attention_count > 0:
        reasons.append("security_delta")
    if same_artifact_drift:
        reasons.append("same_artifact_analysis_drift")
    if existing and not reasons:
        reasons.append("pending_review")

    if critical:
        priority = "critical"
    elif baseline_missing or attention_count > 0 or same_artifact_drift:
        priority = "high"
    else:
        priority = "normal"

    first_seen = _safe_text((existing or {}).get("first_seen_at")) or observed_at
    source_commit = _safe_text(report.get("source_commit"))
    if source_commit and not _SHA40.fullmatch(source_commit):
        source_commit = ""

    return {
        "repository": repository,
        "plugin_name": _safe_text(report.get("plugin_name")),
        "release": release,
        "artifact_sha256": digest if has_identity else "",
        "source_commit": source_commit,
        "final_classification": classification,
        "risk_score": max(0, int(report.get("risk_score") or 0)),
        "priority": priority,
        "reasons": reasons,
        "first_seen_at": first_seen,
        "baseline_release": baseline_release,
        "baseline_artifact_sha256": baseline_digest if _is_sha256(baseline_digest) else "",
        "comparison_status": comparison_status,
        "same_artifact": comparison_same_artifact,
        "reviewer_attention_count": max(0, attention_count),
        "changed_capabilities": changed,
        "error_count": _error_count(report),
    }


def build_queue(
    audit_payload: dict[str, Any],
    baseline_payload: dict[str, Any],
    decisions_payload: dict[str, Any],
    existing_queue: dict[str, Any],
    configured_repositories: set[str],
    *,
    source_run_url: str = "",
) -> tuple[dict[str, Any], dict[str, int]]:
    # A reviewer decision can land between scheduled scans while queue.json still
    # contains the now-decided artifact. The builder's job is to reconcile that
    # transient input state. Validate each document independently first; the
    # rebuilt combined state is required to pass strict cross-state validation.
    validate_decisions(decisions_payload)
    validate_queue(existing_queue)
    reports = _report_index(audit_payload)
    baselines = _baseline_index(baseline_payload)
    latest_decisions = _latest_decisions(decisions_payload)
    existing_index = {_queue_key(item): item for item in existing_queue["items"]}

    observed_at = _safe_text(audit_payload.get("generated_at"))
    try:
        _parse_time(observed_at)
    except ValueError:
        observed_at = _now_iso()

    items: list[dict[str, Any]] = []
    stats = {"critical": 0, "high": 0, "normal": 0, "resolved": 0, "superseded": 0}

    for repository in sorted(configured_repositories):
        report = reports.get(repository)
        if report is None:
            continue
        digest = str(report.get("artifact_sha256") or "").casefold()
        release = _safe_text(report.get("release"))
        key = (repository, digest if _is_sha256(digest) else f"release:{release}")
        existing = existing_index.get(key)

        if _is_sha256(digest) and (repository, digest) in latest_decisions:
            if existing:
                stats["resolved"] += 1
            continue

        item = _build_item(report, baselines.get(repository), existing, observed_at)
        if item is not None:
            items.append(item)
            stats[item["priority"]] += 1

    current_keys = {_queue_key(item) for item in items}
    for old_item in existing_queue["items"]:
        old_key = _queue_key(old_item)
        if old_key in current_keys:
            continue
        repository, identity = old_key
        if repository not in configured_repositories:
            stats["superseded"] += 1
            continue
        digest = old_item.get("artifact_sha256") or ""
        if digest and (repository, digest.casefold()) in latest_decisions:
            continue
        current_report = reports.get(repository)
        if current_report is not None and _queue_key(current_report) != old_key:
            stats["superseded"] += 1

    items.sort(
        key=lambda item: (
            PRIORITY_ORDER[item["priority"]],
            _repo_key(item["repository"]),
            item.get("artifact_sha256") or item.get("release") or "",
        )
    )

    if items == existing_queue["items"]:
        return existing_queue, stats

    payload = {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "generated_at": observed_at,
        "source_run_url": _safe_text(source_run_url),
        "item_count": len(items),
        "items": items,
    }
    validate_state(decisions_payload, payload)
    return payload, stats


def _md(value: object) -> str:
    text = _safe_text(value)
    for char in ("\\", "`", "*", "_", "~", "[", "]", "<", ">", "|"):
        text = text.replace(char, f"\\{char}")
    return text


def _short_sha(value: object) -> str:
    text = str(value or "")
    return text[:12] if text else "unavailable"


def render_markdown(queue: dict[str, Any]) -> str:
    validate_queue(queue)
    counts = {priority: 0 for priority in PRIORITY_ORDER}
    for item in queue["items"]:
        counts[item["priority"]] += 1

    lines = [
        "# Security Review Queue",
        "",
        f"Pending artifacts: **{queue['item_count']}** — critical {counts['critical']}, high {counts['high']}, normal {counts['normal']}.",
    ]
    if queue.get("generated_at"):
        lines.append(f"Generated: `{_md(queue['generated_at'])}`")
    if queue.get("source_run_url"):
        lines.append(f"Source audit run: {_md(queue['source_run_url'])}")
    lines.append("")

    if not queue["items"]:
        lines.append("No artifacts currently require a review decision.")
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(
        [
            "| Priority | Plugin | Candidate | Baseline | Classification | Why |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in queue["items"]:
        candidate = f"{_md(item['release'])} / `{_short_sha(item['artifact_sha256'])}`"
        baseline = (
            f"{_md(item['baseline_release'])} / `{_short_sha(item['baseline_artifact_sha256'])}`"
            if item.get("baseline_artifact_sha256")
            else "unavailable"
        )
        why = ", ".join(_md(reason.replace("_", " ")) for reason in item["reasons"])
        lines.append(
            f"| **{_md(item['priority'].upper())}** | {_md(item['plugin_name'] or item['repository'])} | "
            f"{candidate} | {baseline} | {_md(item['final_classification'])} | {why} |"
        )

    for item in queue["items"]:
        lines.extend(
            [
                "",
                f"## {_md(item['plugin_name'] or item['repository'])}",
                "",
                f"- Repository: `{_md(item['repository'])}`",
                f"- Candidate: `{_md(item['release'])}` — `{_md(item['artifact_sha256'] or 'artifact SHA unavailable')}`",
                f"- Classification: **{_md(item['final_classification'])}** (risk {item['risk_score']})",
                f"- Comparison: `{_md(item['comparison_status'])}`; reviewer-attention changes: {item['reviewer_attention_count']}",
                f"- First seen: `{_md(item['first_seen_at'])}`",
            ]
        )
        if item.get("baseline_artifact_sha256"):
            lines.append(
                f"- Accepted baseline: `{_md(item['baseline_release'])}` — `{_md(item['baseline_artifact_sha256'])}`"
            )
        else:
            lines.append("- Accepted baseline: unavailable")
        if item["same_artifact"] and item["changed_capabilities"]:
            lines.append("- Artifact bytes are unchanged; differences may reflect scanner/rule/coverage drift.")
        if item["error_count"]:
            lines.append(f"- Audit errors: {item['error_count']} (see the full audit artifact/logs for details)")
        if item["changed_capabilities"]:
            lines.append("- Capability changes:")
            for capability in item["changed_capabilities"]:
                attention = " — **review**" if capability["reviewer_attention"] else ""
                summary = capability["summary"] or capability["status_change"] or "changed"
                lines.append(
                    f"  - **{_md(capability['title'])}:** {_md(summary)}{attention}"
                )
        else:
            lines.append("- Capability changes: none observed in the comparison model.")

    return "\n".join(lines).rstrip() + "\n"


def record_decision(
    decisions: dict[str, Any],
    queue: dict[str, Any],
    *,
    repository: str,
    artifact_sha256: str,
    decision: str,
    reviewer: str,
    reason: str,
    decided_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_state(decisions, queue)
    repository_key = _repo_key(repository)
    digest = str(artifact_sha256 or "").casefold()
    if not _is_sha256(digest):
        raise ValueError("decision requires an exact 64-character artifact SHA-256")
    if decision not in DECISION_VALUES:
        raise ValueError("decision must be approved or rejected")
    if not _GITHUB_USER.fullmatch(reviewer):
        raise ValueError("reviewer is not a valid GitHub username")
    reason = _safe_text(reason)
    if not reason or len(reason) > MAX_REASON_LENGTH:
        raise ValueError("decision reason is empty or too long")

    target = next(
        (
            item
            for item in queue["items"]
            if _repo_key(item["repository"]) == repository_key
            and str(item.get("artifact_sha256") or "").casefold() == digest
        ),
        None,
    )
    if target is None:
        raise ValueError("exact artifact is not currently pending in the review queue")

    timestamp = decided_at or _now_iso()
    _parse_time(timestamp)
    new_decisions = json.loads(json.dumps(decisions))
    new_decisions["decisions"].append(
        {
            "repository": target["repository"],
            "release": target["release"],
            "artifact_sha256": digest,
            "decision": decision,
            "decided_by": reviewer,
            "decided_at": timestamp,
            "reason": reason,
        }
    )

    new_queue = json.loads(json.dumps(queue))
    new_queue["items"] = [
        item
        for item in new_queue["items"]
        if not (
            _repo_key(item["repository"]) == repository_key
            and str(item.get("artifact_sha256") or "").casefold() == digest
        )
    ]
    new_queue["item_count"] = len(new_queue["items"])
    new_queue["generated_at"] = timestamp

    validate_state(new_decisions, new_queue)
    return new_decisions, new_queue


def _read_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return payload


def _write_json(path: str | Path, payload: object) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: str | Path, text: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and maintain the store security review queue")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate committed review state")
    validate_parser.add_argument("--decisions", required=True)
    validate_parser.add_argument("--queue", required=True)

    build_parser = subparsers.add_parser("build", help="build a queue from an audit report")
    build_parser.add_argument("--audit-report", required=True)
    build_parser.add_argument("--baseline", required=True)
    build_parser.add_argument("--decisions", required=True)
    build_parser.add_argument("--existing-queue", required=True)
    build_parser.add_argument("--plugins-file", required=True)
    build_parser.add_argument("--output-json", required=True)
    build_parser.add_argument("--output-markdown", required=True)
    build_parser.add_argument("--source-run-url", default="")

    decide_parser = subparsers.add_parser("decide", help="record a decision for an exact queued artifact")
    decide_parser.add_argument("--decisions", required=True)
    decide_parser.add_argument("--queue", required=True)
    decide_parser.add_argument("--queue-markdown", required=True)
    decide_parser.add_argument("--repository", required=True)
    decide_parser.add_argument("--artifact-sha256", required=True)
    decide_parser.add_argument("--decision", choices=sorted(DECISION_VALUES), required=True)
    decide_parser.add_argument("--reviewer", required=True)
    decide_parser.add_argument("--reason", required=True)
    decide_parser.add_argument("--decided-at")

    args = parser.parse_args(argv)

    if args.command == "validate":
        decisions = _read_json(args.decisions)
        queue = _read_json(args.queue)
        validate_state(decisions, queue)
        print(f"Review state is valid: decisions={len(decisions['decisions'])} pending={queue['item_count']}")
        return 0

    if args.command == "build":
        decisions = _read_json(args.decisions)
        queue, stats = build_queue(
            _read_json(args.audit_report),
            _read_json(args.baseline),
            decisions,
            _read_json(args.existing_queue),
            accepted_baseline.read_configured_repositories(args.plugins_file),
            source_run_url=args.source_run_url,
        )
        _write_json(args.output_json, queue)
        _write_text(args.output_markdown, render_markdown(queue))
        print(
            "Security review queue: "
            f"pending={queue['item_count']} critical={stats['critical']} high={stats['high']} "
            f"normal={stats['normal']} resolved={stats['resolved']} superseded={stats['superseded']}"
        )
        return 0

    decisions, queue = record_decision(
        _read_json(args.decisions),
        _read_json(args.queue),
        repository=args.repository,
        artifact_sha256=args.artifact_sha256,
        decision=args.decision,
        reviewer=args.reviewer,
        reason=args.reason,
        decided_at=args.decided_at,
    )
    _write_json(args.decisions, decisions)
    _write_json(args.queue, queue)
    _write_text(args.queue_markdown, render_markdown(queue))
    print(f"Recorded {args.decision} decision; pending={queue['item_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
