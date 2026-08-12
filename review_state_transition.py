"""Validate human review-state changes across a pull request boundary.

Scheduled queue refreshes are produced by a constrained bot job directly on
``main``. Human review decisions, however, are expected to go through pull
requests. This module makes those PR transitions tamper-evident: old decisions
must remain record-for-record unchanged after JSON decoding, every new decision
must target an exact artifact that was pending in the base queue, and the queue
change must be the same deterministic removal performed by
``review_queue.py decide``.

Rare queue-data repairs are tracked separately from human decisions in an
append-only repair ledger. A repair record names exact artifact identities and
can only perform the narrowly validated transformation for its repair kind; it
cannot manufacture an approval, rewrite decision history, or mutate unrelated
pending review state.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

import review_queue

REPAIRS_SCHEMA_VERSION = "1"
REPAIR_KIND_LEGACY_NETWORK = "legacy_cached_network_inventory"
_REPAIR_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_FALSE_NETWORK_SUMMARY = re.compile(r"^network destinations \+0/-[1-9][0-9]*$")
_REPAIRS_TOP_KEYS = {"schema_version", "repairs"}
_REPAIR_KEYS = {
    "id",
    "kind",
    "auditor_ref",
    "repaired_at",
    "reason",
    "source_run_ids",
    "remove_items",
    "remove_capabilities",
}
_IDENTITY_KEYS = {"repository", "artifact_sha256"}
_REMOVE_CAPABILITY_KEYS = {
    "repository",
    "artifact_sha256",
    "capability_id",
    "expected_summary",
}


def _identity(item: dict[str, Any]) -> tuple[str, str]:
    return (
        review_queue._repo_key(item.get("repository")),
        str(item.get("artifact_sha256") or "").casefold(),
    )


def empty_repairs() -> dict[str, Any]:
    return {"schema_version": REPAIRS_SCHEMA_VERSION, "repairs": []}


def validate_repairs(payload: object) -> None:
    if not isinstance(payload, dict) or set(payload) != _REPAIRS_TOP_KEYS:
        raise ValueError("review repair ledger top-level shape is invalid")
    if payload.get("schema_version") != REPAIRS_SCHEMA_VERSION:
        raise ValueError("unsupported review repair ledger schema")
    records = payload.get("repairs")
    if not isinstance(records, list) or len(records) > review_queue.MAX_ITEMS:
        raise ValueError("review repair ledger must be a bounded list")

    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != _REPAIR_KEYS:
            raise ValueError("review repair record shape is invalid")
        repair_id = str(record.get("id") or "")
        if not _REPAIR_ID.fullmatch(repair_id) or repair_id in seen_ids:
            raise ValueError("review repair identifiers must be unique and stable")
        seen_ids.add(repair_id)
        if record.get("kind") != REPAIR_KIND_LEGACY_NETWORK:
            raise ValueError("unsupported review repair kind")
        if not _FULL_SHA.fullmatch(str(record.get("auditor_ref") or "")):
            raise ValueError("review repair auditor reference must be a full commit SHA")
        review_queue._parse_time(record.get("repaired_at"))
        reason = str(record.get("reason") or "").strip()
        if not reason or len(reason) > review_queue.MAX_REASON_LENGTH:
            raise ValueError("review repair reason is empty or too long")

        source_runs = record.get("source_run_ids")
        if (
            not isinstance(source_runs, list)
            or not source_runs
            or len(source_runs) != len(set(source_runs))
            or any(not isinstance(value, int) or value <= 0 for value in source_runs)
        ):
            raise ValueError("review repair source run IDs must be unique positive integers")

        remove_items = record.get("remove_items")
        remove_capabilities = record.get("remove_capabilities")
        if not isinstance(remove_items, list) or not isinstance(remove_capabilities, list):
            raise ValueError("review repair actions must be lists")
        if not remove_items and not remove_capabilities:
            raise ValueError("review repair must contain at least one action")

        removed: set[tuple[str, str]] = set()
        for item in remove_items:
            if not isinstance(item, dict) or set(item) != _IDENTITY_KEYS:
                raise ValueError("review repair removal identity shape is invalid")
            key = _identity(item)
            if not key[0] or not review_queue._is_sha256(key[1]) or key in removed:
                raise ValueError("review repair removal identities must be unique exact artifacts")
            removed.add(key)

        updated: set[tuple[str, str]] = set()
        for item in remove_capabilities:
            if not isinstance(item, dict) or set(item) != _REMOVE_CAPABILITY_KEYS:
                raise ValueError("review repair capability action shape is invalid")
            key = _identity(item)
            if not key[0] or not review_queue._is_sha256(key[1]) or key in updated:
                raise ValueError("review repair capability actions must target unique exact artifacts")
            if key in removed:
                raise ValueError("review repair cannot remove and edit the same artifact")
            updated.add(key)
            if item.get("capability_id") != "network_communication":
                raise ValueError("legacy network repair may only remove network comparison capability data")
            if not _FALSE_NETWORK_SUMMARY.fullmatch(str(item.get("expected_summary") or "")):
                raise ValueError("legacy network repair expected summary is invalid")


def _is_strict_legacy_network_poison(item: dict[str, Any]) -> bool:
    changed = item.get("changed_capabilities") or []
    if len(changed) != 1 or not isinstance(changed[0], dict):
        return False
    capability = changed[0]
    return (
        item.get("priority") == "high"
        and item.get("same_artifact") is True
        and item.get("final_classification") not in {"AUDIT_ERROR", "BLOCK"}
        and set(item.get("reasons") or [])
        == {"security_delta", "same_artifact_analysis_drift"}
        and not item.get("scanner_failures")
        and int(item.get("reviewer_attention_count") or 0) == 1
        and capability.get("id") == "network_communication"
        and capability.get("status_change") == "unchanged"
        and capability.get("reviewer_attention") is True
        and bool(_FALSE_NETWORK_SUMMARY.fullmatch(str(capability.get("summary") or "")))
    )


def _recalculate_priority(item: dict[str, Any]) -> str:
    if item.get("final_classification") in {"AUDIT_ERROR", "BLOCK"}:
        return "critical"
    reasons = set(item.get("reasons") or [])
    if (
        "baseline_unavailable" in reasons
        or "same_artifact_analysis_drift" in reasons
        or int(item.get("reviewer_attention_count") or 0) > 0
    ):
        return "high"
    return "normal"


def apply_repair(queue: dict[str, Any], repair: dict[str, Any]) -> dict[str, Any]:
    """Apply one validated queue-data repair without touching human decisions."""
    review_queue.validate_queue(queue)
    validate_repairs({"schema_version": REPAIRS_SCHEMA_VERSION, "repairs": [repair]})
    repaired = copy.deepcopy(queue)
    indexed = {_identity(item): item for item in repaired["items"]}

    removals = {_identity(item) for item in repair["remove_items"]}
    for key in removals:
        existing = indexed.get(key)
        if existing is None:
            raise ValueError("review repair removal does not target a pending base-queue artifact")
        if not _is_strict_legacy_network_poison(existing):
            raise ValueError("review repair attempted to remove an artifact outside the strict poison signature")

    repaired["items"] = [
        item for item in repaired["items"] if _identity(item) not in removals
    ]
    indexed = {_identity(item): item for item in repaired["items"]}

    for action in repair["remove_capabilities"]:
        key = _identity(action)
        existing = indexed.get(key)
        if existing is None:
            raise ValueError("review repair capability action does not target a pending base-queue artifact")
        if "new_artifact" not in (existing.get("reasons") or []):
            raise ValueError("review repair capability action may only edit a pending new artifact")

        matching = [
            capability
            for capability in existing.get("changed_capabilities") or []
            if capability.get("id") == action["capability_id"]
        ]
        if len(matching) != 1:
            raise ValueError("review repair capability action did not match exactly one capability")
        capability = matching[0]
        if (
            capability.get("status_change") != "unchanged"
            or capability.get("reviewer_attention") is not True
            or capability.get("summary") != action["expected_summary"]
        ):
            raise ValueError("review repair capability action does not match the recorded poisoned delta")

        existing["changed_capabilities"] = [
            item
            for item in existing["changed_capabilities"]
            if item.get("id") != action["capability_id"]
        ]
        existing["reviewer_attention_count"] = sum(
            1 for item in existing["changed_capabilities"] if item.get("reviewer_attention")
        )
        if existing["reviewer_attention_count"] == 0:
            existing["reasons"] = [
                reason for reason in existing["reasons"] if reason != "security_delta"
            ]
        existing["priority"] = _recalculate_priority(existing)

    repaired["items"].sort(
        key=lambda item: (
            review_queue.PRIORITY_ORDER[item["priority"]],
            review_queue._repo_key(item["repository"]),
            item.get("artifact_sha256") or item.get("release") or "",
        )
    )
    repaired["item_count"] = len(repaired["items"])
    repaired["generated_at"] = repair["repaired_at"]
    review_queue.validate_queue(repaired)
    return repaired


def validate_transition(
    previous_decisions: dict[str, Any],
    previous_queue: dict[str, Any],
    current_decisions: dict[str, Any],
    current_queue: dict[str, Any],
    previous_repairs: dict[str, Any] | None = None,
    current_repairs: dict[str, Any] | None = None,
) -> None:
    """Require current review state to be an append-only decision or repair transition."""
    review_queue.validate_state(previous_decisions, previous_queue)
    review_queue.validate_state(current_decisions, current_queue)
    previous_repairs = previous_repairs or empty_repairs()
    current_repairs = current_repairs or empty_repairs()
    validate_repairs(previous_repairs)
    validate_repairs(current_repairs)

    old_records = previous_decisions["decisions"]
    new_records = current_decisions["decisions"]
    if len(new_records) < len(old_records) or new_records[: len(old_records)] != old_records:
        raise ValueError("review decision history is not append-only")
    decision_additions = new_records[len(old_records) :]

    old_repairs = previous_repairs["repairs"]
    new_repairs = current_repairs["repairs"]
    if len(new_repairs) < len(old_repairs) or new_repairs[: len(old_repairs)] != old_repairs:
        raise ValueError("review repair history is not append-only")
    repair_additions = new_repairs[len(old_repairs) :]

    if decision_additions and repair_additions:
        raise ValueError("review decisions and queue-data repairs must be separate transitions")

    if repair_additions:
        if current_decisions != previous_decisions:
            raise ValueError("queue-data repair must not change human decision history")
        expected_queue = copy.deepcopy(previous_queue)
        for repair in repair_additions:
            expected_queue = apply_repair(expected_queue, repair)
        if current_queue != expected_queue:
            raise ValueError("review queue does not match the deterministic result of the appended repair")
        return

    if not decision_additions:
        if current_queue != previous_queue:
            raise ValueError("review queue changed without a new review decision or repair record")
        return

    pending = {
        _identity(item): item
        for item in previous_queue["items"]
        if item.get("artifact_sha256")
    }
    decided_keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for decision in decision_additions:
        key = _identity(decision)
        if key in seen:
            raise ValueError("more than one new decision targets the same queued artifact")
        seen.add(key)
        if key not in pending:
            raise ValueError("new review decision does not target an artifact pending in the base queue")
        decided_keys.append(key)

    expected_queue = copy.deepcopy(previous_queue)
    decided_set = set(decided_keys)
    expected_queue["items"] = [
        item for item in expected_queue["items"] if _identity(item) not in decided_set
    ]
    expected_queue["item_count"] = len(expected_queue["items"])
    expected_queue["generated_at"] = decision_additions[-1]["decided_at"]

    if current_queue != expected_queue:
        raise ValueError("review queue does not match the deterministic result of the appended decisions")


def _read_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate append-only security review-state transitions")
    parser.add_argument("--validate-repairs")
    parser.add_argument("--previous-decisions")
    parser.add_argument("--previous-queue")
    parser.add_argument("--decisions")
    parser.add_argument("--queue")
    parser.add_argument("--previous-repairs")
    parser.add_argument("--repairs")
    args = parser.parse_args(argv)

    if args.validate_repairs:
        validate_repairs(_read_json(args.validate_repairs))
        print(f"Review repair ledger is valid: {args.validate_repairs}")
        return 0

    required = {
        "--previous-decisions": args.previous_decisions,
        "--previous-queue": args.previous_queue,
        "--decisions": args.decisions,
        "--queue": args.queue,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        parser.error(f"required for transition validation: {', '.join(missing)}")

    previous_repairs = (
        _read_json(args.previous_repairs) if args.previous_repairs else empty_repairs()
    )
    current_repairs = _read_json(args.repairs) if args.repairs else empty_repairs()
    validate_transition(
        _read_json(args.previous_decisions),
        _read_json(args.previous_queue),
        _read_json(args.decisions),
        _read_json(args.queue),
        previous_repairs,
        current_repairs,
    )
    current = _read_json(args.decisions)
    previous = _read_json(args.previous_decisions)
    print(
        "Review-state transition is valid: "
        f"appended_decisions={len(current['decisions']) - len(previous['decisions'])} "
        f"appended_repairs={len(current_repairs['repairs']) - len(previous_repairs['repairs'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
