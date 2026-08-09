"""Validate human review-state changes across a pull request boundary.

Scheduled queue refreshes are produced by a constrained bot job directly on
``main``. Human review decisions, however, are expected to go through pull
requests. This module makes those PR transitions tamper-evident: old decisions
must remain byte-for-byte present, every new decision must target an exact
artifact that was pending in the base queue, and the queue change must be the
same deterministic removal performed by ``review_queue.py decide``.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import review_queue


def _identity(item: dict[str, Any]) -> tuple[str, str]:
    return (
        review_queue._repo_key(item.get("repository")),
        str(item.get("artifact_sha256") or "").casefold(),
    )


def validate_transition(
    previous_decisions: dict[str, Any],
    previous_queue: dict[str, Any],
    current_decisions: dict[str, Any],
    current_queue: dict[str, Any],
) -> None:
    """Require a current review state to be an append-only decision transition."""
    review_queue.validate_state(previous_decisions, previous_queue)
    review_queue.validate_state(current_decisions, current_queue)

    old_records = previous_decisions["decisions"]
    new_records = current_decisions["decisions"]
    if len(new_records) < len(old_records) or new_records[: len(old_records)] != old_records:
        raise ValueError("review decision history is not append-only")

    additions = new_records[len(old_records) :]
    if not additions:
        if current_queue != previous_queue:
            raise ValueError("review queue changed without a new review decision")
        return

    pending = {
        _identity(item): item
        for item in previous_queue["items"]
        if item.get("artifact_sha256")
    }
    decided_keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for decision in additions:
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
    # Sequential uses of review_queue.py decide leave the queue timestamp at the
    # timestamp of the final appended decision and preserve the audit source URL.
    expected_queue["generated_at"] = additions[-1]["decided_at"]

    if current_queue != expected_queue:
        raise ValueError("review queue does not match the deterministic result of the appended decisions")


def _read_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an append-only security review-state transition")
    parser.add_argument("--previous-decisions", required=True)
    parser.add_argument("--previous-queue", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--queue", required=True)
    args = parser.parse_args(argv)

    validate_transition(
        _read_json(args.previous_decisions),
        _read_json(args.previous_queue),
        _read_json(args.decisions),
        _read_json(args.queue),
    )
    current = _read_json(args.decisions)
    previous = _read_json(args.previous_decisions)
    print(
        "Review-state transition is valid: "
        f"appended_decisions={len(current['decisions']) - len(previous['decisions'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
