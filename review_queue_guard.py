"""Safety guard for automatic persistence of the store security review queue.

Queue candidates are always built and uploaded for inspection. This module only
protects the durable committed queue from an implausible flood of newly queued,
noncritical same-artifact analysis drift. It intentionally does not suppress
new artifacts, BLOCK results, or AUDIT_ERROR results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import review_queue

MIN_DRIFT_ADDITIONS = 10
MIN_NET_GROWTH = 10
DRIFT_DOMINANCE_NUMERATOR = 1
DRIFT_DOMINANCE_DENOMINATOR = 2


def _is_noncritical_same_artifact_drift(item: dict[str, Any]) -> bool:
    digest = str(item.get("artifact_sha256") or "").casefold()
    baseline_digest = str(item.get("baseline_artifact_sha256") or "").casefold()
    reasons = set(item.get("reasons") or [])
    return (
        item.get("same_artifact") is True
        and item.get("priority") != "critical"
        and item.get("final_classification") not in {"AUDIT_ERROR", "BLOCK"}
        and "same_artifact_analysis_drift" in reasons
        and review_queue._is_sha256(digest)
        and digest == baseline_digest
    )


def analyze_persistence(
    current_queue: dict[str, Any],
    candidate_queue: dict[str, Any],
) -> dict[str, Any]:
    """Return deterministic queue-growth metrics and whether persistence is safe."""
    review_queue.validate_queue(current_queue)
    review_queue.validate_queue(candidate_queue)

    current_keys = {review_queue._queue_key(item) for item in current_queue["items"]}
    additions = [
        item
        for item in candidate_queue["items"]
        if review_queue._queue_key(item) not in current_keys
    ]
    drift_additions = [item for item in additions if _is_noncritical_same_artifact_drift(item)]

    current_count = current_queue["item_count"]
    candidate_count = candidate_queue["item_count"]
    net_growth = candidate_count - current_count
    addition_count = len(additions)
    drift_count = len(drift_additions)
    drift_dominates = (
        addition_count > 0
        and drift_count * DRIFT_DOMINANCE_DENOMINATOR
        >= addition_count * DRIFT_DOMINANCE_NUMERATOR
    )
    blocked = (
        drift_count >= MIN_DRIFT_ADDITIONS
        and net_growth >= MIN_NET_GROWTH
        and drift_dominates
    )

    return {
        "safe": not blocked,
        "current_count": current_count,
        "candidate_count": candidate_count,
        "net_growth": net_growth,
        "addition_count": addition_count,
        "same_artifact_drift_additions": drift_count,
        "drift_dominates_additions": drift_dominates,
    }


def require_safe_persistence(
    current_queue: dict[str, Any],
    candidate_queue: dict[str, Any],
) -> dict[str, Any]:
    result = analyze_persistence(current_queue, candidate_queue)
    if not result["safe"]:
        raise ValueError(
            "review queue flood guard refused durable overwrite: "
            f"current={result['current_count']} "
            f"candidate={result['candidate_count']} "
            f"net_growth={result['net_growth']} "
            f"additions={result['addition_count']} "
            "noncritical_same_artifact_drift_additions="
            f"{result['same_artifact_drift_additions']}. "
            "Inspect the uploaded queue candidate and scanner/auditor changes before persisting it."
        )
    return result


def _read_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse suspicious automatic security review queue floods"
    )
    parser.add_argument("--current", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args(argv)

    try:
        result = require_safe_persistence(
            _read_json(args.current),
            _read_json(args.candidate),
        )
    except ValueError as exc:
        print(f"QUEUE_FLOOD_GUARD_BLOCKED: {exc}")
        return 2

    print(
        "Queue flood guard passed: "
        f"current={result['current_count']} "
        f"candidate={result['candidate_count']} "
        f"net_growth={result['net_growth']} "
        f"additions={result['addition_count']} "
        "noncritical_same_artifact_drift_additions="
        f"{result['same_artifact_drift_additions']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
