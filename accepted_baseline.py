"""Persist comparison-safe security baselines for releases actually distributed.

The store's catalog auto-refreshes from upstream releases, so "accepted" in this
repository means an artifact that is verifiably present in the live stable
catalog.  This module projects a successful full audit into a compact, public-
safe baseline that the standalone auditor can later consume via
``--baseline-report``.

A baseline is immutable for a given artifact SHA-256.  Re-auditing the same
artifact with newer scanners or rules never rewrites its accepted snapshot;
only a different live artifact hash can advance it.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import plugin_release_utils

BASELINE_SCHEMA_VERSION = "1"
SUPPORTED_CAPABILITY_SCHEMA_VERSION = "1"
BASELINE_SEMANTICS = "currently_distributed_live_stable_catalog"
MAX_REPORTS = 10_000

SOURCE_DIFF_CATEGORIES = (
    "zip_only_executables",
    "zip_only_scripts",
    "large_binaries_absent_from_source",
    "unexpected_urls",
    "same_path_modified",
    "grouped_packaged_outputs",
    "generated_or_dependency_differences",
    "other_same_path_differences",
    "expected_build_stamp_differences",
)

_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
)

_REPORT_KEYS = {
    "repository",
    "plugin_name",
    "release",
    "artifact_sha256",
    "source_commit",
    "final_classification",
    "risk_score",
    "schema_version",
    "policy_version",
    "reviewer_capabilities_schema_version",
    "reviewer_capabilities",
    "network_destinations",
    "native_binaries",
    "source_artifact_diff",
    "baseline_captured_at",
    "baseline_source",
    "baseline_live_version",
    "baseline_live_hash",
}

_CAPABILITY_KEYS = {
    "id",
    "title",
    "question",
    "status",
    "rule_ids",
    "finding_count",
    "evidence_count",
    "distinct_evidence_count",
    "evidence_collapsed",
    "evidence_truncated",
}


def _safe_text(value: object) -> str:
    text = str(value or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _is_sha256(value: object) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")))


def _is_full_sha(value: object) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", str(value or "")))


def normalize_repository(value: object) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://github.com/{raw}")
    if parsed.hostname and parsed.hostname.casefold() != "github.com":
        return raw.casefold().removesuffix(".git")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 2:
        return (
            f"github.com/{parts[0].casefold()}/"
            f"{parts[1].casefold().removesuffix('.git')}"
        )
    return raw.casefold().removesuffix(".git")


def read_configured_repositories(path: str | Path) -> set[str]:
    configured: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            key = normalize_repository(value)
            if key:
                configured.add(key)
    return configured


def _reports(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("audit report must be a JSON object")
    reports = payload.get("reports")
    if not isinstance(reports, list):
        raise ValueError("audit report must contain a reports list")
    if len(reports) > MAX_REPORTS:
        raise ValueError(f"audit report contains more than {MAX_REPORTS} reports")
    if not all(isinstance(item, dict) for item in reports):
        raise ValueError("audit report contains a non-object report")
    return list(reports)


def _index_reports(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for report in reports:
        key = normalize_repository(report.get("repository"))
        if not key:
            continue
        if key in indexed:
            raise ValueError("more than one audit report matched the same repository")
        indexed[key] = report
    return indexed


def _live_plugins(catalog: object) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(catalog, list):
        raise ValueError("live catalog must be a JSON list")
    indexed: dict[str, list[dict[str, Any]]] = {}
    for plugin in catalog:
        if not isinstance(plugin, dict):
            continue
        name = str(plugin.get("name") or "").strip().casefold()
        if name:
            indexed.setdefault(name, []).append(plugin)
    return indexed


def _matching_live_version(
    report: dict[str, Any],
    live_index: dict[str, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    plugin_name = str(report.get("plugin_name") or "").strip().casefold()
    digest = str(report.get("artifact_sha256") or "").strip().casefold()
    release = plugin_release_utils.normalize_version(
        str(report.get("release") or "").strip()
    )
    if not plugin_name or not release or not _is_sha256(digest):
        return None

    matches: list[dict[str, Any]] = []
    for plugin in live_index.get(plugin_name, []):
        for version in plugin.get("versions") or []:
            if not isinstance(version, dict):
                continue
            version_name = str(version.get("name") or "").strip()
            version_hash = str(version.get("hash") or "").strip().casefold()
            if version_name == release and version_hash == digest:
                matches.append(version)
    return matches[0] if len(matches) == 1 else None


def _comparison_eligible(report: dict[str, Any]) -> bool:
    if report.get("errors"):
        return False
    if str(report.get("reviewer_capabilities_schema_version") or "") != SUPPORTED_CAPABILITY_SCHEMA_VERSION:
        return False
    capabilities = report.get("reviewer_capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        return False
    if not _is_sha256(report.get("artifact_sha256")):
        return False
    statuses = {"observed", "not_observed", "unknown"}
    return all(
        isinstance(item, dict)
        and item.get("id")
        and item.get("status") in statuses
        for item in capabilities
    )


def _project_capability(capability: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {
        "id": _safe_text(capability.get("id")),
        "title": _safe_text(capability.get("title")),
        "question": _safe_text(capability.get("question")),
        "status": _safe_text(capability.get("status")),
        "rule_ids": sorted(
            {_safe_text(value) for value in capability.get("rule_ids") or [] if value}
        ),
        "finding_count": _safe_int(capability.get("finding_count")),
        "evidence_count": _safe_int(capability.get("evidence_count")),
        "distinct_evidence_count": _safe_int(capability.get("distinct_evidence_count")),
        "evidence_collapsed": _safe_int(capability.get("evidence_collapsed")),
        "evidence_truncated": bool(capability.get("evidence_truncated")),
    }
    return projected


def _project_network(report: dict[str, Any]) -> list[dict[str, str]]:
    values = {
        _safe_text(item.get("destination"))
        for item in report.get("network_destinations") or []
        if isinstance(item, dict) and item.get("destination")
    }
    return [{"destination": value} for value in sorted(values)]


def _project_native(report: dict[str, Any]) -> list[dict[str, str]]:
    values: set[tuple[str, str]] = set()
    for item in report.get("native_binaries") or []:
        if not isinstance(item, dict):
            continue
        path = _safe_text(item.get("path"))
        digest = _safe_text(item.get("sha256"))
        if path or digest:
            values.add((path, digest))
    return [
        {"path": path, "sha256": digest}
        for path, digest in sorted(values)
    ]


def _project_source_diff(report: dict[str, Any]) -> dict[str, list[dict[str, bool]]]:
    source_diff = report.get("source_artifact_diff")
    if not isinstance(source_diff, dict):
        return {}
    projected: dict[str, list[dict[str, bool]]] = {}
    for category in SOURCE_DIFF_CATEGORIES:
        values = source_diff.get(category)
        if isinstance(values, list) and values:
            # PR #16 compares these categories by count.  Persist only the count,
            # not potentially sensitive paths/snippets from the raw diff record.
            projected[category] = [{"counted": True} for _ in values]
    return projected


def project_report(
    report: dict[str, Any],
    live_version: dict[str, Any],
    captured_at: str,
) -> dict[str, Any]:
    source_commit = _safe_text(report.get("source_commit"))
    if source_commit and not _is_full_sha(source_commit):
        source_commit = ""
    digest = str(report.get("artifact_sha256") or "").casefold()
    return {
        "repository": _safe_text(report.get("repository")),
        "plugin_name": _safe_text(report.get("plugin_name")),
        "release": _safe_text(report.get("release")),
        "artifact_sha256": digest,
        "source_commit": source_commit,
        "final_classification": _safe_text(report.get("final_classification")),
        "risk_score": _safe_int(report.get("risk_score")),
        "schema_version": _safe_text(report.get("schema_version")),
        "policy_version": _safe_text(report.get("policy_version")),
        "reviewer_capabilities_schema_version": _safe_text(
            report.get("reviewer_capabilities_schema_version")
        ),
        "reviewer_capabilities": sorted(
            [
                _project_capability(item)
                for item in report.get("reviewer_capabilities") or []
                if isinstance(item, dict)
            ],
            key=lambda item: item["id"],
        ),
        "network_destinations": _project_network(report),
        "native_binaries": _project_native(report),
        "source_artifact_diff": _project_source_diff(report),
        "baseline_captured_at": _safe_text(captured_at),
        "baseline_source": "live_catalog_hash_match",
        "baseline_live_version": _safe_text(live_version.get("name")),
        "baseline_live_hash": _safe_text(live_version.get("hash")).casefold(),
    }


def _contains_secret(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_secret(key) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    if not isinstance(value, str):
        return False
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def validate_baseline(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")
    if str(payload.get("schema_version") or "") != BASELINE_SCHEMA_VERSION:
        raise ValueError("unsupported accepted baseline schema")
    if payload.get("baseline_semantics") != BASELINE_SEMANTICS:
        raise ValueError("unexpected accepted baseline semantics")
    reports = payload.get("reports")
    if not isinstance(reports, list) or len(reports) > MAX_REPORTS:
        raise ValueError("accepted baseline reports must be a bounded list")

    seen: set[str] = set()
    for report in reports:
        if not isinstance(report, dict):
            raise ValueError("accepted baseline contains a non-object report")
        unexpected = set(report) - _REPORT_KEYS
        if unexpected:
            raise ValueError(f"accepted baseline report has unexpected fields: {sorted(unexpected)}")
        key = normalize_repository(report.get("repository"))
        if not key or key in seen:
            raise ValueError("accepted baseline repositories must be unique and non-empty")
        seen.add(key)
        if not _is_sha256(report.get("artifact_sha256")):
            raise ValueError("accepted baseline has an invalid artifact SHA-256")
        if report.get("source_commit") and not _is_full_sha(report.get("source_commit")):
            raise ValueError("accepted baseline has an invalid source commit")
        if str(report.get("reviewer_capabilities_schema_version") or "") != SUPPORTED_CAPABILITY_SCHEMA_VERSION:
            raise ValueError("accepted baseline has an unsupported capability schema")

        capabilities = report.get("reviewer_capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            raise ValueError("accepted baseline is missing reviewer capabilities")
        capability_ids: set[str] = set()
        for capability in capabilities:
            if not isinstance(capability, dict) or set(capability) - _CAPABILITY_KEYS:
                raise ValueError("accepted baseline capability shape is invalid")
            capability_id = str(capability.get("id") or "")
            if not capability_id or capability_id in capability_ids:
                raise ValueError("accepted baseline capability identifiers must be unique")
            capability_ids.add(capability_id)
            if capability.get("status") not in {"observed", "not_observed", "unknown"}:
                raise ValueError("accepted baseline capability status is invalid")

        for item in report.get("network_destinations") or []:
            if not isinstance(item, dict) or set(item) != {"destination"}:
                raise ValueError("accepted baseline network inventory is invalid")
        for item in report.get("native_binaries") or []:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise ValueError("accepted baseline native inventory is invalid")
        source_diff = report.get("source_artifact_diff") or {}
        if not isinstance(source_diff, dict) or set(source_diff) - set(SOURCE_DIFF_CATEGORIES):
            raise ValueError("accepted baseline source-diff inventory is invalid")
        for values in source_diff.values():
            if not isinstance(values, list) or any(item != {"counted": True} for item in values):
                raise ValueError("accepted baseline source-diff count projection is invalid")

    if _contains_secret(payload):
        raise ValueError("accepted baseline contains secret-shaped text")


def empty_baseline(live_catalog_url: str = "") -> dict[str, Any]:
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "baseline_semantics": BASELINE_SEMANTICS,
        "generated_at": "",
        "auditor_ref": "",
        "live_catalog_url": _safe_text(live_catalog_url),
        "entry_count": 0,
        "reports": [],
    }


def build_baseline(
    audit_payload: dict[str, Any],
    live_catalog: list[dict[str, Any]],
    configured_repositories: set[str],
    existing_payload: dict[str, Any] | None = None,
    *,
    auditor_ref: str = "",
    live_catalog_url: str = "",
) -> tuple[dict[str, Any], dict[str, int]]:
    existing = existing_payload or empty_baseline(live_catalog_url)
    validate_baseline(existing)

    current_index = _index_reports(_reports(audit_payload))
    existing_index = _index_reports(list(existing.get("reports") or []))
    live_index = _live_plugins(live_catalog)
    captured_at = str(audit_payload.get("generated_at") or "")

    output_reports: list[dict[str, Any]] = []
    stats = {"advanced": 0, "preserved": 0, "unavailable": 0, "pruned": 0}

    for repository in sorted(configured_repositories):
        previous = existing_index.get(repository)
        current = current_index.get(repository)

        if current is not None and previous is not None:
            if (
                str(current.get("artifact_sha256") or "").casefold()
                == str(previous.get("artifact_sha256") or "").casefold()
            ):
                output_reports.append(previous)
                stats["preserved"] += 1
                continue

        live_version = (
            _matching_live_version(current, live_index)
            if current is not None and _comparison_eligible(current)
            else None
        )
        if current is not None and live_version is not None:
            output_reports.append(project_report(current, live_version, captured_at))
            stats["advanced"] += 1
        elif previous is not None:
            output_reports.append(previous)
            stats["preserved"] += 1
        else:
            stats["unavailable"] += 1

    stats["pruned"] = len(set(existing_index) - configured_repositories)
    output_reports.sort(key=lambda report: normalize_repository(report.get("repository")))

    old_reports = list(existing.get("reports") or [])
    if output_reports == old_reports and stats["pruned"] == 0:
        return existing, stats

    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "baseline_semantics": BASELINE_SEMANTICS,
        "generated_at": _safe_text(captured_at),
        "auditor_ref": _safe_text(auditor_ref),
        "live_catalog_url": _safe_text(live_catalog_url),
        "entry_count": len(output_reports),
        "reports": output_reports,
    }
    validate_baseline(payload)
    return payload, stats


def _read_json(path: str | Path) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: str | Path, payload: object) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or validate the store's accepted security baseline")
    parser.add_argument("--audit-report")
    parser.add_argument("--live-catalog")
    parser.add_argument("--plugins-file")
    parser.add_argument("--existing")
    parser.add_argument("--output")
    parser.add_argument("--auditor-ref", default="")
    parser.add_argument("--live-catalog-url", default="")
    parser.add_argument("--validate-only")
    args = parser.parse_args(argv)

    if args.validate_only:
        validate_baseline(_read_json(args.validate_only))
        print(f"Accepted baseline is valid: {args.validate_only}")
        return 0

    required = {
        "--audit-report": args.audit_report,
        "--live-catalog": args.live_catalog,
        "--plugins-file": args.plugins_file,
        "--output": args.output,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        parser.error(f"required when building a baseline: {', '.join(missing)}")

    existing = (
        _read_json(args.existing)
        if args.existing and Path(args.existing).exists()
        else empty_baseline(args.live_catalog_url)
    )
    payload, stats = build_baseline(
        _read_json(args.audit_report),
        _read_json(args.live_catalog),
        read_configured_repositories(args.plugins_file),
        existing,
        auditor_ref=args.auditor_ref,
        live_catalog_url=args.live_catalog_url,
    )
    _write_json(args.output, payload)
    print(
        "Accepted baseline candidate: "
        f"{payload['entry_count']} entries; "
        f"advanced={stats['advanced']} preserved={stats['preserved']} "
        f"unavailable={stats['unavailable']} pruned={stats['pruned']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
