"""Noise reduction for source-versus-release artifact comparison.

Release archives commonly contain bundled dependencies and generated build output
that do not exist as committed files in the source tree. The core comparison still
finds every ZIP-only script and executable; this layer collapses recognized output
families into a small number of reviewable bundle findings while preserving
individual findings for unexpected plugin-owned files.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any, Callable


_SOURCE_DIFF_RULES = {"ZIP_ONLY_SCRIPT", "ZIP_ONLY_EXECUTABLE"}

_PYTHON_DEPENDENCY_DIRS = {
    "py_modules",
    "site-packages",
    ".venv",
    "venv",
}
_JAVASCRIPT_DEPENDENCY_DIRS = {"node_modules"}
_VENDOR_DEPENDENCY_DIRS = {"vendor", "vendors", "third_party", "third-party"}
_GENERATED_BUILD_DIRS = {
    "dist",
    "build",
    "out",
    ".next",
    ".vite",
    ".webpack",
}
_GENERATED_SCRIPT_NAME = re.compile(
    r"(?:\.min|\.bundle|\.chunk)(?:\.[a-f0-9]{6,})?\.(?:js|mjs|cjs)$",
    re.IGNORECASE,
)
_HASHED_SCRIPT_NAME = re.compile(
    r"(?:^|[._-])[a-f0-9]{8,}\.(?:js|mjs|cjs)$",
    re.IGNORECASE,
)


def _normalised_parts(path: str) -> tuple[str, ...]:
    return PurePosixPath(path.replace("\\", "/")).parts


def _root_through(parts: tuple[str, ...], index: int) -> str:
    return "/".join(parts[: index + 1]).rstrip("/") + "/"


def _classify_packaged_output(path: str) -> tuple[str, str] | None:
    """Return (category, bundle root) for recognized packaged output paths."""

    parts = _normalised_parts(path)
    if not parts:
        return None

    # Only directory components participate in directory-family matching.
    for index, part in enumerate(parts[:-1]):
        lowered = part.lower()
        if lowered in _PYTHON_DEPENDENCY_DIRS:
            return "python_dependencies", _root_through(parts, index)
        if lowered in _JAVASCRIPT_DEPENDENCY_DIRS:
            return "javascript_dependencies", _root_through(parts, index)
        if lowered in _VENDOR_DEPENDENCY_DIRS:
            return "vendored_dependencies", _root_through(parts, index)

    for index, part in enumerate(parts[:-1]):
        if part.lower() in _GENERATED_BUILD_DIRS:
            return "generated_build_output", _root_through(parts, index)

    name = parts[-1].lower()
    if _GENERATED_SCRIPT_NAME.search(name) or _HASHED_SCRIPT_NAME.search(name):
        # Avoid collapsing top-level plugin/archive files solely based on hash-like names.
        if len(parts) < 3:
            return None
        parent = "/".join(parts[:-1]).rstrip("/")
        return "generated_build_output", parent + "/"

    return None


def _group_policy(category: str, original_rule: str) -> tuple[str, str, str]:
    """Return (rule_id, severity, classification) for a grouped finding."""

    executable = original_rule == "ZIP_ONLY_EXECUTABLE"
    if executable:
        if category == "generated_build_output":
            return "GENERATED_BUILD_EXECUTABLES", "high", "MANUAL_REVIEW"
        return "BUNDLED_DEPENDENCY_EXECUTABLES", "high", "MANUAL_REVIEW"

    if category == "generated_build_output":
        return "GENERATED_BUILD_SCRIPTS", "low", "PASS_WITH_WARNINGS"
    if category == "vendored_dependencies":
        # Generic vendor folders are less self-describing than node_modules or
        # Python package directories, so keep a single manual-review finding.
        return "VENDORED_DEPENDENCY_SCRIPTS", "medium", "MANUAL_REVIEW"
    return "BUNDLED_DEPENDENCY_SCRIPTS", "low", "PASS_WITH_WARNINGS"


def _category_label(category: str) -> str:
    return {
        "python_dependencies": "bundled Python dependencies",
        "javascript_dependencies": "bundled JavaScript dependencies",
        "vendored_dependencies": "vendored dependencies",
        "generated_build_output": "generated build output",
    }[category]


def _group_message(category: str, original_rule: str, root: str, count: int) -> str:
    label = _category_label(category)
    if original_rule == "ZIP_ONLY_EXECUTABLE":
        return (
            f"Collapsed {count} ZIP-only native executable file(s) under {root!r} "
            f"that appear to be {label}. Manual review remains required for the "
            "bundle, while malware, vulnerability, binary, credential, and "
            "applicable static scanners continue to inspect the individual files."
        )

    if category == "vendored_dependencies":
        return (
            f"Collapsed {count} ZIP-only script-like file(s) under {root!r}. The "
            "directory appears to contain vendored dependencies, but provenance is "
            "not independently verified; review the bundle as a unit."
        )

    return (
        f"Collapsed {count} ZIP-only script-like file(s) under {root!r} that appear "
        f"to be {label}. Individual source-diff findings were replaced by this "
        "summary; the files remain covered by applicable security scanners."
    )


def _build_group_finding(
    core: Any,
    *,
    category: str,
    root: str,
    original_rule: str,
    paths: list[str],
):
    rule_id, severity, classification = _group_policy(category, original_rule)
    ordered = sorted(set(paths))
    samples = ordered[:5]
    evidence = f"count={len(ordered)}; samples=" + ", ".join(samples)
    return core.Finding(
        rule_id=rule_id,
        severity=severity,
        classification=classification,
        path=root,
        line=0,
        message=_group_message(category, original_rule, root, len(ordered)),
        evidence=core._truncate(evidence, core.EVIDENCE_MAX_LEN),
        scanner="source-artifact-diff",
    )


def _transform_results(
    core: Any,
    summary: dict[str, Any],
    findings: list[Any],
    status: Any,
) -> tuple[dict[str, Any], list[Any], Any]:
    """Collapse recognized package/build output while preserving actionable paths."""

    if getattr(status, "status", None) not in {"found_issue", "passed"}:
        return summary, findings, status

    groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    retained: list[Any] = []

    for finding in findings:
        if finding.rule_id not in _SOURCE_DIFF_RULES:
            retained.append(finding)
            continue

        classified = _classify_packaged_output(finding.path)
        if classified is None:
            retained.append(finding)
            continue

        category, root = classified
        groups[(category, root, finding.rule_id)].append(finding.path)

    grouped_paths = {path for paths in groups.values() for path in paths}

    original_scripts = list(summary.get("zip_only_scripts") or [])
    original_executables = list(summary.get("zip_only_executables") or [])
    summary["zip_only_scripts"] = sorted(
        path for path in original_scripts if path not in grouped_paths
    )
    summary["zip_only_executables"] = sorted(
        path for path in original_executables if path not in grouped_paths
    )

    grouped_summary: list[dict[str, Any]] = []
    for category, root, original_rule in sorted(groups):
        paths = sorted(set(groups[(category, root, original_rule)]))
        finding = _build_group_finding(
            core,
            category=category,
            root=root,
            original_rule=original_rule,
            paths=paths,
        )
        retained.append(finding)
        grouped_summary.append({
            "category": category,
            "root": root,
            "kind": "executable" if original_rule == "ZIP_ONLY_EXECUTABLE" else "script",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "classification": finding.classification,
            "count": len(paths),
            "sample_paths": paths[:5],
        })

    grouped_script_count = sum(
        item["count"] for item in grouped_summary if item["kind"] == "script"
    )
    grouped_executable_count = sum(
        item["count"] for item in grouped_summary if item["kind"] == "executable"
    )
    summary["grouped_packaged_outputs"] = grouped_summary
    summary["original_zip_only_scripts_count"] = len(original_scripts)
    summary["original_zip_only_executables_count"] = len(original_executables)
    summary["grouped_zip_only_scripts_count"] = grouped_script_count
    summary["grouped_zip_only_executables_count"] = grouped_executable_count
    summary["actionable_zip_only_scripts_count"] = len(summary["zip_only_scripts"])
    summary["actionable_zip_only_executables_count"] = len(summary["zip_only_executables"])

    retained.sort(key=lambda item: (item.path, item.rule_id, item.line, item.message))
    status.status = "found_issue" if retained else "passed"
    if groups:
        status.detail = (
            f"Collapsed {grouped_script_count + grouped_executable_count} packaged "
            f"output file(s) into {len(grouped_summary)} group finding(s); "
            f"{len(summary['zip_only_scripts']) + len(summary['zip_only_executables'])} "
            "actionable ZIP-only file(s) remain."
        )
    return summary, retained, status


def install(core: Any) -> None:
    """Install packaged-output grouping onto the source/artifact comparator."""

    if getattr(core, "_artifact_diff_filters_installed", False):
        return

    original_compare: Callable[..., tuple[dict[str, Any], list[Any], Any]] = (
        core.compare_source_and_artifact
    )

    def compare_source_and_artifact(
        extract_dir: str,
        owner: str,
        repo: str,
        ref: str,
    ) -> tuple[dict[str, Any], list[Any], Any]:
        summary, findings, status = original_compare(extract_dir, owner, repo, ref)
        return _transform_results(core, summary, findings, status)

    core.compare_source_and_artifact = compare_source_and_artifact
    core._artifact_diff_filters_installed = True
