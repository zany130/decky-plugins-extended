"""Suppress only exact, understood Decky metadata build stamps.

Adapted from Beallio's scanner-precision work in
beallio/decky-plugins-extended@5c8521f6d4e5ecf7475502f1407a3ad31bdd0a1b.

Decky's release build can legitimately change metadata without changing its
meaning: stamp the release version, remove the development-only ``debug`` flag,
and rewrite ``publish.image`` from the main branch to the matching release tag.
Any other metadata drift—including added privilege flags—remains a same-path
content mismatch requiring manual review.
"""

from __future__ import annotations

import json
import posixpath
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import source_content_comparison as scc


def _metadata_diff_is_build_stamped(
    path: str, source_raw: bytes, artifact_raw: bytes
) -> bool:
    """Return whether metadata drift is limited to Decky's exact build stamps."""
    filename = posixpath.basename(path).casefold()
    if filename not in {"plugin.json", "package.json"}:
        return False
    try:
        source = json.loads(source_raw)
        artifact = json.loads(artifact_raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False
    if not isinstance(source, dict) or not isinstance(artifact, dict):
        return False

    source_version = source.get("version")
    artifact_version = artifact.get("version")
    if (
        source_version != artifact_version
        and isinstance(source_version, str)
        and isinstance(artifact_version, str)
    ):
        source["version"] = artifact_version

    if filename == "package.json":
        return source == artifact

    source_flags = source.get("flags")
    artifact_flags = artifact.get("flags")
    if source_flags != artifact_flags:
        if (
            isinstance(source_flags, list)
            and isinstance(artifact_flags, list)
            and source_flags.count("debug") == 1
            and [flag for flag in source_flags if flag != "debug"] == artifact_flags
        ):
            source["flags"] = artifact_flags

    source_publish = source.get("publish")
    artifact_publish = artifact.get("publish")
    if isinstance(source_publish, dict) and isinstance(artifact_publish, dict):
        source_image = source_publish.get("image")
        artifact_image = artifact_publish.get("image")
        if (
            source_image != artifact_image
            and isinstance(source_image, str)
            and isinstance(artifact_image, str)
            and isinstance(artifact_version, str)
        ):
            release_tag = (
                artifact_version
                if artifact_version.startswith("v")
                else f"v{artifact_version}"
            )
            if source_image.replace("/main/", f"/{release_tag}/") == artifact_image:
                source_publish["image"] = artifact_image

    return source == artifact


def _record_path(record: dict[str, Any]) -> str:
    return str(record.get("artifact_path") or "")


def _filter_expected_build_stamps(
    core: ModuleType,
    extract_dir: str,
    summary: dict[str, Any],
    findings: list[Any],
    status: Any,
) -> tuple[dict[str, Any], list[Any], Any]:
    if getattr(status, "status", None) not in {"passed", "found_issue"}:
        return summary, findings, status

    shared = scc._CURRENT_SHARED_SOURCE.get()
    source_root = str((shared or {}).get("source_root") or "")
    if not source_root:
        return summary, findings, status

    retained_records: list[dict[str, Any]] = []
    expected_records: list[dict[str, Any]] = []
    expected_paths: set[str] = set()

    for record in list(summary.get("same_path_modified") or []):
        artifact_relative = _record_path(record)
        source_relative = str(record.get("source_path") or "")
        filename = posixpath.basename(artifact_relative).casefold()
        if filename not in {"plugin.json", "package.json"}:
            retained_records.append(record)
            continue

        artifact_path = Path(extract_dir).joinpath(
            *Path(artifact_relative.replace("\\", "/")).parts
        )
        source_path = Path(source_root).joinpath(
            *Path(source_relative.replace("\\", "/")).parts
        )
        try:
            source_raw = source_path.read_bytes()
            artifact_raw = artifact_path.read_bytes()
        except OSError:
            retained_records.append(record)
            continue

        if _metadata_diff_is_build_stamped(
            source_relative, source_raw, artifact_raw
        ):
            expected_records.append(record)
            expected_paths.add(artifact_relative)
        else:
            retained_records.append(record)

    if not expected_records:
        return summary, findings, status

    summary["same_path_modified"] = retained_records
    summary["expected_build_stamp_differences"] = sorted(
        expected_records, key=lambda item: _record_path(item).casefold()
    )
    findings = [
        finding
        for finding in findings
        if not (
            getattr(finding, "rule_id", "") == "SAME_PATH_CONTENT_MISMATCH"
            and str(getattr(finding, "path", "")) in expected_paths
        )
    ]

    generated_count = len(summary.get("generated_or_dependency_differences") or [])
    mismatch_count = len(retained_records)
    status.status = "found_issue" if findings else "passed"
    status.detail = (
        f"compared {int(summary.get('same_path_compared') or 0)} same-path files; "
        f"{mismatch_count} security-relevant mismatches; "
        f"{generated_count} grouped generated/dependency mismatches; "
        f"{len(expected_records)} expected metadata build stamp(s) suppressed"
    )
    return summary, findings, status


def install(core: ModuleType) -> ModuleType:
    """Install exact Decky metadata-build-stamp filtering."""
    if getattr(core, "_metadata_build_stamp_filters_installed", False):
        return core
    if not getattr(core, "_source_content_comparison_installed", False):
        raise RuntimeError("source_content_comparison must be installed first")

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
        return _filter_expected_build_stamps(
            core, extract_dir, summary, findings, status
        )

    core.compare_source_and_artifact = compare_source_and_artifact
    core._metadata_build_stamp_filters_installed = True
    return core
