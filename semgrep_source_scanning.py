"""Exact-source Semgrep review assistance for Decky plugin releases.

The local rules and baseline invocation are adapted from
beallio/decky-plugins-extended@f98f5974d5963d7dc08568b30d1a7a728eee15a9.
Unlike the old ``--config auto`` implementation, this module uses only the
checked-in ``semgrep-rules.yml`` with metrics and version checks disabled.

Both the safely extracted release artifact and the exact immutable tagged source
snapshot are scanned. Plugin code is parsed only; it is never imported, built,
installed, or executed. Semgrep findings are capped at MANUAL_REVIEW while the
ruleset's false-positive rate is being measured.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable

import network_destination_filters as network_provenance
import source_content_comparison as source_content

_SEMGREP_CACHE_VERSION = "decky-semgrep-v1"
_SEMGREP_RULES_FILE = str(Path(__file__).with_name("semgrep-rules.yml"))

_SEVERITY_MAP: dict[str, tuple[str, str]] = {
    "error": ("high", "MANUAL_REVIEW"),
    "warning": ("medium", "MANUAL_REVIEW"),
    "info": ("info", "PASS_WITH_WARNINGS"),
}
_SUPPRESSED_CODE_PROVENANCE = {
    "dependency_or_vendored",
    "documentation_or_test",
    "source_map_or_build_metadata",
}
_REVIEWER_GUIDANCE = {
    "decky.python.dynamic-execution": (
        "Confirm the executed value cannot be influenced by frontend/RPC input, "
        "network responses, configuration, or other mutable plugin data."
    ),
    "decky.python.shell-command": (
        "Confirm shell=True is necessary and every command component is fixed or "
        "strictly validated."
    ),
    "decky.javascript.dynamic-execution": (
        "Confirm the evaluated value cannot be influenced by remote or user-controlled "
        "content."
    ),
    "decky.javascript.child-process-exec": (
        "Confirm the command is expected plugin behavior and cannot be influenced by "
        "frontend, RPC, network, or configuration input."
    ),
    "decky.generic.private-key": (
        "Confirm this is non-secret test material; remove and rotate it if it is a "
        "real credential."
    ),
}


def _normalise_path(path: str) -> str:
    value = path.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return PurePosixPath(value).as_posix() if value else ""


def _relative_result_path(raw_path: str, scan_root: str) -> str:
    """Return a stable path relative to the scanned tree."""
    raw = _normalise_path(str(raw_path or ""))
    root = Path(scan_root).resolve()
    candidate = Path(raw_path)

    try:
        if candidate.is_absolute():
            return candidate.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        pass

    # Semgrep normally returns a path relative to the current working directory.
    # Find the shortest suffix that exists below the scan root before falling back.
    parts = PurePosixPath(raw).parts
    for index in range(len(parts)):
        suffix = PurePosixPath(*parts[index:]).as_posix()
        target = root.joinpath(*PurePosixPath(suffix).parts)
        if target.is_file():
            return suffix
    return raw


def _rule_id(check_id: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", check_id.upper()).strip("_")
    return "SEMGREP_" + (normalized or "UNKNOWN")[:80]


def _canonical_path(path: str) -> str:
    candidates = source_content._artifact_candidates(path)
    return (candidates[-1] if candidates else _normalise_path(path)).casefold()


def _result_to_finding(
    core: ModuleType,
    result: dict[str, Any],
    scan_root: str,
    scope: str,
) -> tuple[Any | None, str]:
    check_id = str(result.get("check_id") or "unknown")
    path = _relative_result_path(str(result.get("path") or ""), scan_root)
    provenance, path_confidence = network_provenance.classify_network_source(path)

    # AST findings in dependencies, tests, documentation, maps, and metadata are
    # not evidence of plugin-owned runtime behavior. Private-key material remains
    # visible wherever it is shipped because location does not make a real key safe.
    if (
        check_id != "decky.generic.private-key"
        and provenance in _SUPPRESSED_CODE_PROVENANCE
    ):
        return None, provenance

    extra = result.get("extra") or {}
    raw_severity = str(extra.get("severity") or "INFO").strip().lower()
    severity, classification = _SEVERITY_MAP.get(
        raw_severity, ("high", "MANUAL_REVIEW")
    )
    # No Semgrep rule may auto-block in this observation PR.
    if classification == "BLOCK":
        classification = "MANUAL_REVIEW"

    message = str(extra.get("message") or "Semgrep review finding").strip()
    guidance = _REVIEWER_GUIDANCE.get(check_id)
    if guidance:
        message = f"{message} Reviewer focus: {guidance}"
    message = f"[{scope}; {provenance}; confidence={path_confidence}] {message}"

    evidence = str(extra.get("lines") or "").strip()
    start = result.get("start") or {}
    finding = core.Finding(
        rule_id=_rule_id(check_id),
        severity=severity,
        classification=classification,
        path=path,
        line=int(start.get("line") or 0),
        message=message,
        evidence=core._truncate(evidence, core.EVIDENCE_MAX_LEN),
        scanner="semgrep",
    )
    return finding, provenance


def _parse_error_findings(
    core: ModuleType,
    errors: Any,
    scan_root: str,
    scope: str,
) -> list[Any]:
    if not isinstance(errors, list) or not errors:
        return []

    paths: list[str] = []
    for error in errors:
        if not isinstance(error, dict):
            continue
        raw_path = str(error.get("path") or "")
        if raw_path:
            paths.append(_relative_result_path(raw_path, scan_root))
    unique_paths = list(dict.fromkeys(paths))
    sample = ", ".join(unique_paths[:5]) if unique_paths else "see scanner detail"
    return [
        core.Finding(
            rule_id="SEMGREP_PARTIAL_SCAN",
            severity="low",
            classification="PASS_WITH_WARNINGS",
            path=unique_paths[0] if unique_paths else "",
            line=0,
            message=(
                f"[{scope}] Semgrep reported {len(errors)} parse or target errors; "
                "some code may not have been analyzed."
            ),
            evidence=core._truncate(sample, core.EVIDENCE_MAX_LEN),
            scanner="semgrep",
        )
    ]


def _run_scope(
    core: ModuleType,
    scan_root: str,
    scope: str,
) -> tuple[Any, list[Any], int]:
    if not shutil.which("semgrep"):
        return (
            core.ScannerStatus(
                name="semgrep",
                status="unavailable",
                detail="semgrep executable not found",
            ),
            [],
            0,
        )
    if not os.path.isfile(_SEMGREP_RULES_FILE):
        return (
            core.ScannerStatus(
                name="semgrep",
                status="failed",
                detail=f"local rules file not found: {_SEMGREP_RULES_FILE}",
            ),
            [],
            0,
        )

    _ok, stdout, stderr = core._run_scanner(
        [
            "semgrep",
            "--config",
            _SEMGREP_RULES_FILE,
            "--json",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            "--exclude",
            "node_modules",
            "--exclude",
            ".venv",
            "--exclude",
            "venv",
            "--exclude",
            "__pycache__",
            "--exclude",
            "*.map",
            "--exclude",
            "*.min.js",
            scan_root,
        ],
        "semgrep",
        timeout=300,
    )

    if not stdout.strip():
        detail = stderr[:500] if stderr else "no output"
        return core.ScannerStatus(name="semgrep", status="failed", detail=detail), [], 0

    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return (
            core.ScannerStatus(
                name="semgrep", status="failed", detail=f"JSON parse error: {exc}"
            ),
            [],
            0,
        )

    findings: list[Any] = []
    suppressed = 0
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        finding, _provenance = _result_to_finding(core, result, scan_root, scope)
        if finding is None:
            suppressed += 1
        else:
            findings.append(finding)
    findings.extend(
        _parse_error_findings(core, data.get("errors") or [], scan_root, scope)
    )

    status = "found_issue" if findings else "passed"
    detail = (
        f"{scope} scanned ({len(findings)} report findings; "
        f"{suppressed} dependency/test/metadata matches suppressed)"
    )
    return (
        core.ScannerStatus(
            name="semgrep",
            status=status,
            version=str(data.get("version") or "") or None,
            detail=detail,
        ),
        findings,
        suppressed,
    )


def _merge_scoped_findings(artifact: list[Any], source: list[Any]) -> list[Any]:
    """Deduplicate equivalent artifact/source hits while retaining scope."""
    merged: dict[tuple[str, str, int, str], Any] = {}
    scopes: dict[tuple[str, str, int, str], set[str]] = {}
    order: list[tuple[str, str, int, str]] = []

    for scope, findings in (("artifact", artifact), ("source", source)):
        for finding in findings:
            key = (
                str(getattr(finding, "rule_id", "")),
                _canonical_path(str(getattr(finding, "path", "") or "")),
                int(getattr(finding, "line", 0) or 0),
                str(getattr(finding, "evidence", "")),
            )
            if key not in merged:
                merged[key] = finding
                scopes[key] = {scope}
                order.append(key)
            else:
                scopes[key].add(scope)

    output: list[Any] = []
    for key in order:
        finding = merged[key]
        if scopes[key] == {"artifact", "source"}:
            message = str(getattr(finding, "message", ""))
            message = re.sub(
                r"^\[(?:artifact|source);",
                "[artifact+source;",
                message,
            )
            finding = replace(finding, message=message)
        output.append(finding)
    return output


def _combine_statuses(
    core: ModuleType,
    artifact_status: Any,
    source_status: Any,
    finding_count: int,
) -> Any:
    statuses = {
        str(getattr(artifact_status, "status", "")),
        str(getattr(source_status, "status", "")),
    }
    if "failed" in statuses:
        status = "failed"
    elif "unavailable" in statuses:
        status = "unavailable"
    elif finding_count or "found_issue" in statuses:
        status = "found_issue"
    elif "skipped" in statuses:
        status = "skipped"
    else:
        status = "passed"

    details = [
        str(getattr(artifact_status, "detail", "") or "artifact status unavailable"),
        str(getattr(source_status, "detail", "") or "source status unavailable"),
    ]
    versions = [
        str(getattr(artifact_status, "version", "") or ""),
        str(getattr(source_status, "version", "") or ""),
    ]
    return core.ScannerStatus(
        name="semgrep",
        status=status,
        version=next((value for value in versions if value), None),
        detail="; ".join(dict.fromkeys(details)),
    )


def install(core: ModuleType) -> ModuleType:
    """Install local-rule artifact and exact-source Semgrep scanning."""
    if getattr(core, "_semgrep_source_scanning_installed", False):
        return core
    if not getattr(core, "_source_content_comparison_installed", False):
        raise RuntimeError("source_content_comparison must be installed first")

    raw_run_semgrep: Callable[..., tuple[Any, list[Any]]] = core.run_semgrep
    raw_cache_key: Callable[..., str] = core._cache_key

    def cache_key(
        repository: str,
        release_id: str,
        artifact_sha256: str,
        policy_version: str = core.POLICY_VERSION,
    ) -> str:
        return raw_cache_key(
            repository,
            release_id,
            artifact_sha256,
            f"{policy_version}+{_SEMGREP_CACHE_VERSION}",
        )

    def run_semgrep(
        extract_dir: str,
        policy: dict[str, Any],
    ) -> tuple[Any, list[Any]]:
        if not core._scanner_enabled(policy, "semgrep"):
            return core.ScannerStatus(name="semgrep", status="skipped"), []

        artifact_status, artifact_findings, _artifact_suppressed = _run_scope(
            core, extract_dir, "artifact"
        )

        shared = source_content._CURRENT_SHARED_SOURCE.get()
        if shared is None:
            # Preserve useful artifact-only behavior for direct callers/tests.
            return artifact_status, artifact_findings

        try:
            source_root = source_content._ensure_shared_source(core)
        except Exception as exc:
            return (
                core.ScannerStatus(
                    name="semgrep",
                    status="failed",
                    version=getattr(artifact_status, "version", None),
                    detail=(
                        f"artifact scanned ({len(artifact_findings)} findings); "
                        f"exact source unavailable: {exc}"
                    ),
                ),
                artifact_findings,
            )

        source_status, source_findings, _source_suppressed = _run_scope(
            core, source_root, "source"
        )
        findings = _merge_scoped_findings(artifact_findings, source_findings)
        status = _combine_statuses(
            core, artifact_status, source_status, len(findings)
        )
        return status, findings

    core._raw_run_semgrep_registry_auto = raw_run_semgrep
    core._cache_key = cache_key
    core.run_semgrep = run_semgrep
    core._semgrep_source_scanning_installed = True
    return core
