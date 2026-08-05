"""Exact-source Semgrep review assistance for Decky plugin releases.

The initial Decky-focused review categories were inspired by
beallio/decky-plugins-extended@f98f5974d5963d7dc08568b30d1a7a728eee15a9.
The checked-in rules are independently implemented and use only the local
``semgrep-rules.yml`` with metrics and version checks disabled.

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
    "repository_tooling",
}
_TOOLING_DIRS = {"scripts", "tools", "tooling", "build", "dev"}
_TOOLING_FILE_RE = re.compile(
    r"^(?:(?:package|build|release|publish|bundle)|dev(?:_[a-z0-9_-]+)?)"
    r"\.(?:js|mjs|cjs|ts|mts|cts|py|sh)$",
    re.IGNORECASE,
)
_CONFIG_TOOLING_FILE_RE = re.compile(
    r"^(?:vite|webpack|rollup|esbuild|babel|eslint|prettier)\.config\."
    r"(?:js|mjs|cjs|ts|mts|cts)$",
    re.IGNORECASE,
)
_PRIVATE_KEY_CODE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".rs",
    ".ts",
    ".tsx",
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


def _classify_semgrep_path(path: str) -> tuple[str, str]:
    """Classify runtime ownership, including common repository-only tooling."""
    provenance, confidence = network_provenance.classify_network_source(path)
    normalized = _normalise_path(path).casefold()
    parts = PurePosixPath(normalized).parts
    name = parts[-1] if parts else ""
    parent_parts = set(parts[:-1])

    if provenance == "plugin_runtime" and (
        _CONFIG_TOOLING_FILE_RE.match(name)
        or (
            parent_parts.intersection(_TOOLING_DIRS)
            and _TOOLING_FILE_RE.match(name)
        )
    ):
        return "repository_tooling", "high"
    return provenance, confidence


def _rule_id(check_id: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", check_id.upper()).strip("_")
    return "SEMGREP_" + (normalized or "UNKNOWN")[:80]


def _canonical_path(path: str) -> str:
    candidates = source_content._artifact_candidates(path)
    return (candidates[-1] if candidates else _normalise_path(path)).casefold()


def _result_evidence(
    core: ModuleType,
    result: dict[str, Any],
    scan_root: str,
    relative_path: str,
) -> str:
    """Read matched source locally because Semgrep OSS redacts ``extra.lines``."""
    extra = result.get("extra") or {}
    semgrep_lines = str(extra.get("lines") or "").strip()
    if semgrep_lines and semgrep_lines.casefold() != "requires login":
        return core._truncate(semgrep_lines, core.EVIDENCE_MAX_LEN)

    root = Path(scan_root).resolve()
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return "[matched code unavailable]"

    start = result.get("start") or {}
    end = result.get("end") or {}
    start_line = max(1, int(start.get("line") or 1))
    end_line = max(start_line, int(end.get("line") or start_line))
    # Keep evidence focused and bounded even for unusually large Semgrep ranges.
    selected = lines[start_line - 1 : min(end_line, start_line + 4)]
    evidence = "\n".join(line.strip() for line in selected).strip()
    return core._truncate(evidence or "[matched code unavailable]", core.EVIDENCE_MAX_LEN)


def _result_to_finding(
    core: ModuleType,
    result: dict[str, Any],
    scan_root: str,
    scope: str,
) -> tuple[Any | None, str]:
    check_id = str(result.get("check_id") or "unknown")
    path = _relative_result_path(str(result.get("path") or ""), scan_root)
    provenance, path_confidence = _classify_semgrep_path(path)

    # AST behavior in dependencies, tests, repository tooling, maps, and metadata
    # is not evidence of plugin-owned runtime behavior. Header-only key constants
    # in source code are also handled more accurately by the dedicated credential
    # scanner, which validates complete key material and redacts it.
    if provenance in _SUPPRESSED_CODE_PROVENANCE:
        return None, provenance
    if (
        check_id == "decky.generic.private-key"
        and PurePosixPath(path.casefold()).suffix in _PRIVATE_KEY_CODE_SUFFIXES
    ):
        return None, "credential_scanner_owned"

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

    if check_id == "decky.generic.private-key":
        evidence = "[private-key material redacted]"
    else:
        evidence = _result_evidence(core, result, scan_root, path)
    start = result.get("start") or {}
    finding = core.Finding(
        rule_id=_rule_id(check_id),
        severity=severity,
        classification=classification,
        path=path,
        line=int(start.get("line") or 0),
        message=message,
        evidence=evidence,
        scanner="semgrep",
    )
    return finding, provenance


def _error_detail(error: dict[str, Any]) -> str:
    for key in ("message", "type", "level"):
        value = str(error.get(key) or "").strip()
        if value:
            return value
    return "parse or target error"


def _parse_error_findings(
    core: ModuleType,
    errors: Any,
    scan_root: str,
    scope: str,
) -> tuple[list[Any], int]:
    if not isinstance(errors, list) or not errors:
        return [], 0

    reportable: list[tuple[str, int, str]] = []
    suppressed = 0
    for error in errors:
        if not isinstance(error, dict):
            continue
        raw_path = str(error.get("path") or "")
        if not raw_path:
            reportable.append(("", 0, _error_detail(error)))
            continue
        path = _relative_result_path(raw_path, scan_root)
        provenance, _confidence = _classify_semgrep_path(path)
        if provenance in _SUPPRESSED_CODE_PROVENANCE:
            suppressed += 1
            continue
        location = error.get("location") or {}
        start = location.get("start") if isinstance(location, dict) else {}
        line = int((start or {}).get("line") or 0)
        reportable.append((path, line, _error_detail(error)))

    if not reportable:
        return [], suppressed

    unique: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for entry in reportable:
        if entry not in seen:
            seen.add(entry)
            unique.append(entry)

    sample_paths = [path for path, _line, _detail in unique if path]
    sample = ", ".join(sample_paths[:5]) or "scanner-level error"
    first_detail = unique[0][2]
    evidence = f"{sample}; first error: {first_detail}"
    return [
        core.Finding(
            rule_id="SEMGREP_PARTIAL_SCAN",
            severity="low",
            classification="PASS_WITH_WARNINGS",
            path=unique[0][0],
            line=unique[0][1],
            message=(
                f"[{scope}] Semgrep could not fully analyze {len(unique)} "
                "plugin-owned target(s); review coverage is incomplete."
            ),
            evidence=core._truncate(evidence, core.EVIDENCE_MAX_LEN),
            scanner="semgrep",
        )
    ], suppressed


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
    parse_findings, parse_suppressed = _parse_error_findings(
        core, data.get("errors") or [], scan_root, scope
    )
    findings.extend(parse_findings)
    suppressed += parse_suppressed

    status = "found_issue" if findings else "passed"
    detail = (
        f"{scope} scanned ({len(findings)} report findings; "
        f"{suppressed} non-runtime or redundant matches suppressed)"
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
            rule_id = str(getattr(finding, "rule_id", ""))
            evidence = str(getattr(finding, "evidence", ""))
            # Artifact wrapper paths make partial-scan evidence text differ even
            # when both scopes refer to the same underlying file.
            evidence_key = "" if rule_id == "SEMGREP_PARTIAL_SCAN" else evidence
            key = (
                rule_id,
                _canonical_path(str(getattr(finding, "path", "") or "")),
                int(getattr(finding, "line", 0) or 0),
                evidence_key,
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
            if str(getattr(finding, "rule_id", "")) == "SEMGREP_PARTIAL_SCAN":
                message = re.sub(
                    r"^\[(?:artifact|source)\]",
                    "[artifact+source]",
                    message,
                )
            else:
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
