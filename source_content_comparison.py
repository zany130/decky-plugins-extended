"""Exact-release same-path source/artifact content comparison.

The existing source/artifact audit detects executable or script files that are
present only in a release ZIP. This layer also hashes security-relevant files
that exist at the same normalized path in both the release artifact and the
exact immutable release source tree.

It shares the source snapshot used by :mod:`trivy_source_scanning`, so the
repository archive is downloaded and safely extracted once per audit. Plugin
code is never built, imported, installed, or executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable

import trivy_source_scanning as tss

_SOURCE_CONTENT_CACHE_VERSION = "source-content-v1"
_CURRENT_SHARED_SOURCE: ContextVar[dict[str, Any] | None] = ContextVar(
    "decky_shared_exact_source", default=None
)

_SCRIPT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".service", ".socket",
    ".timer", ".rules", ".desktop",
}
_METADATA_NAMES = {"plugin.json", "package.json"}
_GENERATED_OR_DEPENDENCY_PARTS = {
    "node_modules", "py_modules", "site-packages", "vendor", "third_party",
    "dist", "build", "out", ".next", ".vite", ".webpack", "__pycache__",
    ".venv", "venv",
}
_MINIFIED_OR_CHUNKED = re.compile(
    r"(?:\.min\.(?:js|css)$|(?:^|[._-])(?:chunk|bundle|vendor)(?:[._-]|$)|"
    r"[._-][0-9a-f]{8,}\.(?:js|css)$)",
    re.IGNORECASE,
)


def _normalize_relative(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    return PurePosixPath(normalized).as_posix()


def _artifact_candidates(path: str) -> list[str]:
    normalized = _normalize_relative(path)
    candidates = [normalized]
    parts = PurePosixPath(normalized).parts
    if len(parts) > 1:
        candidates.append(PurePosixPath(*parts[1:]).as_posix())
    return list(dict.fromkeys(candidates))


def _source_file_index(source_root: str) -> dict[str, tuple[str, str]]:
    root = Path(source_root)
    index: dict[str, tuple[str, str]] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        index.setdefault(relative.casefold(), (relative, str(path)))
    return index


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_generated_or_dependency(path: str) -> bool:
    pure = PurePosixPath(_normalize_relative(path))
    parts = {part.casefold() for part in pure.parts[:-1]}
    name = pure.name.casefold()
    return bool(parts & _GENERATED_OR_DEPENDENCY_PARTS) or name.endswith(".map") or bool(
        _MINIFIED_OR_CHUNKED.search(name)
    )


def _is_security_relevant(core: ModuleType, path: str, raw_prefix: bytes, mode: int) -> bool:
    pure = PurePosixPath(_normalize_relative(path))
    name = pure.name.casefold()
    suffix = pure.suffix.casefold()
    if name in _METADATA_NAMES or suffix in _SCRIPT_EXTENSIONS:
        return True
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return True
    return core.identify_binary(raw_prefix[:16], path) is not None


def _ensure_shared_source(core: ModuleType) -> str:
    shared = _CURRENT_SHARED_SOURCE.get()
    exact = tss._CURRENT_SOURCE.get()
    if shared is None or exact is None:
        raise RuntimeError("exact-release source context is unavailable")
    if shared.get("source_root"):
        return str(shared["source_root"])
    if shared.get("error"):
        raise RuntimeError(str(shared["error"]))

    commit_sha = exact.get("commit_sha")
    error = exact.get("error")
    if error or not commit_sha:
        shared["error"] = error or "source commit was not resolved"
        raise RuntimeError(str(shared["error"]))

    try:
        source_root = tss._fetch_source_tree(
            core,
            str(exact["owner"]),
            str(exact["repo"]),
            str(commit_sha),
            str(shared["temporary_directory"].name),
            dict(shared["policy"]),
        )
    except Exception as exc:
        shared["error"] = f"source fetch failed: {exc}"
        raise RuntimeError(str(shared["error"])) from exc

    shared["source_root"] = source_root
    shared["commit_sha"] = str(commit_sha)
    return str(source_root)


def _run_shared_trivy(
    core: ModuleType,
    raw_run_trivy: Callable[..., tuple[Any, list[Any]]],
    extract_dir: str,
    policy: dict[str, Any],
) -> tuple[Any, list[Any]]:
    artifact_status, artifact_findings = raw_run_trivy(extract_dir, policy)
    exact = tss._CURRENT_SOURCE.get()
    if exact is None or tss._status_name(artifact_status) in {"skipped", "unavailable"}:
        return artifact_status, artifact_findings

    try:
        source_root = _ensure_shared_source(core)
    except Exception as exc:
        scoped = [tss._scope_finding(finding, "artifact") for finding in artifact_findings]
        return (
            core.ScannerStatus(
                name="trivy",
                status="failed",
                detail=f"artifact scanned ({len(artifact_findings)} findings); {exc}",
            ),
            scoped,
        )

    source_status, source_findings = raw_run_trivy(source_root, policy)
    findings = tss._merge_scoped_findings(artifact_findings, source_findings)
    status = tss._combine_statuses(
        core,
        artifact_status,
        source_status,
        len(artifact_findings),
        len(source_findings),
    )
    return status, findings


def _compare_from_local_source(
    core: ModuleType,
    extract_dir: str,
    ref: str,
    source_root: str,
    commit_sha: str | None,
) -> tuple[dict[str, Any], list[Any], Any]:
    summary: dict[str, Any] = {
        "ref": ref,
        "source_commit": commit_sha,
        "checked": True,
        "zip_only_executables": [],
        "zip_only_scripts": [],
        "large_binaries_absent_from_source": [],
        "unexpected_urls": [],
        "same_path_compared": 0,
        "same_path_modified": [],
        "generated_or_dependency_differences": [],
        "other_same_path_differences": [],
    }
    findings: list[Any] = []
    source_index = _source_file_index(source_root)

    for root, _dirs, files in os.walk(extract_dir):
        for filename in files:
            artifact_path = os.path.join(root, filename)
            relative = _normalize_relative(os.path.relpath(artifact_path, extract_dir))
            match: tuple[str, str] | None = None
            for candidate in _artifact_candidates(relative):
                match = source_index.get(candidate.casefold())
                if match:
                    break

            try:
                with open(artifact_path, "rb") as handle:
                    prefix = handle.read(2048)
                mode = os.stat(artifact_path).st_mode
            except OSError:
                continue

            binary = core.identify_binary(prefix[:16], relative)
            if match is None:
                short_path = _artifact_candidates(relative)[-1]
                if binary:
                    summary["zip_only_executables"].append(relative)
                    findings.append(core.Finding(
                        rule_id="ZIP_ONLY_EXECUTABLE",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=relative,
                        line=0,
                        message=(
                            f"Binary file {relative!r} ({binary['label']}) is present "
                            "in the release ZIP but absent from the repository source."
                        ),
                        evidence=binary["label"],
                        scanner="source-artifact-diff",
                    ))
                    continue
                executable_bits = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                if core._looks_like_script_asset(short_path.casefold(), prefix, executable_bits):
                    summary["zip_only_scripts"].append(relative)
                    findings.append(core.Finding(
                        rule_id="ZIP_ONLY_SCRIPT",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=relative,
                        line=0,
                        message=(
                            f"Script-like file {relative!r} is present in the release ZIP "
                            "but absent from the repository source."
                        ),
                        evidence="script-heuristic",
                        scanner="source-artifact-diff",
                    ))
                continue

            source_relative, source_path = match
            summary["same_path_compared"] += 1
            artifact_sha = _sha256_file(artifact_path)
            source_sha = _sha256_file(source_path)
            if artifact_sha == source_sha:
                continue

            record = {
                "artifact_path": relative,
                "source_path": source_relative,
                "artifact_sha256": artifact_sha,
                "source_sha256": source_sha,
            }
            if _is_generated_or_dependency(relative) and binary is None:
                summary["generated_or_dependency_differences"].append(record)
                continue
            if not _is_security_relevant(core, relative, prefix, mode):
                summary["other_same_path_differences"].append(record)
                continue

            summary["same_path_modified"].append(record)
            findings.append(core.Finding(
                rule_id="SAME_PATH_CONTENT_MISMATCH",
                severity="high",
                classification="MANUAL_REVIEW",
                path=relative,
                line=0,
                message=(
                    f"Security-relevant file {relative!r} exists in both the release ZIP "
                    f"and tagged source but has different contents (source: {source_relative!r})."
                ),
                evidence=f"artifact_sha256={artifact_sha}; source_sha256={source_sha}",
                scanner="source-artifact-diff",
            ))

    for key in ("zip_only_executables", "zip_only_scripts"):
        summary[key].sort()
    for key in (
        "same_path_modified",
        "generated_or_dependency_differences",
        "other_same_path_differences",
    ):
        summary[key].sort(key=lambda item: item["artifact_path"].casefold())

    generated = summary["generated_or_dependency_differences"]
    if generated:
        sample = ", ".join(item["artifact_path"] for item in generated[:5])
        findings.append(core.Finding(
            rule_id="GENERATED_SAME_PATH_CONTENT_DIFF",
            severity="low",
            classification="PASS_WITH_WARNINGS",
            path="",
            line=0,
            message=(
                f"{len(generated)} generated, built, vendored, or dependency files differ "
                "from same-path tagged source; grouped for review."
            ),
            evidence=sample,
            scanner="source-artifact-diff",
        ))

    status = "found_issue" if findings else "passed"
    detail = (
        f"compared {summary['same_path_compared']} same-path files; "
        f"{len(summary['same_path_modified'])} security-relevant mismatches; "
        f"{len(generated)} grouped generated/dependency mismatches"
    )
    return summary, findings, core.ScannerStatus(
        name="source-artifact-diff", status=status, detail=detail
    )


def install(core: ModuleType) -> ModuleType:
    """Install shared-source Trivy and same-path content comparison."""
    if getattr(core, "_source_content_comparison_installed", False):
        return core
    if not getattr(core, "_trivy_source_scanning_installed", False):
        raise RuntimeError("trivy_source_scanning must be installed first")

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_compare: Callable[..., tuple[dict[str, Any], list[Any], Any]] = (
        core.compare_source_and_artifact
    )
    raw_cache_key: Callable[..., str] = core._cache_key
    raw_artifact_trivy: Callable[..., tuple[Any, list[Any]]] = (
        core._raw_run_trivy_artifact_only
    )

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
            f"{policy_version}+{_SOURCE_CONTENT_CACHE_VERSION}",
        )

    def run_trivy(
        extract_dir: str, policy: dict[str, Any]
    ) -> tuple[Any, list[Any]]:
        return _run_shared_trivy(core, raw_artifact_trivy, extract_dir, policy)

    def compare_source_and_artifact(
        extract_dir: str,
        owner: str,
        repo: str,
        ref: str,
    ) -> tuple[dict[str, Any], list[Any], Any]:
        shared = _CURRENT_SHARED_SOURCE.get()
        exact = tss._CURRENT_SOURCE.get()
        if shared is None or exact is None:
            return raw_compare(extract_dir, owner, repo, ref)
        try:
            source_root = _ensure_shared_source(core)
        except Exception as exc:
            return (
                {"ref": ref, "checked": False},
                [],
                core.ScannerStatus(
                    name="source-artifact-diff",
                    status="failed",
                    detail=str(exc),
                ),
            )
        return _compare_from_local_source(
            core,
            extract_dir,
            ref,
            source_root,
            str(exact.get("commit_sha") or "") or None,
        )

    def audit_repository(
        repo_url: str,
        policy: dict[str, Any],
        exceptions: list[dict[str, Any]],
        cache_dir: str = core.CACHE_DIR,
        skip_cache: bool = False,
    ) -> Any:
        temporary_directory = tempfile.TemporaryDirectory(prefix="decky-exact-source-")
        shared: dict[str, Any] = {
            "temporary_directory": temporary_directory,
            "source_root": None,
            "commit_sha": None,
            "error": None,
            "policy": policy,
        }
        token = _CURRENT_SHARED_SOURCE.set(shared)
        try:
            return raw_audit_repository(
                repo_url,
                policy,
                exceptions,
                cache_dir=cache_dir,
                skip_cache=skip_cache,
            )
        finally:
            _CURRENT_SHARED_SOURCE.reset(token)
            temporary_directory.cleanup()

    core._raw_compare_source_and_artifact_path_only = raw_compare
    core._cache_key = cache_key
    core.run_trivy = run_trivy
    core.compare_source_and_artifact = compare_source_and_artifact
    core.audit_repository = audit_repository
    core._source_content_comparison_installed = True
    return core
