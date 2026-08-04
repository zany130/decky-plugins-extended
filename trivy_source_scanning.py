"""Exact-release source dependency scanning for Trivy.

Adapted from Beallio's implementation in
beallio/decky-plugins-extended@f98f5974d5963d7dc08568b30d1a7a728eee15a9.

Decky release ZIPs commonly omit dependency lockfiles. The core Trivy scan of
only the packaged artifact can therefore complete successfully while resolving
no dependencies. This module keeps the artifact scan and adds a second scan of
the repository source at the release tag's exact resolved commit.

Repository code is never executed: the source tarball is downloaded, validated,
and copied as regular files only. Symlinks and other special members are skipped.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable

_SOURCE_SCAN_CACHE_VERSION = "trivy-source-v1"
_CURRENT_SOURCE: ContextVar[dict[str, Any] | None] = ContextVar(
    "decky_trivy_source", default=None
)


def _resolve_ref_to_commit_sha(core: ModuleType, owner: str, repo: str, ref: str) -> str:
    """Resolve an exact release ref to the immutable commit it identifies."""
    try:
        ref_data = core._gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{ref}"
        )
        obj = (ref_data or {}).get("object") or {}
        obj_type = obj.get("type")
        obj_sha = obj.get("sha")
        if obj_type == "tag" and obj_sha:
            tag_data = core._gh_get(
                f"https://api.github.com/repos/{owner}/{repo}/git/tags/{obj_sha}"
            )
            target = (tag_data or {}).get("object") or {}
            if target.get("type") != "commit" or not target.get("sha"):
                raise ValueError(f"Annotated tag {ref!r} does not point to a commit")
            return str(target["sha"])
        if obj_type == "commit" and obj_sha:
            return str(obj_sha)
        raise ValueError(f"Unsupported tag target for {ref!r}")
    except Exception as exc:
        response = getattr(exc, "response", None)
        if getattr(response, "status_code", None) != 404:
            raise

    # Defensive fallback for direct commit refs or unusual GitHub tag resolution.
    commit_data = core._gh_get(
        f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"
    )
    commit_sha = (commit_data or {}).get("sha")
    if not commit_sha:
        raise ValueError(f"Could not resolve {owner}/{repo}@{ref} to a commit")
    return str(commit_sha)


def _download_source_archive(
    core: ModuleType,
    owner: str,
    repo: str,
    commit_sha: str,
    destination: Path,
    max_bytes: int,
) -> None:
    """Download an immutable GitHub source archive without executing code."""
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{commit_sha}"
    downloaded = 0
    with core._gh_session.get(
        url, stream=True, timeout=core.DOWNLOAD_TIMEOUT
    ) as response:
        response.raise_for_status()
        with destination.open("wb") as archive_file:
            for chunk in response.iter_content(65536):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise ValueError("Source archive exceeds maximum download size")
                archive_file.write(chunk)


def _extract_source_archive(
    core: ModuleType,
    archive_path: Path,
    destination: Path,
    policy: dict[str, Any],
) -> str:
    """Safely materialize regular files from a GitHub source tarball."""
    limits = policy.get("archive", {})
    max_files = int(limits.get("max_files", 10000))
    max_total = int(limits.get("max_uncompressed_bytes", 1073741824))
    max_single = int(limits.get("max_single_file_bytes", 536870912))
    max_depth = int(limits.get("max_path_depth", 30))

    extracted_path = destination / "extracted"
    extracted_path.mkdir(parents=True, exist_ok=True)
    file_count = 0
    total_size = 0
    top_levels: set[str] = set()
    seen_paths: set[str] = set()

    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            safe, reason = core._is_safe_member_path(member.name)
            if not safe:
                raise ValueError(
                    f"Unsafe source archive member {member.name!r}: {reason}"
                )

            relative = PurePosixPath(member.name)
            if not relative.parts:
                continue
            if len(relative.parts) > max_depth:
                raise ValueError(f"Source archive path too deep: {member.name}")
            top_levels.add(relative.parts[0])
            relative_key = relative.as_posix()
            target = extracted_path.joinpath(*relative.parts)

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                # Git symlinks and special files are unnecessary for lockfile scans.
                continue

            if relative_key in seen_paths:
                raise ValueError(f"Duplicate source archive member: {member.name}")
            seen_paths.add(relative_key)

            file_count += 1
            total_size += member.size
            if file_count > max_files:
                raise ValueError("Source archive exceeds maximum file count")
            if member.size > max_single:
                raise ValueError(f"Source archive member too large: {member.name}")
            if total_size > max_total:
                raise ValueError("Source archive exceeds maximum uncompressed size")

            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Could not read source archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)

    if file_count == 0:
        raise ValueError("Source archive contains no regular files")
    if len(top_levels) == 1:
        source_root = extracted_path / next(iter(top_levels))
        if source_root.is_dir():
            return str(source_root)
    return str(extracted_path)


def _fetch_source_tree(
    core: ModuleType,
    owner: str,
    repo: str,
    commit_sha: str,
    destination: str,
    policy: dict[str, Any],
) -> str:
    """Download and safely extract the exact-commit source tree."""
    destination_path = Path(destination)
    destination_path.mkdir(parents=True, exist_ok=True)
    archive_path = destination_path / "source.tar.gz"
    max_download = int(
        policy.get("archive", {}).get("max_uncompressed_bytes", 1073741824)
    )
    _download_source_archive(
        core, owner, repo, commit_sha, archive_path, max_download
    )
    return _extract_source_archive(core, archive_path, destination_path, policy)


def _scope_finding(finding: Any, scope: str) -> Any:
    path = str(getattr(finding, "path", "") or "dependency manifest")
    message = str(getattr(finding, "message", ""))
    if not message.startswith(f"[{scope}]"):
        message = f"[{scope}] {message}"
    return replace(finding, path=f"{scope}:{path}", message=message)


def _merge_scoped_findings(artifact: list[Any], source: list[Any]) -> list[Any]:
    """Deduplicate the same vulnerability when both trees report it."""
    merged: dict[tuple[str, str], Any] = {}
    scopes: dict[tuple[str, str], set[str]] = {}
    order: list[tuple[str, str]] = []

    for scope, findings in (("artifact", artifact), ("source", source)):
        for raw in findings:
            finding = _scope_finding(raw, scope)
            key = (
                str(getattr(finding, "rule_id", "")),
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
        finding_scopes = scopes[key]
        if finding_scopes == {"artifact", "source"}:
            path = str(getattr(finding, "path", ""))
            _, _, unscoped = path.partition(":")
            message = str(getattr(finding, "message", ""))
            if message.startswith("[artifact] "):
                message = "[artifact+source] " + message[len("[artifact] "):]
            finding = replace(
                finding,
                path=f"artifact+source:{unscoped}",
                message=message,
            )
        output.append(finding)
    return output


def _status_name(status: Any) -> str:
    return str(getattr(status, "status", ""))


def _combine_statuses(
    core: ModuleType,
    artifact_status: Any,
    source_status: Any,
    artifact_count: int,
    source_count: int,
) -> Any:
    statuses = {_status_name(artifact_status), _status_name(source_status)}
    detail = (
        f"artifact scanned ({artifact_count} findings); "
        f"source scanned ({source_count} findings)"
    )
    source_detail = getattr(source_status, "detail", None)
    artifact_detail = getattr(artifact_status, "detail", None)
    extras = [d for d in (artifact_detail, source_detail) if d]
    if extras:
        detail += "; " + "; ".join(dict.fromkeys(extras))

    if "failed" in statuses:
        combined = "failed"
    elif "unavailable" in statuses:
        combined = "unavailable"
    elif artifact_count or source_count or "found_issue" in statuses:
        combined = "found_issue"
    elif "skipped" in statuses:
        combined = "skipped"
    else:
        combined = "passed"
    return core.ScannerStatus(name="trivy", status=combined, detail=detail)


def install(core: ModuleType) -> ModuleType:
    """Install exact-source Trivy scanning into the modular auditor."""
    if getattr(core, "_trivy_source_scanning_installed", False):
        return core

    raw_run_trivy: Callable[..., tuple[Any, list[Any]]] = core.run_trivy
    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_find_best_release: Callable[..., Any] = core.find_best_release
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
            f"{policy_version}+{_SOURCE_SCAN_CACHE_VERSION}",
        )

    def find_best_release(releases: list[dict[str, Any]]) -> Any:
        release = raw_find_best_release(releases)
        context = _CURRENT_SOURCE.get()
        if context is None:
            return release
        if release is None:
            context["error"] = "source resolution failed: no eligible release"
            return release

        tag_name = str(release.get("tag_name") or "")
        if not tag_name:
            context["error"] = "source resolution failed: release has no tag name"
            return release
        try:
            context["commit_sha"] = _resolve_ref_to_commit_sha(
                core,
                str(context["owner"]),
                str(context["repo"]),
                tag_name,
            )
        except Exception as exc:
            context["error"] = f"source resolution failed: {exc}"
        return release

    def run_trivy(
        extract_dir: str, policy: dict[str, Any]
    ) -> tuple[Any, list[Any]]:
        context = _CURRENT_SOURCE.get()
        artifact_status, artifact_findings = raw_run_trivy(extract_dir, policy)

        if context is None or _status_name(artifact_status) in {"skipped", "unavailable"}:
            return artifact_status, artifact_findings

        error = context.get("error")
        commit_sha = context.get("commit_sha")
        if error or not commit_sha:
            scoped = [_scope_finding(f, "artifact") for f in artifact_findings]
            return (
                core.ScannerStatus(
                    name="trivy",
                    status="failed",
                    detail=(
                        f"artifact scanned ({len(artifact_findings)} findings); "
                        f"{error or 'source commit was not resolved'}"
                    ),
                ),
                scoped,
            )

        with tempfile.TemporaryDirectory(prefix="decky-source-") as source_temp:
            try:
                source_root = _fetch_source_tree(
                    core,
                    str(context["owner"]),
                    str(context["repo"]),
                    str(commit_sha),
                    source_temp,
                    policy,
                )
            except Exception as exc:
                scoped = [_scope_finding(f, "artifact") for f in artifact_findings]
                return (
                    core.ScannerStatus(
                        name="trivy",
                        status="failed",
                        detail=(
                            f"artifact scanned ({len(artifact_findings)} findings); "
                            f"source fetch failed: {exc}"
                        ),
                    ),
                    scoped,
                )
            source_status, source_findings = raw_run_trivy(source_root, policy)

        findings = _merge_scoped_findings(artifact_findings, source_findings)
        status = _combine_statuses(
            core,
            artifact_status,
            source_status,
            len(artifact_findings),
            len(source_findings),
        )
        return status, findings

    def audit_repository(
        repo_url: str,
        policy: dict[str, Any],
        exceptions: list[dict[str, Any]],
        cache_dir: str = core.CACHE_DIR,
        skip_cache: bool = False,
    ) -> Any:
        try:
            owner, repo = core.parse_owner_repo(repo_url)
            context: dict[str, Any] = {
                "owner": owner,
                "repo": repo,
                "commit_sha": None,
                "error": None,
            }
        except Exception as exc:
            context = {
                "owner": None,
                "repo": None,
                "commit_sha": None,
                "error": f"source resolution failed: {exc}",
            }

        token = _CURRENT_SOURCE.set(context)
        try:
            return raw_audit_repository(
                repo_url,
                policy,
                exceptions,
                cache_dir=cache_dir,
                skip_cache=skip_cache,
            )
        finally:
            _CURRENT_SOURCE.reset(token)

    core._raw_run_trivy_artifact_only = raw_run_trivy
    core._raw_audit_repository_without_source_trivy = raw_audit_repository
    core._raw_find_best_release_without_source_resolution = raw_find_best_release
    core._cache_key = cache_key
    core.find_best_release = find_best_release
    core.run_trivy = run_trivy
    core.audit_repository = audit_repository
    core._trivy_source_scanning_installed = True
    return core
