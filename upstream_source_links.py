"""Attach immutable upstream source links to audit findings.

Links resolve the audited release tag to an exact commit SHA and only point to
paths that exist in that commit's tree. Release-only/generated findings are
explicitly marked instead of receiving a misleading link.
"""

from __future__ import annotations

import re
from types import ModuleType
from typing import Any, Callable
from urllib.parse import quote


_NOT_APPLICABLE_SCANNERS = {
    "trivy",
    "clamav",
    "zip-inspector",
}
_RELEASE_ONLY_PREFIXES = (
    "ZIP_ONLY_",
    "BUNDLED_DEPENDENCY_",
    "GENERATED_BUILD_",
    "VENDORED_",
)
_METADATA_REF_PATH = re.compile(r"^(plugin\.json|package\.json)@.+$", re.IGNORECASE)

# In-memory only; one scheduled run may audit many findings from the same repo.
_SOURCE_TREE_CACHE: dict[
    tuple[str, str, str],
    tuple[str, dict[str, str], str],
] = {}


def _normalise_path(path: str) -> str:
    value = path.replace("\\", "/").strip()
    metadata = _METADATA_REF_PATH.match(value)
    if metadata:
        value = metadata.group(1)
    while value.startswith("./"):
        value = value[2:]
    return value.strip("/")


def _resolve_source_tree(
    core: ModuleType,
    owner: str,
    repo: str,
    ref: str,
) -> tuple[str, dict[str, str], str]:
    """Return (commit SHA, lowercase-path map, error detail)."""
    key = (owner.lower(), repo.lower(), ref)
    cached = _SOURCE_TREE_CACHE.get(key)
    if cached is not None:
        return cached

    try:
        encoded_ref = quote(ref, safe="")
        commit_data = core._gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{encoded_ref}"
        )
        if not isinstance(commit_data, dict) or not commit_data.get("sha"):
            raise ValueError("commit response did not contain a SHA")
        commit_sha = str(commit_data["sha"])
        tree_sha = str(
            ((commit_data.get("commit") or {}).get("tree") or {}).get("sha") or ""
        )
        if not tree_sha:
            raise ValueError("commit response did not contain a tree SHA")

        tree_data = core._gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1"
        )
        if not isinstance(tree_data, dict):
            raise ValueError("tree response was not a mapping")
        if tree_data.get("truncated") is True:
            raise ValueError("GitHub returned a truncated source tree")

        path_map: dict[str, str] = {}
        for item in tree_data.get("tree") or []:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path = str(item.get("path") or "")
            if path:
                path_map[path.lower()] = path

        result = (commit_sha, path_map, "")
    except Exception as exc:  # Link generation must never fail the security audit.
        result = ("", {}, str(exc))

    _SOURCE_TREE_CACHE[key] = result
    return result


def _find_source_path(path_map: dict[str, str], finding_path: str) -> str:
    normalised = _normalise_path(finding_path)
    if not normalised:
        return ""

    candidates = [normalised]
    # Release ZIPs commonly wrap every file in one top-level plugin directory.
    if "/" in normalised:
        candidates.append(normalised.split("/", 1)[1])

    for candidate in candidates:
        actual = path_map.get(candidate.lower())
        if actual:
            return actual
    return ""


def _unmapped_status(finding: Any) -> str:
    path = str(getattr(finding, "path", "") or "")
    rule_id = str(getattr(finding, "rule_id", "") or "")
    scanner = str(getattr(finding, "scanner", "") or "")

    if not path or path.startswith("<") or "," in path:
        return "not-applicable"
    if scanner in _NOT_APPLICABLE_SCANNERS:
        return "not-applicable"
    if rule_id.startswith(_RELEASE_ONLY_PREFIXES) or scanner == "source-artifact-diff":
        return "release-only"
    if scanner in {
        "decky-static-rules",
        "credential-exposure-scanner",
        "secrets-scanner",
        "semgrep",
        "binary-detector",
        "metadata-checker",
    }:
        return "release-only"
    return "unmapped"


def enrich_report_source_links(core: ModuleType, report: Any) -> Any:
    """Attach source URL/status attributes to each finding in ``report``."""
    repository = str(getattr(report, "repository", "") or "")
    ref = str(getattr(report, "release", "") or "")

    try:
        owner, repo = core.parse_owner_repo(repository)
    except Exception as exc:
        owner = repo = ""
        commit_sha, path_map, error = "", {}, str(exc)
    else:
        if ref:
            commit_sha, path_map, error = _resolve_source_tree(
                core, owner, repo, ref
            )
        else:
            commit_sha, path_map, error = "", {}, "release ref is unavailable"

    report.source_commit = commit_sha
    report.source_link_error = error

    for finding in getattr(report, "findings", []):
        finding.source_path = ""
        finding.source_url = ""
        finding.source_commit = commit_sha
        if not commit_sha:
            finding.source_status = "unresolved"
            continue

        source_path = _find_source_path(path_map, str(finding.path or ""))
        if not source_path:
            finding.source_status = _unmapped_status(finding)
            continue

        encoded_path = quote(source_path, safe="/")
        url = f"https://github.com/{owner}/{repo}/blob/{commit_sha}/{encoded_path}"
        if int(getattr(finding, "line", 0) or 0) > 0:
            url += f"#L{int(finding.line)}"

        finding.source_path = source_path
        finding.source_url = url
        finding.source_status = "linked"

    report._source_links_enriched = True
    return report


def _inject_source_fields(report: Any, data: dict[str, Any]) -> dict[str, Any]:
    if not getattr(report, "_source_links_enriched", False):
        return data

    data["source_commit"] = str(getattr(report, "source_commit", "") or "")
    error = str(getattr(report, "source_link_error", "") or "")
    if error:
        data["source_link_error"] = error

    serialized = data.get("findings") or []
    for finding, finding_data in zip(getattr(report, "findings", []), serialized):
        finding_data["source_status"] = str(
            getattr(finding, "source_status", "unresolved")
        )
        finding_data["source_url"] = str(getattr(finding, "source_url", "") or "")
        finding_data["source_commit"] = str(
            getattr(finding, "source_commit", "") or ""
        )
        source_path = str(getattr(finding, "source_path", "") or "")
        if source_path:
            finding_data["source_path"] = source_path
    return data


def _add_markdown_links(core: ModuleType, report: Any, markdown: str) -> str:
    for finding in getattr(report, "findings", []):
        severity_emoji = core._SEVERITY_EMOJI.get(finding.severity, "⚪")
        base = (
            f"- {severity_emoji} **{finding.rule_id}** "
            f"`{finding.path}:{finding.line}` — {finding.message}"
        )
        source_url = str(getattr(finding, "source_url", "") or "")
        status = str(getattr(finding, "source_status", "") or "")
        if source_url:
            replacement = base + f" ([View upstream code]({source_url}))"
        elif status == "release-only":
            replacement = base + " _(release-only file; no upstream source link)_"
        else:
            continue
        markdown = markdown.replace(base, replacement, 1)
    return markdown


def install(core: ModuleType) -> ModuleType:
    """Install source-link enrichment and report serialization hooks."""
    if getattr(core, "_upstream_source_links_installed", False):
        return core

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_report_to_dict: Callable[[Any], dict[str, Any]] = core._report_to_dict
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        return enrich_report_source_links(core, report)

    def report_to_dict(report: Any) -> dict[str, Any]:
        data = raw_report_to_dict(report)
        return _inject_source_fields(report, data)

    def generate_markdown_report(report: Any) -> str:
        if not getattr(report, "_source_links_enriched", False):
            enrich_report_source_links(core, report)
        markdown = raw_generate_markdown(report)
        return _add_markdown_links(core, report, markdown)

    def clear_source_link_cache() -> None:
        _SOURCE_TREE_CACHE.clear()

    core._audit_repository_without_source_links = raw_audit_repository
    core._report_to_dict_without_source_links = raw_report_to_dict
    core._generate_markdown_report_without_source_links = raw_generate_markdown
    core.audit_repository = audit_repository
    core._report_to_dict = report_to_dict
    core.generate_markdown_report = generate_markdown_report
    core.enrich_report_source_links = lambda report: enrich_report_source_links(core, report)
    core.clear_source_link_cache = clear_source_link_cache
    core._upstream_source_links_installed = True
    return core
