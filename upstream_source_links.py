"""Attach immutable upstream source links to audit evidence.

Links resolve the audited release tag to an exact commit SHA and only point to
paths that exist in that commit's tree. Release-only/generated evidence is
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
_NETWORK_SECTION = re.compile(
    r"(?ms)^## Network Destinations\s*\n.*?(?=^##\s+|\Z)"
)
_SOURCE_DIFFERENCE_KEYS = (
    "same_path_modified",
    "generated_or_dependency_differences",
    "other_same_path_differences",
    "expected_build_stamp_differences",
)

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


def _path_keys(path: str) -> set[str]:
    """Return normalized artifact-path keys with an optional ZIP wrapper removed."""
    normalised = _normalise_path(path)
    if not normalised:
        return set()
    keys = {normalised.casefold()}
    if "/" in normalised:
        keys.add(normalised.split("/", 1)[1].casefold())
    return keys


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

    commit_sha = ""
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
        # Preserve a successfully resolved commit even when the tree lookup fails.
        result = (commit_sha, {}, str(exc))

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


def _source_url(
    owner: str,
    repo: str,
    commit_sha: str,
    source_path: str,
    line: int = 0,
) -> str:
    encoded_path = quote(source_path, safe="/")
    url = f"https://github.com/{owner}/{repo}/blob/{commit_sha}/{encoded_path}"
    if line > 0:
        url += f"#L{line}"
    return url


def _source_difference_paths(report: Any) -> set[str]:
    """Return normalized artifact paths whose tagged-source contents differ."""
    summary = getattr(report, "source_artifact_diff", None) or {}
    paths: set[str] = set()
    for key in _SOURCE_DIFFERENCE_KEYS:
        for record in summary.get(key) or []:
            if not isinstance(record, dict):
                continue
            paths.update(_path_keys(str(record.get("artifact_path") or "")))
    return paths


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


def _enrich_network_sources(
    report: Any,
    owner: str,
    repo: str,
    commit_sha: str,
    path_map: dict[str, str],
    error: str,
) -> None:
    """Attach commit-pinned source links to network-destination evidence."""
    comparison = getattr(report, "source_artifact_diff", None) or {}
    comparison_checked = bool(comparison.get("checked"))
    differing_paths = _source_difference_paths(report)

    for destination in getattr(report, "network_destinations", []) or []:
        for source in destination.get("sources") or []:
            source["source_path"] = ""
            source["source_url"] = ""
            source["source_commit"] = commit_sha
            source["source_line_exact"] = False
            source.pop("source_note", None)

            artifact_path = str(source.get("path") or "")
            line = int(source.get("line") or 0)
            if not commit_sha:
                source["source_status"] = "unresolved"
                continue
            if error:
                source["source_status"] = "unmapped"
                continue

            source_path = _find_source_path(path_map, artifact_path)
            if not source_path:
                source["source_status"] = "release-only"
                continue

            source["source_path"] = source_path
            path_differs = bool(_path_keys(artifact_path) & differing_paths)
            exact_line = comparison_checked and not path_differs and line > 0
            if exact_line:
                source["source_url"] = _source_url(
                    owner, repo, commit_sha, source_path, line
                )
                source["source_status"] = "linked"
                source["source_line_exact"] = True
                continue

            # A commit-pinned file link is still useful, but an artifact line
            # must not be presented as an exact source line unless same-path
            # contents were verified identical.
            source["source_url"] = _source_url(
                owner, repo, commit_sha, source_path
            )
            source["source_status"] = "file-only"
            if path_differs:
                source["source_note"] = (
                    "release contents differ from tagged source; artifact line is not exact"
                )
            elif not comparison_checked:
                source["source_note"] = (
                    "same-path source contents were not verified; artifact line is not exact"
                )
            else:
                source["source_note"] = "source file linked; no exact line is available"


def enrich_report_source_links(core: ModuleType, report: Any) -> Any:
    """Attach source URL/status attributes to findings and network evidence."""
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
        if error:
            fallback = _unmapped_status(finding)
            finding.source_status = (
                "not-applicable" if fallback == "not-applicable" else "unmapped"
            )
            continue

        source_path = _find_source_path(path_map, str(finding.path or ""))
        if not source_path:
            finding.source_status = _unmapped_status(finding)
            continue

        finding.source_url = _source_url(
            owner,
            repo,
            commit_sha,
            source_path,
            int(getattr(finding, "line", 0) or 0),
        )
        finding.source_path = source_path
        finding.source_status = "linked"

    _enrich_network_sources(
        report,
        owner,
        repo,
        commit_sha,
        path_map,
        error,
    )
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


def _add_finding_markdown_links(core: ModuleType, report: Any, markdown: str) -> str:
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


def _network_source_markdown(source: dict[str, Any]) -> str:
    path = str(source.get("path") or "")
    line = int(source.get("line") or 0)
    label = f"`{path}:{line}`"
    source_url = str(source.get("source_url") or "")
    status = str(source.get("source_status") or "")

    if status == "linked" and source_url:
        return f"[{label}]({source_url})"
    if status == "file-only" and source_url:
        note = str(source.get("source_note") or "upstream file only")
        return f"[{label}]({source_url}) _({note})_"
    if status == "release-only":
        return label + " _(release-only; no tagged-source line)_"
    if status == "unmapped":
        return label + " _(tagged-source path could not be mapped)_"
    if status == "unresolved":
        return label + " _(source commit could not be resolved)_"
    return label


def _add_network_markdown_links(report: Any, markdown: str) -> str:
    match = _NETWORK_SECTION.search(markdown)
    if match is None:
        return markdown

    section = match.group(0)
    # The network renderer shows at most the first three sources per
    # destination. Walk the same order so repeated path:line labels are linked
    # to the correct destination occurrence. Match only plain tokens: the same
    # artifact line can contain multiple destinations and must not be replaced
    # again inside a link created for an earlier destination.
    for destination in getattr(report, "network_destinations", []) or []:
        for source in (destination.get("sources") or [])[:3]:
            path = str(source.get("path") or "")
            line = int(source.get("line") or 0)
            label = f"`{path}:{line}`"
            plain_label = re.compile(rf"(?<!\[){re.escape(label)}")
            replacement = _network_source_markdown(source)
            section = plain_label.sub(
                lambda _match: replacement,
                section,
                count=1,
            )

    return markdown[: match.start()] + section + markdown[match.end():]


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
        markdown = _add_finding_markdown_links(core, report, markdown)
        return _add_network_markdown_links(report, markdown)

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
