"""Make Semgrep source links honest about artifact/source identity.

Semgrep scans two scopes: the shipped release artifact and the exact tagged
source. A source-scope hit can link directly to its tagged line. An artifact-only
hit may use that line only when same-path contents were verified identical;
otherwise the report links to the tagged file without claiming that the
artifact line is exact.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any, Callable

import upstream_source_links as source_links


def _semgrep_source_scope(finding: Any) -> bool:
    message = str(getattr(finding, "message", "") or "")
    return message.startswith("[source;") or message.startswith("[artifact+source;")


def _harden_report(report: Any) -> list[tuple[Any, str]]:
    """Harden Semgrep finding links and return their pre-change URLs."""
    comparison = getattr(report, "source_artifact_diff", None) or {}
    comparison_checked = bool(comparison.get("checked"))
    differing_paths = source_links._source_difference_paths(report)
    changed: list[tuple[Any, str]] = []

    for finding in getattr(report, "findings", []) or []:
        if str(getattr(finding, "scanner", "") or "") != "semgrep":
            continue

        finding.source_line_exact = False
        if hasattr(finding, "source_note"):
            delattr(finding, "source_note")

        line = int(getattr(finding, "line", 0) or 0)
        status = str(getattr(finding, "source_status", "") or "")
        source_url = str(getattr(finding, "source_url", "") or "")

        # A finding emitted by the exact-source scan is already anchored to the
        # tagged source tree. An artifact+source finding also has direct tagged
        # evidence even when the packaged file was transformed.
        if _semgrep_source_scope(finding):
            finding.source_line_exact = status == "linked" and line > 0
            continue

        if status != "linked" or not source_url:
            continue

        artifact_path = str(getattr(finding, "path", "") or "")
        path_differs = bool(
            source_links._path_keys(artifact_path) & differing_paths
        )
        if comparison_checked and not path_differs:
            finding.source_line_exact = line > 0
            continue

        previous_url = source_url
        finding.source_url = source_url.split("#L", 1)[0]
        finding.source_status = "file-only"
        finding.source_line_exact = False
        if path_differs:
            finding.source_note = (
                "release contents differ from tagged source; artifact line is not exact"
            )
        else:
            finding.source_note = (
                "same-path source contents were not verified; artifact line is not exact"
            )
        changed.append((finding, previous_url))

    return changed


def _inject_semgrep_link_fields(report: Any, data: dict[str, Any]) -> dict[str, Any]:
    serialized = data.get("findings") or []
    for finding, finding_data in zip(
        getattr(report, "findings", []) or [], serialized
    ):
        if str(getattr(finding, "scanner", "") or "") != "semgrep":
            continue
        finding_data["source_line_exact"] = bool(
            getattr(finding, "source_line_exact", False)
        )
        note = str(getattr(finding, "source_note", "") or "")
        if note:
            finding_data["source_note"] = note
    return data


def _fix_markdown_links(
    report: Any,
    markdown: str,
    changed: list[tuple[Any, str]],
) -> str:
    changed_by_id = {id(finding): old_url for finding, old_url in changed}
    for finding in getattr(report, "findings", []) or []:
        if str(getattr(finding, "scanner", "") or "") != "semgrep":
            continue
        if str(getattr(finding, "source_status", "") or "") != "file-only":
            continue

        new_url = str(getattr(finding, "source_url", "") or "")
        if not new_url:
            continue
        old_url = changed_by_id.get(id(finding), new_url)
        note = str(
            getattr(finding, "source_note", "")
            or "tagged source file linked; artifact line is not exact"
        )
        old_fragment = f"([View upstream code]({old_url}))"
        replacement = f"([View tagged source file]({new_url})) _({note})_"
        if old_fragment in markdown:
            markdown = markdown.replace(old_fragment, replacement, 1)
            continue

        # The report may have been hardened before Markdown rendering, in which
        # case the shared source-link layer used the already de-anchored URL.
        current_fragment = f"([View upstream code]({new_url}))"
        markdown = markdown.replace(current_fragment, replacement, 1)
    return markdown


def install(core: ModuleType) -> ModuleType:
    """Install Semgrep-specific source-link identity hardening."""
    if getattr(core, "_semgrep_source_link_hardening_installed", False):
        return core
    if not getattr(core, "_upstream_source_links_installed", False):
        raise RuntimeError("upstream_source_links must be installed first")

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_report_to_dict: Callable[[Any], dict[str, Any]] = core._report_to_dict
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        _harden_report(report)
        return report

    def report_to_dict(report: Any) -> dict[str, Any]:
        if not getattr(report, "_source_links_enriched", False):
            core.enrich_report_source_links(report)
        _harden_report(report)
        data = raw_report_to_dict(report)
        return _inject_semgrep_link_fields(report, data)

    def generate_markdown_report(report: Any) -> str:
        markdown = raw_generate_markdown(report)
        changed = _harden_report(report)
        return _fix_markdown_links(report, markdown, changed)

    core.audit_repository = audit_repository
    core._report_to_dict = report_to_dict
    core.generate_markdown_report = generate_markdown_report
    core._semgrep_source_link_hardening_installed = True
    return core
