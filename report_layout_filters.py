"""Make long Markdown audit reports easier to review without hiding risk.

Each plugin report is collapsed behind a summary that still exposes its release,
classification, and risk score. Inside the report, blocking and manual-review
findings stay expanded by default, while repetitive supporting inventories are
collapsed. The JSON report and security classification are untouched.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from types import ModuleType
from typing import Callable


@dataclass(frozen=True)
class _SectionRule:
    heading: str
    icon: str
    open_when_populated: bool = False
    singular: str | None = None
    plural: str | None = None


_SECTION_RULES = (
    _SectionRule(
        "### Blocking Findings",
        "🚫",
        open_when_populated=True,
        singular="finding",
        plural="findings",
    ),
    _SectionRule(
        "### Manual Review Required",
        "🔍",
        open_when_populated=True,
        singular="finding",
        plural="findings",
    ),
    _SectionRule(
        "### Warnings",
        "⚠️",
        singular="warning",
        plural="warnings",
    ),
    _SectionRule(
        "## Root and Privilege Usage",
        "🔐",
        singular="entry",
        plural="entries",
    ),
    _SectionRule(
        "## Network Destinations",
        "🌐",
        singular="destination",
        plural="destinations",
    ),
    _SectionRule(
        "## Included Native Binaries",
        "⚙️",
        singular="binary",
        plural="binaries",
    ),
    _SectionRule("## Archive Statistics", "📦"),
    _SectionRule("## Malware Scan Results", "🛡️"),
    _SectionRule(
        "## Scanner Status",
        "🔬",
        singular="scanner",
        plural="scanners",
    ),
)

_CLASSIFICATION_ICONS = {
    "PASS": "✅",
    "PASS_WITH_WARNINGS": "⚠️",
    "MANUAL_REVIEW": "🔍",
    "BLOCK": "🚫",
    "AUDIT_ERROR": "❌",
}
_PLUGIN_REPORT_MARKER = "<!-- collapsible-plugin-audit-report -->"
_NONE_BODIES = {"*none.*", "_none._", "none."}


def _item_count(body: str) -> int:
    """Count top-level Markdown list items without counting evidence quotes."""
    return len(re.findall(r"(?m)^- ", body))


def _summary_text(rule: _SectionRule, body: str) -> tuple[str, int, bool]:
    count = _item_count(body)
    is_none = body.strip().lower() in _NONE_BODIES
    label = rule.heading.lstrip("#").strip()

    if is_none:
        return f"{rule.icon} {label} — none", count, True
    if rule.singular and count:
        noun = rule.singular if count == 1 else (rule.plural or f"{rule.singular}s")
        return f"{rule.icon} {label} — {count} {noun}", count, False
    return f"{rule.icon} {label}", count, False


def _collapse_section(markdown: str, rule: _SectionRule) -> str:
    level = len(rule.heading) - len(rule.heading.lstrip("#"))
    heading_match = re.search(rf"(?m)^{re.escape(rule.heading)}\s*$", markdown)
    if heading_match is None:
        return markdown

    body_start = heading_match.end()
    if body_start < len(markdown) and markdown[body_start] == "\n":
        body_start += 1

    next_heading = re.search(
        rf"(?m)^#{{1,{level}}}\s+.+$",
        markdown[body_start:],
    )
    body_end = (
        body_start + next_heading.start()
        if next_heading is not None
        else len(markdown)
    )
    body = markdown[body_start:body_end].strip("\n")
    summary, count, is_none = _summary_text(rule, body)
    open_attr = (
        " open"
        if rule.open_when_populated and count > 0 and not is_none
        else ""
    )

    replacement = (
        f"<details{open_attr}>\n"
        f"<summary>{summary}</summary>\n\n"
        f"{body}\n\n"
        "</details>\n\n"
    )
    return (
        markdown[: heading_match.start()]
        + replacement
        + markdown[body_end:].lstrip("\n")
    )


def apply_collapsible_report_layout(markdown: str) -> str:
    """Collapse repetitive report sections while keeping risk visible by default."""
    rendered = markdown
    for rule in _SECTION_RULES:
        rendered = _collapse_section(rendered, rule)
    return rendered


def _report_value(report: object, name: str, default: object = "") -> object:
    if isinstance(report, dict):
        return report.get(name, default)
    return getattr(report, name, default)


def _plugin_summary(report: object) -> str:
    plugin_name = (
        _report_value(report, "plugin_name")
        or _report_value(report, "repository")
        or "Unknown plugin"
    )
    release = _report_value(report, "release") or "unknown release"
    classification = str(
        _report_value(report, "final_classification") or "UNKNOWN"
    )
    risk_score = _report_value(report, "risk_score", 0)
    icon = _CLASSIFICATION_ICONS.get(classification, "❓")

    return (
        f"{icon} <strong>{html.escape(str(plugin_name))}</strong>"
        f" — <code>{html.escape(str(release))}</code>"
        f" — <strong>{html.escape(classification)}</strong>"
        f" — risk {html.escape(str(risk_score))}"
    )


def wrap_collapsible_plugin_report(markdown: str, report: object) -> str:
    """Wrap one rendered plugin report in a collapsed top-level details block."""
    stripped = markdown.strip()
    if stripped.startswith(_PLUGIN_REPORT_MARKER):
        return markdown

    return (
        f"{_PLUGIN_REPORT_MARKER}\n"
        "<details>\n"
        f"<summary>{_plugin_summary(report)}</summary>\n\n"
        f"{stripped}\n\n"
        "</details>\n"
    )


def install(core: ModuleType) -> ModuleType:
    """Install the Markdown-only layout transformation."""
    if getattr(core, "_report_layout_filters_installed", False):
        return core

    raw_generate_markdown: Callable[[object], str] = core.generate_markdown_report

    def generate_markdown_report(report: object) -> str:
        rendered = apply_collapsible_report_layout(raw_generate_markdown(report))
        return wrap_collapsible_plugin_report(rendered, report)

    core._generate_markdown_report_without_layout = raw_generate_markdown
    core.generate_markdown_report = generate_markdown_report
    core.apply_collapsible_report_layout = apply_collapsible_report_layout
    core.wrap_collapsible_plugin_report = wrap_collapsible_plugin_report
    core._report_layout_filters_installed = True
    return core
