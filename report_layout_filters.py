"""Make long Markdown audit reports easier to review without hiding risk.

Blocking and manual-review findings stay expanded by default, while repetitive
supporting inventories are collapsed. The JSON report and security classification
are untouched.
"""

from __future__ import annotations

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


def install(core: ModuleType) -> ModuleType:
    """Install the Markdown-only layout transformation."""
    if getattr(core, "_report_layout_filters_installed", False):
        return core

    raw_generate_markdown: Callable[[object], str] = core.generate_markdown_report

    def generate_markdown_report(report: object) -> str:
        return apply_collapsible_report_layout(raw_generate_markdown(report))

    core._generate_markdown_report_without_layout = raw_generate_markdown
    core.generate_markdown_report = generate_markdown_report
    core.apply_collapsible_report_layout = apply_collapsible_report_layout
    core._report_layout_filters_installed = True
    return core
