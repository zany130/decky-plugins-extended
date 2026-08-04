"""Precise network-destination extraction with source provenance.

The audit scans packaged runtime code, generated bundles, dependency trees,
documentation, tests, source maps, and build metadata. A flat host list makes
all of those references look equally important. This module preserves the
legacy destination inventory while also recording where each reference came
from and how strongly it suggests actual plugin network behavior.
"""

from __future__ import annotations

import ipaddress
import re
from contextvars import ContextVar
from dataclasses import field, make_dataclass
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable
from urllib.parse import urlsplit

_NETWORK_PROVENANCE_CACHE_VERSION = "network-provenance-v1"

_URL_PATTERN = re.compile(
    r"\b(?:https?|wss?)://[^\s\"'<>\[\]{}|\\^`]+",
    re.IGNORECASE,
)
_IPV4_CANDIDATE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_NUMERIC_DOTTED_HOST = re.compile(r"^[0-9.]+$")
_NETWORK_CONTEXT = re.compile(
    r"(?:"
    r"\b(?:host(?:name)?|server|endpoint|address|addr|proxy|gateway|dns|"
    r"remote|origin|socket|connect|bind|listen|ip(?:v[46])?)\b"
    r"|\b(?:base|api|remote|proxy|server)[_-]?url\b"
    r"|\b(?:dns[_-]servers?|name[_-]servers?|host[_-]ip|server[_-]ip|ip[_-](?:address|addr))\b"
    r"|--(?:host|hostname|server|bind|listen|address|proxy|dns)\b"
    r")",
    re.IGNORECASE,
)
_VERSION_CONTEXT = re.compile(
    r"\b(?:version|semver|release|revision|dependency|package)\b",
    re.IGNORECASE,
)
_NETWORK_OPERATION_CONTEXT = re.compile(
    r"\b(?:connect|bind|listen|socket|endpoint|address|proxy|gateway|dns)\b",
    re.IGNORECASE,
)
_LOCAL_SINGLE_LABEL_HOSTS = {"localhost"}
_MAX_RAW_IP_LINE_LENGTH = 2000
_CONTEXT_RADIUS = 120
_TRAILING_URL_PUNCTUATION = ".,;!?)]}'\""

_DOCUMENTATION_OR_TEST_PARTS = {
    "doc", "docs", "documentation", "example", "examples", "fixture",
    "fixtures", "test", "tests", "__tests__", "spec", "specs", ".github",
}
_DEPENDENCY_PARTS = {
    "node_modules", "site-packages", "vendor", "vendors",
    "third_party", "third-party", "deps", "dependencies", ".venv", "venv",
}
_GENERATED_RUNTIME_PARTS = {
    "dist", "build", "out", ".next", ".vite", ".webpack", "bundle", "bundles",
}
_DOCUMENTATION_NAMES = {
    "readme", "readme.md", "readme.rst", "changelog", "changelog.md",
    "license", "license.md", "notice", "notice.md", "contributing.md",
    "code_of_conduct.md", "security.md",
}
_BUILD_METADATA_NAMES = {
    "package.json", "plugin.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "uv.lock",
    "poetry.lock", "pdm.lock", "pipfile.lock", "requirements.txt",
    "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "tsconfig.json", "rollup.config.js", "rollup.config.mjs", "vite.config.js",
    "vite.config.ts", "webpack.config.js",
}
_MINIFIED_OR_CHUNKED = re.compile(
    r"(?:\.min\.(?:js|css)$|(?:^|[._-])(?:chunk|bundle|vendor)(?:[._-]|$)|"
    r"[._-][0-9a-f]{8,}\.(?:js|css)$)",
    re.IGNORECASE,
)
_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_PROVENANCE_LABELS = {
    "plugin_runtime": "plugin runtime",
    "generated_runtime_bundle": "generated runtime bundle",
    "dependency_or_vendored": "dependency or vendored code",
    "documentation_or_test": "documentation, test, or example",
    "source_map_or_build_metadata": "source map or build metadata",
}

_CURRENT_FILE: ContextVar[dict[str, Any] | None] = ContextVar(
    "decky_network_current_file", default=None
)
_CURRENT_REFERENCES: ContextVar[list[dict[str, Any]] | None] = ContextVar(
    "decky_network_references", default=None
)


def _normalise_host(host: str) -> str | None:
    candidate = host.strip().rstrip(".")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    # A dotted numeric value that is not accepted by ipaddress is not a domain.
    if _NUMERIC_DOTTED_HOST.fullmatch(candidate):
        return None

    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None

    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None

    if len(labels) == 1 and ascii_host not in _LOCAL_SINGLE_LABEL_HOSTS:
        return None

    return ascii_host


def _format_destination(host: str, port: int | None) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{rendered_host}:{port}" if port is not None else rendered_host


def _parse_url(raw_url: str) -> tuple[str, str, str] | None:
    url = raw_url.rstrip(_TRAILING_URL_PUNCTUATION)
    try:
        parsed = urlsplit(url)
        host = _normalise_host(parsed.hostname or "")
        if host is None:
            return None
        port = parsed.port
    except (ValueError, UnicodeError):
        return None

    destination = _format_destination(host, port)
    # Reports preserve only the normalized origin. Userinfo, paths, queries,
    # and fragments may contain credentials or opaque tokens and are not needed
    # to establish destination provenance.
    report_url = f"{parsed.scheme.lower()}://{destination}"
    return url, destination, report_url


def _overlaps(span: tuple[int, int], other_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(
        start < other_end and end > other_start
        for other_start, other_end in other_spans
    )


def _raw_ip_has_network_context(line: str, start: int, end: int) -> bool:
    if len(line) > _MAX_RAW_IP_LINE_LENGTH:
        return False
    window = line[
        max(0, start - _CONTEXT_RADIUS): min(len(line), end + _CONTEXT_RADIUS)
    ]
    if not _NETWORK_CONTEXT.search(window):
        return False
    if _VERSION_CONTEXT.search(window) and not _NETWORK_OPERATION_CONTEXT.search(window):
        return False
    return True


def extract_network_references(content: str) -> list[dict[str, Any]]:
    """Return every validated network reference with its source line.

    Repeated occurrences are retained here. Aggregation happens later so the
    report can distinguish corroboration across files from repetition inside a
    single generated bundle.
    """
    references: list[dict[str, Any]] = []
    lines = content.splitlines() or [content]

    for line_number, line in enumerate(lines, start=1):
        url_spans: list[tuple[int, int]] = []
        for match in _URL_PATTERN.finditer(line):
            parsed = _parse_url(match.group(0))
            url_spans.append(match.span())
            if parsed is None:
                continue
            url, destination, report_url = parsed
            references.append({
                "destination": destination,
                "url": url,
                "report_url": report_url,
                "line": line_number,
                "kind": "url",
            })

        for match in _IPV4_CANDIDATE.finditer(line):
            if _overlaps(match.span(), url_spans):
                continue
            if not _raw_ip_has_network_context(line, *match.span()):
                continue
            try:
                ip = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if ip.version == 4:
                references.append({
                    "destination": str(ip),
                    "url": None,
                    "line": line_number,
                    "kind": "raw_ip",
                })

    return references


def extract_urls_and_domains(content: str) -> tuple[list[str], list[str]]:
    """Return unique URLs and normalized destinations from text content."""
    urls: list[str] = []
    seen_urls: set[str] = set()
    destinations: set[str] = set()

    for reference in extract_network_references(content):
        url = reference.get("url")
        if isinstance(url, str) and url not in seen_urls:
            urls.append(url)
            seen_urls.add(url)
        destinations.add(str(reference["destination"]))

    return urls, sorted(destinations)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _packaged_python_provenance(parts: list[str]) -> tuple[str, str] | None:
    """Distinguish a plugin's own package from dependencies in py_modules."""
    try:
        index = parts.index("py_modules")
    except ValueError:
        return None

    if index + 1 >= len(parts):
        return "dependency_or_vendored", "low"
    package = parts[index + 1]
    wrapper = parts[0] if index > 0 else ""
    if wrapper and _slug(package) == _slug(wrapper):
        return "plugin_runtime", "high"
    return "dependency_or_vendored", "low"


def classify_network_source(path: str) -> tuple[str, str]:
    """Classify a packaged path and return ``(provenance, confidence)``."""
    normalized = path.replace("\\", "/").lstrip("./")
    pure = PurePosixPath(normalized)
    parts = [part.casefold() for part in pure.parts]
    directories = set(parts[:-1])
    name = pure.name.casefold()

    # Path ownership takes precedence over a file's basename. For example,
    # node_modules/pkg/README.md is dependency evidence, not plugin docs.
    if name.endswith(".map"):
        return "source_map_or_build_metadata", "low"
    packaged_python = _packaged_python_provenance(parts)
    if packaged_python is not None:
        return packaged_python
    if directories & _DEPENDENCY_PARTS:
        return "dependency_or_vendored", "low"
    if directories & _DOCUMENTATION_OR_TEST_PARTS or name in _DOCUMENTATION_NAMES:
        return "documentation_or_test", "low"
    if name in _BUILD_METADATA_NAMES:
        return "source_map_or_build_metadata", "low"
    if directories & _GENERATED_RUNTIME_PARTS or _MINIFIED_OR_CHUNKED.search(name):
        return "generated_runtime_bundle", "medium"
    return "plugin_runtime", "high"


def _aggregate_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_destination: dict[str, list[dict[str, Any]]] = {}
    for reference in references:
        destination = str(reference.get("destination") or "")
        if destination:
            by_destination.setdefault(destination, []).append(reference)

    aggregated: list[dict[str, Any]] = []
    for destination, items in by_destination.items():
        unique_sources: list[dict[str, Any]] = []
        seen_sources: set[tuple[Any, ...]] = set()
        for item in sorted(
            items,
            key=lambda value: (
                str(value.get("path") or "").casefold(),
                int(value.get("line") or 0),
                str(value.get("report_url") or value.get("url") or ""),
            ),
        ):
            source = {
                "path": str(item.get("path") or ""),
                "line": int(item.get("line") or 0),
                "provenance": str(item.get("provenance") or "plugin_runtime"),
                "confidence": str(item.get("confidence") or "high"),
                "kind": str(item.get("kind") or "url"),
                "url": item.get("report_url") or item.get("url"),
            }
            key = (
                source["path"],
                source["line"],
                source["provenance"],
                source["kind"],
                source["url"],
            )
            if key not in seen_sources:
                unique_sources.append(source)
                seen_sources.add(key)

        provenances = {source["provenance"] for source in unique_sources}
        distinct_paths = {
            source["path"] for source in unique_sources if source["path"]
        }
        if "plugin_runtime" in provenances:
            confidence = "high"
            reason = "referenced by plugin-owned runtime code"
        elif "generated_runtime_bundle" in provenances:
            confidence = "medium"
            reason = "referenced by a generated runtime bundle"
        elif len(distinct_paths) >= 2:
            confidence = "medium"
            reason = "corroborated by multiple lower-confidence files"
        else:
            confidence = "low"
            reason = "reference-only or dependency/build evidence"

        priority = {
            "high": "primary",
            "medium": "supporting",
            "low": "inventory",
        }[confidence]
        aggregated.append({
            "destination": destination,
            "confidence": confidence,
            "review_priority": priority,
            "reason": reason,
            "source_count": len(unique_sources),
            "sources": unique_sources,
        })

    return sorted(
        aggregated,
        key=lambda item: (
            -_CONFIDENCE_RANK.get(str(item.get("confidence")), 0),
            str(item.get("destination")).casefold(),
        ),
    )


def _summarize_destinations(destinations: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    occurrences = 0
    for destination in destinations:
        confidence = str(destination.get("confidence") or "low")
        counts[confidence] = counts.get(confidence, 0) + 1
        occurrences += int(destination.get("source_count") or 0)
    return {
        "total_destinations": len(destinations),
        "high_confidence": counts.get("high", 0),
        "medium_confidence": counts.get("medium", 0),
        "low_confidence": counts.get("low", 0),
        "source_occurrences": occurrences,
    }


def _render_network_section(
    destinations: list[dict[str, Any]],
    summary: dict[str, Any],
) -> str:
    lines = [
        "## Network Destinations",
        "",
        (
            f"**{summary.get('total_destinations', 0)} destinations:** "
            f"{summary.get('high_confidence', 0)} high-confidence runtime, "
            f"{summary.get('medium_confidence', 0)} supporting, "
            f"{summary.get('low_confidence', 0)} inventory-only."
        ),
        "",
    ]

    labels = {
        "high": "High-confidence runtime destinations",
        "medium": "Supporting or corroborated destinations",
        "low": "Reference-only inventory",
    }
    caps = {"high": 50, "medium": 35, "low": 25}

    for confidence in ("high", "medium", "low"):
        group = [
            item for item in destinations
            if item.get("confidence") == confidence
        ]
        if not group:
            continue
        lines.extend([f"### {labels[confidence]}", ""])
        for item in group[: caps[confidence]]:
            sources = item.get("sources") or []
            rendered_sources: list[str] = []
            for source in sources[:3]:
                provenance = _PROVENANCE_LABELS.get(
                    str(source.get("provenance")),
                    str(source.get("provenance")),
                )
                rendered_sources.append(
                    f"`{source.get('path')}:{source.get('line')}` ({provenance})"
                )
            suffix = f"; +{len(sources) - 3} more" if len(sources) > 3 else ""
            evidence = "; ".join(rendered_sources) + suffix
            lines.append(
                f"- **`{item.get('destination')}`** — {item.get('reason')}. "
                f"{evidence}"
            )
        if len(group) > caps[confidence]:
            lines.append(
                f"- _{len(group) - caps[confidence]} additional {confidence}-confidence "
                "destinations are preserved in the JSON report._"
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def _replace_network_section(markdown: str, replacement: str) -> str:
    match = re.search(
        r"(?ms)^## Network Destinations\s*\n.*?(?=^##\s+|\Z)",
        markdown,
    )
    if match is None:
        return markdown
    return (
        markdown[: match.start()]
        + replacement
        + "\n\n"
        + markdown[match.end():].lstrip("\n")
    )


def install(core: ModuleType) -> ModuleType:
    """Install precise extraction and per-file destination provenance."""
    if getattr(core, "_network_destination_filters_installed", False):
        return core

    base_report = core.AuditReport
    if "network_destinations" not in getattr(base_report, "__dataclass_fields__", {}):
        provenance_report = make_dataclass(
            "AuditReport",
            [
                (
                    "network_destinations",
                    list[dict[str, Any]],
                    field(default_factory=list),
                ),
                (
                    "network_destination_summary",
                    dict[str, Any],
                    field(default_factory=dict),
                ),
            ],
            bases=(base_report,),
        )
        provenance_report.__module__ = base_report.__module__
        core.AuditReport = provenance_report

    original_scan_text: Callable[..., Any] = core.scan_text_content
    original_audit_repository: Callable[..., Any] = core.audit_repository
    original_generate_markdown: Callable[[Any], str] = core.generate_markdown_report
    original_cache_key: Callable[..., str] = core._cache_key

    def scan_text_content(content: str, path: str, ext: str) -> Any:
        provenance, confidence = classify_network_source(path)
        _CURRENT_FILE.set({
            "path": path.replace("\\", "/"),
            "ext": ext,
            "provenance": provenance,
            "confidence": confidence,
        })
        return original_scan_text(content, path, ext)

    def extract_with_provenance(content: str) -> tuple[list[str], list[str]]:
        references = extract_network_references(content)
        collector = _CURRENT_REFERENCES.get()
        current_file = _CURRENT_FILE.get()
        if collector is not None and current_file is not None:
            for reference in references:
                collector.append({**reference, **current_file})

        urls: list[str] = []
        seen_urls: set[str] = set()
        destinations: set[str] = set()
        for reference in references:
            url = reference.get("url")
            if isinstance(url, str) and url not in seen_urls:
                urls.append(url)
                seen_urls.add(url)
            destinations.add(str(reference["destination"]))
        return urls, sorted(destinations)

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        references: list[dict[str, Any]] = []
        references_token = _CURRENT_REFERENCES.set(references)
        file_token = _CURRENT_FILE.set(None)
        try:
            report = original_audit_repository(*args, **kwargs)
            # Cache hits return an already-populated report without walking
            # files in this invocation. Preserve that stored provenance.
            if references:
                aggregated = _aggregate_references(references)
                report.network_destinations = aggregated
                report.network_destination_summary = _summarize_destinations(
                    aggregated
                )
                report.extracted_domains = [
                    str(item["destination"]) for item in aggregated
                ]
            elif not getattr(report, "network_destinations", None):
                report.network_destinations = []
                report.network_destination_summary = _summarize_destinations([])
            return report
        finally:
            _CURRENT_FILE.reset(file_token)
            _CURRENT_REFERENCES.reset(references_token)

    def generate_markdown_report(report: Any) -> str:
        rendered = original_generate_markdown(report)
        destinations = list(getattr(report, "network_destinations", []) or [])
        if not destinations:
            return rendered
        summary = dict(
            getattr(report, "network_destination_summary", {}) or {}
        )
        return _replace_network_section(
            rendered,
            _render_network_section(destinations, summary),
        )

    def cache_key(
        repository: str,
        release_id: str,
        artifact_sha256: str,
        policy_version: str = core.POLICY_VERSION,
    ) -> str:
        return original_cache_key(
            repository,
            release_id,
            artifact_sha256,
            f"{policy_version}|{_NETWORK_PROVENANCE_CACHE_VERSION}",
        )

    core.scan_text_content = scan_text_content
    core.extract_urls_and_domains = extract_with_provenance
    core.extract_network_references = extract_network_references
    core.classify_network_source = classify_network_source
    core.aggregate_network_references = _aggregate_references
    core.summarize_network_destinations = _summarize_destinations
    core.audit_repository = audit_repository
    core.generate_markdown_report = generate_markdown_report
    core._cache_key = cache_key
    core._network_destination_filters_installed = True
    return core
