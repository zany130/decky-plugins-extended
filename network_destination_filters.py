"""Precision filters for network-destination extraction.

The audit scans packaged source, dependency bundles, and generated JavaScript.
Numeric dotted sequences in lockfiles, source maps, and minified output frequently
look like IPv4 addresses even though they are versions or encoded data. This
module keeps URL hosts and context-backed raw IP literals while rejecting
syntactically invalid or context-free numeric noise.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

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
_CANONICAL_HOST_ALIASES = {
    # GitHub redirects this legacy hostname to its canonical apex host. Keep one
    # review target rather than reporting both spellings as separate services.
    "www.github.com": "github.com",
}
_MAX_RAW_IP_LINE_LENGTH = 2000
_CONTEXT_RADIUS = 120
_TRAILING_URL_PUNCTUATION = ".,;!?)]}'\""


def _normalise_host(host: str) -> str | None:
    candidate = host.strip().rstrip(".")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    # A dotted numeric value that is not accepted by ipaddress is not a domain.
    # This rejects leading-zero and out-of-range pseudo-addresses such as
    # 011.031.025.058 and 999.1.2.3.
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

    # A URL parser accepts single-label names such as http://bar, http://error,
    # and http://myrepo. In packaged test fixtures and dependency documentation,
    # those values are overwhelmingly placeholders rather than destinations.
    # Preserve the one universally meaningful local endpoint while requiring a
    # DNS-style dotted name for all other hostname destinations.
    if len(labels) == 1 and ascii_host not in _LOCAL_SINGLE_LABEL_HOSTS:
        return None

    return _CANONICAL_HOST_ALIASES.get(ascii_host, ascii_host)


def _format_destination(host: str, port: int | None) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{rendered_host}:{port}" if port is not None else rendered_host


def _parse_url(raw_url: str) -> tuple[str, str] | None:
    url = raw_url.rstrip(_TRAILING_URL_PUNCTUATION)
    try:
        parsed = urlsplit(url)
        host = _normalise_host(parsed.hostname or "")
        if host is None:
            return None
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    return url, _format_destination(host, port)


def _overlaps(span: tuple[int, int], other_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < other_end and end > other_start for other_start, other_end in other_spans)


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


def extract_urls_and_domains(content: str) -> tuple[list[str], list[str]]:
    """Return unique URLs and normalized network destinations from text.

    URL destinations are retained when their hosts are valid DNS-style names,
    IP addresses, or localhost. Bare IPv4 literals are retained only when a
    nearby network-related token indicates they are being used as an endpoint.
    This avoids treating placeholders, versions, and random source-map/minified
    numeric sequences as network activity.
    """

    urls: list[str] = []
    seen_urls: set[str] = set()
    destinations: set[str] = set()

    for line in content.splitlines() or [content]:
        url_spans: list[tuple[int, int]] = []
        for match in _URL_PATTERN.finditer(line):
            parsed = _parse_url(match.group(0))
            url_spans.append(match.span())
            if parsed is None:
                continue
            url, destination = parsed
            if url not in seen_urls:
                urls.append(url)
                seen_urls.add(url)
            destinations.add(destination)

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
                destinations.add(str(ip))

    return urls, sorted(destinations)


def install(core: Any) -> Any:
    """Install deterministic, context-aware destination extraction."""

    if getattr(core, "_network_destination_filters_installed", False):
        return core
    core.extract_urls_and_domains = extract_urls_and_domains
    core._network_destination_filters_installed = True
    return core
