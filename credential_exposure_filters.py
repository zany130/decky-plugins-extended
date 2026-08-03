"""Credential-exposure policy for the Decky plugin security audit.

The scanner still reports plausible leaked credentials, but credential exposure is
kept separate from malware classification. Generic names such as ``token`` or
``api_key`` only produce findings when assigned a plausible hard-coded literal.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any


_GITHUB_TOKEN = re.compile(
    r"\b(?:ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"
)
_AWS_ACCESS_KEY_ID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----"
    r"(?P<body>.*?)"
    r"-----END (?P=kind)-----",
    re.DOTALL,
)

_QUOTED_VALUE = r"(?P<quote>['\"])(?P<value>[^'\"\r\n]+)(?P=quote)"
_GENERIC_ASSIGNMENTS: tuple[tuple[str, re.Pattern[str], int, bool], ...] = (
    (
        "generic_api_key",
        re.compile(
            rf"(?i)(?:['\"]?\b(?:api[_-]?key|apikey|api_secret)\b['\"]?)"
            rf"\s*(?:=|:)\s*{_QUOTED_VALUE}"
        ),
        16,
        True,
    ),
    (
        "bearer_token",
        re.compile(
            rf"(?i)(?:['\"]?\b(?:bearer_token|access_token|auth_token|token)\b['\"]?)"
            rf"\s*(?:=|:)\s*{_QUOTED_VALUE}"
        ),
        20,
        True,
    ),
    (
        "cloudflare_token",
        re.compile(
            rf"(?i)(?:['\"]?\b(?:cf[-_](?:token|key|api)|cloudflare[_-]?(?:token|key))\b['\"]?)"
            rf"\s*(?:=|:)\s*{_QUOTED_VALUE}"
        ),
        20,
        True,
    ),
    (
        "password_literal",
        re.compile(
            rf"(?i)(?:['\"]?\bpassword\b['\"]?)\s*(?:=|:)\s*{_QUOTED_VALUE}"
        ),
        8,
        False,
    ),
)

_BEARER_HEADER = re.compile(
    r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+\-/]{20,}={0,2})"
)

_SUPPRESSED_PARTS = {
    "node_modules",
    "vendor",
    "vendors",
    "third_party",
    "site-packages",
    "py_modules",
    "__pycache__",
    ".venv",
    "venv",
    "fixtures",
}
_GENERATED_SUFFIXES = (
    ".map",
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".bundle.js",
    ".bundle.mjs",
    ".bundle.cjs",
)

_PLACEHOLDER_EXACT = {
    "changeme",
    "change_me",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "insert_here",
    "replace_me",
    "not_a_real_secret",
}
_PLACEHOLDER_PREFIXES = (
    "your_",
    "example_",
    "dummy_",
    "fake_",
    "sample_",
    "test_",
    "placeholder_",
    "replace_",
    "insert_",
)
_FIXTURE_MARKERS = (
    "test fixture",
    "example",
    "placeholder",
    "dummy",
    "fake",
    "mock",
    "not a real",
    "todo",
    "fixme",
)
_FIXTURE_PATH_PARTS = {"test", "tests", "example", "examples", "fixture", "fixtures"}


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _normalised_path(path: str) -> PurePosixPath:
    return PurePosixPath(path.replace("\\", "/"))


def _suppress_generic_patterns(path: str) -> bool:
    parsed = _normalised_path(path)
    parts = {part.lower() for part in parsed.parts}
    name = parsed.name.lower()
    if parts & _SUPPRESSED_PARTS:
        return True
    if name.endswith(_GENERATED_SUFFIXES):
        return True
    if "dist" in parts and parsed.suffix.lower() in {".js", ".mjs", ".cjs"}:
        return True
    return False


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    low = stripped.lower()
    if not stripped:
        return True
    if low in _PLACEHOLDER_EXACT or low.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if stripped.startswith("${") or stripped.startswith("{{") or stripped.startswith("<"):
        return True
    if "process.env" in low or "os.environ" in low or "getenv(" in low:
        return True
    alnum = re.sub(r"[^A-Za-z0-9]", "", stripped)
    if alnum and len(set(alnum.lower())) <= 2:
        return True
    if re.fullmatch(r"[xX*._-]{8,}", stripped):
        return True
    return False


def _plausible_literal(value: str, min_length: int, require_entropy: bool) -> bool:
    if len(value) < min_length or _is_placeholder(value):
        return False
    if require_entropy and _entropy(value) < 3.0:
        return False
    return True


def _looks_like_fixture(path: str, context: str, value: str = "") -> bool:
    parsed = _normalised_path(path)
    parts = {part.lower() for part in parsed.parts}
    name = parsed.name.lower()
    low_context = context.lower()
    return (
        bool(parts & _FIXTURE_PATH_PARTS)
        or name.startswith(("test_", "example_", "mock_"))
        or any(marker in low_context for marker in _FIXTURE_MARKERS)
        or (bool(value) and _is_placeholder(value))
    )


def _finding(
    core: Any,
    *,
    rule_id: str,
    severity: str,
    classification: str,
    path: str,
    line: int,
    message: str,
):
    return core.Finding(
        rule_id=rule_id,
        severity=severity,
        classification=classification,
        path=path,
        line=line,
        message=message,
        evidence=f"[credential pattern matched] {core.SECRET_REDACT}",
        scanner="credential-exposure-scanner",
    )


def _append_unique(findings: list[Any], seen: set[tuple[str, int]], finding: Any) -> None:
    key = (finding.rule_id, finding.line)
    if key not in seen:
        findings.append(finding)
        seen.add(key)


def scan_for_credentials(core: Any, content: str, path: str) -> list[Any]:
    """Return credential-exposure findings without classifying them as malware."""

    findings: list[Any] = []
    seen: set[tuple[str, int]] = set()
    lines = content.splitlines()

    # Provider-specific tokens remain active even in generated or vendored files.
    for match in _GITHUB_TOKEN.finditer(content):
        line_no = _line_number(content, match.start())
        line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        fixture = _looks_like_fixture(path, line, match.group(0))
        _append_unique(
            findings,
            seen,
            _finding(
                core,
                rule_id="SECRET_GITHUB_TOKEN",
                severity="low" if fixture else "high",
                classification="MANUAL_REVIEW",
                path=path,
                line=line_no,
                message=(
                    "Potential hard-coded GitHub token detected (redacted). "
                    "This indicates possible credential exposure, not malware."
                ),
            ),
        )

    for match in _AWS_ACCESS_KEY_ID.finditer(content):
        line_no = _line_number(content, match.start())
        _append_unique(
            findings,
            seen,
            _finding(
                core,
                rule_id="SECRET_AWS_KEY",
                severity="medium",
                classification="PASS_WITH_WARNINGS",
                path=path,
                line=line_no,
                message=(
                    "Potential AWS access-key identifier detected (redacted). "
                    "The identifier alone is not a credential; verify that no paired secret leaked."
                ),
            ),
        )

    complete_key_ranges: list[tuple[int, int]] = []
    for match in _PRIVATE_KEY_BLOCK.finditer(content):
        body = re.sub(r"\s+", "", match.group("body"))
        if len(body) < 64 or not re.fullmatch(r"[A-Za-z0-9+/=]+", body):
            continue
        complete_key_ranges.append(match.span())
        line_no = _line_number(content, match.start())
        context = content[match.start(): match.end()]
        fixture = _looks_like_fixture(path, context)
        _append_unique(
            findings,
            seen,
            _finding(
                core,
                rule_id="SECRET_PRIVATE_KEY",
                severity="low" if fixture else "high",
                classification="MANUAL_REVIEW",
                path=path,
                line=line_no,
                message=(
                    "Complete private-key block detected (redacted). "
                    "Review and rotate it if real; this is not evidence of malware."
                ),
            ),
        )

    # Preserve a low-severity signal for a lone header, but do not treat it as a key.
    for match in _PRIVATE_KEY_HEADER.finditer(content):
        if any(start <= match.start() < end for start, end in complete_key_ranges):
            continue
        line_no = _line_number(content, match.start())
        _append_unique(
            findings,
            seen,
            _finding(
                core,
                rule_id="SECRET_PRIVATE_KEY_HEADER",
                severity="low",
                classification="PASS_WITH_WARNINGS",
                path=path,
                line=line_no,
                message=(
                    "Private-key header text detected without a complete plausible key block. "
                    "This may be documentation or library code."
                ),
            ),
        )

    if _suppress_generic_patterns(path):
        return findings

    for lineno, line in enumerate(lines, start=1):
        for name, pattern, min_length, require_entropy in _GENERIC_ASSIGNMENTS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group("value").strip()
            if not _plausible_literal(value, min_length, require_entropy):
                continue
            fixture = _looks_like_fixture(path, line, value)
            classification = "PASS_WITH_WARNINGS"
            severity = "low" if fixture or name != "cloudflare_token" else "medium"
            _append_unique(
                findings,
                seen,
                _finding(
                    core,
                    rule_id="SECRET_" + name.upper(),
                    severity=severity,
                    classification=classification,
                    path=path,
                    line=lineno,
                    message=(
                        f"Potential hard-coded {name.replace('_', ' ')} detected (redacted). "
                        "Review as credential exposure; it does not indicate malicious behavior."
                    ),
                ),
            )

        bearer = _BEARER_HEADER.search(line)
        if bearer:
            value = bearer.group("value")
            if (
                not _GITHUB_TOKEN.fullmatch(value)
                and not _AWS_ACCESS_KEY_ID.fullmatch(value)
                and _plausible_literal(value, 20, True)
            ):
                _append_unique(
                    findings,
                    seen,
                    _finding(
                        core,
                        rule_id="SECRET_BEARER_TOKEN",
                        severity="low",
                        classification="PASS_WITH_WARNINGS",
                        path=path,
                        line=lineno,
                        message=(
                            "Potential hard-coded bearer token detected (redacted). "
                            "Review as credential exposure; it does not indicate malware."
                        ),
                    ),
                )

    return findings


def install(core: Any) -> None:
    """Install credential-exposure classification onto the core audit module."""
    if getattr(core, "_credential_exposure_policy_installed", False):
        return

    def scan_for_secrets(content: str, path: str) -> list[Any]:
        return scan_for_credentials(core, content, path)

    core.scan_for_secrets = scan_for_secrets
    core._credential_exposure_policy_installed = True
