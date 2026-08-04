"""Context filters for persistence and encoded-asset static findings.

The core rules intentionally favor recall. This module adds the missing context:
object properties named ``profile`` are not shell startup files, and long base64
strings that decode to common image/font formats are assets rather than hidden
code. Real writes to shell profile files and unknown encoded blobs remain visible.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict, deque
from types import ModuleType
from typing import Callable


# A shell profile target must look like a filesystem filename/path. The negative
# lookbehind excludes JavaScript/Python property access such as snapshot.profile
# and optional chaining such as snapshot?.profile.
_PROFILE_TARGET = re.compile(
    r"(?ix)(?:"
    r"(?<![A-Za-z0-9_$?])\.(?:bashrc|bash_profile|profile|zshrc|zprofile)\b"
    r"|/etc/profile(?:\.d/[A-Za-z0-9_.-]+)?\b"
    r")"
)

# Require mutation intent on the same line. The underlying scanner is line-based,
# so this deliberately mirrors its scope rather than pretending to understand a
# multi-line data flow that it cannot currently model.
_PROFILE_WRITE_INTENT = re.compile(
    r"(?ix)(?:"
    r">>?"
    r"|\btee\b"
    r"|\bsed\s+-i\b"
    r"|\b(?:cp|mv|install|touch|truncate|rm|unlink|remove|chmod|chown)\b"
    r"|\b(?:write|append|writeFile|writeFileSync|appendFile|appendFileSync|"
    r"createWriteStream|write_text|write_bytes|replace)\w*\s*\("
    r"|\bopen\s*\([^\n]*(?:mode\s*=\s*)?[\"'][wax](?:\+)?[\"']"
    r"|\bfopen\s*\([^\n]*[\"'][wa](?:\+)?[\"']"
    r")"
)


_IMAGE_OR_FONT_MAGIC = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"BM",
    b"\x00\x00\x01\x00",  # ICO
    b"wOFF",
    b"wOF2",
    b"\x00\x01\x00\x00",  # TrueType
    b"OTTO",  # OpenType
)


def _is_profile_modification(line: str) -> bool:
    return bool(_PROFILE_TARGET.search(line) and _PROFILE_WRITE_INTENT.search(line))


def _decode_base64_prefix(value: str) -> bytes:
    """Decode enough bytes to identify an asset without materializing it all."""
    # 256 base64 characters decode to 192 bytes, far more than any magic header.
    prefix = value[:256]
    prefix = prefix[: len(prefix) - (len(prefix) % 4)]
    if not prefix:
        return b""
    try:
        return base64.b64decode(prefix, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _is_recognized_encoded_asset(value: str) -> bool:
    decoded = _decode_base64_prefix(value)
    if not decoded:
        return False
    if any(decoded.startswith(magic) for magic in _IMAGE_OR_FONT_MAGIC):
        return True
    # WebP uses a RIFF container with WEBP at byte offset 8.
    if len(decoded) >= 12 and decoded.startswith(b"RIFF") and decoded[8:12] == b"WEBP":
        return True
    return False


def install(core: ModuleType) -> ModuleType:
    """Install persistence and encoded-asset filtering on the audit core."""
    if getattr(core, "_behavior_false_positive_filters_installed", False):
        return core

    raw_scan: Callable[[str, str, str], list[object]] = core.scan_text_content

    def scan_text_content(content: str, path: str, ext: str) -> list[object]:
        findings = raw_scan(content, path, ext)

        # Use the same comment-stripped view as the previously installed noise
        # filter when available, preserving line numbers.
        cleaned = (
            core.strip_comments(content, ext)
            if hasattr(core, "strip_comments")
            else content
        )
        lines = cleaned.splitlines()

        candidates_by_line: dict[int, deque[str]] = defaultdict(deque)
        if any(f.rule_id == "OBFUSCATION_LARGE_BASE64" for f in findings):
            for match in core._OBFUSCATION_BASE64.finditer(cleaned):
                value = match.group(0)
                if len(value) < 200:
                    continue
                line_number = cleaned.count("\n", 0, match.start()) + 1
                candidates_by_line[line_number].append(value)
        filtered: list[object] = []
        profile_lines: set[int] = set()
        for finding in findings:
            if finding.rule_id == "PERSIST_PROFILE_MOD":
                line = (
                    lines[finding.line - 1]
                    if 0 < finding.line <= len(lines)
                    else ""
                )
                if not _is_profile_modification(line):
                    continue
                profile_lines.add(finding.line)

            if finding.rule_id == "OBFUSCATION_LARGE_BASE64":
                queue = candidates_by_line.get(finding.line)
                value = queue.popleft() if queue else ""
                if value and _is_recognized_encoded_asset(value):
                    continue

            filtered.append(finding)

        # Expand the original filename list to include zprofile while retaining
        # the same severity/classification for true writes.
        for line_number, line in enumerate(lines, start=1):
            if line_number in profile_lines or not _is_profile_modification(line):
                continue
            filtered.append(core.Finding(
                rule_id="PERSIST_PROFILE_MOD",
                severity="medium",
                classification="MANUAL_REVIEW",
                path=path,
                line=line_number,
                message="shell profile modification",
                evidence=core._truncate(line.strip(), core.EVIDENCE_MAX_LEN),
                scanner="decky-static-rules",
            ))

        return filtered

    core._pre_behavior_filter_scan_text_content = raw_scan
    core.scan_text_content = scan_text_content
    core.is_profile_modification = _is_profile_modification
    core.is_recognized_encoded_asset = _is_recognized_encoded_asset
    core._behavior_false_positive_filters_installed = True
    return core
