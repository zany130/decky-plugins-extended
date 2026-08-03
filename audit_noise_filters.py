"""False-positive filters for the Decky plugin static audit.

The core scanner intentionally uses broad regular expressions. This module
adds context before those expressions affect risk scores: documentation gets a
separate informational treatment, comments are removed without deleting real
string literals, and generated/vendored files are left to ClamAV and Trivy.
"""

from __future__ import annotations

import io
import os
import re
import tokenize
from types import ModuleType
from typing import Callable

_DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".adoc", ".asciidoc"}
_DOC_NAME_PREFIXES = (
    "readme", "changelog", "changes", "license", "copying",
    "contributing", "security", "authors", "notice",
)
_VENDORED_PARTS = {
    "node_modules", "vendor", "vendors", "third_party", "third-party",
    "__pycache__", ".venv", "venv",
}
_SHELL_EXTENSIONS = {"", ".sh", ".bash", ".zsh", ".fish"}

_DOC_RISKY_INSTALL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)
_EXECUTION_CONTEXT = re.compile(
    r"\b(?:"
    r"os\.(?:system|popen)|"
    r"subprocess\.(?:Popen|run|call|check_call|check_output)|"
    r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)|"
    r"(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
    r")",
    re.IGNORECASE,
)

# Bare words such as "mount" should only count when used as commands.
_COMMAND_RULES: dict[str, tuple[str, ...]] = {
    "PRIVILEGE_MOUNT": ("mount", "umount"),
    "PRIVILEGE_SYSTEMCTL": ("systemctl",),
    "PRIVILEGE_SYSTEMCTL_SHELL": ("systemctl",),
    "PRIVILEGE_MODPROBE": ("modprobe", "insmod", "rmmod"),
    "PERSIST_KERNEL_MODULE_SHELL": ("modprobe", "insmod"),
    "PRIVILEGE_IPTABLES": ("iptables", "ip6tables", "nft"),
    "PRIVILEGE_STEAMOS_READONLY": ("steamos-readonly",),
}


def _normalise_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def is_documentation_path(path: str) -> bool:
    """Return True for user-facing documentation, not executable source."""
    normalised = _normalise_path(path)
    parts = [part for part in normalised.split("/") if part]
    name = parts[-1] if parts else normalised
    stem, ext = os.path.splitext(name)

    if ext in _DOC_EXTENSIONS:
        return True
    if any(part in {"docs", "doc", "documentation"} for part in parts[:-1]):
        return True
    return any(
        name.startswith(prefix) or stem.startswith(prefix)
        for prefix in _DOC_NAME_PREFIXES
    )


def is_generated_or_vendored_path(path: str) -> bool:
    """Return True when broad source regexes would mostly scan generated code."""
    normalised = _normalise_path(path)
    parts = [part for part in normalised.split("/") if part]
    name = parts[-1] if parts else normalised

    if any(part in _VENDORED_PARTS for part in parts[:-1]):
        return True
    return name.endswith((
        ".map", ".pyc", ".pyo", ".min.js", ".min.mjs", ".min.cjs",
    ))


def _blank_range(
    lines: list[str], start: tuple[int, int], end: tuple[int, int]
) -> None:
    """Replace a token span with spaces while preserving newlines/line count."""
    start_line, start_col = start
    end_line, end_col = end
    for line_number in range(start_line, end_line + 1):
        index = line_number - 1
        if index < 0 or index >= len(lines):
            continue
        line = lines[index]
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        left = start_col if line_number == start_line else 0
        right = end_col if line_number == end_line else len(body)
        left = min(max(left, 0), len(body))
        right = min(max(right, left), len(body))
        lines[index] = (
            body[:left] + (" " * (right - left)) + body[right:] + newline
        )


def _strip_python_comments_and_docstrings(content: str) -> str:
    lines = content.splitlines(keepends=True)
    at_statement_start = True
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return _strip_hash_comments(content)

    for token in tokens:
        token_type = token.type
        if token_type == tokenize.COMMENT:
            _blank_range(lines, token.start, token.end)
            continue
        if token_type == tokenize.STRING and at_statement_start:
            # Module/class/function docstrings are documentation, not behavior.
            _blank_range(lines, token.start, token.end)
        if token_type in (tokenize.ENCODING, tokenize.NL, tokenize.COMMENT):
            continue
        if token_type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
            at_statement_start = True
        elif token_type != tokenize.ENDMARKER:
            at_statement_start = False
    return "".join(lines)


def _strip_javascript_comments(content: str) -> str:
    """Remove // and /* */ comments while preserving strings and line numbers."""
    output = list(content)
    state = "normal"
    escaped = False
    i = 0

    while i < len(content):
        char = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""

        if state == "line_comment":
            if char == "\n":
                state = "normal"
            else:
                output[i] = " "
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                output[i] = output[i + 1] = " "
                state = "normal"
                i += 2
            else:
                if char != "\n":
                    output[i] = " "
                i += 1
            continue

        if state in {"single", "double", "template"}:
            quote = {"single": "'", "double": '"', "template": "`"}[state]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "normal"
            i += 1
            continue

        if char == "'":
            state = "single"
        elif char == '"':
            state = "double"
        elif char == "`":
            state = "template"
        elif char == "/" and nxt == "/":
            output[i] = output[i + 1] = " "
            state = "line_comment"
            i += 2
            continue
        elif char == "/" and nxt == "*":
            output[i] = output[i + 1] = " "
            state = "block_comment"
            i += 2
            continue
        i += 1

    return "".join(output)


def _strip_hash_comments(content: str) -> str:
    """Strip shell-style comments while preserving # inside quotes."""
    cleaned: list[str] = []
    for line in content.splitlines(keepends=True):
        quote: str | None = None
        escaped = False
        comment_at: int | None = None
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\" and quote != "'":
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char == "#" and (index == 0 or line[index - 1].isspace()):
                comment_at = index
                break
        if comment_at is None:
            cleaned.append(line)
            continue
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        cleaned.append(
            body[:comment_at] + (" " * (len(body) - comment_at)) + newline
        )
    return "".join(cleaned)


def strip_comments(content: str, ext: str) -> str:
    ext = ext.lower()
    if ext in {".py", ".pyw"}:
        return _strip_python_comments_and_docstrings(content)
    if ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
        return _strip_javascript_comments(content)
    if ext in _SHELL_EXTENSIONS:
        return _strip_hash_comments(content)
    return content


def _shell_command_is_active(line: str, commands: tuple[str, ...]) -> bool:
    command_group = "|".join(re.escape(command) for command in commands)
    command_pattern = re.compile(
        rf"^(?:(?:if|then|elif|while|until|do|sudo|env|command|!)\s+)*"
        rf"(?:/[A-Za-z0-9_./-]+/)?(?:{command_group})\b",
        re.IGNORECASE,
    )
    return any(
        command_pattern.search(segment.strip())
        for segment in re.split(r"&&|\|\||[;|]", line)
    )


def _command_finding_is_active(
    line: str, ext: str, commands: tuple[str, ...]
) -> bool:
    command_group = "|".join(re.escape(command) for command in commands)
    if not re.search(rf"\b(?:{command_group})\b", line, re.IGNORECASE):
        return False
    if ext.lower() in _SHELL_EXTENSIONS:
        return _shell_command_is_active(line, commands)
    if re.search(r"\bExec(?:Start|Stop|Reload)\s*=", line, re.IGNORECASE):
        return True
    return bool(_EXECUTION_CONTEXT.search(line))


def _scan_documentation(core: ModuleType, content: str, path: str) -> list[object]:
    findings: list[object] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not _DOC_RISKY_INSTALL.search(line):
            continue
        findings.append(core.Finding(
            rule_id="DOCUMENTATION_RISKY_INSTALL",
            severity="low",
            classification="PASS_WITH_WARNINGS",
            path=path,
            line=line_number,
            message=(
                "Documentation recommends piping a network download directly "
                "to a shell."
            ),
            evidence=core._truncate(line.strip(), core.EVIDENCE_MAX_LEN),
            scanner="documentation-review",
        ))
    return findings


def install(core: ModuleType) -> ModuleType:
    """Install context-aware filtering into an imported audit core module."""
    if getattr(core, "_noise_filters_installed", False):
        return core

    raw_scan: Callable[[str, str, str], list[object]] = core.scan_text_content

    def scan_text_content(content: str, path: str, ext: str) -> list[object]:
        if is_generated_or_vendored_path(path):
            return []
        if is_documentation_path(path):
            return _scan_documentation(core, content, path)

        cleaned = strip_comments(content, ext)
        findings = raw_scan(cleaned, path, ext)
        lines = cleaned.splitlines()
        filtered: list[object] = []
        for finding in findings:
            commands = _COMMAND_RULES.get(finding.rule_id)
            if commands:
                line = (
                    lines[finding.line - 1]
                    if 0 < finding.line <= len(lines)
                    else ""
                )
                if not _command_finding_is_active(line, ext, commands):
                    continue
            filtered.append(finding)
        return filtered

    core._raw_scan_text_content = raw_scan
    core.scan_text_content = scan_text_content
    core.is_documentation_path = is_documentation_path
    core.is_generated_or_vendored_path = is_generated_or_vendored_path
    core.strip_comments = strip_comments
    core._noise_filters_installed = True
    return core
