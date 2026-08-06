"""Reviewer-focused capa enrichment for native binaries in Decky releases.

capa is run statically against eligible PE and ELF files from the safely
extracted release artifact. It never executes plugin code. Rather than emitting
one audit finding per capa rule, this module groups top-level capabilities into
small reviewer-facing summaries and enriches the existing ``NATIVE_BINARY``
finding and ``native_binaries`` inventory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable

import network_destination_filters as path_provenance

_CAPA_CACHE_VERSION = "decky-capa-v1"
_CAPA_RESULT_SCHEMA = 1
_SUPPORTED_TYPES = {"elf_binary", "pe_binary"}
_DEFAULT_MAX_BINARY_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_BINARIES = 8
_DEFAULT_TIMEOUT_SECONDS = 90
_PROVENANCE_PRIORITY = {
    "plugin_runtime": 0,
    "generated_runtime_bundle": 1,
    "dependency_or_vendored": 2,
    "documentation_or_test": 3,
    "source_map_or_build_metadata": 4,
}
_GROUP_PRIORITY = {
    "anti-analysis and packing": 0,
    "persistence and service changes": 1,
    "process and command execution": 2,
    "sensitive data and collection": 3,
    "network communication": 4,
    "filesystem and system interaction": 5,
    "cryptography and data transformation": 6,
    "code loading and runtime": 7,
    "other capabilities": 8,
}
_CURRENT_CAPA_RUN: ContextVar[dict[str, Any] | None] = ContextVar(
    "decky_capa_current_run", default=None
)


def _scanner_config(policy: dict[str, Any]) -> dict[str, Any]:
    value = (policy.get("scanners") or {}).get("capa") or {}
    return value if isinstance(value, dict) else {"enabled": bool(value)}


def _normalise_path(path: str) -> str:
    value = str(path or "").replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return PurePosixPath(value).as_posix() if value else ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version_slug(version: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9_.-]+", "-", version.strip()).strip("-")
    return rendered or "unknown"


def _cache_path(cache_dir: str, sha256: str, version: str) -> Path:
    return (
        Path(cache_dir)
        / "capa"
        / _CAPA_CACHE_VERSION
        / _version_slug(version)
        / f"{sha256}.json"
    )


def _load_cached_document(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("cache_schema") != _CAPA_RESULT_SCHEMA:
        return None
    document = data.get("document")
    return document if isinstance(document, dict) else None


def _save_cached_document(path: Path, document: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {"cache_schema": _CAPA_RESULT_SCHEMA, "document": document},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError:
        pass


def _capa_version(core: ModuleType) -> tuple[str | None, str | None]:
    ok, stdout, stderr = core._run_scanner(
        ["capa", "--version"], "capa", timeout=30
    )
    output = (stdout or stderr or "").strip()
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", output)
    if ok and match:
        return match.group(1), None
    return None, output or "capa --version failed"


def _group_for(namespace: str, name: str) -> str:
    text = f"{namespace} {name}".casefold()
    if any(token in text for token in ("anti-analysis", "anti-vm", "packer", "obfuscat")):
        return "anti-analysis and packing"
    if any(token in text for token in ("persistence", "service", "autorun", "startup", "scheduled task")):
        return "persistence and service changes"
    if any(token in text for token in ("process", "command", "shell", "execution", "spawn", "inject")):
        return "process and command execution"
    if any(token in text for token in ("credential", "password", "keylog", "collection", "clipboard", "browser")):
        return "sensitive data and collection"
    if any(token in text for token in ("network", "http", "socket", "dns", "communication", "c2/")):
        return "network communication"
    if any(token in text for token in ("file-system", "filesystem", "registry", "device", "driver", "host-interaction")):
        return "filesystem and system interaction"
    if any(token in text for token in ("crypto", "encrypt", "decrypt", "encode", "decode", "hash")):
        return "cryptography and data transformation"
    if any(token in text for token in ("load-code", "runtime", "library", "module", "reflect")):
        return "code loading and runtime"
    return "other capabilities"


def _render_framework_entries(value: Any) -> list[str]:
    entries: list[str] = []
    if not isinstance(value, list):
        return entries
    for item in value:
        if isinstance(item, str):
            rendered = item.strip()
        elif isinstance(item, dict):
            rendered = str(
                item.get("id")
                or item.get("technique")
                or item.get("objective")
                or item.get("name")
                or ""
            ).strip()
        else:
            rendered = ""
        if rendered and rendered not in entries:
            entries.append(rendered)
    return entries


def _parse_capa_document(document: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, deterministic summary of capa's result document."""
    rules = document.get("rules") or {}
    if not isinstance(rules, dict):
        rules = {}

    capabilities: list[dict[str, Any]] = []
    suppressed = 0
    packed = False
    for fallback_name, raw_entry in rules.items():
        if not isinstance(raw_entry, dict):
            continue
        meta = raw_entry.get("meta") or {}
        if not isinstance(meta, dict):
            meta = {}
        name = str(meta.get("name") or fallback_name or "unnamed capability").strip()
        namespace = str(meta.get("namespace") or "").strip()
        lower_name = name.casefold()
        lower_namespace = namespace.casefold()
        if (
            bool(meta.get("lib"))
            or lower_name.startswith("(internal)")
            or lower_namespace.startswith("internal/")
            or lower_namespace.startswith("nursery/")
        ):
            suppressed += 1
            continue
        if "packer" in lower_namespace or "packed" in lower_name:
            packed = True
        capabilities.append(
            {
                "name": name,
                "namespace": namespace,
                "group": _group_for(namespace, name),
                "attack": _render_framework_entries(meta.get("attack"))[:4],
                "mbc": _render_framework_entries(meta.get("mbc"))[:4],
            }
        )

    capabilities.sort(
        key=lambda item: (
            _GROUP_PRIORITY.get(item["group"], 99),
            item["name"].casefold(),
        )
    )
    groups: dict[str, list[str]] = {}
    for capability in capabilities:
        names = groups.setdefault(capability["group"], [])
        if capability["name"] not in names:
            names.append(capability["name"])

    group_summaries = [
        {
            "name": group,
            "count": len(names),
            "examples": names[:4],
        }
        for group, names in sorted(
            groups.items(), key=lambda item: (_GROUP_PRIORITY.get(item[0], 99), item[0])
        )
    ]
    attack: list[str] = []
    mbc: list[str] = []
    for capability in capabilities:
        for item in capability["attack"]:
            if item not in attack:
                attack.append(item)
        for item in capability["mbc"]:
            if item not in mbc:
                mbc.append(item)

    return {
        "capability_count": len(capabilities),
        "groups": group_summaries,
        "representative_capabilities": [item["name"] for item in capabilities[:12]],
        "attack": attack[:8],
        "mbc": mbc[:8],
        "suppressed_internal_or_experimental": suppressed,
        "packed_or_obfuscated": packed,
    }


def _discover_binaries(core: ModuleType, extract_dir: str) -> list[dict[str, Any]]:
    root = Path(extract_dir).resolve()
    discovered: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = Path(current) / name
            try:
                with path.open("rb") as handle:
                    header = handle.read(32)
                relative = path.resolve().relative_to(root).as_posix()
                identified = core.identify_binary(header, relative)
                if not identified:
                    continue
                size = path.stat().st_size
            except (OSError, ValueError):
                continue
            provenance, confidence = path_provenance.classify_network_source(relative)
            item = dict(identified)
            item.update(
                {
                    "path": relative,
                    "full_path": str(path),
                    "size_bytes": size,
                    "provenance": provenance,
                    "confidence": confidence,
                }
            )
            discovered.append(item)
    return sorted(
        discovered,
        key=lambda item: (
            _PROVENANCE_PRIORITY.get(str(item.get("provenance")), 99),
            str(item.get("path")).casefold(),
        ),
    )


def _analyze_binary(
    core: ModuleType,
    binary: dict[str, Any],
    cache_dir: str,
    version: str,
    timeout: int,
) -> dict[str, Any]:
    path = Path(str(binary["full_path"]))
    sha256 = _sha256_file(path)
    cache_path = _cache_path(cache_dir, sha256, version)
    document = _load_cached_document(cache_path)
    cached = document is not None
    stderr = ""

    if document is None:
        _ok, stdout, stderr = core._run_scanner(
            ["capa", "-j", str(path)], "capa", timeout=timeout
        )
        if not stdout.strip():
            return {
                "status": "failed",
                "sha256": sha256,
                "cached": False,
                "detail": core._truncate(stderr or "capa returned no JSON output", 300),
            }
        try:
            parsed = json.loads(stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            return {
                "status": "failed",
                "sha256": sha256,
                "cached": False,
                "detail": f"invalid capa JSON: {exc}",
            }
        if not isinstance(parsed, dict):
            return {
                "status": "failed",
                "sha256": sha256,
                "cached": False,
                "detail": "capa JSON document is not an object",
            }
        document = parsed
        _save_cached_document(cache_path, document)

    summary = _parse_capa_document(document)
    limitations: list[str] = []
    if summary["packed_or_obfuscated"] or "packed" in stderr.casefold():
        limitations.append("packed or obfuscated input may produce incomplete static results")
    return {
        "status": "analyzed",
        "sha256": sha256,
        "cached": cached,
        "version": version,
        "capability_count": summary["capability_count"],
        "groups": summary["groups"],
        "representative_capabilities": summary["representative_capabilities"],
        "attack": summary["attack"],
        "mbc": summary["mbc"],
        "suppressed_internal_or_experimental": summary[
            "suppressed_internal_or_experimental"
        ],
        "limitations": limitations,
    }


def _run_capa(
    core: ModuleType,
    extract_dir: str,
    policy: dict[str, Any],
    cache_dir: str,
) -> tuple[Any, dict[str, dict[str, Any]]]:
    if not core._scanner_enabled(policy, "capa"):
        return core.ScannerStatus(name="capa", status="skipped"), {}
    if not shutil.which("capa"):
        return (
            core.ScannerStatus(
                name="capa", status="unavailable", detail="capa not found in PATH"
            ),
            {},
        )

    version, version_error = _capa_version(core)
    if version is None:
        return (
            core.ScannerStatus(name="capa", status="failed", detail=version_error),
            {},
        )

    config = _scanner_config(policy)
    max_bytes = int(config.get("max_binary_bytes") or _DEFAULT_MAX_BINARY_BYTES)
    max_binaries = int(config.get("max_binaries_per_plugin") or _DEFAULT_MAX_BINARIES)
    timeout = int(config.get("timeout_seconds") or _DEFAULT_TIMEOUT_SECONDS)
    include_dependencies = bool(config.get("include_dependencies", False))

    discovered = _discover_binaries(core, extract_dir)
    results: dict[str, dict[str, Any]] = {}
    eligible: list[dict[str, Any]] = []
    skipped_dependency = 0
    skipped_format = 0
    skipped_size = 0

    for binary in discovered:
        path = str(binary["path"])
        result = {
            "status": "skipped",
            "size_bytes": int(binary.get("size_bytes") or 0),
            "provenance": binary.get("provenance"),
            "confidence": binary.get("confidence"),
            "type": binary.get("type"),
        }
        if binary.get("type") not in _SUPPORTED_TYPES:
            result["reason"] = "format not supported by static capa integration"
            skipped_format += 1
        elif (
            binary.get("provenance") == "dependency_or_vendored"
            and not include_dependencies
        ):
            result["reason"] = "dependency or vendored binary collapsed from primary review"
            skipped_dependency += 1
        elif int(binary.get("size_bytes") or 0) > max_bytes:
            result["reason"] = f"binary exceeds configured {max_bytes}-byte capa limit"
            skipped_size += 1
        else:
            eligible.append(binary)
            continue
        results[path] = result

    selected = eligible[:max_binaries]
    for binary in eligible[max_binaries:]:
        results[str(binary["path"])] = {
            "status": "skipped",
            "size_bytes": int(binary.get("size_bytes") or 0),
            "provenance": binary.get("provenance"),
            "confidence": binary.get("confidence"),
            "type": binary.get("type"),
            "reason": f"per-plugin capa limit reached ({max_binaries})",
        }

    analyzed = 0
    failed = 0
    capability_total = 0
    cache_hits = 0
    for binary in selected:
        result = _analyze_binary(core, binary, cache_dir, version, timeout)
        result.update(
            {
                "size_bytes": int(binary.get("size_bytes") or 0),
                "provenance": binary.get("provenance"),
                "confidence": binary.get("confidence"),
                "type": binary.get("type"),
            }
        )
        results[str(binary["path"])] = result
        if result["status"] == "analyzed":
            analyzed += 1
            capability_total += int(result.get("capability_count") or 0)
            cache_hits += int(bool(result.get("cached")))
        else:
            failed += 1

    status = "failed" if selected and analyzed == 0 else "passed"
    detail = (
        f"{analyzed} binary/binaries analyzed; {capability_total} top-level "
        f"capabilities grouped; {cache_hits} cache hit(s); {failed} incomplete; "
        f"{skipped_dependency} dependency, {skipped_format} unsupported-format, "
        f"{skipped_size} oversize skipped"
    )
    return (
        core.ScannerStatus(name="capa", status=status, version=version, detail=detail),
        results,
    )


def _merge_results_into_report(
    core: ModuleType,
    report: Any,
    status: Any,
    results: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> None:
    statuses = getattr(report, "scanner_statuses", [])
    if not any(getattr(item, "name", None) == "capa" for item in statuses):
        statuses.append(status)

    by_path = {
        _normalise_path(str(item.get("path") or "")): item
        for item in getattr(report, "native_binaries", [])
        if isinstance(item, dict)
    }
    for path, result in results.items():
        target = by_path.get(_normalise_path(path))
        if target is not None:
            target["capa"] = result
            target["sha256"] = result.get("sha256") or target.get("sha256")
            target["size_bytes"] = result.get("size_bytes") or target.get("size_bytes")
            target["provenance"] = result.get("provenance")
            target["confidence"] = result.get("confidence")

    for finding in getattr(report, "findings", []):
        if getattr(finding, "rule_id", "") != "NATIVE_BINARY":
            continue
        result = results.get(_normalise_path(getattr(finding, "path", "")))
        if not result or result.get("status") != "analyzed":
            continue
        groups = result.get("groups") or []
        group_text = ", ".join(
            f"{group.get('name')} ({group.get('count')})" for group in groups[:5]
        ) or "no top-level capability matches"
        finding.message = core._truncate(
            f"{finding.message}; capa summary: {group_text}", 500
        )
        representative = result.get("representative_capabilities") or []
        finding.evidence = core._truncate(
            "; ".join(representative[:6]) or "capa completed with no top-level matches",
            core.EVIDENCE_MAX_LEN,
        )

    report.final_classification, report.risk_score = core.classify_findings(
        report.findings,
        has_error=bool(getattr(report, "errors", [])),
        scanner_statuses=report.scanner_statuses,
        policy=policy,
    )


def _binary_capability_markdown(report: Any) -> str:
    binaries = [
        item
        for item in getattr(report, "native_binaries", [])
        if isinstance(item, dict) and isinstance(item.get("capa"), dict)
    ]
    if not binaries:
        return ""

    analyzed = [item for item in binaries if item["capa"].get("status") == "analyzed"]
    skipped = [item for item in binaries if item["capa"].get("status") == "skipped"]
    failed = [item for item in binaries if item["capa"].get("status") == "failed"]
    lines = ["## Native Binary Capability Analysis", ""]
    lines.append(
        f"capa statically analyzed {len(analyzed)} binary/binaries; "
        f"{len(skipped)} skipped and {len(failed)} incomplete. "
        "Capabilities are reviewer evidence, not proof of maliciousness or safety."
    )
    lines.append("")

    for item in analyzed:
        result = item["capa"]
        sha = str(result.get("sha256") or "")
        lines.append(
            f"- `{item.get('path')}` — {result.get('capability_count', 0)} "
            f"top-level capabilities; {result.get('provenance')}; "
            f"SHA-256 `{sha[:12]}`"
        )
        groups = result.get("groups") or []
        if groups:
            lines.append(
                "  - Groups: "
                + "; ".join(
                    f"{group.get('name')} ({group.get('count')})"
                    for group in groups[:6]
                )
            )
        representative = result.get("representative_capabilities") or []
        if representative:
            lines.append(
                "  - Representative matches: "
                + "; ".join(f"`{name}`" for name in representative[:6])
            )
        limitations = result.get("limitations") or []
        if limitations:
            lines.append("  - Limitations: " + "; ".join(limitations))

    if skipped:
        lines.extend(["", "<details>", f"<summary>Skipped binary inventory — {len(skipped)}</summary>", ""])
        for item in skipped:
            result = item["capa"]
            lines.append(f"- `{item.get('path')}` — {result.get('reason', 'not analyzed')}")
        lines.extend(["", "</details>"])
    if failed:
        lines.extend(["", "### Incomplete capa checks", ""])
        for item in failed:
            lines.append(
                f"- `{item.get('path')}` — {item['capa'].get('detail', 'analysis failed')}"
            )
    lines.append("")
    return "\n".join(lines)


def install(core: ModuleType) -> ModuleType:
    """Install artifact-only capa analysis and reviewer-focused reporting."""
    if getattr(core, "_capa_binary_analysis_installed", False):
        return core

    raw_run_semgrep: Callable[..., tuple[Any, list[Any]]] = core.run_semgrep
    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report
    raw_cache_key: Callable[..., str] = core._cache_key

    def cache_key(
        repository: str,
        release_id: str,
        artifact_sha256: str,
        policy_version: str = core.POLICY_VERSION,
    ) -> str:
        return raw_cache_key(
            repository,
            release_id,
            artifact_sha256,
            f"{policy_version}+{_CAPA_CACHE_VERSION}",
        )

    def run_semgrep(extract_dir: str, policy: dict[str, Any]) -> tuple[Any, list[Any]]:
        status, findings = raw_run_semgrep(extract_dir, policy)
        state = _CURRENT_CAPA_RUN.get()
        if state is not None and not state.get("ran"):
            state["ran"] = True
            capa_status, results = _run_capa(
                core,
                extract_dir,
                policy,
                str(state.get("cache_dir") or ".audit-cache"),
            )
            state["status"] = capa_status
            state["results"] = results
        return status, findings

    def audit_repository(
        repo_url: str,
        policy: dict[str, Any],
        exceptions: list[dict[str, Any]],
        cache_dir: str = core.CACHE_DIR,
        skip_cache: bool = False,
    ) -> Any:
        state: dict[str, Any] = {
            "cache_dir": cache_dir,
            "ran": False,
            "status": None,
            "results": {},
        }
        token = _CURRENT_CAPA_RUN.set(state)
        try:
            report = raw_audit_repository(
                repo_url,
                policy,
                exceptions,
                cache_dir=cache_dir,
                skip_cache=skip_cache,
            )
        finally:
            _CURRENT_CAPA_RUN.reset(token)

        if not any(
            getattr(item, "name", None) == "capa"
            for item in getattr(report, "scanner_statuses", [])
        ):
            capa_status = state.get("status")
            if capa_status is None:
                if core._scanner_enabled(policy, "capa"):
                    capa_status = core.ScannerStatus(
                        name="capa",
                        status="unavailable",
                        detail="extraction did not reach capa analysis",
                    )
                else:
                    capa_status = core.ScannerStatus(name="capa", status="skipped")
            _merge_results_into_report(
                core,
                report,
                capa_status,
                state.get("results") or {},
                policy,
            )
        return report

    def generate_markdown_report(report: Any) -> str:
        rendered = raw_generate_markdown(report)
        section = _binary_capability_markdown(report)
        if not section:
            return rendered
        marker = "## Archive Statistics"
        if marker in rendered:
            return rendered.replace(marker, section + "\n" + marker, 1)
        return rendered.rstrip() + "\n\n" + section

    core._raw_run_semgrep_before_capa = raw_run_semgrep
    core._raw_audit_repository_before_capa = raw_audit_repository
    core._generate_markdown_report_before_capa = raw_generate_markdown
    core._cache_key = cache_key
    core.run_semgrep = run_semgrep
    core.audit_repository = audit_repository
    core.generate_markdown_report = generate_markdown_report
    core._capa_binary_analysis_installed = True
    return core
