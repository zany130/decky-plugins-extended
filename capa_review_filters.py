"""Corpus-derived prioritization and coverage rules for capa analysis.

The first native-binary corpus baseline showed that deterministic path ordering
could spend the bounded capa budget on large or unsupported binaries before
smaller reviewer-relevant targets. This module keeps the generic scanner
implementation separate from corpus-informed policy:

* common bundled GStreamer plugin directories are treated as dependencies;
* direct ARM64 ELF inputs are recorded as unsupported by this CLI integration;
* supported x86/x86-64 binaries are preferred, then smaller files;
* any selected binary that fails or times out makes capa coverage incomplete,
  even when another selected binary produced useful capability evidence.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable

import capa_binary_analysis as capa

_ARM64_MARKERS = {"arm64", "aarch64"}
_X86_64_MARKERS = {"x86_64", "x64", "amd64"}
_X86_MARKERS = {"i386", "i486", "i586", "i686", "x86"}
_DEPENDENCY_DIRECTORIES = {"gst-plugins", "gstreamer-1.0"}


def _path_parts(path: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in PurePosixPath(path.replace("\\", "/")).parts)


def _contains_marker(parts: tuple[str, ...], markers: set[str]) -> bool:
    for part in parts:
        normalized = part.replace("-", "_").replace(".", "_")
        if any(marker in normalized for marker in markers):
            return True
    return False


def _architecture_priority(item: dict[str, Any]) -> int:
    parts = _path_parts(str(item.get("path") or ""))
    if _contains_marker(parts, _X86_64_MARKERS):
        return 0
    if _contains_marker(parts, _X86_MARKERS):
        return 1
    if _contains_marker(parts, _ARM64_MARKERS):
        return 3
    return 2


def _review_priority(item: dict[str, Any]) -> tuple[int, int, int, str]:
    provenance = str(item.get("provenance") or "")
    return (
        capa._PROVENANCE_PRIORITY.get(provenance, 99),
        _architecture_priority(item),
        int(item.get("size_bytes") or 0),
        str(item.get("path") or "").casefold(),
    )


def prepare_discovered_binaries(
    discovered: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply corpus-derived provenance/platform policy and deterministic order."""
    for item in discovered:
        path = str(item.get("path") or "")
        parts = _path_parts(path)

        if any(part in _DEPENDENCY_DIRECTORIES for part in parts):
            item["provenance"] = "dependency_or_vendored"
            item["confidence"] = "high"

        if (
            item.get("type") == "elf_binary"
            and _contains_marker(parts, _ARM64_MARKERS)
        ):
            # The direct vivisect-backed CLI integration does not analyze these
            # corpus samples reliably. Keep the binary visible while avoiding a
            # misleading crash or timeout in the primary analysis budget.
            item["type"] = "elf_arm64_unsupported"

    return sorted(discovered, key=_review_priority)


def finalize_capa_results(
    core_module: ModuleType,
    status: Any,
    results: dict[str, dict[str, Any]],
) -> tuple[Any, dict[str, dict[str, Any]]]:
    """Make platform limitations and partial selected-target coverage explicit."""
    for result in results.values():
        if (
            result.get("status") == "skipped"
            and result.get("type") == "elf_arm64_unsupported"
        ):
            result["reason"] = (
                "direct ARM64 ELF analysis is unsupported by the pinned "
                "capa CLI backend; retain for manual binary review"
            )

    incomplete = sum(
        1 for result in results.values() if result.get("status") == "failed"
    )
    if incomplete and getattr(status, "status", "") == "passed":
        detail = str(getattr(status, "detail", "") or "")
        status = core_module.ScannerStatus(
            name="capa",
            status="failed",
            version=getattr(status, "version", None),
            detail=(
                f"{detail}; coverage incomplete for {incomplete} selected "
                "binary/binaries"
            ),
        )
    return status, results


def install(core: ModuleType) -> ModuleType:
    """Install corpus-derived capa prioritization before capa wraps the core."""
    if getattr(capa, "_capa_review_filters_installed", False):
        return core

    raw_discover: Callable[..., list[dict[str, Any]]] = capa._discover_binaries
    raw_run: Callable[..., tuple[Any, dict[str, dict[str, Any]]]] = capa._run_capa

    def discover_binaries(
        core_module: ModuleType,
        extract_dir: str,
    ) -> list[dict[str, Any]]:
        return prepare_discovered_binaries(raw_discover(core_module, extract_dir))

    def run_capa(
        core_module: ModuleType,
        extract_dir: str,
        policy: dict[str, Any],
        cache_dir: str,
    ) -> tuple[Any, dict[str, dict[str, Any]]]:
        status, results = raw_run(core_module, extract_dir, policy, cache_dir)
        return finalize_capa_results(core_module, status, results)

    capa._raw_discover_binaries_before_review_filters = raw_discover
    capa._raw_run_capa_before_review_filters = raw_run
    capa._discover_binaries = discover_binaries
    capa._run_capa = run_capa
    capa._capa_review_filters_installed = True
    return core
