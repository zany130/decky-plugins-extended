"""Hardening for shared exact-source content comparison.

Keeps direct Trivy calls backward compatible outside a full repository audit and
rejects case-insensitive source-path collisions before same-path mapping can
silently choose the wrong file.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import source_content_comparison as scc


def _source_case_collisions(source_root: str) -> list[list[str]]:
    """Return deterministic groups of source files colliding under casefold()."""
    root = Path(source_root)
    grouped: dict[str, list[str]] = defaultdict(list)
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            grouped[relative.casefold()].append(relative)
    return [
        sorted(paths)
        for _key, paths in sorted(grouped.items())
        if len(paths) > 1
    ]


def install(core: ModuleType) -> ModuleType:
    """Install context fallback and ambiguous-source-path protection."""
    if getattr(core, "_source_content_hardening_installed", False):
        return core
    if not getattr(core, "_source_content_comparison_installed", False):
        raise RuntimeError("source_content_comparison must be installed first")

    shared_run_trivy: Callable[..., tuple[Any, list[Any]]] = core.run_trivy
    artifact_run_trivy: Callable[..., tuple[Any, list[Any]]] = (
        core._raw_run_trivy_artifact_only
    )
    original_compare: Callable[..., tuple[dict[str, Any], list[Any], Any]] = (
        core.compare_source_and_artifact
    )

    def run_trivy(
        extract_dir: str, policy: dict[str, Any]
    ) -> tuple[Any, list[Any]]:
        # Direct scanner callers do not own the shared exact-source lifecycle.
        # Preserve their previous artifact-only behavior rather than manufacturing
        # a source-fetch failure from an absent outer audit context.
        if scc._CURRENT_SHARED_SOURCE.get() is None:
            return artifact_run_trivy(extract_dir, policy)
        return shared_run_trivy(extract_dir, policy)

    def compare_source_and_artifact(
        extract_dir: str,
        owner: str,
        repo: str,
        ref: str,
    ) -> tuple[dict[str, Any], list[Any], Any]:
        shared = scc._CURRENT_SHARED_SOURCE.get()
        if shared is None:
            return original_compare(extract_dir, owner, repo, ref)

        source_root = str(shared.get("source_root") or "")
        if not source_root:
            try:
                source_root = scc._ensure_shared_source(core)
            except Exception:
                # The installed content comparator already produces the canonical
                # fail-closed status and detail for source retrieval failures.
                return original_compare(extract_dir, owner, repo, ref)

        collisions = _source_case_collisions(source_root)
        if collisions:
            flattened = [path for group in collisions for path in group]
            return (
                {
                    "ref": ref,
                    "source_commit": shared.get("commit_sha"),
                    "checked": False,
                    "source_case_collisions": collisions,
                },
                [],
                core.ScannerStatus(
                    name="source-artifact-diff",
                    status="failed",
                    detail=(
                        "Ambiguous case-insensitive source paths prevent safe "
                        f"artifact mapping: {', '.join(flattened[:10])}"
                    ),
                ),
            )
        return original_compare(extract_dir, owner, repo, ref)

    core.run_trivy = run_trivy
    core.compare_source_and_artifact = compare_source_and_artifact
    core._source_content_hardening_installed = True
    return core
