#!/usr/bin/env python3
"""Compatibility entry point for the Decky plugin security audit.

The implementation remains in :mod:`audit_plugins_core`; context-aware noise,
network-destination, exact-source dependency, Semgrep, capa binary-capability,
content-comparison, source-mapping hardening, exact metadata build-stamp,
behavioral false-positive, credential-exposure, packaged-artifact, source-link,
and report-layout policies are installed before the module is exposed to callers
or the CLI runs.
"""

from __future__ import annotations

import sys

import audit_plugins_core as _core
from artifact_diff_filters import install as install_artifact_diff_filters
from audit_noise_filters import install as install_noise_filters
from behavior_false_positive_filters import install as install_behavior_filters
from capa_binary_analysis import install as install_capa_binary_analysis
from capa_review_filters import install as install_capa_review_filters
from credential_exposure_filters import install as install_credential_policy
from metadata_build_stamp_filters import install as install_metadata_build_stamp_filters
from network_destination_filters import install as install_network_destination_filters
from report_layout_filters import install as install_report_layout
from semgrep_source_link_hardening import install as install_semgrep_link_hardening
from semgrep_source_scanning import install as install_semgrep_source_scanning
from source_content_comparison import install as install_source_content_comparison
from source_content_hardening import install as install_source_content_hardening
from trivy_source_scanning import install as install_trivy_source_scanning
from upstream_source_links import install as install_source_links

# New optional scanners must be opt-in for custom or missing policies. The
# repository's checked-in security-policy.yml explicitly enables capa, while a
# caller that omits the setting retains the pre-capa behavior.
_default_policy_without_capa = _core._default_policy


def _default_policy_with_capa() -> dict:
    policy = _default_policy_without_capa()
    policy.setdefault("scanners", {}).setdefault(
        "capa", {"enabled": False, "required": False}
    )
    return policy


_core._default_policy = _default_policy_with_capa

install_noise_filters(_core)
install_network_destination_filters(_core)
install_trivy_source_scanning(_core)
install_source_content_comparison(_core)
install_source_content_hardening(_core)
install_semgrep_source_scanning(_core)
install_capa_review_filters(_core)
install_capa_binary_analysis(_core)
install_metadata_build_stamp_filters(_core)
install_behavior_filters(_core)
install_credential_policy(_core)
install_artifact_diff_filters(_core)
install_source_links(_core)
install_semgrep_link_hardening(_core)
install_report_layout(_core)

if __name__ == "__main__":
    raise SystemExit(_core.main())

# Preserve the historical import surface and, importantly, ensure mocks such as
# patch("audit_plugins._gh_get") modify the globals used by core functions.
sys.modules[__name__] = _core
