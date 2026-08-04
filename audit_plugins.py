#!/usr/bin/env python3
"""Compatibility entry point for the Decky plugin security audit.

The implementation remains in :mod:`audit_plugins_core`; context-aware noise,
network-destination, exact-source dependency and content comparison, exact
metadata build-stamp, behavioral false-positive, credential-exposure,
packaged-artifact, source-link, and report-layout policies are installed before
the module is exposed to callers or the CLI runs.
"""

from __future__ import annotations

import sys

import audit_plugins_core as _core
from artifact_diff_filters import install as install_artifact_diff_filters
from audit_noise_filters import install as install_noise_filters
from behavior_false_positive_filters import install as install_behavior_filters
from credential_exposure_filters import install as install_credential_policy
from metadata_build_stamp_filters import install as install_metadata_build_stamp_filters
from network_destination_filters import install as install_network_destination_filters
from report_layout_filters import install as install_report_layout
from source_content_comparison import install as install_source_content_comparison
from trivy_source_scanning import install as install_trivy_source_scanning
from upstream_source_links import install as install_source_links

install_noise_filters(_core)
install_network_destination_filters(_core)
install_trivy_source_scanning(_core)
install_source_content_comparison(_core)
install_metadata_build_stamp_filters(_core)
install_behavior_filters(_core)
install_credential_policy(_core)
install_artifact_diff_filters(_core)
install_source_links(_core)
install_report_layout(_core)

if __name__ == "__main__":
    raise SystemExit(_core.main())

# Preserve the historical import surface and, importantly, ensure mocks such as
# patch("audit_plugins._gh_get") modify the globals used by core functions.
sys.modules[__name__] = _core
