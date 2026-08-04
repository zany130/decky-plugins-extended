#!/usr/bin/env python3
"""Compatibility entry point for the Decky plugin security audit.

The implementation remains in :mod:`audit_plugins_core`; context-aware noise,
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
from credential_exposure_filters import install as install_credential_policy
from report_layout_filters import install as install_report_layout
from upstream_source_links import install as install_source_links

install_noise_filters(_core)
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
