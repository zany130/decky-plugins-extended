#!/usr/bin/env bash
set -euo pipefail

SOURCE_REPO="${1:-https://github.com/zany130/decky-plugins-extended.git}"
TARGET_REPO="${2:-}"
WORKDIR="${3:-$(pwd)/.auditor-migration}"
SOURCE_MAIN_REF="refs/heads/main"
SOURCE_CAPA_REF="refs/heads/agent/capa-binary-capabilities"
TARGET_CAPA_REF="refs/heads/experimental/capa-binary-analysis"

usage() {
  cat <<'EOF'
Usage:
  scripts/extract_auditor_history.sh [source-repo] <empty-target-repo> [workdir]

Example:
  scripts/extract_auditor_history.sh \
    https://github.com/zany130/decky-plugins-extended.git \
    git@github.com:zany130/decky-plugin-auditor.git

The target repository must already exist and have no branches. The script keeps
only the stable auditor history from main plus the capa feature branch, filters
out store/deployment files, renames the capa branch, and pushes both branches.
EOF
}

if [[ -z "$TARGET_REPO" ]]; then
  usage >&2
  exit 2
fi

for command in git git-filter-repo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Missing required command: $command" >&2
    echo "Install git-filter-repo before running this migration." >&2
    exit 1
  fi
done

if [[ -e "$WORKDIR" ]]; then
  echo "Refusing to reuse existing work directory: $WORKDIR" >&2
  exit 1
fi

if git ls-remote --heads "$TARGET_REPO" | grep -q .; then
  echo "Target repository already contains branches; create an empty repository." >&2
  exit 1
fi

mkdir -p "$WORKDIR"
MIRROR="$WORKDIR/decky-plugin-auditor.git"

echo "Cloning source history..."
git clone --mirror "$SOURCE_REPO" "$MIRROR"
cd "$MIRROR"

for required_ref in "$SOURCE_MAIN_REF" "$SOURCE_CAPA_REF"; do
  if ! git show-ref --verify --quiet "$required_ref"; then
    echo "Required source ref is missing: $required_ref" >&2
    exit 1
  fi
done

# Keep only the stable baseline and the unmerged capa work. Removing unrelated
# refs before filtering avoids carrying store feature branches into the new
# standalone repository.
while IFS= read -r ref; do
  case "$ref" in
    "$SOURCE_MAIN_REF"|"$SOURCE_CAPA_REF") ;;
    *) git update-ref -d "$ref" ;;
  esac
done < <(git for-each-ref --format='%(refname)')

FILTER_ARGS=(
  --path .github/workflows/plugin-security-audit.yml
  --path .github/workflows/scheduled-security-audit.yml
  --path .github/workflows/capa-binary-smoke.yml
  --path .gitignore
  --path LICENSE
  --path additional_plugins.txt
  --path artifact_diff_filters.py
  --path audit_noise_filters.py
  --path audit_plugins.py
  --path audit_plugins_core.py
  --path behavior_false_positive_filters.py
  --path credential_exposure_filters.py
  --path metadata_build_stamp_filters.py
  --path network_destination_filters.py
  --path plugin_release_utils.py
  --path pyproject.toml
  --path report_layout_filters.py
  --path security-allowlist.yml
  --path security-policy.yml
  --path semgrep-fixtures
  --path semgrep-rules.yml
  --path semgrep_source_link_hardening.py
  --path semgrep_source_scanning.py
  --path source_content_comparison.py
  --path source_content_hardening.py
  --path trivy_source_scanning.py
  --path upstream_source_links.py
  --path uv.lock

  # Audit tests from main. Store/catalog tests are intentionally excluded.
  --path tests/test_artifact_diff_filters.py
  --path tests/test_artifact_diff_reporting.py
  --path tests/test_audit_noise_filters.py
  --path tests/test_audit_plugins.py
  --path tests/test_behavior_false_positive_filters.py
  --path tests/test_credential_exposure_filters.py
  --path tests/test_metadata_build_stamp_filters.py
  --path tests/test_network_destination_filters.py
  --path tests/test_network_destination_packaged_python.py
  --path tests/test_network_destination_provenance.py
  --path tests/test_report_layout_filters.py
  --path tests/test_semgrep_full_store_noise_filters.py
  --path tests/test_semgrep_rule_contract.py
  --path tests/test_semgrep_source_link_hardening.py
  --path tests/test_semgrep_source_scanning.py
  --path tests/test_source_content_comparison.py
  --path tests/test_source_content_hardening.py
  --path tests/test_trivy_source_scanning.py
  --path tests/test_upstream_source_link_duplicates.py
  --path tests/test_upstream_source_links.py

  # Paths that exist only on the capa branch. Keeping them preserves a clean
  # feature diff without placing capa on the new repository's main branch.
  --path capa-fixtures
  --path capa_binary_analysis.py
  --path capa_review_filters.py
  --path scripts/install_capa.sh
  --path tests/test_capa_binary_analysis.py
  --path tests/test_capa_policy_defaults.py
  --path tests/test_capa_review_filters.py
)

echo "Filtering repository history to auditor-owned paths..."
git filter-repo --force "${FILTER_ARGS[@]}"

# Present capa honestly as experimental work in the new repository.
git branch -m agent/capa-binary-capabilities experimental/capa-binary-analysis
git symbolic-ref HEAD refs/heads/main

git remote add target "$TARGET_REPO"

echo "Pushing extracted branches..."
git push target "$SOURCE_MAIN_REF:$SOURCE_MAIN_REF"
git push target "$TARGET_CAPA_REF:$TARGET_CAPA_REF"

cat <<EOF

Extraction complete.

Pushed:
  main
  experimental/capa-binary-analysis

Next steps:
  1. Set main as the target repository's default branch.
  2. Run the full test suite on main.
  3. Add an auditor-specific README in a separate bootstrap commit.
  4. Open experimental/capa-binary-analysis as a draft PR against main.
  5. Do not delete audit code from the store repository until parity passes.

Filtered mirror retained at:
  $MIRROR
EOF
