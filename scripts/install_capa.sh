#!/usr/bin/env bash
# Install the official standalone capa release with its matching embedded rules.
# The release asset and SHA-256 are pinned so CI never consumes mutable rules.
set -euo pipefail

CAPA_VERSION="9.4.0"
CAPA_ARCHIVE_SHA256="07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4"
CAPA_ARCHIVE_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip"
INSTALL_DIR="${1:-${HOME}/.local/bin}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

python3 - "$CAPA_ARCHIVE_URL" "$CAPA_ARCHIVE_SHA256" "$work_dir" <<'PYEOF'
from __future__ import annotations

import hashlib
import pathlib
import shutil
import sys
import urllib.request
import zipfile

url, expected_sha256, work_dir_raw = sys.argv[1:]
work_dir = pathlib.Path(work_dir_raw).resolve()
archive = work_dir / "capa.zip"
extract_dir = work_dir / "extracted"

request = urllib.request.Request(
    url,
    headers={"User-Agent": "decky-plugin-security-audit/capa-installer"},
)
with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
    shutil.copyfileobj(response, output)

actual_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
if actual_sha256 != expected_sha256:
    raise SystemExit(
        f"capa archive SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
    )

extract_dir.mkdir()
with zipfile.ZipFile(archive) as bundle:
    root = extract_dir.resolve()
    for member in bundle.infolist():
        destination = (extract_dir / member.filename).resolve()
        try:
            destination.relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"unsafe capa archive path: {member.filename!r}") from exc
    bundle.extractall(extract_dir)
PYEOF

capa_binary="$(find "$work_dir/extracted" -type f -name capa -print -quit)"
if [[ -z "$capa_binary" ]]; then
  echo "ERROR: official capa archive did not contain a capa executable" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$capa_binary" "$INSTALL_DIR/capa"

version_output="$($INSTALL_DIR/capa --version)"
if [[ "$version_output" != *"${CAPA_VERSION}"* ]]; then
  echo "ERROR: installed capa reported unexpected version: $version_output" >&2
  exit 1
fi
printf '%s\n' "$version_output"
