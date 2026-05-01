#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/checksums.sha256" >&2
  exit 2
fi

manifest=$1
if [[ ! -f "$manifest" ]]; then
  echo "Manifest not found: $manifest" >&2
  exit 1
fi

manifest_dir="$(cd "$(dirname "$manifest")" && pwd)"
manifest_file="$(basename "$manifest")"

cd "$manifest_dir"
sha256sum --check --strict "$manifest_file"
