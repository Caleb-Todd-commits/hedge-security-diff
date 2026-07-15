#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-/tmp/hedge-demo-notes}"

node "$root/examples/demo-notes/scripts/create-demo-repo.mjs" "$target"

echo
echo "Prepared demo repository: $target"
echo "Use the commands in examples/demo-notes/README.md to replay the risk, silence, remediation, and injection scenarios."
