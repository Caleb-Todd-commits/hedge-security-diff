#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
replay_output="$(mktemp -d "${TMPDIR:-/tmp}/hedge-release-replay.XXXXXX")"
trap 'rm -rf "$replay_output"' EXIT
cd "$root"

npm run format:check
npm run typecheck
npm test
node dist/cli/index.cjs --help >/dev/null
node dist/cli/index.cjs doctor --root . >/dev/null
node dist/cli/index.cjs verify-bundle examples/demo-output/proof/manifest.json >/dev/null
node dist/cli/index.cjs replay examples/replays/upload-invariant --output "$replay_output" >/dev/null
[[ -f dist/action/index.cjs ]]
[[ -x dist/cli/index.cjs ]]
[[ -f schemas/attack-surface.schema.json ]]
[[ -f schemas/security-invariant.schema.json ]]
[[ -f "$replay_output/replay-result.json" ]]
[[ -f examples/demo-output/security-diff.html ]]
[[ -f examples/demo-output/results.sarif ]]

echo "Hedge release validation passed."
