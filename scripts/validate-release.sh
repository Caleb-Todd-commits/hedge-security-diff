#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
replay_output="$(mktemp -d "${TMPDIR:-/tmp}/hedge-release-replay.XXXXXX")"
install_root="$(mktemp -d "${TMPDIR:-/tmp}/hedge-release-install.XXXXXX")"
trap 'rm -rf "$replay_output" "$install_root"' EXIT
cd "$root"

npm run format:check
npm run typecheck
npm test
node dist/cli/index.cjs --help >/dev/null
node dist/cli/index.cjs doctor --root . >/dev/null
node dist/cli/index.cjs verify-bundle examples/demo-output/proof/manifest.json >/dev/null
node dist/cli/index.cjs replay examples/replays/upload-invariant --output "$replay_output" >/dev/null
git -C "$install_root" init --quiet
(
  cd "$(dirname "$install_root")"
  node "$root/dist/cli/index.cjs" install \
    --root "$install_root" \
    --action-ref example/hedge@0123456789012345678901234567890123456789 \
    --full >/dev/null
)
mkdir -p "$install_root/nested/project"
(
  cd "$install_root/nested/project"
  node "$root/dist/cli/index.cjs" doctor --root ../.. >/dev/null
)
[[ -f dist/action/index.cjs ]]
[[ -x dist/cli/index.cjs ]]
[[ -f dist/workflows/hedge.yml ]]
[[ -f "$install_root/.github/workflows/hedge.yml" ]]
[[ -f "$install_root/.github/workflows/hedge-fix.yml" ]]
[[ -f "$install_root/.github/workflows/hedge-verify.yml" ]]
[[ -f schemas/attack-surface.schema.json ]]
[[ -f schemas/run-manifest.schema.json ]]
[[ -f schemas/collection-bundle.schema.json ]]
[[ -f schemas/reason-bundle.schema.json ]]
[[ -f schemas/security-invariant.schema.json ]]
[[ -f "$replay_output/replay-result.json" ]]
[[ -f examples/demo-output/security-diff.html ]]
[[ -f examples/demo-output/results.sarif ]]

echo "Hedge release validation passed."
