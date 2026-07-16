#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
demo="$(mktemp -d "${TMPDIR:-/tmp}/hedge-demo-source.XXXXXX")"
stage="$(mktemp -d "${TMPDIR:-/tmp}/hedge-demo-output.XXXXXX")"
output="$root/examples/demo-output"
cli="$root/dist/cli/index.cjs"

package_version="$(node -p "require('$root/package.json').version")"
cli_version="$(node "$cli" --version)"
if [[ "$cli_version" != "$package_version" ]]; then
  echo "Built CLI version $cli_version does not match package version $package_version." >&2
  exit 1
fi

node "$root/examples/demo-notes/scripts/create-demo-repo.mjs" "$demo" >/dev/null
cd "$demo"
base_sha="$(git rev-parse main)"
head_sha="$(git rev-parse demo/01-file-upload-risk)"

git switch main >/dev/null
GITHUB_SHA="$base_sha" node "$cli" init --root . >/dev/null

git switch demo/01-file-upload-risk >/dev/null
GITHUB_SHA="$head_sha" node "$cli" check \
  --root . \
  --base "$base_sha" \
  --head "$head_sha" \
  --offline \
  --persist \
  --json "$stage/run.json" >/dev/null
node "$cli" witness HEDGE-001 --root . --output hedge-001.security.test.ts >/dev/null
node "$cli" bundle \
  --root . \
  --output .hedge/proof \
  --base "$base_sha" \
  --head "$head_sha" >/dev/null
node "$cli" verify-bundle .hedge/proof/manifest.json >/dev/null

cp .hedge/report.html "$stage/security-diff.html"
cp .hedge/report.md "$stage/security-diff.md"
cp .hedge/results.sarif "$stage/results.sarif"
cp .hedge/delta.json "$stage/delta.json"
cp .hedge/analysis.json "$stage/analysis.json"
cp hedge-001.security.test.ts "$stage/hedge-001.security.test.ts"
mkdir -p "$stage/proof/artifacts"
cp .hedge/proof/manifest.json "$stage/proof/manifest.json"
cp -R .hedge/proof/artifacts/. "$stage/proof/artifacts/"

node - "$stage" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[2];
const read = (name) => JSON.parse(fs.readFileSync(path.join(root, name), "utf8"));
const run = read("run.json");
const analysis = read("analysis.json");
const delta = read("delta.json");
if (JSON.stringify(run.analysis) !== JSON.stringify(analysis)) {
  throw new Error("Generated run and analysis artifacts disagree.");
}
if (JSON.stringify(run.delta) !== JSON.stringify(delta)) {
  throw new Error("Generated run and delta artifacts disagree.");
}
if (run.surfaceChanged !== true || analysis.surfaceChanged !== true || analysis.findings.length < 1) {
  throw new Error("Generated risk scenario did not record an architecture delta and finding.");
}
if (analysis.coverage?.status !== "complete" || analysis.analysisHealth?.status !== "complete") {
  throw new Error("Generated flagship demo does not have complete supported coverage and health.");
}
if (analysis.confirmedNoDelta === true) {
  throw new Error("Generated risk demo incorrectly claims confirmed no-delta.");
}
NODE

node "$cli" verify-bundle "$stage/proof/manifest.json" >/dev/null
mkdir -p "$output/proof/artifacts"
for name in security-diff.html security-diff.md results.sarif delta.json analysis.json run.json hedge-001.security.test.ts; do
  cp "$stage/$name" "$output/$name"
done
cp "$stage/proof/manifest.json" "$output/proof/manifest.json"
cp -R "$stage/proof/artifacts/." "$output/proof/artifacts/"

echo "Regenerated Hedge demo output from $base_sha..$head_sha."
