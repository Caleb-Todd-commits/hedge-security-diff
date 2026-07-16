#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
demo="$(mktemp -d "${TMPDIR:-/tmp}/hedge-release-demo.XXXXXX")"
trap 'rm -rf "$demo"' EXIT

package_version="$(node -p "require('$root/package.json').version")"
cli_version="$(node "$root/dist/cli/index.cjs" --version)"
if [[ "$cli_version" != "$package_version" ]]; then
  echo "Built CLI version $cli_version does not match package version $package_version." >&2
  exit 1
fi

node "$root/examples/demo-notes/scripts/create-demo-repo.mjs" "$demo" >/dev/null
cd "$demo"
git switch main >/dev/null
node "$root/dist/cli/index.cjs" init --root . >/dev/null

git switch demo/01-file-upload-risk >/dev/null
node "$root/dist/cli/index.cjs" check \
  --root . \
  --base main \
  --head demo/01-file-upload-risk \
  --offline \
  --json "$demo/risk.json" >/dev/null
HEDGE_OUTCOME_PATH="$demo/vulnerable-witness.json" node scripts/witness.mjs > "$demo/vulnerable-witness.stdout.json"
cmp "$demo/vulnerable-witness.json" "$demo/vulnerable-witness.stdout.json"
node -e "const fs=require('node:fs'),crypto=require('node:crypto'); process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync('scripts/witness.mjs')).digest('hex'))" > "$demo/vulnerable-witness.sha256"

git switch demo/03-upload-remediation >/dev/null
HEDGE_OUTCOME_PATH="$demo/repaired-witness.json" node scripts/witness.mjs > "$demo/repaired-witness.stdout.json"
cmp "$demo/repaired-witness.json" "$demo/repaired-witness.stdout.json"
node -e "const fs=require('node:fs'),crypto=require('node:crypto'); process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync('scripts/witness.mjs')).digest('hex'))" > "$demo/repaired-witness.sha256"
node scripts/legitimate.mjs >/dev/null

git switch demo/02-benign-refactor >/dev/null
node "$root/dist/cli/index.cjs" check \
  --root . \
  --base main \
  --head demo/02-benign-refactor \
  --offline \
  --json "$demo/benign.json" >/dev/null

node - "$demo/risk.json" "$demo/benign.json" "$demo/vulnerable-witness.json" "$demo/repaired-witness.json" "$demo/vulnerable-witness.sha256" "$demo/repaired-witness.sha256" <<'NODE'
const fs = require("node:fs");
const [riskPath, benignPath, vulnerablePath, repairedPath, vulnerableDigestPath, repairedDigestPath] = process.argv.slice(2);
const risk = JSON.parse(fs.readFileSync(riskPath, "utf8"));
const benign = JSON.parse(fs.readFileSync(benignPath, "utf8"));
const vulnerable = JSON.parse(fs.readFileSync(vulnerablePath, "utf8"));
const repaired = JSON.parse(fs.readFileSync(repairedPath, "utf8"));
const vulnerableDigest = fs.readFileSync(vulnerableDigestPath, "utf8");
const repairedDigest = fs.readFileSync(repairedDigestPath, "utf8");
const findings = (value) => value.findings ?? value.newFindings ?? value.register?.findings ?? [];
const surfaceChanged = (value) => value.surfaceChanged ?? value.delta?.surfaceChanged;
if (surfaceChanged(risk) !== true || findings(risk).length === 0) {
  throw new Error("The vulnerable demo branch did not produce a security architecture delta and finding.");
}
if (surfaceChanged(benign) !== false || findings(benign).length !== 0) {
  throw new Error("The benign demo branch did not remain silent.");
}
if (vulnerableDigest !== repairedDigest) {
  throw new Error("The vulnerable and repaired demo did not execute identical witness bytes.");
}
if (vulnerable.outcome !== "reproduced") {
  throw new Error("The vulnerable demo did not return the structured reproduced outcome.");
}
if (repaired.outcome !== "blocked-by-control") {
  throw new Error("The repaired demo did not return the structured blocked-by-control outcome.");
}
NODE

node "$root/dist/cli/index.cjs" verify-bundle "$root/examples/demo-output/proof/manifest.json" >/dev/null
node - "$root/examples/demo-output" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[2];
const read = (name) => JSON.parse(fs.readFileSync(path.join(root, name), "utf8"));
const run = read("run.json");
const analysis = read("analysis.json");
const delta = read("delta.json");
if (JSON.stringify(run.analysis) !== JSON.stringify(analysis)) {
  throw new Error("Committed demo run and analysis artifacts disagree.");
}
if (JSON.stringify(run.delta) !== JSON.stringify(delta)) {
  throw new Error("Committed demo run and delta artifacts disagree.");
}
if (analysis.coverage?.status !== "complete" || analysis.analysisHealth?.status !== "complete") {
  throw new Error("Committed flagship demo does not have complete supported coverage and health.");
}
if (analysis.confirmedNoDelta === true) {
  throw new Error("Committed risk demo incorrectly claims confirmed no-delta.");
}
NODE

echo "Hedge demo validation passed."
