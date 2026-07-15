#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
demo="$(mktemp -d "${TMPDIR:-/tmp}/hedge-release-demo.XXXXXX")"
trap 'rm -rf "$demo"' EXIT

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
node scripts/witness.mjs >/dev/null

git switch demo/03-upload-remediation >/dev/null
if node scripts/witness.mjs >/dev/null 2>&1; then
  echo "Expected the repaired branch to block the exploit witness." >&2
  exit 1
fi
node scripts/legitimate.mjs >/dev/null

git switch demo/02-benign-refactor >/dev/null
node "$root/dist/cli/index.cjs" check \
  --root . \
  --base main \
  --head demo/02-benign-refactor \
  --offline \
  --json "$demo/benign.json" >/dev/null

node - "$demo/risk.json" "$demo/benign.json" <<'NODE'
const fs = require("node:fs");
const [riskPath, benignPath] = process.argv.slice(2);
const risk = JSON.parse(fs.readFileSync(riskPath, "utf8"));
const benign = JSON.parse(fs.readFileSync(benignPath, "utf8"));
const findings = (value) => value.findings ?? value.newFindings ?? value.register?.findings ?? [];
const surfaceChanged = (value) => value.surfaceChanged ?? value.delta?.surfaceChanged;
if (surfaceChanged(risk) !== true || findings(risk).length === 0) {
  throw new Error("The vulnerable demo branch did not produce a security architecture delta and finding.");
}
if (surfaceChanged(benign) !== false || findings(benign).length !== 0) {
  throw new Error("The benign demo branch did not remain silent.");
}
NODE

echo "Hedge demo validation passed."
