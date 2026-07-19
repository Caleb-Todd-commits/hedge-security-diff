# Start here

This archive is the working Hedge v0.5 Build Week package.

## What changed in v0.5

Hedge now supports explicit repository security invariants, keeps deterministic observations separate from risk inferences and merge decisions, and makes the recorded decision the GitHub Action failure authority. A new `hedge replay` command reproduces the complete base/head pipeline with optional schema-validated recorded model responses and expected-result assertions.

## Validate it

```bash
npm ci
npm run schemas
npm run typecheck
npm test
npm run eval
npm run build
npm run validate:release
npm run validate:demo
npm run audit:high
```

Current included validation target:

- 259 unit, workflow-contract, replay, and schema tests.
- 47 deterministic DriftBench cases.
- Next.js App Router routes, Pages API routes, middleware, Server Actions, Express ordering/scope, Prisma, GitHub workflow, policy, report, state-integrity, migration, and adversarial fixtures.
- Demo repository branch materialization and counterfactual upload witness.

These numbers describe only the included corpus, not general vulnerability-detection accuracy.

## Run it locally

```bash
node dist/cli/index.cjs doctor
node dist/cli/index.cjs context --template
node dist/cli/index.cjs init
node dist/cli/index.cjs check --base HEAD~1 --head HEAD --offline
```

Useful follow-on commands:

```bash
node dist/cli/index.cjs explain HEDGE-001
node dist/cli/index.cjs witness HEDGE-001
node dist/cli/index.cjs history
node dist/cli/index.cjs bundle --base HEAD~1 --head HEAD
node dist/cli/index.cjs verify-bundle .hedge/proof/manifest.json
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

## Install into a judge repository

```bash
curl -LO https://github.com/Caleb-Todd-commits/hedge-security-diff/releases/download/v0.5.2/hedge-v0.5.2-bundles.zip
curl -LO https://github.com/Caleb-Todd-commits/hedge-security-diff/releases/download/v0.5.2/hedge-v0.5.2-SHA256SUMS
curl -LO https://github.com/Caleb-Todd-commits/hedge-security-diff/releases/download/v0.5.2/manifest.json
curl -LO https://github.com/Caleb-Todd-commits/hedge-security-diff/releases/download/v0.5.2/security-diff.html
shasum -a 256 -c hedge-v0.5.2-SHA256SUMS
unzip hedge-v0.5.2-bundles.zip
node hedge-v0.5.2/dist/cli/index.cjs install \
  --action-ref Caleb-Todd-commits/hedge-security-diff@FULL_40_CHARACTER_COMMIT_SHA \
  --full
node hedge-v0.5.2/dist/cli/index.cjs doctor
node hedge-v0.5.2/dist/cli/index.cjs init --configure
```

## Read in this order

1. `README.md`
2. `MASTER_PLAN.md`
3. `docs/IMPLEMENTATION_STATUS.md`
4. `docs/ARCHITECTURE.md`
5. `docs/SECURITY.md`
6. `docs/EVALUATION.md`
7. `docs/DEMO_SCRIPT.md`
8. `AGENTS.md` before continuing in the primary Codex session

## Highest-value remaining work

Human-review the frozen evaluation adjudication sheet, then publish the proven commit and immutable release artifacts. Do not rerun or tune against the frozen corpus: its recorded operational gate failed and is part of the release evidence.
