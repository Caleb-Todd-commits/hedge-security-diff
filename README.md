# Hedge

**Security architecture diffs for pull requests.**

[![CI](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/ci.yml)
[![Demo](https://img.shields.io/badge/demo-security%20diff-1f6f50)](https://caleb-todd-commits.github.io/hedge-security-diff/)

> Git shows which lines changed. Hedge shows how the system's attack surface, trust boundaries, privilege, controls, and data flows changed.

Hedge is a TypeScript GitHub Action and CLI that maintains an evidence-linked security architecture model. It stays silent on changes that do not alter the modeled surface. When a pull request changes a meaningful path, Hedge explains the delta, records design-level risks, suggests executable regression witnesses, and supports an approval-gated Codex remediation flow.

Hedge **surfaces attack-surface changes and design risks**. It does not claim to find or prove vulnerabilities.

## What is implemented

- `hedge install`, `hedge doctor`, `hedge init`, `hedge context`, `hedge check`, `hedge explain`, `hedge history`, `hedge witness`, `hedge bundle`, `hedge verify-bundle`, `hedge status`, `hedge prune`, `hedge verify`, `hedge fix-plan`, `hedge replay`, and `hedge eval`.
- Node 24 GitHub Action bundle and Node 22 CLI bundle.
- Handler-scoped TypeScript AST extraction for Next.js App Router, exported Server Actions, Next.js middleware matchers, and basic Express routing.
- Dynamic, required catch-all, optional catch-all, and route-group normalization; exported aliases; inline/named handlers; custom Express router receivers; and order/path-aware middleware.
- Evidence-linked routes and Server Actions, authentication, authorization, ownership, validation, rate limits, upload limits, database operations, object storage, external calls, command execution, logging, environment credentials, workflows, dependencies, and Prisma models.
- Stable attack-surface graph and Mermaid rendering with red risk paths, amber additions, and green verified paths.
- Security architecture graph diffs and silence-by-default behavior.
- Trusted-base loading of `.hedge.yml`, `.hedge/context.yml`, and `threatmodel.json` for pull requests.
- GitHub API patch collection bounded by the trusted base policy.
- GPT-5.6 Luna/Sol routing with Structured Outputs and combined token usage reporting.
- Evidence-reference validation: unsupported model claims are omitted rather than converted into fake provenance.
- Prompt-injection isolation: repository content is delimited untrusted data, credential-shaped values are redacted before model/report use, analysis receives no shell or GitHub-write tools, and a boundary-failure response is discarded.
- Stable `HEDGE-NNN` register, fingerprint deduplication, recorded acceptance, verification history, bounded architecture-run history, atomic state writes, and full-register integrity sealing.
- Lifecycle: `open → mitigation-detected → verification-available → verified`.
- Idempotent PR reports containing a machine-readable handoff payload.
- Approval-gated `@hedge fix HEDGE-NNN` example using `openai/codex-action@v1`, an isolated patch artifact, and a separate draft-PR publishing job.
- Secretless counterfactual verification workflow that records executable evidence through the published Action and opens a reviewable state PR.
- Reviewable post-merge model-refresh PR workflow.
- 45-case deterministic DriftBench suite and 121 unit/contract/schema tests.
- A materialized demo repository with prepared Git branches and a real before/after upload witness.
- Standalone interactive HTML dashboard, Markdown report, SARIF 2.1.0, machine-readable delta/analysis JSON, and GitHub annotations.
- Organization-defined deterministic architecture policies in trusted `.hedge.yml`.
- First-class security invariants that transition between `satisfied`, `violated`, `not-applicable`, and `unknown` and can directly drive the Action decision.
- Strict observation → inference → decision separation so deterministic repository facts never silently become model conclusions or merge verdicts.
- Replayable end-to-end fixtures that run base/head extraction, graph diffing, recorded model boundaries, invariant evaluation, reports, SARIF, and expected-result assertions.
- Tamper-evident proof bundles with artifact SHA-256 digests and a self-verifying manifest.
- Generated Draft 2020-12 JSON Schemas for every public Hedge artifact.

## Quick start

### Judge in 30 seconds

Open the [hosted, no-install security-diff dashboard](https://caleb-todd-commits.github.io/hedge-security-diff/). It is a recorded deterministic demo artifact, so it requires no account, API key, package installation, or rebuild. The dashboard links the architecture delta to the same Markdown, SARIF, analysis JSON, and evidence included under `examples/demo-output/`.

For an executable offline demonstration after installing locked dependencies:

```bash
npm ci
npm run build
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

Supported judge platform: macOS or Linux with Node.js 22 or newer and Git. The GitHub Action runs on GitHub-hosted Linux using Node 24. Windows is not part of the Build Week validation matrix.

### Install into a repository

Install Hedge into another repository after publishing and pinning the Action:

```bash
hedge install --action-ref YOUR_ORG/hedge@PINNED_COMMIT_SHA --full
hedge doctor
hedge init --configure
```

Develop from this source package:

```bash
npm ci
npm run build
node dist/cli/index.cjs context --template
node dist/cli/index.cjs init
```

For interactive context review:

```bash
node dist/cli/index.cjs context
# or
node dist/cli/index.cjs init --configure
```

After a code change:

```bash
node dist/cli/index.cjs check --base HEAD~1 --head HEAD --offline
```

Enable GPT-5.6 reasoning:

```bash
export OPENAI_API_KEY="..."
node dist/cli/index.cjs check --base HEAD~1 --head HEAD
```

Create durable review artifacts:

```bash
node dist/cli/index.cjs explain HEDGE-001
node dist/cli/index.cjs witness HEDGE-001
node dist/cli/index.cjs history
node dist/cli/index.cjs bundle --base HEAD~1 --head HEAD
node dist/cli/index.cjs verify-bundle .hedge/proof/manifest.json
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

Run quality gates:

```bash
npm run typecheck
npm test
npm run eval
npm run build
npm run validate:release
npm run validate:demo
npm run audit:high
```

## Generated artifacts

- `THREATMODEL.md` — human-readable assets, surfaces, risks, assumptions, unknowns, and Mermaid graph.
- `threatmodel.json` — machine-readable graph, risks, statuses, evidence, verification, and acceptance history.
- `.hedge/context.yml` — reviewed facts source code cannot reliably infer.
- `.hedge/graph.json` — standalone graph snapshot.
- `.hedge/report.md` — current security-diff report.
- `.hedge/report.html` — standalone interactive security-diff dashboard.
- `.hedge/results.sarif` — SARIF 2.1.0 results for GitHub code scanning.
- `.hedge/delta.json` and `.hedge/analysis.json` — machine-readable architecture delta and reasoning result.
- `.hedge/proof/` — tamper-evident evidence bundle and digest manifest.
- `schemas/` — Draft 2020-12 schemas for graph, register, config, context, verification, and analysis artifacts.

## GitHub Action

Use a published Hedge revision pinned to an immutable commit. The target repository's pull-request workflow may check out the head for **reading only**; Hedge loads policy, manual context, and baseline state from the trusted base SHA through the GitHub API.

```yaml
name: Hedge
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  security-diff:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false

      - uses: YOUR_ORG/hedge@PINNED_COMMIT_SHA
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          github-token: ${{ github.token }}
```

See `examples/workflows/` for the PR check, model refresh, Codex remediation, and counterfactual verification workflows.

## Core pipeline

```text
Trusted base policy, context, and register
                  +
       Pull-request source evidence
                  ↓
     Handler-scoped AST extraction
                  +
 Trusted policies + explicit security invariants
                  ↓
   Evidence-linked attack-surface graph
                  ↓
        Security architecture diff
                  ↓
 No delta → no model call and no PR comment
                  ↓
 Luna triage → forced Sol interpretation for sensitive deltas
                  ↓
 Schema validation + evidence resolution
                  ↓
 Observation → inference → decision record
                  ↓
 Stable risk + invariant + suggested witness
                  ↓
 Maintainer-approved Codex draft repair PR
                  ↓
 Secretless before/after verification evidence
                  ↓
 Reviewable state update + proof bundle
```

## Product principles

1. **Security diff, not scanner replacement.** The unit of value is a changed path, privilege, control, or trust boundary.
2. **Evidence before interpretation.** Deterministic extraction establishes what changed; GPT-5.6 explains why it may matter.
3. **Silence is a feature.** No modeled delta means no comment and no model spend.
4. **Unknown stays unknown.** Deployment facts are reviewed through five context questions or shown as uncertainty.
5. **A test file is not proof.** Verification requires a reproduced witness, a blocked repaired witness, preserved legitimate behavior, and an architecture-control change.
6. **Codex acts only after approval.** It edits an isolated checkout and transfers a patch to a separate publishing job.
7. **PRs cannot weaken their own judge.** Policy, reviewed context, baseline state, and patch budgets come from the trusted base revision.
8. **Audit evidence must survive the comment thread.** Reports, SARIF, schemas, run history, and proof bundles are first-class outputs.
9. **Organization policy is deterministic.** Custom control requirements execute before model reasoning and carry exact repository evidence.
10. **Evidence must not leak credentials.** Credential-shaped literals are redacted before model calls and report generation; managed secret references remain visible as architecture.
11. **Reports are untrusted output too.** Model text is HTML-escaped, mention-neutralized, fence-safe, and bound to the analyzed commit with a digest.
12. **Partial coverage must be disclosed.** File/byte limits, skipped binaries, unreadable files, and unsupported matcher behavior remain explicit unknowns.
13. **Facts, hypotheses, and verdicts are separate.** Observations are deterministic, inferences carry confidence and assumptions, and decisions identify the policy or threshold that produced them.
14. **Security commitments are executable configuration.** Explicit invariants are versioned with the trusted base and evaluated before model reasoning.
15. **The full demo must be replayable.** Recorded model boundaries may reproduce a run, but are labeled as recorded rather than fresh API output.

## Demonstration

```bash
node examples/demo-notes/scripts/create-demo-repo.mjs /tmp/hedge-demo-notes
cd /tmp/hedge-demo-notes
git branch --list
```

The generated repository includes the upload-risk, benign-refactor, remediation, admin-route, and prompt-injection branches used by the video script.

A complete deterministic replay is also included:

```bash
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

See `docs/REPLAY.md`.

## Honest limitations

The Build Week implementation is narrow by design: TypeScript, Next.js App Router, basic Express, common Prisma/storage/network patterns, and same-repository PRs. It does not perform complete interprocedural data-flow analysis, prove deployment exposure, replace SAST/DAST or human review, or guarantee that Codex can safely repair every surfaced risk. The Codex and GitHub examples have been statically validated but cannot be claimed end-to-end against a live repository until installed with real credentials.

## Documentation

Start with [`START_HERE.md`](START_HERE.md), then read [`MASTER_PLAN.md`](MASTER_PLAN.md), [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md), [`docs/SECURITY.md`](docs/SECURITY.md), and [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md). Build Week contribution boundaries and snapshot evidence are recorded in [`docs/BUILD_WEEK_PROVENANCE.md`](docs/BUILD_WEEK_PROVENANCE.md).

## How Codex and GPT-5.6 shaped Hedge

The initial Build Week foundation was created in ChatGPT with GPT-5.6 Sol, then transferred into a primary Codex thread. GPT-5.6 is also part of Hedge's runtime: deterministic extraction establishes the architecture delta, Luna performs bounded triage, and Sol interprets evidence through strict Structured Outputs. Codex is used for repository implementation, tests, evaluation, security-boundary review, and the approval-gated draft remediation workflow. The human author retained the product direction, security commitments, and final decisions. See the [provenance record](docs/BUILD_WEEK_PROVENANCE.md) and [decision log](docs/DECISIONS.md).

## License

MIT. See [`LICENSE`](LICENSE).
