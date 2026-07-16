# Hedge

**Security architecture diffs for pull requests.**

[![CI](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/ci.yml)
[![Action self-test](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/action-self-test.yml/badge.svg)](https://github.com/Caleb-Todd-commits/hedge-security-diff/actions/workflows/action-self-test.yml)
[![Release](https://img.shields.io/github/v/release/Caleb-Todd-commits/hedge-security-diff)](https://github.com/Caleb-Todd-commits/hedge-security-diff/releases/latest)
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
- Exact base/head graph extraction from bounded Git object bytes, independent of the checked-out working tree and stored graph cache.
- First-class `coverage`, `analysisHealth`, and `confirmedNoDelta` results; inferred controls and incomplete evidence remain unknown.
- Trusted-base loading of `.hedge.yml`, `.hedge/context.yml`, and `threatmodel.json` for pull requests.
- GitHub API patch collection bounded by the trusted base policy.
- Cost-bounded GPT-5.6 routing with strict Structured Outputs: routine deterministic recommendations use zero calls, sensitive/high-consequence deltas go directly to Sol, and ambiguous deltas use Luna before optional Sol.
- Credential-separated PR execution: secretless collection, no-checkout model reasoning, and a no-OpenAI-key publisher connected by RunManifest v0.1 SHA-256 bindings.
- Evidence-reference validation: unsupported model claims are omitted rather than converted into fake provenance.
- Prompt-injection isolation: repository content is delimited untrusted data, credential-shaped values are redacted before model/report use, analysis receives no shell or GitHub-write tools, and a boundary-failure response is discarded.
- Stable `HEDGE-NNN` register, fingerprint deduplication, recorded acceptance, verification history, bounded architecture-run history, atomic state writes, and full-register integrity sealing.
- Lifecycle: `open → mitigation-detected → verification-available → verified`.
- Idempotent PR reports containing a machine-readable handoff payload.
- Approval-gated `@hedge fix HEDGE-NNN` example using an immutable `openai/codex-action` commit, an isolated patch artifact, normalized per-risk concurrency, and a separate draft-PR publishing job.
- Secretless counterfactual verification workflow that records executable evidence through the published Action and opens a reviewable state PR.
- Reviewable post-merge model-refresh PR workflow.
- 45-case deterministic DriftBench suite and 254 unit, contract, replay, and schema tests.
- A materialized demo repository with prepared Git branches and a real before/after upload witness.
- Standalone interactive HTML dashboard, Markdown report, SARIF 2.1.0, machine-readable delta/analysis JSON, and GitHub annotations.
- Organization-defined deterministic architecture policies in trusted `.hedge.yml`.
- First-class security invariants that transition between `satisfied`, `violated`, `not-applicable`, and `unknown` and can directly drive the Action decision.
- Strict observation → inference → decision separation so deterministic repository facts never silently become model conclusions or merge verdicts.
- Replayable end-to-end fixtures that run base/head extraction, graph diffing, recorded model boundaries, invariant evaluation, reports, SARIF, and expected-result assertions.
- Tamper-evident proof bundles with artifact SHA-256 digests and a self-verifying manifest.
- Generated Draft 2020-12 JSON Schemas for the graph, register, configuration, context, verification, analysis, invariant, RunManifest, collection-bundle, and reason-bundle interfaces.

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
hedge install --action-ref OWNER/REPOSITORY@FULL_40_CHARACTER_COMMIT_SHA --full
hedge doctor
hedge init --configure
```

Replace the placeholder with the immutable commit SHA of the published green release.

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

### Model spend guardrails

Hedge spends model tokens only where deterministic evidence leaves useful interpretation work:

| Result                                             | Model route                      | Maximum calls |
| -------------------------------------------------- | -------------------------------- | ------------: |
| Complete exact no-delta                            | No model                         |             0 |
| Low/medium deterministic recommendation            | No model                         |             0 |
| Deterministically sensitive or high/critical delta | Sol directly                     |             1 |
| Ambiguous architecture delta                       | Luna, then Sol only if requested |             2 |

Luna uses minimal reasoning, a 384-output-token ceiling, and at most 12 KiB of UTF-8-safe patch data. Sol uses low reasoning, a 4,096-output-token ceiling, and at most 48 KiB of patch data. The complete serialized request is also rejected locally above 48 KiB for Luna or 160 KiB for Sol. The output ceilings cover visible and reasoning output; they are not total request-token caps. Structured prompt inputs are minified, automatic retries are disabled, and accepted model claims must still resolve to the exact deterministic evidence index. Coverage and health remain independent: skipping unnecessary model work never upgrades a partial result to complete.

Usage reports provider-returned input, output, cached-input, reasoning, and total tokens rather than guessing a dollar price. Hedge relies only on provider-default implicit prompt caching; explicit cache writes remain disabled until repeated stable-prefix reuse is measured, since low reuse can make an explicit write policy cost more.

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
- `.hedge/pipeline/` — bounded collection/reason bundles and RunManifest v0.1 handoffs for GitHub jobs.
- `.hedge/proof/` — tamper-evident evidence bundle and digest manifest.
- `schemas/` — Draft 2020-12 schemas for graph, register, config, context, verification, analysis, invariants, RunManifest, and staged collection/reason bundles.

## GitHub Action

Use a published Hedge revision pinned to its immutable 40-character commit SHA. `hedge install` writes the complete three-job workflow from `examples/workflows/hedge.yml`: `collect` has a read-only checkout and no OpenAI key, `reason` has the OpenAI key but no checkout or write authority, and `publish` has GitHub write authority but no OpenAI key. The workflow definition comes from the trusted base branch through `pull_request_target`; the pull-request head is checked out only in the secretless collector and is never executed.

```bash
hedge install \
  --action-ref OWNER/REPOSITORY@FULL_40_CHARACTER_COMMIT_SHA \
  --full
```

The installer is additive by default and will not overwrite an existing workflow unless `--force` is supplied. Run `hedge doctor` afterward from the repository root; from a nested directory, pass the repository path with `--root`.

You do not create or paste a GitHub personal access token for the installed workflows. GitHub automatically issues the short-lived `${{ github.token }}` with each job's declared permissions. Local repository administration uses your normal `gh auth login --web` session; only `OPENAI_API_KEY` is stored as a repository secret for the isolated reasoning and Codex jobs.

See `examples/workflows/` for the PR check, model refresh, Codex remediation, and counterfactual verification workflows.

## Core pipeline

```text
Trusted base policy, context, and valid lifecycle register
                  +
       Exact base/head Git object bytes
                  ↓
     Handler-scoped AST extraction
                  +
 Trusted policies + explicit security invariants
                  ↓
   Evidence-linked attack-surface graph
                  ↓
        Security architecture diff
                  ↓
 Complete exact no delta → no model call/comment; remove stale report
                  ↓
 RunManifest-bound handoff to no-checkout reasoning job
                  ↓
 Cost router → deterministic-only / direct Sol / Luna → optional Sol
                  ↓
 Schema validation + evidence resolution
                  ↓
 Observation → inference → decision record
                  ↓
 Stale-head recheck in no-OpenAI-key publisher
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
16. **Spend follows uncertainty.** Complete routine deterministic results use no model; bounded reasoning is reserved for sensitive or ambiguous architecture changes.

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

The initial Build Week foundation was created in ChatGPT with GPT-5.6 Sol, then transferred into a primary Codex thread. GPT-5.6 is also part of Hedge's runtime: deterministic extraction establishes the architecture delta, routine recommendations remain deterministic-only, sensitive changes route directly to Sol, and Luna triages only ambiguous changes before optional Sol interpretation through strict Structured Outputs. Codex is used for repository implementation, tests, evaluation, security-boundary review, and the approval-gated draft remediation workflow. The human author retained the product direction, security commitments, and final decisions. See the [provenance record](docs/BUILD_WEEK_PROVENANCE.md) and [decision log](docs/DECISIONS.md).

## License

MIT. See [`LICENSE`](LICENSE).
