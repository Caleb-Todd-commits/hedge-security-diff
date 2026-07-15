# Changelog

## 0.5.1 — public, installable Build Week release

- Published the bundled Node 24 Action entry point so repository refs execute without a local build.
- Added a GitHub-hosted self-test that invokes the packaged Action against the demo repository.
- Repaired the lockfile's public-registry portability and made evaluation/schema generation deterministic.
- Added the no-install Pages dashboard, release artifacts, Build Week provenance, and expanded clean-run CI.
- Expanded the automated suite from 120 to 121 tests.

## 0.5.0 — invariants, evidence layers, and reproducible replays

- Added first-class security invariants with explicit matching, required controls, four-state evaluation, evidence, and deterministic invariant findings.
- Added strict deterministic observation, security inference, and policy decision artifacts to every meaningful analysis.
- Made the recorded `allow`, `warn`, or `block` decision the GitHub Action failure authority and exposed it as an Action output.
- Persisted latest invariant evaluations in the sealed threat register and rendered them in the living threat model.
- Added `hedge replay` for complete base/head pipeline reproduction with optional recorded GPT-5.6 boundaries and expected-result assertions.
- Added a bundled upload-invariant replay that produces Markdown, HTML, SARIF, delta, analysis, and replay-result artifacts.
- Added report and SARIF visibility for invariant states, evidence-layer counts, and decisions.
- Expanded the automated suite from 113 to 117 tests.

## 0.4.0 — correctness and adversarial hardening

- Made Express middleware application source-order-aware and path-aware instead of treating every `app.use` as global protection.
- Added custom Express router receivers, chained route declarations, identifier middleware inference, and same-file helper taint propagation.
- Added Next.js middleware matcher support with conservative handling of complex patterns and evidence pointing to the middleware source file.
- Added module-level and function-level Next.js Server Actions as first-class callable entry points.
- Added stable semantic operation/control identities so harmless line movement no longer appears as an architecture change.
- Added request and secret influence propagation through destructuring, assignments, helper arguments, and multiple same-line operations.
- Added explicit source-coverage accounting for skipped binaries, limits, symlinks, unreadable files, and unsupported evidence.
- Made state writes atomic and extended integrity protection from the graph to findings, run history, verification, and acceptance records.
- Added a versioned integrity format with safe legacy graph-digest migration through `hedge doctor` and the next baseline refresh.
- Corrected unresolved-risk accounting so `mitigation-detected` and `verification-available` findings continue to block until verified or accepted.
- Forced deep GPT-5.6 review for deterministically sensitive deltas even when low-cost triage would suppress escalation.
- Reject model responses that report an instruction-boundary failure or cite evidence outside the actual architecture delta.
- Bound machine-readable PR handoffs to the exact source commit and a payload digest; reject stale remediation commands.
- Escaped model-generated HTML/Markdown, neutralized GitHub mentions, hardened code fences and Mermaid labels, and expanded credential redaction.
- Prioritized GitHub patch evidence by security relevance and made byte truncation UTF-8 safe.
- Hardened verification refs, JSON evidence generation, and risk-acceptance reason transport against shell/output injection.
- Expanded DriftBench from 38 to 45 cases and the automated suite from 72 to 113 tests.

## 0.3.0 — expanded product foundation

- Replaced broad file heuristics with handler-scoped TypeScript analysis that follows same-file helpers, wrappers, and Express middleware.
- Added request-influence tracking, fixed-host SSRF distinction, secret-alias logging detection, sensitive Prisma model analysis, and GitHub workflow privilege checks.
- Added interactive HTML, SARIF 2.1.0, GitHub annotations, machine-readable delta/analysis JSON, and generated public JSON Schemas.
- Added trusted organization architecture policies to `.hedge.yml`.
- Added state-integrity and policy/context/source binding checks plus bounded run history.
- Added `install`, `doctor`, `explain`, `history`, `witness`, `bundle`, and `verify-bundle` CLI commands.
- Added tamper-evident proof bundles and artifact digest verification.
- Completed Action-backed verification and risk-acceptance state workflows.
- Added pre-model and pre-report credential redaction while preserving safe managed-secret references.
- Marked OpenAI and GitHub credentials as masked values in the Action runtime.
- Expanded DriftBench to 38 cases and the automated suite to 72 tests.

## 0.2.0 — Working Build Week foundation

- Replaced broad pattern-only route analysis with handler-scoped TypeScript AST extraction.
- Added Next.js aliases, route groups, dynamic/catch-all routes, and Express inline/named handlers.
- Added control and capability extraction for auth, authorization, ownership, validation, upload limits, Prisma, storage, network, command execution, logs, and credential use.
- Added reviewed five-question context through `.hedge/context.yml` and `hedge context`.
- Loaded PR policy, context, baseline register, and patch budgets from the trusted base SHA.
- Added GitHub API PR patch collection.
- Added evidence-reference validation for model findings and combined Luna/Sol usage accounting.
- Expanded deterministic rules for control regressions, storage boundaries, data writes, secrets, SSRF, command execution, logging, and risky workflows.
- Added machine-readable PR payloads and an approval-gated Codex remediation workflow example.
- Added secretless counterfactual verification and reviewable post-merge model-refresh workflows.
- Added recorded risk acceptance and full verification history.
- Expanded DriftBench from 7 to 30 cases.
- Expanded tests from 10 to 27.
- Added a real demo repository generator with prepared Git branches and before/after witness scripts.
- Improved Mermaid diagrams with risk, addition, and verified path styling.

## 0.1.0 — Initial Build Week skeleton

- Added Action, CLI, schemas, graph, register, model routing, initial heuristics, seven fixtures, and planning documentation.
