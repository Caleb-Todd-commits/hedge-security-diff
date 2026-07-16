# Implementation status

## Working in the package

| Area                                      | Status                          | Evidence                                                                                 |
| ----------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------------- |
| TypeScript project                        | Working                         | `npm run typecheck`                                                                      |
| GitHub Action and CLI                     | Built                           | committed `dist/action/index.cjs`; release-packaged `dist/cli/index.cjs`                 |
| Installer and diagnostics                 | Working                         | `hedge install`, `hedge doctor`                                                          |
| Baseline and reviewed context             | Working                         | atomic writes, full-register digest, policy/context/source binding, legacy migration     |
| Security architecture diff                | Working                         | node/edge added, removed, and changed sets                                               |
| Next.js / Express AST extraction          | Working, intentionally narrow   | Server Actions, matchers, wrappers, ordered/scoped middleware, helper/request influence  |
| Prisma sensitivity extraction             | Working, common schema patterns | sensitive fields and public read paths                                                   |
| GitHub workflow analysis                  | Working                         | permissions, secrets, untrusted interpolation, PR-head checkout                          |
| Explicit security invariants              | Working                         | trusted configuration, four-state evaluation, evidence-linked findings, Action decisions |
| Observation/inference/decision model      | Working                         | deterministic facts, confidence-bearing hypotheses, auditable allow/warn/block record    |
| End-to-end replay harness                 | Working                         | `hedge replay`, base/head fixture, recorded model boundary, expected-result assertions   |
| Deterministic custom policies             | Working                         | trusted `.hedge.yml` policy rules                                                        |
| GPT-5.6 routing                           | Implemented                     | Luna triage, Sol interpretation, Structured Outputs, safe fallback                       |
| Evidence validation                       | Working                         | model findings must cite actual delta evidence                                           |
| Prompt-injection boundary                 | Working                         | no tools, redaction, boundary-failure rejection, evidence-only claims, safe rendering    |
| Reports                                   | Working                         | Markdown, interactive HTML, SARIF, delta JSON, analysis JSON                             |
| GitHub annotations and idempotent comment | Working                         | file/line annotations and one marked comment                                             |
| Risk lifecycle                            | Working                         | open, mitigation detected, verification available, verified, accepted                    |
| Run history                               | Working                         | bounded persisted graph/risk history                                                     |
| Suggested witness materialization         | Working                         | `hedge witness HEDGE-NNN`                                                                |
| Codex remediation handoff                 | Implemented workflow            | authorized comment, isolated Codex job, patch-only handoff, draft PR                     |
| Counterfactual verification               | Implemented workflow            | vulnerable/repaired/legitimate checks and state PR                                       |
| Risk acceptance                           | Implemented workflow            | authorized reason, actor/time record, state PR                                           |
| Proof bundle                              | Working                         | SHA-256 manifest plus graph/register/source coherence                                    |
| Public JSON Schemas                       | Generated                       | `schemas/*.schema.json`                                                                  |
| DriftBench                                | 45 cases pass                   | `eval/results.md`, `eval/results.json`                                                   |
| Unit/contract/replay/schema tests         | 226 pass                        | `npm test`                                                                               |
| Demo repository                           | Working generator               | prepared branches and executable witness                                                 |

## Implemented but not live-validated here

The prior published v0.5.1 Action is invoked by a GitHub-hosted self-test without an OpenAI key. This v0.5.2 candidate is validated locally and still needs its own hosted smoke test. The approval-gated Codex remediation and verification workflows require a target pull request, repository permissions, and OpenAI credentials. Their local contracts and security boundaries are tested, but this package does not claim that a remote Codex remediation PR has already been opened or that production precision/cost has been measured.

## Deliberately limited

- TypeScript only; focused on Next.js App Router and common Express patterns.
- No complete cross-file or cross-language data-flow proof.
- Same-repository pull requests in the Build Week workflow.
- No automatic exploitability verdict or guarantee of safe remediation.
- Custom policy matching is intentionally small and deterministic.
- The proof bundle is tamper-evident but not cryptographically signed.
- GPT-5.6 precision, repeated-run stability, latency, and cost require API-backed runs.

## Submission quality gate

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

A live repository must then prove the complete remote workflow before recording the final video.
