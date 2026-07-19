# Implementation status

## Working in the package

| Area                                      | Status                          | Evidence                                                                                                              |
| ----------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| TypeScript project                        | Working                         | `npm run typecheck`                                                                                                   |
| GitHub Action and CLI                     | Built                           | committed `dist/action/index.cjs`; release-packaged `dist/cli/index.cjs`                                              |
| Installer and diagnostics                 | Working                         | `hedge install`, `hedge doctor`                                                                                       |
| Baseline and reviewed context             | Working                         | atomic writes, full-register digest, policy/context/source binding, legacy migration                                  |
| Security architecture diff                | Working                         | node/edge added, removed, and changed sets                                                                            |
| Next.js / Express AST extraction          | Working, intentionally narrow   | App Router, Pages API routes, Server Actions, matchers, wrappers, ordered/scoped middleware, helper/request influence |
| Prisma sensitivity extraction             | Working, common schema patterns | sensitive fields and public read paths                                                                                |
| GitHub workflow analysis                  | Working                         | permissions, secrets, untrusted interpolation, PR-head checkout                                                       |
| Explicit security invariants              | Working                         | trusted configuration, four-state evaluation, evidence-linked findings, Action decisions                              |
| Observation/inference/decision model      | Working                         | deterministic facts, confidence-bearing hypotheses, auditable allow/warn/block record                                 |
| End-to-end replay harness                 | Working                         | `hedge replay`, base/head fixture, recorded model boundary, expected-result assertions                                |
| Deterministic custom policies             | Working                         | trusted `.hedge.yml` policy rules                                                                                     |
| Cost-bounded GPT-5.6 routing              | Implemented                     | Zero-call deterministic paths, direct Sol for sensitive deltas, Luna for ambiguity                                    |
| Evidence validation                       | Working                         | model findings must cite actual delta evidence                                                                        |
| Prompt-injection boundary                 | Working                         | no tools, redaction, boundary-failure rejection, evidence-only claims, safe rendering                                 |
| Reports                                   | Working                         | Markdown, interactive HTML, SARIF, delta JSON, analysis JSON                                                          |
| GitHub annotations and idempotent comment | Working                         | file/line annotations and one marked comment                                                                          |
| Risk lifecycle                            | Working                         | open, mitigation detected, verification available, verified, accepted                                                 |
| Run history                               | Working                         | bounded persisted graph/risk history                                                                                  |
| Suggested witness materialization         | Working                         | `hedge witness HEDGE-NNN`                                                                                             |
| Codex remediation handoff                 | Implemented workflow            | authorized comment, isolated Codex job, patch-only handoff, draft PR                                                  |
| Counterfactual verification               | Live-proven once                | vulnerable reproduction, repaired block, legitimate success, architecture proof, reviewed state PR                    |
| Risk acceptance                           | Implemented workflow            | authorized reason, actor/time record, state PR                                                                        |
| Proof bundle                              | Working                         | SHA-256 manifest plus graph/register/source coherence                                                                 |
| Public JSON Schemas                       | Generated                       | `schemas/*.schema.json`                                                                                               |
| DriftBench                                | 47 cases pass                   | `eval/results.md`, `eval/results.json`                                                                                |
| Unit/contract/replay/schema tests         | 259 pass                        | `npm test`                                                                                                            |
| Demo repository                           | Working generator               | prepared branches and executable witness                                                                              |

## Live validation status

The v0.5.2 candidate passed public CI and its GitHub-hosted Action self-test. A judge-lab benign PR proved silence and zero model calls, while a live upload canary completed collection, GPT-5.6 Sol reasoning, publication, exact evidence, and a recorded `BLOCK` decision. The Codex remediation job produced a bounded patch after authorization, but secretless target validation exposed a fixture test-script defect, so the exact artifact was published only as an experimental draft. A separate remote run then passed vulnerable reproduction, repaired blocking, legitimate behavior, and exact architecture-control change before recording HEDGE-009 as `verified` through a reviewable state PR.

The frozen ten-case, three-repeat API batch recorded 30 runs and failed its operational gate because 12 model-routed runs failed. Accepted results retained exact evidence and the instruction boundary held. This is narrow reliability and usage evidence, not a production precision or cost claim.

## Deliberately limited

- TypeScript only; focused on Next.js App Router, Next.js Pages API routes, and common Express patterns.
- No complete cross-file or cross-language data-flow proof.
- Same-repository pull requests in the Build Week workflow.
- No automatic exploitability verdict or guarantee of safe remediation.
- Custom policy matching is intentionally small and deterministic.
- The proof bundle is tamper-evident but not cryptographically signed.
- GPT-5.6 precision, general accuracy, and dollar cost remain unmeasured; the recorded batch measures only the frozen corpus's routing, stability, token usage, latency, failures, evidence validity, and instruction boundary.

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

The final video must show only the remote stages that actually passed. Automated remediation publication remains experimental; the four-part counterfactual verification may be shown as one proven judge-lab result rather than a general reliability claim.
