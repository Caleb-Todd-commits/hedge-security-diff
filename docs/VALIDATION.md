# Release validation record

This record describes the local, real-repository, GitHub-hosted, and API-backed evidence produced for the `0.5.2` Build Week release candidate. It is deliberately narrower than a production assurance claim.

## Automated checks

Regenerate public interfaces and deterministic evaluation evidence, build the distributable artifacts, then run the release gates:

```bash
npm run schemas
npm run typecheck
npm test
npm run eval
npm run build
npm run validate:release
npm run validate:demo
npm run audit:high
```

It verifies:

- Prettier formatting.
- TypeScript compilation without emitting files.
- Unit and workflow-contract tests.
- The deterministic DriftBench fixture suite through the unit/contract test gate, keeping the working tree unchanged.
- The presence and startup behavior of the already-built GitHub Action and CLI artifacts.
- CLI startup and executable permissions.
- Reproducible no-build release assembly, checksums, clean extraction, installation, doctor diagnostics, and first offline architecture result.
- Generated Draft 2020-12 JSON Schemas.
- Standalone HTML, SARIF, delta, analysis, and proof-bundle artifacts.
- Credential-shaped repository literals are redacted before model/report evidence is created; model-controlled Markdown, HTML, mentions, code fences, and Mermaid labels are sanitized.
- Installer/doctor behavior, versioned integrity migration, atomic register writes, explicit invariant enforcement, and organization-defined policy enforcement.
- Observation/inference/decision separation and Action decision output.
- The bundled full-system replay with recorded model boundaries and expected-result assertions.
- A generated Git repository containing the full prepared demo branch sequence.
- A vulnerable upload witness that returns the structured `reproduced` outcome before remediation.
- The same witness bytes returning the structured `blocked-by-control` outcome after remediation.
- Legitimate upload behavior remaining functional after remediation.
- Silence on the benign-refactor branch.

## Real-repository smoke tests

The candidate was installed without rebuilding into one public App Router repository, one public Pages API repository, and one public Express repository. No target dependencies were installed, no target code was executed, and no model call was made. All three documentation-only changes were silent. All three supported upload/storage changes produced deterministic findings linked to the exact added route and storage operation.

The App Router and Pages API repositories reported partial coverage with specific diagnostics; the Express repository reported complete coverage. Exact source commits, entry-point counts, outcomes, and residual limitations are recorded in [REAL_REPOSITORY_VALIDATION.md](REAL_REPOSITORY_VALIDATION.md).

## Live GitHub and model record

- [Judge-lab PR 1](https://github.com/Caleb-Todd-commits/hedge-judge-lab/pull/1) proved benign silence: collection passed, reasoning was skipped, no model call was made, and no Hedge comment was published.
- [Judge-lab PR 2](https://github.com/Caleb-Todd-commits/hedge-judge-lab/pull/2) completed the live `collect -> reason -> publish` path with complete coverage, exact evidence, one rejected unsupported proposal, and a recorded `BLOCK` decision. Its single Sol call reported 1,739 input, 1,713 output, and 3,452 total tokens.
- The bounded access probe reported 59 tokens.
- The frozen evaluation reported 76,062 total tokens across 27 model calls. It recorded all 30 slots but failed operationally on 12 model-routed runs; see `eval/live-results/results.md`.
- [The Codex remediation run](https://github.com/Caleb-Todd-commits/hedge-judge-lab/actions/runs/29704446757) reported 18,185 tokens and produced a source-bound, digest-bound three-file patch. Secretless target validation then stopped on the fixture's pre-existing empty Vitest suite, so [draft PR 5](https://github.com/Caleb-Todd-commits/hedge-judge-lab/pull/5) is explicitly experimental.
- [Counterfactual verification run 29705400423](https://github.com/Caleb-Todd-commits/hedge-judge-lab/actions/runs/29705400423) passed vulnerable reproduction, repaired blocking, legitimate behavior, and exact architecture-control change without network or credentials. [State PR 8](https://github.com/Caleb-Todd-commits/hedge-judge-lab/pull/8) recorded HEDGE-009 as `verified` on protected `main`.

Total reported usage for the probe, live canary, frozen batch, and successful Codex run is **97,758 tokens**. The sources expose different levels of token detail, so this ledger preserves their reported values without inventing a common breakdown. Failed requests that returned no usage are excluded rather than estimated.

## Packaged result

At packaging time:

- **53** test files passed.
- **259** unit, contract, replay, and schema tests passed.
- **47 of 47** bundled deterministic evaluation cases passed.
- The vulnerable demo branch produced an evidence-linked security architecture delta and two findings.
- The benign demo branch produced no graph delta and no finding.
- The vulnerable witness returned `reproduced` before the fix.
- The repaired witness returned `blocked-by-control` while the legitimate-behavior script still passed.
- `npm run audit:high` completed against the public npm advisory service with **0 vulnerabilities** reported.
- Hedge's own graph is regenerated with complete source coverage under the repository-specific one-megabyte budget; generated `dist/**` bundles remain covered by build and release checks rather than duplicate graph extraction.

## Claim boundary

The fixture numbers measure known, bundled cases and are not general vulnerability-detection accuracy. One live judge-lab canary proved collect/reason/publish with exact evidence and a recorded decision. The frozen 30-run API batch measured usage and latency but failed operationally on 12 runs; its human adjudication is still unchecked. Codex produced a bounded repair artifact, but automated target validation did not complete, so the recovered draft is experimental. One finding reached `verified` only after all four counterfactual requirements passed; that canary is not a general verification-reliability claim.
