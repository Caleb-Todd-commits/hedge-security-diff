# Release validation record

This record describes the local evidence produced for the `0.5.2` Build Week release candidate. It is deliberately narrower than a production assurance claim; remote GitHub and API-backed gates remain unclaimed until recorded.

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

## Packaged result

At packaging time:

- **53** test files passed.
- **258** unit, contract, replay, and schema tests passed.
- **47 of 47** bundled deterministic evaluation cases passed.
- The vulnerable demo branch produced an evidence-linked security architecture delta and two findings.
- The benign demo branch produced no graph delta and no finding.
- The vulnerable witness returned `reproduced` before the fix.
- The repaired witness returned `blocked-by-control` while the legitimate-behavior script still passed.
- `npm run audit:high` completed against the public npm advisory service with **0 vulnerabilities** reported.
- Hedge's own graph is regenerated with complete source coverage under the repository-specific one-megabyte budget; generated `dist/**` bundles remain covered by build and release checks rather than duplicate graph extraction.

## Claim boundary

The fixture numbers measure known, bundled cases and are not general vulnerability-detection accuracy. GPT-5.6 precision, repeated-run stability, latency, and cost still require API-backed measurements. The GitHub and Codex workflows are implemented and contract-tested, but must still be exercised in a real remote repository with actual permissions and credentials before the submission video is recorded.
