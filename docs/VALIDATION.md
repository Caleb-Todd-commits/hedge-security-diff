# Release validation record

This record describes the evidence produced for the packaged `0.5.1` Build Week release. It is deliberately narrower than a production assurance claim.

## Automated checks

Build the distributable artifacts, then run the release gate:

```bash
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
- Generated Draft 2020-12 JSON Schemas.
- Standalone HTML, SARIF, delta, analysis, and proof-bundle artifacts.
- Credential-shaped repository literals are redacted before model/report evidence is created; model-controlled Markdown, HTML, mentions, code fences, and Mermaid labels are sanitized.
- Installer/doctor behavior, versioned integrity migration, atomic register writes, explicit invariant enforcement, and organization-defined policy enforcement.
- Observation/inference/decision separation and Action decision output.
- The bundled full-system replay with recorded model boundaries and expected-result assertions.
- A generated Git repository containing the full prepared demo branch sequence.
- A vulnerable upload witness that succeeds before remediation.
- The same witness being blocked after remediation.
- Legitimate upload behavior remaining functional after remediation.
- Silence on the benign-refactor branch.

## Packaged result

At packaging time:

- **37** test files passed.
- **121** unit, contract, replay, and schema tests passed.
- **45 of 45** bundled deterministic evaluation cases passed.
- The vulnerable demo branch produced an evidence-linked security architecture delta and two findings.
- The benign demo branch produced no graph delta and no finding.
- The vulnerable witness exited successfully before the fix.
- The repaired witness was blocked while the legitimate-behavior script still passed.
- A separate `npm run audit:high` check reported zero vulnerabilities at packaging time.

## Claim boundary

The fixture numbers measure known, bundled cases and are not general vulnerability-detection accuracy. GPT-5.6 precision, repeated-run stability, latency, and cost still require API-backed measurements. The GitHub and Codex workflows are implemented and contract-tested, but must still be exercised in a real remote repository with actual permissions and credentials before the submission video is recorded.
