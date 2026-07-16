# Product specification

## User

Primary: a developer or small engineering team that knows threat modeling matters but does not keep a static model synchronized with code changes.

Secondary: security engineers who need a reviewable architectural change record rather than another unprioritized scanner feed.

## Job to be done

“When a pull request changes the security architecture of my application, tell me exactly what changed, why it may matter, where the evidence is, and how to verify a focused repair—without commenting on ordinary refactors.”

## Product taste

Hedge is quiet, precise, and non-alarmist. It speaks only when the modeled surface changes. A report should be useful during code review and defensible during audit.

## Commands

### `hedge init`

Creates a baseline. It must complete without an OpenAI key in deterministic mode. GPT-5.6 may enhance labels and identify questions, but generated architecture must retain evidence provenance.

### `hedge check`

Builds authoritative graphs from the exact requested base and head revisions using trusted Hedge policy and context. Integrity-bound stored state supplies lifecycle history but is not the comparison authority. It writes `.hedge/report.md`; in GitHub Actions, publication is silent whenever no graph delta is observed. Only an exact, complete no-delta result removes a previous Hedge report; partial or unsupported observations leave the previous complete report intact.

### `hedge fix-plan HEDGE-NNN`

Outputs the constrained Codex remediation contract. The approval-gated example workflow exposes that contract through `@hedge fix HEDGE-NNN` and opens at most one draft repair PR.

### `hedge replay <fixture>`

Reproduces a complete base/head analysis with optional recorded model boundaries and asserts the expected decision, findings, observations, and invariant states.

### `hedge eval`

Runs local deterministic fixtures. Final evaluation must add API-backed repeated runs.

## Configuration

Initial `.hedge.yml` stays small:

```yaml
framework: nextjs
fail_on: high
ignored_paths:
  - docs/**
  - "**/*.test.ts"
models:
  triage: gpt-5.6-luna
  analysis: gpt-5.6-sol
invariants:
  - id: INV-UPLOAD
    description: Public upload routes require authentication and a size limit.
    severity: high
    applies_to:
      label_pattern: "* /api/files/*"
    requires:
      controls: [authentication, size-limit]
    rationale: Anonymous unbounded uploads can consume storage.
limits:
  max_files: 120
  max_bytes: 350000
```

## Status behavior

- Exact, complete no delta: green, no comment, no model call; remove a stale Hedge report.
- No observed delta with partial or unsupported coverage: remain silent, retain any previous complete report, and do not claim a confirmed healthy result or advance lifecycle state.
- Delta with no concrete finding: green or neutral; one concise report is allowed.
- Medium finding: report, normally no failure.
- Deterministic, trusted-policy, or explicit-invariant finding at the configured threshold: produce a recorded `block` decision. Model-origin findings remain reviewable inferences but cannot directly block.
- Explicit invariant violation: record its status and contribute directly to the decision through an evidence-linked invariant finding.
- Accepted risk: remains visible with who/when/why.
- Verified risk: one immutable witness reproduces on the vulnerable revision and is blocked by the intended control on the repair, legitimate behavior succeeds, and an exact graph delta proves the relevant architecture control or path change.

## Definition of done for Build Week

- One supported framework works end to end.
- One risk scenario is detected from deterministic architecture evidence.
- One Codex fix flow creates a draft PR.
- One witness runs before and after repair.
- One benign change remains silent.
- One injection attempt does not influence output.
- A fresh clone installs and runs from README instructions.
- The three-minute demo contains no fake live waits or unsupported claims.

## Durable output surfaces

The same security diff must be useful in five contexts: a concise PR comment, GitHub annotations, an interactive standalone dashboard, SARIF/code scanning, and an audit-ready proof bundle. Suggested witnesses can be materialized into a real test file, but their existence never closes a risk; only counterfactual execution and architecture-control confirmation can do so.

## Evidence model

Every meaningful run exposes three distinct layers:

1. **Observation:** deterministic facts from the graph delta.
2. **Inference:** a security hypothesis with confidence, assumptions, evidence linkage, and origin.
3. **Decision:** the auditable allow/warn/block outcome with its policy or threshold source.

Free-form model text never becomes the Action verdict.
