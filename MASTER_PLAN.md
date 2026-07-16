# HEDGE — OpenAI Build Week Master Plan

> Current planning documents: [`docs/DEADLINE_PLAN.md`](docs/DEADLINE_PLAN.md) is the deadline-locked execution contract, and [`docs/PRODUCT_MASTER_PLAN.md`](docs/PRODUCT_MASTER_PLAN.md) preserves the complete post-deadline product roadmap. This historical master plan remains intact below.

## Thesis

**One-liner:** Hedge is a GitHub Action that maintains an evidence-linked security architecture model of a TypeScript repository and shows the exact security delta introduced by each pull request.

**Primary tagline:** Your threat model, alive.

**Supporting lines:**

- A threat model that grows with your code.
- Hedge surfaces the change. Codex proposes a repair. Evidence verifies the result.
- Every pull request deserves a security diff.

**Track:** Developer Tools.

**Submission deadline supplied by the challenge:** Tuesday, July 21, 2026 at 5:00 PM Pacific. Internal target: noon Pacific.

## Why the thesis changed

A generic AI-generated living threat model is not sufficiently differentiated. Existing threat-modeling tools and newer coding-security systems can already generate models, review changes, and recommend remediation. Hedge must own a sharper primitive:

> Git shows code before and after. Hedge shows attack surface before and after.

The living threat model is the persistent artifact. The product is the security architecture diff.

## Product contract

### `hedge init`

Scans the supported repository and generates:

- `THREATMODEL.md` with assets, entry points, trust zones, controls, assumptions, unknowns, risks, and a Mermaid graph.
- `threatmodel.json` containing the evidence-linked graph and machine-readable risk register.
- Stable risk IDs in the form `HEDGE-NNN`.

The first production version should propose answers to no more than five high-value questions and allow developer confirmation:

1. Which data is most sensitive?
2. Which components are internet-facing?
3. What authenticates users and services?
4. Which roles have privileged access?
5. Which external systems are trusted?

Unknown facts remain unknown.

### Pull-request behavior

1. Deterministically classify changed paths.
2. Extract supported architecture facts from repository evidence.
3. Compute graph delta.
4. If no meaningful delta exists, make no model call, post no comment, and return a green check.
5. If a delta exists, route through Luna for inexpensive scope triage.
6. Use Sol only when deeper security interpretation is justified.
7. Post or update one idempotent report.
8. Link every claim to source evidence and confidence.
9. Suggest a security invariant and executable counterexample, not a verdict.
10. Fail only when a surfaced risk reaches the repository's configured threshold.

### Merge behavior

A trusted merge workflow refreshes the model state after the default branch changes. Production implementation should create a model-update pull request or use a protected bot workflow rather than silently bypass branch protections.

### Remediation

`@hedge fix HEDGE-003` starts an approval-gated Codex workflow:

- Read the finding and evidence.
- Plan the smallest focused repair.
- Add a regression witness.
- Demonstrate the witness on the vulnerable revision.
- Apply the patch on an isolated branch.
- Re-run legitimate tests.
- Open a draft pull request.
- Link the remediation to the original Hedge risk.

A ready-to-paste prompt is insufficient for the final demonstration; the command must initiate a real workflow.

### Verification lifecycle

```text
OPEN
  ↓
MITIGATION DETECTED
  ↓
VERIFICATION AVAILABLE
  ↓
VERIFIED
```

A later test file does not close a finding. `VERIFIED` requires:

- The witness succeeds against the vulnerable revision.
- The same witness is blocked against the repaired revision.
- Legitimate behavior continues to pass.
- The relevant architecture edge or control state changes.
- Commands and results are recorded.

Risk acceptance is separate:

```text
@hedge prune HEDGE-012 reason:"internal-only service"
```

It records who, when, and why. This is the first feature to cut if schedule slips.

## Finding structure

Required:

- Asset
- Attacker capability
- Entry point
- Trust boundary
- Preconditions
- Attack path
- Potential impact
- Existing controls
- Missing controls
- Security invariant
- Evidence
- Confidence

Optional:

- STRIDE categories
- CWE identifiers
- OWASP mapping

Never force a CWE mapping to make a report look sophisticated.

## Visual language

- Existing components: neutral gray.
- Newly added components: green outline.
- Newly exposed or concerning attack paths: red edges.
- Partial controls or unresolved uncertainty: amber/dashed.
- Verified controls: shield markers or green edges.
- Keep the garden motif restrained. One small leaf in report headers is enough.

The dangerous object is normally an attack path or trust-boundary edge, not a red component.

## Supported competition scope

- TypeScript only.
- Next.js App Router first.
- Limited Express support only after Next.js is reliable.
- Common auth patterns.
- Prisma data models and operations.
- Common object-storage and filesystem operations.
- Environment-backed secrets.
- Basic external network calls.
- Same-repository pull requests only.

## Non-goals

- Replacing SAST, DAST, dependency scanning, code review, or penetration testing.
- Proving exploitability from source evidence alone.
- Supporting every language or framework.
- Executing arbitrary model-generated shell commands.
- Automatically fixing code without approval.
- Closing risk because a test exists.
- Treating prompt-like strings in source as application vulnerabilities.

## Model routing

```text
Deterministic prefilter
      ↓
No relevant graph delta → no API call
      ↓
Luna triage: does this delta require security reasoning?
      ↓
Sol analysis: why does this evidence-linked delta matter?
```

Current default IDs at project creation:

- `gpt-5.6-luna`
- `gpt-5.6-sol`

Pin model snapshots before final submission if available and validated. Do not publish a typical-PR cost claim until real measurements exist. Report median cost, p95 cost, median latency, p95 latency, percent of runs with no model call, and percent escalated to Sol.

## Self-hardening

Hedge runs on Hedge.

Its own threat model includes:

- Prompt injection through source, diff, PR title, body, and comments.
- Secret exposure through same-repository PR workflows.
- Model output crossing into shell execution.
- Untrusted test execution.
- Excessive GitHub token permissions.
- Poisoned generated state.
- Comment spam and duplicate findings.
- Cost denial of service through huge changes.

Controls:

- Repository content is explicitly delimited and labeled untrusted.
- Analysis jobs have no shell, repository-write, or network tools controlled by the model.
- Structured Outputs validate every model response.
- Model output is never interpolated into a shell command.
- Diff size and file count are capped.
- Relevant paths are prioritized.
- Comments are idempotent.
- Risk fingerprints deduplicate known findings.
- Verification runs without the OpenAI key or repository-write token.
- Remediation requires explicit approval and opens a draft PR.

An instruction-like string should create an analysis-integrity signal only when relevant; it should not automatically become an application-security finding.

## Proof of quality

Target a 30-case DriftBench before submission:

- 10 benign changes.
- 15 attack-surface changes.
- 3 mitigation changes.
- 2 prompt-injection/adversarial changes.

Metrics:

- Surface-change recall.
- Benign silence rate.
- Risk precision with evidence support.
- Structured-output validity.
- Deduplication rate.
- Verification accuracy.
- Stability across repeated runs.
- Median and p95 cost.
- Median and p95 latency.

Do not publish one blended “accuracy” number. Do not fabricate perfect results.

## Demo sequence

1. `hedge init` creates a model and evidence-linked Mermaid graph.
2. File-upload PR adds one public entry point, one trust-boundary crossing, and one privileged storage operation.
3. Hedge surfaces the changed attack path, missing controls, evidence, and witness.
4. `@hedge fix HEDGE-003` triggers Codex.
5. Codex opens a draft repair PR with focused controls and a regression witness.
6. The witness succeeds on the vulnerable revision, is blocked after repair, and legitimate upload still succeeds.
7. Hedge marks the risk verified and updates the graph.
8. A benign refactor receives a green check and no comment.
9. Optional: an attempted prompt injection does not alter analysis behavior.

## Cut order

1. `@hedge prune`.
2. Badge.
3. Express support.
4. Broad CWE mapping.
5. Automatic state-update PR.
6. Model override options.
7. General repository support.

Never cut:

- Evidence-linked graph delta.
- Silence by default.
- One real Codex remediation.
- Counterfactual verification.
- Prompt-injection-resistant architecture.
- Evaluation evidence.

## Winning standard

A finished Hedge submission should make the following claim honestly:

> Hedge gives every pull request a security diff. GPT-5.6 explains the change, Codex repairs it, and executable evidence verifies the result.

## Structural additions implemented in v0.5

### Explicit security invariants

Hedge now supports versioned repository commitments in trusted `.hedge.yml`. Each invariant matches changed architecture surfaces, declares required controls, records a four-state evaluation, and creates an evidence-linked deterministic finding when violated.

### Observation → inference → decision

Analysis artifacts now preserve deterministic observations separately from confidence-bearing security inferences and auditable allow/warn/block decisions. The Action failure result is driven by the decision record, never by free-form model prose.

### Full-system replay

`hedge replay` executes a versioned base/head fixture through extraction, graph diffing, optional recorded model boundaries, invariant evaluation, reports, SARIF, and expected-result assertions. The bundled upload-invariant fixture is the reproducible demo fallback.
