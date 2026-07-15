# Security design and self-threat model

Hedge analyzes adversarial content. Security is part of the product, not a later hardening pass.

## Trusted and untrusted inputs

**Trusted for a PR run:**

- Workflow definition from the base branch or a pinned published Action.
- `.hedge.yml` from the PR base SHA.
- `.hedge/context.yml` from the PR base SHA.
- `threatmodel.json` from the PR base SHA, or an explicit empty baseline when absent.
- Maintainer permissions returned by GitHub.

**Always untrusted:**

- PR title, body, source branch, changed files, patches, code comments, filenames, commit messages, and issue comments.
- Model-generated prose, test code, and repair patches until reviewed and verified.

## Prompt injection through repository content

Controls:

- Explicit untrusted-data delimiters.
- System prompt states that repository text is never instruction.
- Strict Structured Outputs.
- No model-controlled tools during analysis.
- Credential-shaped literals are redacted before repository evidence reaches GPT-5.6 or generated reports.
- References such as `process.env.API_KEY` and `${{ secrets.OPENAI_API_KEY }}` remain visible because they describe a trust boundary without exposing the value.
- OpenAI and GitHub credentials are registered with the Actions masking API before use.
- Evidence references must resolve to deterministic graph provenance.
- Unsupported model proposals are omitted and disclosed. A response that admits the instruction boundary failed is discarded entirely.
- Model output is never interpolated directly into a shell command.
- Adversarial fixtures cover instruction-like source content.

An instruction-like string is not automatically an application vulnerability. Hedge records whether the analysis boundary held.

## Secret exfiltration from GitHub Actions

Hackathon controls:

- Same-repository PRs only.
- Base configuration, context, and state fetched through the GitHub API.
- Published/pinned Hedge Action in the consumer workflow—not Action code from the PR.
- The secret-bearing analysis job does not build or execute target code.
- Minimal GitHub permissions and no persisted checkout credentials.
- Verification jobs contain no OpenAI credential or repository-write token.
- Codex remediation and patch publication occur in separate jobs.

Production controls:

- Prefer OpenAI workload identity federation when available.
- Pin third-party actions to reviewed immutable commit SHAs.
- Add environment protection for remediation and publishing.
- Never use `pull_request_target` to execute untrusted head code.
- Bind generated state and remediation payloads to the analyzed commit; consider external signing for production identity/non-repudiation.

## Model output crossing into execution

Controls:

- Analysis produces schema-validated findings, not arbitrary shell command strings.
- Local execution uses repository-owned allowlisted commands and `execFile`-style argument separation.
- `@hedge fix` accepts only a strict risk-ID command from a write-authorized actor.
- Codex runs in a constrained workspace and emits a binary patch artifact.
- The publisher applies the patch in a separate job and opens a draft PR.
- Every repair remains reviewable and must pass verification.

## Risk closure spoofing

A contributor may add a meaningless passing test to close a finding.

Controls:

- Test existence does not close a finding.
- Witness must demonstrate the behavior on the vulnerable revision.
- Witness must be blocked on the repaired revision.
- Legitimate behavior must still pass.
- A relevant modeled control or attack path must change.
- Revisions, commands, actor, notes, and artifacts are recorded.

## State poisoning

Controls:

- PR-head `.hedge.yml`, context, and register never govern the run reviewing that PR.
- Missing base state means an empty baseline, never a head-state fallback.
- Generated state updates are reviewable.
- The graph and complete register are sealed with a versioned digest and written atomically.
- Legacy graph-only integrity is accepted only as an explicit migration state and upgraded on refresh.
- Risk acceptance requires actor, time, and reason.
- Known findings deduplicate through stable fingerprints.

## Repository file-boundary safety

A malicious repository could use symbolic links or unusual paths to make a source collector read files outside the checked-out project.

Controls:

- Source discovery never follows symbolic links.
- Each candidate is checked with `lstat` and rejected when it is a symlink.
- Resolved real paths must remain inside the repository root.
- Binary-looking files are skipped rather than sent to analyzers or models.
- File and byte budgets still apply after path validation.

## Cost denial of service

Controls:

- File and byte budgets loaded from trusted policy.
- Deterministic relevance filter before model routing.
- No model call when no graph delta exists.
- Luna triage before Sol analysis.
- Truncation is disclosed in the report.

Production should additionally enforce repository- and organization-level spend ceilings.

## Current assurance boundary

The local package validates schemas, graph extraction, lifecycle behavior, workflow contracts, rendering boundaries, integrity migration, and 45 deterministic fixtures. It does not claim live GitHub or API-backed assurance until the workflows are exercised in a real repository with pinned releases and recorded outputs. See `docs/SELF_THREAT_MODEL.md` and `docs/LIMITATIONS.md`.

## Proof and lifecycle state

Verification and acceptance never write directly to the protected branch. The published Action updates a checked-out trusted state, and the workflow opens a separate reviewable state pull request. Proof bundles hash copied report artifacts and expose a self-verifying manifest; they are tamper-evident but deliberately do not claim cryptographic identity or non-repudiation.

The stored graph and complete register are bound to policy, reviewed context, source revision, and versioned integrity digests. Hedge warns when a trusted baseline is internally valid but stale relative to the policy or revision used for the current review.
