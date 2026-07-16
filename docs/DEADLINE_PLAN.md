# Hedge deadline execution plan

## Deadline contract

The official OpenAI Build Week deadline is Tuesday, July 21, 2026 at 5:00 PM PDT. Hedge uses a safer internal product cutoff of noon PDT.

The complete product roadmap is a multi-week program. “Everything by the deadline” means every must-ship item in this document is complete and green. Longer-term work remains preserved in `docs/PRODUCT_MASTER_PLAN.md` and cannot jeopardize the working product.

Feature freeze is Sunday, July 19 at 6:00 PM PDT. Monday and Tuesday are stabilization-only.

## Execution model

Work proceeds in small, green increments across three lanes:

- Analysis correctness and schemas.
- GitHub workflows, remediation, and verification.
- User experience, installer, and evaluation.

The primary lane integrates and reviews every increment. Main must remain green after each merge.

## Thursday, July 16 — exact and honest results

- Build graphs from the exact PR base and head SHAs using the same trusted base policy and context.
- Use a stored graph only as a cache when source, policy, context, and integrity bindings match the base SHA.
- Never compare a head against an empty graph merely because the baseline is missing or stale.
- Treat a failed full-register digest as invalidating graph, lifecycle, acceptance, verification, IDs, and counters.
- Add `coverage.status: complete | partial | unsupported`.
- Add `analysisHealth.status: complete | degraded | failed`.
- Record omitted files, limits, parser failures, unresolved imports, unavailable patches, and unsupported constructs.
- Require exact revisions plus complete coverage for confirmed no delta.
- Prevent partial coverage from silently advancing lifecycle state.
- Emit invariant `unknown` for unresolved helpers, dynamic matching, inferred controls, or partial coverage.
- Prevent model-origin findings from directly blocking. Deterministic findings, trusted policies, and explicit invariants remain eligible for threshold decisions.
- Preserve no graph delta → no model call and no new PR comment.

Gate:

- Tests cover stale/missing state, deletions, malformed source, truncation, model failure, unresolved helpers, and dynamic matchers.
- A stale graph produces the same delta as exact-base/head extraction.
- Partial/unsupported analysis cannot appear confirmed healthy.
- Typecheck and all tests pass.

## Friday, July 17 — credential and publication isolation

Implement:

```text
Secretless exact base/head collection
            ↓ RunManifest + bounded evidence
OpenAI reasoning: no checkout, no target execution, no write token
            ↓ validated analysis bundle
Secretless publisher: GitHub write permissions, no OpenAI key
```

- Add `RunManifest v0.1` bound to repository, PR, base/head SHAs, workflow/Action versions, policy/context/extractor digests, coverage/health, model/prompt/schema versions, and artifact digests.
- Validate schemas, sizes, identity, head freshness, and digests before publication.
- Reject stale and tampered bundles.
- Update only the newest idempotent comment.
- Remove an earlier stale Hedge comment after a confirmed no-delta result.
- Add per-PR concurrency and obsolete-run cancellation.
- Preserve backward-compatible local CLI operation.

Gate:

- Contract tests prove the model job has no checkout/write authority and the publisher has no OpenAI credential.
- Artifact tampering, identity mismatch, and stale-head tests fail closed.
- Source content never becomes a shell command.

Fallback: if the split model path is not green, install a deterministic-only GitHub workflow rather than co-locating model credentials and write authority.

## Saturday, July 18 — defensible repair and verification

Remediation:

1. Authorize the exact command and current run artifact.
2. Let Codex inspect/edit without GitHub write authority.
3. Run target tests only in a later secretless validation job.
4. Publish a validated patch as a draft PR without an OpenAI credential.

Require per-risk concurrency, stale-head rejection, patch limits, path/mode checks, rejection of unsafe/protected changes, sanitized Codex output, one draft PR, and no protected-branch push.

Verification:

- Bind one immutable witness bundle and digest to both vulnerable and repaired runs.
- Return `reproduced`, `blocked-by-control`, or `inconclusive`.
- Treat crashes, timeouts, dependency/setup failures, assertion failures, and unrelated nonzero exits as inconclusive.
- Run target code only in secretless bounded jobs.
- Run legitimate behavior separately on the repaired revision.
- Derive architecture-control change from exact graph comparison.
- Remove the user-controlled architecture-change boolean.
- Aggregate evidence in a fresh trusted job.

`verified` requires vulnerable reproduction, identical repaired witness blocking, legitimate success, and relevant architecture change.

Gate:

- Witness tampering cannot close a risk.
- A crash or ordinary failure cannot count as blocked.
- Duplicate commands cannot create duplicate repair/state PRs.
- One remote repair opens one draft PR and never writes to the protected branch.

Fallback: disable automatic transition to `verified` if the full contract is not green.

## Sunday, July 19 — coherent experience and live validation

Reviewer experience:

- Lead with semantic architecture change, decision/source, exact evidence, next action, and coverage/health.
- Add commit-pinned base/head evidence links.
- Collapse graphs, witness code, model usage, integrity detail, and machine payloads.
- Keep the visible comment below 32 KiB.
- Preserve one idempotent comment and bounded annotations.

Installation:

- Fix workflow-template loading outside the Hedge source checkout.
- Validate install and doctor from root and nested directories.
- Never overwrite existing workflows without `--force`.
- Preserve deterministic use without an API key.

Live validation:

- Run 10 held-out PR pairs three times each once an isolated API credential is available.
- Record evidence validity, finding/decision stability, routing, tokens, latency, failures, and prompt-boundary behavior.
- Exercise no delta, supported delta, partial coverage, model outage, stale run, draft repair, and successful/inconclusive verification through real GitHub workflows.

Gate by 6:00 PM PDT:

- Clean setup to first PR result is under ten minutes.
- Every model claim resolves to exact evidence.
- Confirmed no delta creates no model request or PR comment.
- All required checks pass.
- Feature freeze begins.

## Monday, July 20 — stabilization only

From a fresh clone run:

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

Rerun the remote workflow matrix. Only correctness, security, installation, regression, and truthful documentation fixes are allowed. No new schemas, commands, analyzers, frameworks, dashboard features, or unrelated refactors. Code freeze is 6:00 PM PDT.

## Tuesday, July 21 — contingency

Before 9:00 AM PDT, repeat clean-clone installation, required checks, one no-delta smoke test, one architecture-delta smoke test, repair/verification state checks, and bundle/source consistency checks.

From 9:00 AM to noon PDT, fix only release blockers. Disable or revert anything that cannot meet its contract. Stop product changes at noon.

## Deadline interface changes

- Analysis result gains coverage, health, and confirmed-no-delta fields.
- Decision gains `analysis-health` as a source.
- Controls gain assurance; legacy controls default conservatively to inferred.
- Add `RunManifest v0.1`.
- Verification gains witness digest, structured outcomes, graph-delta digest, and architecture evidence.
- Add internal collect/reason/publish Action stages while preserving local check.
- Action outputs gain coverage status, analysis status, confirmed-no-delta, and run-manifest path.
- Reports gain exact commit links and prominent health state.

All changes are additive and backward-readable. The full v1 configuration migration is deferred.

## Deadline success criteria

- Exact base/head comparison is authoritative.
- Full-register integrity failure discards all affected state.
- Coverage loss cannot masquerade as confirmed safety.
- Invariant `unknown` works deterministically.
- No graph delta causes no model call and no new comment.
- Model-only findings cannot directly block.
- No job combines target execution, an OpenAI credential, and GitHub write authority.
- Every published claim has exact evidence.
- Stale runs cannot overwrite current output.
- `verified` requires all four proof conditions.
- Remediation opens only a draft PR.
- Installation works outside the source checkout.
- All local and remote gates pass.

## Optional work after must-ship gates

1. Repair progress/status updates.
2. A thin `hedge setup` wrapper.
3. Minor dashboard finding-to-node linking.
4. Expand live evaluation from 10 to 20 pairs.
5. Acceptance-expiry metadata.

## Deferred roadmap

- Large expert/adversarial corpus.
- Full TypeScript Program and monorepo analysis.
- Additional frameworks and extractor SDK.
- Fork-PR broker.
- Full v1 configuration migration, policy packs, and `@hedge adopt`.
- New risk-ID system and upgrade tooling.
- Windows support, large-repository optimization, caching, telemetry, organization views, attestations, and major dashboard redesign.
- Hosted services, IDE extensions, and all competition-submission work.

## Cut rules

- Exact comparison precedes coverage semantics.
- Coverage precedes invariant/lifecycle decisions.
- RunManifest precedes workflow separation.
- Workflow separation precedes live model testing.
- Structured witness outcomes precede `verified`.
- Optional work never begins while a must-ship gate is red.
- If time slips, disable or defer the affected feature; never weaken evidence, isolation, verification, silence, or required checks.
