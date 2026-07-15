# DriftBench evaluation

## Included deterministic suite

The package contains 45 before/after fixtures covering:

- Benign refactors and comment-only changes.
- New unauthenticated mutations.
- Protected database writes.
- Upload boundaries and upload remediation.
- Authentication, ownership, and validation removal.
- Admin authorization.
- Dynamic SSRF and static outbound calls.
- Command execution.
- Secret-bearing request flows and logging.
- `pull_request_target`, `issue_comment`, and manual workflow boundaries.
- Next.js aliases, dynamic routes, catch-all routes, and handler scoping.
- Express inline and named handlers.
- Security-relevant dependency changes.
- Prompt-injection text that must remain inert data.
- Non-secret environment configuration.
- Sensitive Prisma reads and protected variants.
- Workflow permission expansion, shell interpolation, and privileged PR-head checkout.
- Fixed-host dynamic queries that must not be mislabeled as SSRF.
- Next.js authentication wrappers, static middleware matchers, complex-matcher uncertainty, and Server Actions.
- Express middleware chains, source ordering, path scope, and custom router receivers.
- Multiple dangerous operations sharing one source line without evidence collapse.

Run:

```bash
npm run eval
```

The result reports:

- Benign silence rate.
- Surface-change recall.
- Expected-finding recall.
- Finding-count expectation rate.
- Repeated deterministic stability.
- Per-case failures and titles.

## Current included result

All 45 bundled cases pass with 100% on the metrics above. That result is intentionally narrow: the fixtures were written for the supported deterministic extractors and rules. It is **not** general vulnerability-detection accuracy.

## API-backed evaluation still required

Before submission claims about GPT-5.6, run repeated evaluations that measure:

- Evidence-reference validity.
- Risk precision under human review.
- Stability across repeated runs.
- Luna escalation rate.
- Median and P95 input/output tokens.
- Median and P95 latency.
- Median and P95 estimated cost.
- Injection-boundary behavior.
- Unsupported or omitted claims.

Record raw results, model IDs, date, prompt/schema versions, and failures. Do not collapse unlike metrics into one “accuracy” number.

## Full-system replay gate

The bundled `examples/replays/upload-invariant` fixture exercises base/head extraction, recorded GPT-5.6 boundaries, explicit invariant evaluation, observation/inference/decision construction, report generation, SARIF, and expected-result assertions.

```bash
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

A passing replay is evidence of deterministic pipeline reproducibility, not live-model precision.
