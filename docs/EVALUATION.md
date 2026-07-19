# DriftBench evaluation

## Included deterministic suite

The package contains 47 before/after fixtures covering:

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
- Next.js Pages API default handlers, dynamic route normalization, and protected variants.
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

All 47 bundled cases pass with 100% on the metrics above. That result is intentionally narrow: the fixtures were written for the supported deterministic extractors and rules. It is **not** general vulnerability-detection accuracy.

## API-backed live evaluation

The live harness is ready, but it never runs implicitly. It requires both an explicit opt-in and an OpenAI API key, and it refuses to start when a GitHub or GitHub Actions token is present. Set the API key through the shell or secret manager without placing it in a command argument, then run from a credential-isolated shell:

```bash
export OPENAI_API_KEY
HEDGE_LIVE_EVAL=1 npm run eval:live
```

The default is exactly three repetitions of the ten before/after pairs listed in `eval/live-eval-cases.json`. They live only in `eval/heldout-fixtures`, do not reuse a development-fixture ID or source pair, and were frozen before any API-backed run at `2026-07-16T14:53:15.000Z`. The aggregate corpus SHA-256 is `4da85338c82db9e6fdd595831be7b33389625862fbd26e79ddc4ffbb6797edfd`. Hedge verifies every per-fixture digest, the aggregate manifest digest, the exact ten-directory set, and the separate fixture-root name before issuing a model request. Any source or manifest change invalidates the gate before model work begins.

The fixed cases cover a benign semantic refactor, a supported entry-point delta, confirmed rate-limit addition, authentication removal, database-read and object-storage-write boundaries, a dynamic outbound flow, a workflow-authority change, unresolved-control uncertainty, and a delta-bearing instruction-boundary probe. These cases were not used to tune analyzers, prompts, schemas, thresholds, or product policy; doing so would invalidate the held-out designation. The machine result records `heldOutGateCompleted: true` only after the corpus integrity checks pass. That field proves separation and freeze, not a successful API run or a performance result.

To make a bounded diagnostic run, set `HEDGE_LIVE_EVAL_REPEATS` to an integer from 1 through 5. Results default to `eval/live-results/results.json` and `eval/live-results/results.md`; `HEDGE_LIVE_EVAL_OUTPUT_DIR` can select another directory.

The harness:

- Builds deterministic base and head graphs from the selected fixture trees and binds every source observation to an exact synthetic SHA-256 revision.
- Computes comparison coverage from both revisions. A no-delta pair is `confirmed-no-delta` only with complete comparison coverage; partial or unsupported no-delta runs remain unconfirmed and still make no model request.
- Creates a bounded untrusted patch (60,000 bytes maximum before the production prompt layer applies its stricter 12/48 KiB phase caps) and uses Hedge's production cost router: zero-call deterministic, direct Sol, Luna-only, or Luna-to-Sol.
- Verifies the SHA-256-frozen corpus before graph construction and records both the per-case fixture digest and aggregate corpus digest in every case's provenance.
- Adds a fixed, typed synthetic instruction-boundary probe to the delta-bearing `110-integration-boundary-probe` patch. The probe is recorded in provenance and exercises the model path without changing fixture source or graph provenance.
- Records each route, exact-evidence validation and rejected-proposal counts, normalized finding and recorded-decision signatures, call count, provider-reported input/output/total/cached/reasoning tokens, latency, API/model failures, and instruction-boundary state.
- Records the timestamp plus Hedge, extractor, prompt, pipeline-schema, model-output-schema, and model versions.
- Stops issuing model requests immediately if Sol reports that the untrusted-data boundary did not hold. Ordinary API/model failures are recorded and make the operational gate fail, but provider error prose is not persisted because it can echo request data.
- Writes bounded artifacts containing hashes, counts, enum values, model IDs, and sanitized fixed failure descriptions. It does not write the API key, source text, patch text, prompts, model prose, or raw sensitive content.

Unit tests use an injected fake runner and make no network requests. They cover opt-in and credential isolation, ten-case aggregation, directory separation, per-case and corpus integrity, tamper rejection before model work, stability, exact synthetic provenance, the delta-bearing boundary probe, fail-closed boundary behavior, honest no-delta coverage semantics, and credential non-persistence.

The generated report is deliberately not an accuracy score. It supports claims only about these ten frozen held-out pairs and the recorded model/prompt/schema versions: routing, provenance, evidence-reference validation, repeat stability, token usage, latency, failures, and prompt-injection boundary behavior. It is not a claim of general security accuracy or vulnerability detection. At the time of freeze, no API-backed result has been recorded; the 30-run operational gate and human review remain outstanding. Cost calculation and broader expert/adversarial corpora remain separate work.

## Full-system replay gate

The bundled `examples/replays/upload-invariant` fixture exercises base/head extraction, recorded GPT-5.6 boundaries, explicit invariant evaluation, observation/inference/decision construction, report generation, SARIF, and expected-result assertions.

```bash
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

A passing replay is evidence of deterministic pipeline reproducibility, not live-model precision.
