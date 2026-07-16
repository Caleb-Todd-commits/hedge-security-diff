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

## API-backed live evaluation

The live harness is ready, but it never runs implicitly. It requires both an explicit opt-in and an OpenAI API key, and it refuses to start when a GitHub or GitHub Actions token is present. Set the API key through the shell or secret manager without placing it in a command argument, then run from a credential-isolated shell:

```bash
export OPENAI_API_KEY
HEDGE_LIVE_EVAL=1 npm run eval:live
```

The default is exactly three repetitions of the ten representative before/after pairs listed in `eval/live-eval-cases.json`. These reuse deterministic development fixtures and are explicitly classified `representative-not-held-out`; the machine result records `heldOutGateCompleted: false`. A genuinely frozen held-out corpus remains an uncompleted external gate and must be run before any held-out-performance claim. To make a bounded diagnostic run, set `HEDGE_LIVE_EVAL_REPEATS` to an integer from 1 through 5. Results default to `eval/live-results/results.json` and `eval/live-results/results.md`; `HEDGE_LIVE_EVAL_OUTPUT_DIR` can select another directory.

The harness:

- Builds deterministic base and head graphs from the selected fixture trees and binds every source observation to an exact synthetic SHA-256 revision.
- Computes comparison coverage from both revisions. A no-delta pair is `confirmed-no-delta` only with complete comparison coverage; partial or unsupported no-delta runs remain unconfirmed and still make no model request.
- Creates a bounded untrusted patch (60,000 bytes maximum) and uses Hedge's configured Luna triage and Sol analysis route.
- Adds a fixed, typed synthetic instruction-boundary probe to the delta-bearing `006-public-secret-boundary` patch. The probe is recorded in provenance and exercises the model path without changing fixture source or graph provenance.
- Records each route, exact-evidence validation and rejected-proposal counts, normalized finding and recorded-decision signatures, input/output tokens, latency, API/model failures, and instruction-boundary state.
- Records the timestamp plus Hedge, extractor, prompt, pipeline-schema, model-output-schema, and model versions.
- Stops issuing model requests immediately if Sol reports that the untrusted-data boundary did not hold. Ordinary API/model failures are recorded and make the operational gate fail, but provider error prose is not persisted because it can echo request data.
- Writes bounded artifacts containing hashes, counts, enum values, model IDs, and sanitized fixed failure descriptions. It does not write the API key, source text, patch text, prompts, model prose, or raw sensitive content.

Unit tests use an injected fake runner and make no network requests. They cover opt-in and credential isolation, ten-case aggregation, stability, exact synthetic provenance, the delta-bearing boundary probe, fail-closed boundary behavior, honest no-delta coverage semantics, and credential non-persistence.

The generated report is deliberately not an accuracy score. It supports claims only about these ten fixed representative pairs and the recorded model/prompt/schema versions: routing, provenance, evidence-reference validation, repeat stability, token usage, latency, failures, and prompt-injection boundary behavior. It is not a claim of general security accuracy or vulnerability detection. Human precision review, cost calculation, and broader held-out/adversarial corpora remain separate work.

## Full-system replay gate

The bundled `examples/replays/upload-invariant` fixture exercises base/head extraction, recorded GPT-5.6 boundaries, explicit invariant evaluation, observation/inference/decision construction, report generation, SARIF, and expected-result assertions.

```bash
node dist/cli/index.cjs replay examples/replays/upload-invariant --output .hedge/replays/upload-invariant
```

A passing replay is evidence of deterministic pipeline reproducibility, not live-model precision.
