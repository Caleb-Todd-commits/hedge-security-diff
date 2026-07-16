# Limitations and claim boundaries

- Hedge supports a narrow TypeScript target: Next.js App Router, basic Express, common Prisma, object-storage, network, workflow, and credential patterns.
- Handler-scoped AST analysis is not complete interprocedural data flow. Same-file helper propagation and supported middleware are modeled, but imported helpers, decorators, generated routes, runtime-computed matchers, infrastructure policy, and deployment topology may remain unknown.
- A detected control means relevant code is associated with the supported handler or middleware path; it does not prove semantic correctness, runtime reachability, or complete enforcement.
- Working-tree collection refuses symlinks and out-of-root real paths. PR comparison instead reads bounded regular blobs directly from exact Git commits; the required base and head objects must exist in the local object database.
- A surfaced risk is not an exploitability verdict.
- CWE and STRIDE labels are optional metadata, not the core evidence.
- The competition workflow is same-repository only. Fork-safe operation needs a separate approval or credential architecture.
- The prior published v0.5.1 Action is self-tested on GitHub. This v0.5.2 candidate is validated locally but still needs its own hosted smoke test, and the approval-gated Codex workflow has not yet opened a remote draft remediation PR against a target repository with real model credentials.
- Counterfactual verification depends on a reviewed, repository-owned self-contained witness and legitimate-behavior script. Hedge seals the witness bytes, runs both revisions and legitimate behavior without network or credentials, and derives the exact graph change automatically; these controls do not make a poorly designed witness semantically authoritative.
- GPT-5.6 integration is implemented with fail-safe deterministic fallback, but model precision, stability, cost, and latency remain unmeasured until repeated API-backed runs.
- The isolated live harness currently uses ten representative development fixtures, not a genuinely frozen held-out corpus; its machine output records `heldOutGateCompleted: false`, and no held-out-performance claim is allowed until that separate gate runs.
- The staged publisher validates schemas, artifact digests, exact PR bindings, and the current head, but the full collect/reason/publish workflow still needs a recorded remote run with a real OpenAI credential before that live path is claimed proven.
- The hardened remote verification workflow is contract-tested locally but has not yet recorded a successful and an inconclusive run on GitHub-hosted infrastructure for this release candidate.
- The public dashboard is a recorded deterministic artifact for no-install judging; it does not claim to be the output of a live GitHub or GPT-5.6 run.
- The current risk ID allocator is stable against the committed register; brand-new uncommitted findings can be renumbered if the set/order of simultaneous new findings changes before merge. Semantic graph identities are line-independent, but structural refactors can still legitimately alter them.
- Hedge does not replace SAST, DAST, dependency scanning, secrets scanning, penetration testing, architecture review, or human judgment.
- The deadline build deliberately defers the full TypeScript Program, complete monorepo analysis, additional framework adapters, fork-PR broker, v1 configuration migration, hosted fleet views, Windows validation, and the large held-out expert corpus. These remain tracked in `docs/PRODUCT_MASTER_PLAN.md` rather than being implied by current behavior.
