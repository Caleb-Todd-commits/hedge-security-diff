# Limitations and claim boundaries

- Hedge supports a narrow TypeScript target: Next.js App Router, basic Express, common Prisma, object-storage, network, workflow, and credential patterns.
- Handler-scoped AST analysis is not complete interprocedural data flow. Same-file helper propagation and supported middleware are modeled, but imported helpers, decorators, generated routes, runtime-computed matchers, infrastructure policy, and deployment topology may remain unknown.
- A detected control means relevant code is associated with the supported handler or middleware path; it does not prove semantic correctness, runtime reachability, or complete enforcement.
- Source collection refuses symlinks and out-of-root real paths, but repository archives should still be unpacked by a hardened caller before Hedge runs.
- A surfaced risk is not an exploitability verdict.
- CWE and STRIDE labels are optional metadata, not the core evidence.
- The competition workflow is same-repository only. Fork-safe operation needs a separate approval or credential architecture.
- GitHub/Codex workflows are implemented as installable examples and statically tested, but this package has not opened a real remote draft PR because no target repository or credentials are available here.
- Counterfactual verification depends on repository-owned witness and legitimate-behavior scripts. A subsequent graph comparison is still required to confirm the modeled control change.
- GPT-5.6 integration is implemented with fail-safe deterministic fallback, but model precision, stability, cost, and latency remain unmeasured until repeated API-backed runs.
- The current risk ID allocator is stable against the committed register; brand-new uncommitted findings can be renumbered if the set/order of simultaneous new findings changes before merge. Semantic graph identities are line-independent, but structural refactors can still legitimately alter them.
- Hedge does not replace SAST, DAST, dependency scanning, secrets scanning, penetration testing, architecture review, or human judgment.
