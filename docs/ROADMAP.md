# Roadmap and expansion estimates

Hedge's next release should earn more trust before it earns more framework badges. The priorities below preserve the current contract: deterministic observations, exact evidence, explicit coverage, bounded model interpretation, policy-owned decisions, and counterfactual verification.

## What "support" means

A language or framework is not supported merely because Hedge can recognize an endpoint. A release-quality adapter must include:

- A maintained parser or compiler frontend rather than broad source regexes.
- Stable entry-point, control, data-operation, workflow, and trust-boundary identities.
- Exact file-and-line evidence for every deterministic observation.
- Request and secret influence tracking for the framework's common patterns.
- Conservative handling of middleware, decorators, wrappers, imported helpers, and generated routes.
- Explicit complete, partial, or unsupported coverage from `hedge doctor` and every comparison.
- Benign-silence, dangerous-change, protected-change, and uncertainty fixtures.
- Source-only validation on at least two real repositories.
- Release packaging, schemas, documentation, and held-out evaluation appropriate to the new surface.

Anything less should be labeled experimental detection, not support.

## Estimate assumptions

These are engineering ranges, not promises. They assume one experienced engineer working full time with Codex, reuse of Hedge's existing graph and publication pipeline, access to representative open-source repositories, and no major upstream API change. "Alpha" means useful behind an explicit experimental flag. "Release" means the adapter meets the evidence and coverage contract above.

| Expansion                                    |                Alpha |      Release quality | Main work                                                                                                                                    |
| -------------------------------------------- | -------------------: | -------------------: | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Current TypeScript reliability milestone     |            1-2 weeks |            3-4 weeks | Repair workflow diagnostics, retry-free failure classification, model stability work, and a larger expert-reviewed corpus.                   |
| Cross-file TypeScript controls and monorepos |            3-5 weeks |            6-8 weeks | TypeScript Program integration, import graph, workspace boundaries, budgets, and conservative call summaries.                                |
| Fastify, NestJS, or tRPC                     |       2-3 weeks each |       4-6 weeks each | Framework routing, middleware/guard semantics, validation libraries, and real-repository fixtures.                                           |
| Python FastAPI and Flask                     |            4-6 weeks |           8-12 weeks | Python AST frontend, decorators, dependency injection, request influence, SQLAlchemy/storage/network mappings, and packaging.                |
| Python Django, after the Python frontend     | 3-5 additional weeks | 6-8 additional weeks | URL configuration, views, middleware, permissions, ORM semantics, settings, and generated/admin surfaces.                                    |
| Go `net/http`, Gin, and Chi                  |            5-7 weeks |           9-12 weeks | Go parser/types integration, router composition, middleware order, context propagation, SQL/storage/network mappings, and module workspaces. |
| Ruby on Rails                                |            6-8 weeks |          10-14 weeks | Routes, controllers, filters, policies, Active Record, jobs, metaprogramming uncertainty, and Bundler packaging.                             |
| Java Spring                                  |           8-10 weeks |          12-16 weeks | Annotation and dependency-injection semantics, filters/security config, JPA, Gradle/Maven projects, and multi-module coverage.               |

Parallel engineering can shorten calendar time, but parser review, evidence design, real-repository validation, and held-out evaluation cannot be responsibly compressed to zero.

## Detection roadmap

| Detection area                                      |  Useful alpha |       Release quality | Why it matters                                                                                                |
| --------------------------------------------------- | ------------: | --------------------: | ------------------------------------------------------------------------------------------------------------- |
| Imported TypeScript auth and validation helpers     |     2-3 weeks |             4-6 weeks | Reduces partial coverage without treating a helper name as proof.                                             |
| GraphQL and typed RPC entry points                  |     2-4 weeks |             4-7 weeks | Covers callable surfaces that do not look like REST routes.                                                   |
| Queue consumers, scheduled jobs, and event handlers |     3-4 weeks |             5-8 weeks | Extends trust-boundary analysis beyond request/response code.                                                 |
| Terraform and cloud exposure context                |     4-6 weeks |            8-10 weeks | Connects source behavior to externally reachable infrastructure without claiming deployment certainty.        |
| Framework-specific authorization libraries          | 3-7 days each |        2-3 weeks each | Improves control precision for well-defined, versioned APIs.                                                  |
| Expert and adversarial evaluation corpus            |     3-4 weeks | 6-8 weeks and ongoing | Measures false positives, missed patterns, model stability, and coverage across projects Hedge did not shape. |

## Near-term release order

1. Finish the current remediation publication path and make failure diagnostics actionable.
2. Investigate the preserved live-evaluation failures without tuning against the frozen corpus; freeze a new corpus before rerunning.
3. Add imported-helper and monorepo-aware TypeScript analysis.
4. Add one TypeScript framework adapter based on user demand.
5. Extract a language-frontend interface and begin Python with FastAPI and Flask.

The goal is not to claim "any repository." The goal is for every supported repository to receive useful evidence and every unsupported repository to receive an honest boundary.
