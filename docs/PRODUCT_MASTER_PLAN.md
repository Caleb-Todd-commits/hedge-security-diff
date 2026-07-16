# Hedge product master plan

## Product direction

Hedge will become the most trustworthy security-architecture diff for GitHub-hosted Next.js TypeScript teams. It is not a broad scanner or universal code reviewer.

Primary users are 5–100-person Next.js teams without dedicated AppSec. Secondary users are security and platform engineers who need trusted policies and durable evidence.

“Works in any situation” means:

- **Supported:** precise, evidence-linked results.
- **Partial:** explicit uncertainty; never false confidence.
- **Unsupported:** safe refusal with useful diagnostics.
- **No API key or model outage:** deterministic analysis remains useful.
- **Large or adversarial repositories:** bounded execution without secret leakage.
- **Ordinary refactors:** no model call and no PR comment.

The product remains GitHub-native: CLI, reusable workflow, Action primitives, and a standalone dashboard. Hosted SaaS and broad language support are deferred until the Next.js quality bar is met.

## Long-term implementation roadmap

### 1. Independent quality baseline

- Build 150 expert-labeled Next.js PR pairs covering benign changes, architecture changes, controls, data flows, workflows, auth, storage, databases, and unsupported patterns.
- Add 100 metamorphic and adversarial variants covering renames, formatting, file moves, malformed syntax, Unicode, huge files, symlinks, prompt injection, stale state, concurrency, and API failures.
- Separate development cases from a held-out gate and use two reviewers plus adjudication for ambiguous labels.
- Run model-backed cases repeatedly and record exact model ID, prompt/schema digest, evidence validity, stability, latency, tokens, and failures.
- Preserve DriftBench and unit tests as regression gates.

### 2. Trustworthy evidence and decisions

- Build graphs from the exact PR base and head SHAs under the same trusted base policy and context.
- Use the stored graph only as a cache when source, policy, context, and integrity bindings match the base SHA.
- Treat any complete-register integrity failure as invalidating graph, findings, acceptance, verification, and counters.
- Add first-class coverage and analysis-health records; coverage loss must never appear as confirmed safety.
- Keep deterministic observations, security inferences, and policy decisions separate.
- Make model-only inferences warning-only until a maintainer promotes them into a trusted invariant.
- Give invariants real `satisfied`, `violated`, `unknown`, and `not-applicable` semantics based on evidence completeness and control assurance.

### 3. Credential and authority separation

Use a three-stage GitHub-native pipeline:

```text
Secretless exact base/head collector
                ↓ schema-bound run bundle
OpenAI reasoning job: no checkout, no write token, no tools
                ↓ validated analysis bundle
Secretless publisher: GitHub write permissions, no OpenAI key
```

- Bind artifacts to repository, PR, base/head SHAs, workflow identity, Action version, config/context digests, extractor version, model ID, prompt/schema version, and artifact digests.
- Cancel obsolete PR runs and reject stale publication.
- Replace comment-embedded self-hashes as remediation authority with trusted workflow-run artifacts.

### 4. Exceptional Next.js analysis

- Move from isolated file parsing to a bounded TypeScript `Program` supporting tsconfig paths, project references, imports/exports, aliases, and cross-file dependency closure.
- Follow supported imported authentication, authorization, ownership, validation, storage, database, and middleware helpers without executing code.
- Deepen App Router support for route handlers, Server Actions, route groups, middleware matching, webhooks, uploads, common auth providers, Prisma, Drizzle, object storage, and outbound calls.
- Track request influence separately from simple call reachability.
- Add workspace-aware monorepo analysis with per-app context and combined reporting.
- Make graph identities stable across formatting, comments, extraction order, harmless moves, and equivalent refactors.
- Add a canonical fingerprint-derived risk UID while preserving existing `HEDGE-NNN` aliases.
- Add repository-scoped content-addressed caching without shared raw-source telemetry.

Only after Next.js gates pass, expand through a versioned extractor interface in this order:

1. Next.js Pages Router.
2. Richer Express.
3. tRPC and GraphQL.
4. Queues, cron, and event consumers.
5. Additional TypeScript frameworks.

Unsupported frameworks must never fall back to generic model guessing.

### 5. Effortless adoption and review

- Make the CLI publishable and self-contained.
- Add a guided `hedge setup` flow that detects framework/workspaces, previews changes, proposes context and starter invariants for confirmation, installs immutable workflows, initializes the baseline, and runs diagnostics.
- Add `hedge doctor --github` with stable diagnostic codes and actionable corrections.
- Add explicit schema/configuration upgrade previews and reversible migrations.
- Support Linux, macOS, and Windows for local CLI use.
- Redesign the PR report around semantic change, decision basis, exact evidence, next action, coverage, and uncertainty.
- Keep graphs, witnesses, model usage, and deep integrity details in collapsed sections or artifacts.
- Enhance the standalone dashboard with base/head views, delta focus, evidence links, lifecycle history, exports, keyboard access, and print support.

### 6. Team adoption flywheel

- Default new installations to observe mode and provide an explicit ratchet to enforcement.
- Ship versioned, reviewable Next.js policy packs.
- Add `@hedge adopt <risk>` to open a draft configuration PR converting a reviewed inference into a narrowly matched trusted invariant.
- Make `accept` the primary risk-acceptance language while retaining `prune` temporarily for compatibility.
- Require acceptance owner, reason, expiry/review date, and optional ticket.
- Route notifications only through trusted base configuration or CODEOWNERS.

### 7. Defensible remediation and verification

- Split remediation into authorization, credential-bearing static edit, secretless validation, and secretless draft-PR publication.
- Prevent the credential-bearing Codex job from executing repository-owned commands.
- Validate patch source binding, size, paths, file modes, symlinks, binaries, and protected files before publication.
- Bind one immutable witness bundle to both vulnerable and repaired revisions.
- Use structured witness outcomes that distinguish reproduced, blocked by the intended control, and inconclusive infrastructure/test failure.
- Compute the relevant architecture delta automatically.
- Keep `verified` impossible without vulnerable reproduction, identical repaired witness blocking, legitimate success, and architecture-control confirmation.

### 8. Operational hardening and safe expansion

- Add per-phase deadlines, cancellation, bounded retries, token ceilings, and circuit-breaker behavior.
- Keep source telemetry off by default.
- Support fork PRs through a secretless collector and protected artifact broker.
- Pin generated third-party Actions to immutable commits.
- Maintain N-1 schema compatibility, reversible migrations, atomic state reconciliation, and workflow contract tests.
- Add provenance attestations and signed distribution artifacts where supported.

## Long-term public interfaces

- `.hedge.yml` gains an explicit schema version, observe/enforce mode, workspaces, policy packs, enforcement behavior, and verification settings.
- Evidence records exact snapshot/commit, subject, extractor version, and assurance.
- Controls gain `trusted`, `confirmed`, `inferred`, and `unknown` assurance.
- Analysis gains coverage, health, and confirmed-no-delta state.
- Risks gain a canonical machine UID, lifecycle relations, and acceptance binding/expiry.
- Run artifacts gain a versioned manifest binding all inputs and outputs.
- Verification replaces a user-controlled architecture boolean with structured outcomes and derived graph evidence.
- Extractors implement a versioned, non-executing normalized-fact interface.

## Long-term quality gates

- 100% evidence-reference validity and deterministic repeatability.
- At least 95% supported architecture-delta recall and 98% benign silence on a held-out corpus.
- At least 90% expert acceptance of model-origin hypotheses and 95% repeated-run stability.
- Zero prompt-boundary escapes, credential leaks, or unsupported evidence claims.
- No job may combine target-code execution, OpenAI credentials, and GitHub write authority.
- P95 deterministic analysis below 20 seconds on the agreed large-monorepo benchmark.
- Clean local setup under five minutes and first GitHub result under ten minutes.
- No stale publication, duplicate remediation PR, or duplicate state PR under stress tests.

## Product boundaries

- Hedge surfaces architecture changes and design risks; it never claims to find or prove vulnerabilities.
- It does not replace SAST, DAST, secrets scanning, dependency scanning, penetration testing, or human review.
- It never executes target code in the secret-bearing analysis job.
- It never writes directly to a protected branch.
- It does not broaden beyond Next.js TypeScript until the relevant quality gates pass.
- Product, security, scope, and evaluation changes must update `docs/DECISIONS.md`; introduced or resolved limitations must update `docs/LIMITATIONS.md`.
