# Real-repository compatibility record

This record captures a deterministic source-only smoke test of the `0.5.2` release candidate on three public TypeScript repositories. Hedge did not install dependencies, execute target code, or make OpenAI API calls. Each repository was tested at the exact upstream commit shown below.

## Method

For each repository, the packaged CLI was installed with the candidate Action pinned to commit `d2756029fdf46bd7fc73e7c9afb9f041f1a179ed`, then `hedge init` and `hedge doctor` were run. Two isolated commits followed:

1. An ignored documentation-only change, expected to produce no architecture delta, no finding, and no model call.
2. A supported public upload route with a request-influenced object-storage write and no detected authentication, size, ownership, or content-type control.

The second change is an intentionally synthetic architecture change inside a real repository. It measures extractor compatibility and evidence precision, not the security posture of the upstream project.

## Results

| Target                         | Exact upstream commit                      | Detection          | Doctor coverage | Supported entry points | Benign change            | Supported architecture change                                                                           |
| ------------------------------ | ------------------------------------------ | ------------------ | --------------- | ---------------------: | ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `nextjs/saas-starter`          | `6e33e58b1e553a41fe22e6b941a7229a002de361` | Next.js App Router | Partial         |                     19 | Silent; zero model calls | 2 deterministic high-severity findings with exact route and storage evidence                            |
| `Ekoda/Monolith`               | `5adfaecb015b89fe9ef6468628a620fedd3123ba` | Next.js Pages API  | Partial         |                      7 | Silent; zero model calls | 1 deterministic high-severity storage-control finding with exact `ANY /api/hedge-smoke/upload` evidence |
| `edwinhern/express-typescript` | `983fa0413659cd921c5754b00f7817903eb91364` | Express            | Complete        |                     12 | Silent; zero model calls | 2 deterministic high-severity findings with exact route and storage evidence                            |

All three supported architecture changes reported `surfaceChanged: true` and used the deterministic-only route. No noisy finding appeared on any documentation-only change.

## Coverage disclosures

- The App Router repository reported partial coverage because a complex middleware matcher could not be used to confirm route protection. No file or byte budget was exceeded.
- The Pages API repository reported partial coverage because an imported `getServerSession` control helper could not be confirmed semantically. No file or byte budget was exceeded.
- Pages API default exports intentionally normalize to an `ANY` method entry point. This preserves truthful method uncertainty, but method-specific authentication recommendations may be less complete than for an explicit App Router or Express mutation.
- The Express repository reported complete coverage for the collected source and no diagnostics.

These results establish compatibility with three real repository shapes, not general accuracy. Imported-helper data flow, runtime-computed matchers, deployment reachability, and framework patterns outside the documented boundary remain limitations.
