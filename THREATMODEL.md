# Hedge Threat Model

> Generated from repository evidence. This document surfaces design-level risks; it is not a vulnerability verdict or a replacement for SAST, DAST, review, or penetration testing.

**Generated:** 2026-07-15T03:16:18.457Z
**Framework:** nextjs
**Open risks:** 0

## Attack-surface graph

```mermaid
flowchart LR
  n_auth_control_context_89aab952967de433[OpenAI authentication uses a repository secret in the hackathon example/ workload identity]
  class n_auth_control_context_89aab952967de433 application;
  n_auth_control_context_cbf9288723423d05[GitHub repository permissions identify maintainers and workflow actors]
  class n_auth_control_context_cbf9288723423d05 application;
  n_component_role_cc376e7c003f6b31[Privileged role: GitHub Actions bot in trusted publisher jobs]
  class n_component_role_cc376e7c003f6b31 privileged;
  n_component_role_e5edff0b9caa3ccb[Privileged role: Repository maintainers with write permission]
  class n_component_role_e5edff0b9caa3ccb privileged;
  n_component_role_f5d324e0dbf0ddde[Privileged role: OpenAI organization administrators configuring workload identity]
  class n_component_role_f5d324e0dbf0ddde privileged;
  n_data_model_context_1949d29087d8d631[OpenAI credentials or short-lived workload identities]
  class n_data_model_context_1949d29087d8d631 data;
  n_data_model_context_6bd9613716aad913[GitHub tokens and repository write authority]
  class n_data_model_context_6bd9613716aad913 data;
  n_data_model_context_78b05125287ae02b[Maintainer approval boundary for Codex remediation]
  class n_data_model_context_78b05125287ae02b data;
  n_data_model_context_a42b5c90eea88e5d[Integrity of threatmodel.json, finding history, and verification evidence]
  class n_data_model_context_a42b5c90eea88e5d data;
  n_dependency_openai[openai@^6.46.0]
  class n_dependency_openai external;
  n_entrypoint_a81fdb37e9c82f4c([Workflow CI pull_request])
  class n_entrypoint_a81fdb37e9c82f4c public;
  n_entrypoint_bdc60ceb8a465b49([GitHub Action: Hedge Security Diff])
  class n_entrypoint_bdc60ceb8a465b49 application;
  n_entrypoint_cc80244f096f4928([Workflow CI push])
  class n_entrypoint_cc80244f096f4928 application;
  n_external_service_context_0be45133050ea32f[OpenAI Responses API and Codex GitHub Action]
  class n_external_service_context_0be45133050ea32f external;
  n_external_service_context_5fefe690ac00b9e2[GitHub API and GitHub Actions]
  class n_external_service_context_5fefe690ac00b9e2 external;
  n_secret_07d154c042bee004[OPENAI_API_KEY]
  class n_secret_07d154c042bee004 privileged;
  n_secret_6b6b2d1fd282b2e6[GITHUB_TOKEN]
  class n_secret_6b6b2d1fd282b2e6 privileged;
  n_secret_action_input_github_token[github-token]
  class n_secret_action_input_github_token privileged;
  n_secret_action_input_openai_api_key[openai-api-key]
  class n_secret_action_input_openai_api_key privileged;
  n_entrypoint_bdc60ceb8a465b49 -->|GitHub Action: Hedge Security Diff receives openai-api-key| n_secret_action_input_openai_api_key
  n_entrypoint_bdc60ceb8a465b49 -->|GitHub Action: Hedge Security Diff receives github-token| n_secret_action_input_github_token
  classDef public fill:#f4f4f5,stroke:#71717a,color:#18181b;
  classDef application fill:#dcfce7,stroke:#15803d,color:#14532d;
  classDef privileged fill:#fef3c7,stroke:#b45309,color:#78350f;
  classDef data fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
  classDef external fill:#ede9fe,stroke:#7c3aed,color:#4c1d95;
  classDef unknown fill:#f4f4f5,stroke:#a1a1aa,color:#3f3f46,stroke-dasharray: 5 5;
  classDef added fill:#ecfccb,stroke:#65a30d,color:#365314,stroke-width:2px;
  classDef verified fill:#dcfce7,stroke:#16a34a,color:#14532d,stroke-width:3px;
  classDef risk fill:#fee2e2,stroke:#dc2626,color:#7f1d1d,stroke-width:3px;
```

## Security invariants

No repository-defined security invariants were evaluated in the latest persisted run.

## Assets and surfaces

- **OpenAI authentication uses a repository secret in the hackathon example; workload identity is preferred for production** — auth-control; trust zone: application; evidence: not available
- **GitHub repository permissions identify maintainers and workflow actors** — auth-control; trust zone: application; evidence: not available
- **Privileged role: GitHub Actions bot in trusted publisher jobs** — component; trust zone: privileged; evidence: not available
- **Privileged role: Repository maintainers with write permission** — component; trust zone: privileged; evidence: not available
- **Privileged role: OpenAI organization administrators configuring workload identity** — component; trust zone: privileged; evidence: not available
- **OpenAI credentials or short-lived workload identities** — data-model; trust zone: data; evidence: not available
- **GitHub tokens and repository write authority** — data-model; trust zone: data; evidence: not available
- **Maintainer approval boundary for Codex remediation** — data-model; trust zone: data; evidence: not available
- **Integrity of threatmodel.json, finding history, and verification evidence** — data-model; trust zone: data; evidence: not available
- **openai@^6.46.0** — dependency; trust zone: external; evidence: `package.json`
- **Workflow CI (pull_request)** — entrypoint; trust zone: public; evidence: `.github/workflows/ci.yml:6`
- **GitHub Action: Hedge Security Diff** — entrypoint; trust zone: application; evidence: `action.yml:1`
- **Workflow CI (push)** — entrypoint; trust zone: application; evidence: `.github/workflows/ci.yml:4`
- **OpenAI Responses API and Codex GitHub Action** — external-service; trust zone: external; evidence: not available
- **GitHub API and GitHub Actions** — external-service; trust zone: external; evidence: not available
- **OPENAI_API_KEY** — secret; trust zone: privileged; evidence: `src/action/index.ts:33`, `src/cli/index.ts:231`
- **GITHUB_TOKEN** — secret; trust zone: privileged; evidence: `src/action/index.ts:34`
- **github-token** — secret; trust zone: privileged; evidence: `action.yml`
- **openai-api-key** — secret; trust zone: privileged; evidence: `action.yml`

## Open risk register

No open evidence-linked risks are recorded.

## Recorded decisions and verified risks

No verified, accepted, or closed risks are recorded.

## Recent model history

| Recorded                 | Revision | Nodes | Edges | Open risks | Highest | Analysis      |
| ------------------------ | -------- | ----: | ----: | ---------: | ------- | ------------- |
| 2026-07-15T03:16:18.473Z | unknown  |    19 |     2 |          0 | info    | deterministic |
| 2026-07-15T01:09:19.638Z | unknown  |    19 |     2 |          0 | info    | deterministic |
| 2026-07-15T01:07:24.663Z | unknown  |    19 |     2 |          0 | info    | deterministic |
| 2026-07-14T14:51:38.794Z | unknown  |    19 |     2 |          0 | info    | deterministic |
| 2026-07-14T14:46:09.505Z | unknown  |    19 |     2 |          0 | info    | deterministic |

## Assumptions

- Maintainer-confirmed internet-facing surfaces: Pull-request event and diff evidence received through the GitHub API, issue_comment commands such as @hedge fix, Published GitHub Action inputs, OpenAI Responses API requests from the trusted analysis job.
- Maintainer-confirmed authentication mechanisms: GitHub repository permissions identify maintainers and workflow actors, OpenAI authentication uses a repository secret in the hackathon example; workload identity is preferred for production.
- Maintainer-confirmed privileged roles: Repository maintainers with write permission, GitHub Actions bot in trusted publisher jobs, OpenAI organization administrators configuring workload identity.
- Maintainer-confirmed trusted external services: GitHub API and GitHub Actions, OpenAI Responses API and Codex GitHub Action.
- Maintainer context: Pull-request source, metadata, comments, patches, and model-visible repository text are untrusted data.
- Maintainer context: Secret-bearing analysis jobs never execute pull-request code.
- Maintainer context: Verification jobs have no OpenAI credential or repository-write token.
- Detected controls are evidence that relevant code exists, not proof that the control is correct or complete.
- Public exposure is inferred from supported route and workflow conventions and must be confirmed against deployment configuration.
- AST analysis is handler-scoped for supported TypeScript and JavaScript entry points; same-file helpers and supported Next.js middleware are followed, while arbitrary imported helper behavior remains partially unknown.
- Repository evidence coverage: 52/74 candidate files and 349914 bytes analyzed.

## Unknowns

- Analysis coverage was bounded: 52/74 candidate files (349914 bytes) were inspected; 0 exceeded the file limit and 22 exceeded the byte budget.

## Update contract

- `hedge init` establishes or refreshes this baseline.
- Pull requests are compared against the stored graph in `threatmodel.json`.
- A finding moves to `verified` only after executable counterevidence succeeds on the vulnerable revision and is blocked on the repaired revision while legitimate behavior remains intact.
- Deterministic observations, security inferences, and merge decisions remain separate artifacts.
- Risk acceptance must record who, when, and why; it is never inferred from silence.
