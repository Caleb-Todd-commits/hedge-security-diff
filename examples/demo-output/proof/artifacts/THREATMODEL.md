# Hedge Threat Model

> Generated from repository evidence. This document surfaces design-level risks; it is not a vulnerability verdict or a replacement for SAST, DAST, review, or penetration testing.

**Generated:** 2026-07-15T01:09:45.011Z
**Framework:** nextjs
**Open risks:** 2

## Attack-surface graph

```mermaid
flowchart LR
  n_auth_control_7bf2b37d213596d1[Authentication check: auth]
  class n_auth_control_7bf2b37d213596d1 application;
  n_authorization_control_f2e1d5e80a7ef898[Resource ownership constraint]
  class n_authorization_control_f2e1d5e80a7ef898 application;
  n_data_model_Note[Note]
  class n_data_model_Note data;
  n_data_model_User[User]
  class n_data_model_User data;
  n_database_754eec4f7490bdab[Database read: note.findMany]
  class n_database_754eec4f7490bdab data;
  n_dependency__aws_sdk_client_s3[@aws-sdk/client-s3@^3.0.0]
  class n_dependency__aws_sdk_client_s3 external;
  n_dependency_next[next@16.0.0]
  class n_dependency_next external;
  n_dependency_prisma[prisma@^6.0.0]
  class n_dependency_prisma external;
  n_entrypoint_7687698fbe395d3f([GET /api/notes])
  class n_entrypoint_7687698fbe395d3f public;
  n_entrypoint_7821443e29938cb4([POST /api/files/upload])
  class n_entrypoint_7821443e29938cb4 risk;
  n_storage_ac193b90989396d6[Storage write]
  class n_storage_ac193b90989396d6 risk;
  n_entrypoint_7821443e29938cb4 -->|Storage write| n_storage_ac193b90989396d6
  n_entrypoint_7687698fbe395d3f -->|authorizes| n_authorization_control_f2e1d5e80a7ef898
  n_entrypoint_7687698fbe395d3f -->|Database read: note.findMany| n_database_754eec4f7490bdab
  n_database_754eec4f7490bdab -->|Database read: note.findMany| n_data_model_Note
  n_entrypoint_7687698fbe395d3f -->|authenticates| n_auth_control_7bf2b37d213596d1
  linkStyle 0 stroke:#dc2626,stroke-width:3px;
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

## Assets and surfaces

- **Authentication check: auth** — auth-control; trust zone: application; evidence: `app/api/notes/route.ts:2`
- **Resource ownership constraint** — authorization-control; trust zone: application; evidence: `app/api/notes/route.ts:4`
- **Note** — data-model; trust zone: data; evidence: `prisma/schema.prisma:6`
- **User** — data-model; trust zone: data; evidence: `prisma/schema.prisma:1`
- **Database read: note.findMany** — database; trust zone: data; evidence: `app/api/notes/route.ts:4`
- **@aws-sdk/client-s3@^3.0.0** — dependency; trust zone: external; evidence: `package.json`
- **next@16.0.0** — dependency; trust zone: external; evidence: `package.json`
- **prisma@^6.0.0** — dependency; trust zone: external; evidence: `package.json`
- **GET /api/notes** — entrypoint; trust zone: public; evidence: `app/api/notes/route.ts:1`
- **POST /api/files/upload** — entrypoint; trust zone: public; evidence: `app/api/files/upload/route.ts:4`
- **Storage write** — storage; trust zone: data; evidence: `app/api/files/upload/route.ts:13`

## Open risk register

### HEDGE-001: New mutating entry point has no detected authentication control

- **Severity:** high
- **Status:** open
- **Attack path:** Public user → POST /api/files/upload → Privileged application operation
- **Security invariant:** Only authenticated and authorized principals may invoke POST /api/files/upload.
- **Missing controls:** Verified authentication, Authorization scoped to the target resource
- **Evidence:** `app/api/files/upload/route.ts:4`
- **Confidence:** 90%

### HEDGE-002: New storage write crosses a trust boundary without complete upload controls

- **Severity:** high
- **Status:** open
- **Attack path:** External user → POST /api/files/upload → Storage write
- **Security invariant:** Uploaded content must be authenticated, tenant-scoped, type-checked, and bounded before storage.
- **Missing controls:** Verified authentication, Payload or file size limit, Object ownership constraint
- **Evidence:** `app/api/files/upload/route.ts:4`, `app/api/files/upload/route.ts:13`
- **Confidence:** 90%


## Recorded decisions and verified risks

No verified, accepted, or closed risks are recorded.

## Recent model history

| Recorded | Revision | Nodes | Edges | Open risks | Highest | Analysis |
|---|---|---:|---:|---:|---|---|
| 2026-07-15T01:09:45.024Z | unknown | 11 | 5 | 2 | high | deterministic-only |
| 2026-07-15T01:09:44.362Z | unknown | 9 | 4 | 0 | info | deterministic |

## Assumptions

- Detected controls are evidence that relevant code exists, not proof that the control is correct or complete.
- Public exposure is inferred from supported route and workflow conventions and must be confirmed against deployment configuration.
- AST analysis is handler-scoped for supported TypeScript and JavaScript entry points; same-file helpers and supported Next.js middleware are followed, while arbitrary imported helper behavior remains partially unknown.
- Repository evidence coverage: 11/11 candidate files and 29910 bytes analyzed.

## Unknowns

- Sensitive assets were not confirmed in .hedge/context.yml.
- Internet-facing deployment surfaces were not confirmed in .hedge/context.yml.
- Authentication mechanisms were inferred from code and not confirmed in .hedge/context.yml.
- Privileged roles were not confirmed in .hedge/context.yml.
- Trusted external services were not confirmed in .hedge/context.yml.

## Update contract

- `hedge init` establishes or refreshes this baseline.
- Pull requests are compared against the stored graph in `threatmodel.json`.
- A finding moves to `verified` only after executable counterevidence succeeds on the vulnerable revision and is blocked on the repaired revision while legitimate behavior remains intact.
- Risk acceptance must record who, when, and why; it is never inferred from silence.
