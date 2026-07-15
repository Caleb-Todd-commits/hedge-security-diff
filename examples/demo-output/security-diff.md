<!-- hedge-security-diff -->
## 🌿 Hedge security diff

**Result:** 2 evidence-linked risk(s) surfaced; highest severity **high**.

Hedge surfaced 2 evidence-linked risk(s) using deterministic analysis. Model reasoning was skipped because no API key was supplied.

### Architecture delta

- +2 security-relevant node(s)
- +1 attack-surface edge(s)

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

### Findings

<details open>
<summary><strong>HEDGE-001 · HIGH · OPEN · New mutating entry point has no detected authentication control</strong></summary>

**Attack path:** `Public user` → `POST /api/files/upload` → `Privileged application operation`

**Potential impact:** An unauthenticated actor may invoke a state-changing operation.

**Existing controls:** Content type allowlist

**Missing controls:** Verified authentication, Authorization scoped to the target resource

**Security invariant:** Only authenticated and authorized principals may invoke POST /api/files/upload.

**Evidence:** `app/api/files/upload/route.ts:4`

**Confidence:** 90%

**Origin:** deterministic

**Suggested regression witness (not proof until executed):**

```ts
it("rejects unauthenticated access to POST /api/files/upload", async () => {
  const response = await requestWithoutSession();
  expect([401, 403]).toContain(response.status);
});
```

**Codex handoff:**

```text
@hedge fix HEDGE-001
```

</details>

<details open>
<summary><strong>HEDGE-002 · HIGH · OPEN · New storage write crosses a trust boundary without complete upload controls</strong></summary>

**Attack path:** `External user` → `POST /api/files/upload` → `Storage write`

**Potential impact:** Unexpected content, oversized payloads, or cross-tenant object writes may reach privileged storage.

**Existing controls:** Content type allowlist

**Missing controls:** Verified authentication, Payload or file size limit, Object ownership constraint

**Security invariant:** Uploaded content must be authenticated, tenant-scoped, type-checked, and bounded before storage.

**Evidence:** `app/api/files/upload/route.ts:4`, `app/api/files/upload/route.ts:13`

**Confidence:** 90%

**Origin:** deterministic

**Suggested regression witness (not proof until executed):**

```ts
it("enforces upload boundaries for POST /api/files/upload", async () => {
  const response = await uploadFixture({ type: "application/x-executable", bytes: MAX_ALLOWED_BYTES + 1 });
  expect([400, 413, 415]).toContain(response.status);
});
```

**Codex handoff:**

```text
@hedge fix HEDGE-002
```

</details>

<!-- hedge-findings-json:eyJzY2hlbWFWZXJzaW9uIjoiMC4yIiwiZmluZGluZ3MiOlt7ImlkIjoiSEVER0UtMDAxIiwiZmluZ2VycHJpbnQiOiIwMDE4MWVmNDI0MjM1OGM2ZWNmYTNjNTIiLCJ0aXRsZSI6Ik5ldyBtdXRhdGluZyBlbnRyeSBwb2ludCBoYXMgbm8gZGV0ZWN0ZWQgYXV0aGVudGljYXRpb24gY29udHJvbCIsInNldmVyaXR5IjoiaGlnaCIsIm9yaWdpbiI6ImRldGVybWluaXN0aWMiLCJzZWN1cml0eUludmFyaWFudCI6Ik9ubHkgYXV0aGVudGljYXRlZCBhbmQgYXV0aG9yaXplZCBwcmluY2lwYWxzIG1heSBpbnZva2UgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZC4iLCJhdHRhY2tQYXRoIjpbIlB1YmxpYyB1c2VyIiwiUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZCIsIlByaXZpbGVnZWQgYXBwbGljYXRpb24gb3BlcmF0aW9uIl0sIm1pc3NpbmdDb250cm9scyI6WyJWZXJpZmllZCBhdXRoZW50aWNhdGlvbiIsIkF1dGhvcml6YXRpb24gc2NvcGVkIHRvIHRoZSB0YXJnZXQgcmVzb3VyY2UiXSwiZXZpZGVuY2UiOlt7ImZpbGUiOiJhcHAvYXBpL2ZpbGVzL3VwbG9hZC9yb3V0ZS50cyIsImxpbmUiOjQsInNuaXBwZXQiOiJleHBvcnQgYXN5bmMgZnVuY3Rpb24gUE9TVChyZXF1ZXN0OiBSZXF1ZXN0KSB7IiwiZXh0cmFjdG9yIjoibmV4dGpzLWFzdC1yb3V0ZSJ9XSwic3VnZ2VzdGVkVGVzdCI6eyJ0aXRsZSI6IlJlZ3Jlc3Npb24gd2l0bmVzcyBmb3IgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZCIsImZyYW1ld29yayI6InZpdGVzdCIsImxhbmd1YWdlIjoidHlwZXNjcmlwdCIsInB1cnBvc2UiOiJPbmx5IGF1dGhlbnRpY2F0ZWQgYW5kIGF1dGhvcml6ZWQgcHJpbmNpcGFscyBtYXkgaW52b2tlIFBPU1QgL2FwaS9maWxlcy91cGxvYWQuIiwiY29kZSI6Iml0KFwicmVqZWN0cyB1bmF1dGhlbnRpY2F0ZWQgYWNjZXNzIHRvIFBPU1QgL2FwaS9maWxlcy91cGxvYWRcIiwgYXN5bmMgKCkgPT4ge1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHJlcXVlc3RXaXRob3V0U2Vzc2lvbigpO1xuICBleHBlY3QoWzQwMSwgNDAzXSkudG9Db250YWluKHJlc3BvbnNlLnN0YXR1cyk7XG59KTsifX0seyJpZCI6IkhFREdFLTAwMiIsImZpbmdlcnByaW50IjoiOTU2MjVjNTY1OWQ3ZTUzOTI3MDUyMjVmIiwidGl0bGUiOiJOZXcgc3RvcmFnZSB3cml0ZSBjcm9zc2VzIGEgdHJ1c3QgYm91bmRhcnkgd2l0aG91dCBjb21wbGV0ZSB1cGxvYWQgY29udHJvbHMiLCJzZXZlcml0eSI6ImhpZ2giLCJvcmlnaW4iOiJkZXRlcm1pbmlzdGljIiwic2VjdXJpdHlJbnZhcmlhbnQiOiJVcGxvYWRlZCBjb250ZW50IG11c3QgYmUgYXV0aGVudGljYXRlZCwgdGVuYW50LXNjb3BlZCwgdHlwZS1jaGVja2VkLCBhbmQgYm91bmRlZCBiZWZvcmUgc3RvcmFnZS4iLCJhdHRhY2tQYXRoIjpbIkV4dGVybmFsIHVzZXIiLCJQT1NUIC9hcGkvZmlsZXMvdXBsb2FkIiwiU3RvcmFnZSB3cml0ZSJdLCJtaXNzaW5nQ29udHJvbHMiOlsiVmVyaWZpZWQgYXV0aGVudGljYXRpb24iLCJQYXlsb2FkIG9yIGZpbGUgc2l6ZSBsaW1pdCIsIk9iamVjdCBvd25lcnNoaXAgY29uc3RyYWludCJdLCJldmlkZW5jZSI6W3siZmlsZSI6ImFwcC9hcGkvZmlsZXMvdXBsb2FkL3JvdXRlLnRzIiwibGluZSI6NCwic25pcHBldCI6ImV4cG9ydCBhc3luYyBmdW5jdGlvbiBQT1NUKHJlcXVlc3Q6IFJlcXVlc3QpIHsiLCJleHRyYWN0b3IiOiJuZXh0anMtYXN0LXJvdXRlIn0seyJmaWxlIjoiYXBwL2FwaS9maWxlcy91cGxvYWQvcm91dGUudHMiLCJsaW5lIjoxMywic25pcHBldCI6ImF3YWl0IGNsaWVudC5zZW5kKCIsImV4dHJhY3RvciI6InR5cGVzY3JpcHQtYXN0LW9wZXJhdGlvbiJ9XSwic3VnZ2VzdGVkVGVzdCI6eyJ0aXRsZSI6IlJlZ3Jlc3Npb24gd2l0bmVzcyBmb3IgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZCIsImZyYW1ld29yayI6InZpdGVzdCIsImxhbmd1YWdlIjoidHlwZXNjcmlwdCIsInB1cnBvc2UiOiJVcGxvYWRlZCBjb250ZW50IG11c3QgYmUgYXV0aGVudGljYXRlZCwgdGVuYW50LXNjb3BlZCwgdHlwZS1jaGVja2VkLCBhbmQgYm91bmRlZCBiZWZvcmUgc3RvcmFnZS4iLCJjb2RlIjoiaXQoXCJlbmZvcmNlcyB1cGxvYWQgYm91bmRhcmllcyBmb3IgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZFwiLCBhc3luYyAoKSA9PiB7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBsb2FkRml4dHVyZSh7IHR5cGU6IFwiYXBwbGljYXRpb24veC1leGVjdXRhYmxlXCIsIGJ5dGVzOiBNQVhfQUxMT1dFRF9CWVRFUyArIDEgfSk7XG4gIGV4cGVjdChbNDAwLCA0MTMsIDQxNV0pLnRvQ29udGFpbihyZXNwb25zZS5zdGF0dXMpO1xufSk7In19XSwicGF5bG9hZERpZ2VzdCI6ImM2ZTY2YTdlNDE5MGZlNWNjNWM0Y2I0OWFmMjIyZWM3Zjc0ZjQ2NjRjZTc1ZTU2ZjcxNmQxMDZlM2NiZGFhM2EifQ== -->

### Analysis integrity

- Untrusted instruction-like content observed: **no**
- Analysis boundary held: **yes**
- Offline analysis mode: repository content was parsed as data and no model call was made.

### Limits

- GPT-5.6 architectural interpretation was not run.

<sub>Hedge surfaces attack-surface changes and design risks. It does not claim to find or prove vulnerabilities.</sub>
