<!-- hedge-security-diff -->
## 🌿 Hedge security architecture diff

**Result:** 2 evidence-linked design risk(s) surfaced; highest severity **high**.

### 1. What changed

Hedge surfaced 2 evidence-linked risk\(s\) using deterministic analysis. Model reasoning was skipped because no API key was supplied.

- +2 security-relevant node\(s\)
- +1 attack-surface edge\(s\)

### 2. Recorded decision

- Outcome: **BLOCK**
- Source: **threshold**
- Basis: 2 unresolved finding\(s\) meet or exceed the high failure threshold.

### 3. Exact evidence

- **HEDGE-001:** `app/api/files/upload/route.ts:3`
- **HEDGE-002:** `app/api/files/upload/route.ts:3`
- **HEDGE-002:** `app/api/files/upload/route.ts:6`

### 4. Next action

Resolve the recorded decision before merge. Review the evidence, then use `@​hedge fix HEDGE-001` to request a draft repair.

### 5. Coverage and health

- Coverage: **COMPLETE**
- Analysis health: **COMPLETE**
- Confirmed no-delta: **no**
- Included: **17/17 files**, **9742 bytes**

<details>
<summary><strong>HEDGE-001 · HIGH · OPEN · New mutating entry point has no detected authentication control</strong></summary>

**Attack path:** `Public user` → `POST /api/files/upload` → `Privileged application operation`

**Potential impact:** An unauthenticated actor may invoke a state-changing operation.

**Existing controls:** none detected

**Missing controls:** Verified authentication, Authorization scoped to the target resource

**Security invariant:** Only authenticated and authorized principals may invoke POST /api/files/upload.

**Evidence:** `app/api/files/upload/route.ts:3`

**Confidence:** 90%

**Origin:** deterministic

**Suggested regression witness (not proof until executed):**

```ts
it("rejects unauthenticated access to POST /api/files/upload", async () => {
  const response = await requestWithoutSession();
  expect([401, 403]).toContain(response.status);
});
```

**Draft repair handoff:**

```text
@hedge fix HEDGE-001
```

</details>

<details>
<summary><strong>HEDGE-002 · HIGH · OPEN · New storage write crosses a trust boundary without complete upload controls</strong></summary>

**Attack path:** `External user` → `POST /api/files/upload` → `Storage write`

**Potential impact:** Unexpected content, oversized payloads, or cross-tenant object writes may reach privileged storage.

**Existing controls:** none detected

**Missing controls:** Verified authentication, Payload or file size limit, Content type allowlist, Object ownership constraint

**Security invariant:** Uploaded content must be authenticated, tenant-scoped, type-checked, and bounded before storage.

**Evidence:** `app/api/files/upload/route.ts:3`, `app/api/files/upload/route.ts:6`

**Confidence:** 90%

**Origin:** deterministic

**Suggested regression witness (not proof until executed):**

```ts
it("enforces upload boundaries for POST /api/files/upload", async () => {
  const response = await uploadFixture({ type: "application/x-executable", bytes: MAX_ALLOWED_BYTES + 1 });
  expect([400, 413, 415]).toContain(response.status);
});
```

**Draft repair handoff:**

```text
@hedge fix HEDGE-002
```

</details>

<details>
<summary><strong>Technical details, graph, and limitations</strong></summary>

#### Architecture graph

```mermaid
flowchart LR
  n_auth_control_7bf2b37d213596d1[Authentication check: auth]
  class n_auth_control_7bf2b37d213596d1 application;
  n_authorization_control_20b83844dc80aa0d[Resource ownership derivation]
  class n_authorization_control_20b83844dc80aa0d application;
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
  n_entrypoint_7687698fbe395d3f -->|authorizes| n_authorization_control_20b83844dc80aa0d
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

#### Evidence model

- Deterministic observations: **3**
- Security inferences: **2**
- Recorded decisions: **1**

#### Analysis integrity

- Untrusted instruction-like content observed: **no**
- Analysis boundary held: **yes**
- Offline analysis mode: repository content was parsed as data and no model call was made.

#### Limits

- GPT-5.6 architectural interpretation was not run.

</details>

<sub>Hedge surfaces security-architecture changes and design risks. It does not claim to find or prove vulnerabilities.</sub>

<!-- hedge-findings-json:eyJzY2hlbWFWZXJzaW9uIjoiMC4zIiwic291cmNlQ29tbWl0IjoiOTQ1M2UxMDdkNmFhYjVlYWRhYmZiMTg1ZTJlOTc0ZmNmMTZiNmE0MSIsInRvdGFsRmluZGluZ0NvdW50IjoyLCJvbWl0dGVkRmluZGluZ0NvdW50IjowLCJmaW5kaW5ncyI6W3siaWQiOiJIRURHRS0wMDEiLCJmaW5nZXJwcmludCI6IjAwMTgxZWY0MjQyMzU4YzZlY2ZhM2M1MiIsInRpdGxlIjoiTmV3IG11dGF0aW5nIGVudHJ5IHBvaW50IGhhcyBubyBkZXRlY3RlZCBhdXRoZW50aWNhdGlvbiBjb250cm9sIiwic2V2ZXJpdHkiOiJoaWdoIiwib3JpZ2luIjoiZGV0ZXJtaW5pc3RpYyIsInNlY3VyaXR5SW52YXJpYW50IjoiT25seSBhdXRoZW50aWNhdGVkIGFuZCBhdXRob3JpemVkIHByaW5jaXBhbHMgbWF5IGludm9rZSBQT1NUIC9hcGkvZmlsZXMvdXBsb2FkLiIsImF0dGFja1BhdGgiOlsiUHVibGljIHVzZXIiLCJQT1NUIC9hcGkvZmlsZXMvdXBsb2FkIiwiUHJpdmlsZWdlZCBhcHBsaWNhdGlvbiBvcGVyYXRpb24iXSwibWlzc2luZ0NvbnRyb2xzIjpbIlZlcmlmaWVkIGF1dGhlbnRpY2F0aW9uIiwiQXV0aG9yaXphdGlvbiBzY29wZWQgdG8gdGhlIHRhcmdldCByZXNvdXJjZSJdLCJldmlkZW5jZSI6W3siZmlsZSI6ImFwcC9hcGkvZmlsZXMvdXBsb2FkL3JvdXRlLnRzIiwibGluZSI6MywiZXh0cmFjdG9yIjoibmV4dGpzLWFzdC1yb3V0ZSIsImNvbW1pdCI6Ijk0NTNlMTA3ZDZhYWI1ZWFkYWJmYjE4NWUyZTk3NGZjZjE2YjZhNDEifV0sInN1Z2dlc3RlZFRlc3QiOnsidGl0bGUiOiJSZWdyZXNzaW9uIHdpdG5lc3MgZm9yIFBPU1QgL2FwaS9maWxlcy91cGxvYWQiLCJmcmFtZXdvcmsiOiJ2aXRlc3QiLCJsYW5ndWFnZSI6InR5cGVzY3JpcHQiLCJwdXJwb3NlIjoiT25seSBhdXRoZW50aWNhdGVkIGFuZCBhdXRob3JpemVkIHByaW5jaXBhbHMgbWF5IGludm9rZSBQT1NUIC9hcGkvZmlsZXMvdXBsb2FkLiIsImNvZGUiOiJpdChcInJlamVjdHMgdW5hdXRoZW50aWNhdGVkIGFjY2VzcyB0byBQT1NUIC9hcGkvZmlsZXMvdXBsb2FkXCIsIGFzeW5jICgpID0+IHtcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCByZXF1ZXN0V2l0aG91dFNlc3Npb24oKTtcbiAgZXhwZWN0KFs0MDEsIDQwM10pLnRvQ29udGFpbihyZXNwb25zZS5zdGF0dXMpO1xufSk7In19LHsiaWQiOiJIRURHRS0wMDIiLCJmaW5nZXJwcmludCI6ImNlNDVhNjcwYTMwYTU1MTI0NDI0MDMzYiIsInRpdGxlIjoiTmV3IHN0b3JhZ2Ugd3JpdGUgY3Jvc3NlcyBhIHRydXN0IGJvdW5kYXJ5IHdpdGhvdXQgY29tcGxldGUgdXBsb2FkIGNvbnRyb2xzIiwic2V2ZXJpdHkiOiJoaWdoIiwib3JpZ2luIjoiZGV0ZXJtaW5pc3RpYyIsInNlY3VyaXR5SW52YXJpYW50IjoiVXBsb2FkZWQgY29udGVudCBtdXN0IGJlIGF1dGhlbnRpY2F0ZWQsIHRlbmFudC1zY29wZWQsIHR5cGUtY2hlY2tlZCwgYW5kIGJvdW5kZWQgYmVmb3JlIHN0b3JhZ2UuIiwiYXR0YWNrUGF0aCI6WyJFeHRlcm5hbCB1c2VyIiwiUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZCIsIlN0b3JhZ2Ugd3JpdGUiXSwibWlzc2luZ0NvbnRyb2xzIjpbIlZlcmlmaWVkIGF1dGhlbnRpY2F0aW9uIiwiUGF5bG9hZCBvciBmaWxlIHNpemUgbGltaXQiLCJDb250ZW50IHR5cGUgYWxsb3dsaXN0IiwiT2JqZWN0IG93bmVyc2hpcCBjb25zdHJhaW50Il0sImV2aWRlbmNlIjpbeyJmaWxlIjoiYXBwL2FwaS9maWxlcy91cGxvYWQvcm91dGUudHMiLCJsaW5lIjozLCJleHRyYWN0b3IiOiJuZXh0anMtYXN0LXJvdXRlIiwiY29tbWl0IjoiOTQ1M2UxMDdkNmFhYjVlYWRhYmZiMTg1ZTJlOTc0ZmNmMTZiNmE0MSJ9LHsiZmlsZSI6ImFwcC9hcGkvZmlsZXMvdXBsb2FkL3JvdXRlLnRzIiwibGluZSI6NiwiZXh0cmFjdG9yIjoidHlwZXNjcmlwdC1hc3Qtb3BlcmF0aW9uIiwiY29tbWl0IjoiOTQ1M2UxMDdkNmFhYjVlYWRhYmZiMTg1ZTJlOTc0ZmNmMTZiNmE0MSJ9XSwic3VnZ2VzdGVkVGVzdCI6eyJ0aXRsZSI6IlJlZ3Jlc3Npb24gd2l0bmVzcyBmb3IgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZCIsImZyYW1ld29yayI6InZpdGVzdCIsImxhbmd1YWdlIjoidHlwZXNjcmlwdCIsInB1cnBvc2UiOiJVcGxvYWRlZCBjb250ZW50IG11c3QgYmUgYXV0aGVudGljYXRlZCwgdGVuYW50LXNjb3BlZCwgdHlwZS1jaGVja2VkLCBhbmQgYm91bmRlZCBiZWZvcmUgc3RvcmFnZS4iLCJjb2RlIjoiaXQoXCJlbmZvcmNlcyB1cGxvYWQgYm91bmRhcmllcyBmb3IgUE9TVCAvYXBpL2ZpbGVzL3VwbG9hZFwiLCBhc3luYyAoKSA9PiB7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBsb2FkRml4dHVyZSh7IHR5cGU6IFwiYXBwbGljYXRpb24veC1leGVjdXRhYmxlXCIsIGJ5dGVzOiBNQVhfQUxMT1dFRF9CWVRFUyArIDEgfSk7XG4gIGV4cGVjdChbNDAwLCA0MTMsIDQxNV0pLnRvQ29udGFpbihyZXNwb25zZS5zdGF0dXMpO1xufSk7In19XSwicGF5bG9hZERpZ2VzdCI6IjYwM2U0ZDFhYTU3YzliYzk3ZTYxYmYyZDZjNzI4NTlmYTBmOWEzNTM4ZTc1YmM2ODM5ZWM1YmE0ZWUwMDllNzcifQ== -->
