# Demo script — under three minutes

## 0:00–0:20 — Hook

“Code review shows which lines changed. It does not show how the system's security architecture changed. And most threat models are stale before the next sprint.”

Show a static threat-model document beside a repository with many later commits.

## 0:20–0:45 — Bootstrap

Run:

```bash
npx hedge init
```

Show `THREATMODEL.md`, evidence links, and Mermaid graph.

Narration:

“Hedge extracts supported routes, trust zones, controls, data operations, and privileged capabilities from code evidence. GPT-5.6 does not invent the architecture.”

## 0:45–1:25 — Money shot

Open the prepared file-upload PR.

Show:

```text
+1 public entry point
+1 trust-boundary crossing
+1 privileged storage operation
0 complete upload-control sets
```

Animate or highlight the new red attack path:

```text
Public user → POST /api/files/upload → object storage
```

Show exact file and line evidence, missing controls, and suggested witness.

## 1:25–2:05 — Codex remediation

Comment:

```text
@hedge fix HEDGE-003
```

Show Codex creating a focused draft PR with:

- Authentication or authorization where required.
- Tenant-scoped object key.
- Content-type allowlist.
- Size limit.
- Regression witness.

Narration must explicitly explain how Codex built the repair and tests.

## 2:05–2:30 — Verification

Show:

```text
Vulnerable revision: witness succeeds
Repaired revision: witness blocked
Legitimate upload: succeeds
Architecture control: changed
```

Risk becomes `verified`, and the graph gains a verified control.

## 2:30–2:43 — Silence

Open a benign refactor. Green check, no comment, no model call.

## 2:43–2:55 — Build story

Show a rapid Codex-session montage, Structured Output schema, Luna/Sol routing, and measured eval numbers.

Narration must explicitly cover both GPT-5.6 and Codex.

## 2:55–3:00 — Finish

“Hedge gives every pull request a security diff. GPT-5.6 explains it, Codex repairs it, and evidence proves the result.”

## Production notes

- Record at 1080p or higher.
- Use large terminal and editor fonts.
- Include captions because judges may watch muted.
- Pre-run and cache model outputs; do not film an API wait.
- Show real output, not fabricated screenshots.
- Keep optional prompt-injection footage only if the main sequence remains under time.
